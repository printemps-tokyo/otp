//! Command-line entry point for otp.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};

use otp::{
    code_at, find_entry, hotp_uri, import_payload, parse_store, resolve_entry, resolve_secret,
    seconds_remaining, set_counter, suggest_service_name, validate_service_name, Resolution,
};

/// Generate TOTP one-time passwords from a local secrets file.
#[derive(Parser, Debug)]
#[command(name = "otp", version, about, long_about = None)]
#[command(args_conflicts_with_subcommands = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command_>,

    #[command(flatten)]
    generate: GenerateArgs,
}

/// Arguments for the default action: generate a code for a service.
#[derive(Args, Debug)]
struct GenerateArgs {
    /// Service to generate a code for. Omit to list available services.
    service: Option<String>,

    /// Print only the code (no label) and do not touch the clipboard.
    #[arg(short, long)]
    quiet: bool,

    /// Do not copy the code to the clipboard.
    #[arg(long)]
    no_copy: bool,
}

#[derive(Subcommand, Debug)]
enum Command_ {
    /// Add a service. SECRET may be a base32 secret, an otpauth:// URI, or `-`
    /// to read it from stdin (so it stays out of your shell history).
    Add {
        service: String,
        secret: String,
        /// The secret is for HOTP (counter-based) codes, not TOTP.
        #[arg(long)]
        hotp: bool,
        /// With --hotp: the counter of the next code (default 0).
        #[arg(long, requires = "hotp")]
        counter: Option<u64>,
    },
    /// Remove a service.
    Rm { service: String },
    /// List available services.
    Ls {
        /// Also show each TOTP service's current code and how long it is
        /// valid (HOTP codes are shown only when asked for, as each one uses
        /// up a counter value).
        #[arg(short, long)]
        codes: bool,
    },
    /// Add the accounts in a QR code image (PNG or JPEG): an otpauth:// code
    /// or a Google Authenticator export, which can hold several accounts.
    /// `-` reads the QR's text (an otpauth:// or otpauth-migration:// URI)
    /// from stdin instead.
    Import {
        image: PathBuf,
        /// Service name, for a code with a single account (default: from the
        /// issuer).
        #[arg(long)]
        name: Option<String>,
        /// Show the services that would be added, and add nothing.
        #[arg(long)]
        dry_run: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(Command_::Add {
            service,
            secret,
            hotp,
            counter,
        }) => cmd_add(&service, &secret, hotp.then(|| counter.unwrap_or(0))),
        Some(Command_::Rm { service }) => cmd_rm(&service),
        Some(Command_::Ls { codes }) => cmd_list(codes),
        Some(Command_::Import {
            image,
            name,
            dry_run,
        }) => cmd_import(&image, name.as_deref(), dry_run),
        None => match cli.generate.service.clone() {
            Some(service) => cmd_generate(&service, &cli.generate),
            None => cmd_list(false),
        },
    }
}

/// The secrets file: `$OTP_SECRETS_FILE`, else `~/.otp_secrets`.
fn secrets_path() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("OTP_SECRETS_FILE") {
        if !path.is_empty() {
            return Ok(PathBuf::from(path));
        }
    }
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|_| anyhow!("cannot find home directory (set OTP_SECRETS_FILE)"))?;
    Ok(PathBuf::from(home).join(".otp_secrets"))
}

fn read_store(path: &PathBuf) -> Result<String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e).with_context(|| format!("failed to read {}", path.display())),
    }
}

/// Write the store through a new owner-only (0600) file renamed over the old
/// one: the secrets are never readable by others, not even for a moment, and
/// an interrupted write leaves the old store whole.
fn write_store(path: &PathBuf, content: &str) -> Result<()> {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut tmp = None;
    for n in 0..100 {
        let candidate = dir.join(format!(".{name}.{}.{n}.tmp", std::process::id()));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        match opts.open(&candidate) {
            Ok(f) => {
                tmp = Some((candidate, f));
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e).with_context(|| format!("failed to write {}", path.display())),
        }
    }
    let (tmp_path, mut f) =
        tmp.ok_or_else(|| anyhow!("failed to write {}: no free temporary name", path.display()))?;
    let result = f
        .write_all(content.as_bytes())
        .and_then(|_| f.sync_all())
        .and_then(|_| std::fs::rename(&tmp_path, path));
    if let Err(e) = result {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e).with_context(|| format!("failed to write {}", path.display()));
    }
    Ok(())
}

/// The store with the value of `service`'s line replaced, everything else
/// (comments, blank lines, order) kept.
fn replace_value(raw: &str, service: &str, value: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    for line in raw.lines() {
        let t = line.trim();
        let is_target = !t.is_empty()
            && !t.starts_with('#')
            && t.split_once(':').is_some_and(|(s, _)| s.trim() == service);
        out.push(if is_target {
            format!("{service}:{value}")
        } else {
            line.to_string()
        });
    }
    let mut content = out.join("\n");
    content.push('\n');
    content
}

fn unix_now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before 1970")?
        .as_secs())
}

fn cmd_generate(service: &str, opts: &GenerateArgs) -> Result<()> {
    // An empty query would substring-match every entry; reject it up front
    // instead of reporting the whole store as "ambiguous".
    if service.trim().is_empty() {
        bail!("service name required");
    }
    let path = secrets_path()?;
    let entries = parse_store(&read_store(&path)?);
    // Resolve the name: exact match first, then unique prefix, then unique
    // substring. Anything ambiguous is an error, so scripts never get a code
    // for a service the user did not mean.
    let entry = match resolve_entry(&entries, service) {
        Resolution::Unique(entry) => entry,
        Resolution::Ambiguous(candidates) => bail!(
            "service {service:?} is ambiguous; candidates:\n  {}",
            candidates.join("\n  ")
        ),
        Resolution::NotFound(suggestions) if suggestions.is_empty() => {
            bail!("service {service:?} not found (see: otp ls)")
        }
        Resolution::NotFound(suggestions) => bail!(
            "service {service:?} not found; did you mean:\n  {}",
            suggestions.join("\n  ")
        ),
    };
    if entry.service != service {
        eprintln!("otp: matched service {}", entry.service);
    }

    let params = resolve_secret(&entry.value)
        .with_context(|| format!("invalid secret for service {:?}", entry.service))?;
    let now = unix_now()?;
    let code = code_at(&params, now);
    let validity = match params.hotp_counter {
        Some(counter) => {
            // Advance the counter before showing the code, so a code is never
            // shown twice even if this run is interrupted.
            let raw = read_store(&path)?;
            let next = set_counter(&entry.value, counter + 1);
            write_store(&path, &replace_value(&raw, &entry.service, &next))?;
            format!("HOTP counter {counter}")
        }
        None => format!("valid {}s", seconds_remaining(&params, now)),
    };

    if opts.quiet {
        println!("{code}");
        return Ok(());
    }

    let copied = if opts.no_copy {
        false
    } else {
        copy_to_clipboard(&code).is_ok()
    };
    if copied {
        println!("OTP: {code} (copied to clipboard, {validity})");
    } else {
        println!("OTP: {code} ({validity})");
    }
    Ok(())
}

fn cmd_add(service: &str, secret_arg: &str, hotp_counter: Option<u64>) -> Result<()> {
    validate_service_name(service)?;

    let secret = if secret_arg == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("failed to read secret from stdin")?;
        buf.trim().to_string()
    } else {
        secret_arg.trim().to_string()
    };
    if secret.is_empty() {
        bail!("no secret provided");
    }
    let secret = match hotp_counter {
        Some(_) if secret.starts_with("otpauth://") => {
            bail!("--hotp is for a bare secret; an otpauth:// URI says its own type")
        }
        Some(counter) => hotp_uri(service, &secret, counter),
        None => secret,
    };
    // Validate up front so we never store something that cannot generate.
    resolve_secret(&secret).context("the provided secret is not valid")?;

    let path = secrets_path()?;
    let raw = read_store(&path)?;
    if find_entry(&parse_store(&raw), service).is_some() {
        bail!("service {service:?} already exists (remove it first: otp rm {service})");
    }

    let mut content = raw;
    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
    content.push_str(&format!("{service}:{secret}\n"));
    write_store(&path, &content)?;
    eprintln!("otp: added {service}");
    Ok(())
}

fn cmd_rm(service: &str) -> Result<()> {
    let path = secrets_path()?;
    let raw = read_store(&path)?;
    if find_entry(&parse_store(&raw), service).is_none() {
        bail!("service {service:?} not found");
    }

    // Keep comments, blanks, and unrelated lines; drop only the matching entry.
    let mut kept: Vec<&str> = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        let is_target = !trimmed.is_empty()
            && !trimmed.starts_with('#')
            && trimmed
                .split_once(':')
                .map(|(s, _)| s.trim() == service)
                .unwrap_or(false);
        if !is_target {
            kept.push(line);
        }
    }
    let mut content = kept.join("\n");
    if !content.is_empty() {
        content.push('\n');
    }
    write_store(&path, &content)?;
    eprintln!("otp: removed {service}");
    Ok(())
}

fn cmd_list(codes: bool) -> Result<()> {
    let path = secrets_path()?;
    let entries = parse_store(&read_store(&path)?);
    if entries.is_empty() {
        println!("No services yet. Add one with: otp add <service> <secret>");
        return Ok(());
    }
    if !codes {
        println!("Usage: otp <service>");
        println!("Available services:");
        for entry in &entries {
            println!("  - {}", entry.service);
        }
        return Ok(());
    }
    let now = unix_now()?;
    let width = entries
        .iter()
        .map(|e| e.service.chars().count())
        .max()
        .unwrap_or(0);
    for entry in &entries {
        let shown = match resolve_secret(&entry.value) {
            Ok(p) if p.hotp_counter.is_some() => {
                "(HOTP: otp <service> uses the next counter)".to_string()
            }
            Ok(p) => format!("{}  {:>2}s", code_at(&p, now), seconds_remaining(&p, now)),
            Err(_) => "(invalid secret)".to_string(),
        };
        println!("{:<width$}  {shown}", entry.service);
    }
    Ok(())
}

/// Read the QR codes in an image and return their text.
fn decode_qr_image(path: &std::path::Path) -> Result<Vec<String>> {
    let img = image::open(path)
        .with_context(|| format!("failed to read {} as a PNG or JPEG image", path.display()))?
        .to_luma8();
    let (w, h) = img.dimensions();
    let mut prepared =
        rqrr::PreparedImage::prepare_from_greyscale(w as usize, h as usize, |x, y| {
            img.get_pixel(x as u32, y as u32)[0]
        });
    let mut out = Vec::new();
    for grid in prepared.detect_grids() {
        match grid.decode() {
            Ok((_, text)) => out.push(text),
            Err(e) => eprintln!("otp: a QR code in the image could not be read: {e}"),
        }
    }
    if out.is_empty() {
        bail!("no readable QR code in {}", path.display());
    }
    Ok(out)
}

fn cmd_import(image: &std::path::Path, name: Option<&str>, dry_run: bool) -> Result<()> {
    let payloads = if image.as_os_str() == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("failed to read from stdin")?;
        vec![buf]
    } else {
        decode_qr_image(image)?
    };
    let mut items = Vec::new();
    for p in &payloads {
        items.extend(import_payload(p)?);
    }
    if name.is_some() && items.len() != 1 {
        bail!(
            "--name needs a code with exactly one account (this one has {})",
            items.len()
        );
    }

    let path = secrets_path()?;
    let raw = read_store(&path)?;
    let existing = parse_store(&raw);
    let mut planned: Vec<(String, String, String)> = Vec::new();
    for item in &items {
        let service = name
            .map(str::to_string)
            .unwrap_or_else(|| suggest_service_name(item));
        validate_service_name(&service)?;
        if find_entry(&existing, &service).is_some()
            || planned.iter().any(|(s, _, _)| *s == service)
        {
            bail!(
                "service {service:?} already exists or is imported twice; nothing was added (use --name, or otp rm {service})"
            );
        }
        // Check that it generates before anything is stored.
        resolve_secret(&item.uri)
            .with_context(|| format!("the account for {service:?} is not usable"))?;
        let who = match (item.issuer.is_empty(), item.account.is_empty()) {
            (false, false) => format!("{}, {}", item.issuer, item.account),
            (false, true) => item.issuer.clone(),
            _ => item.account.clone(),
        };
        planned.push((service, item.uri.clone(), who));
    }

    if dry_run {
        for (service, _, who) in &planned {
            println!("would add {service} ({who})");
        }
        return Ok(());
    }
    let mut content = raw;
    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
    for (service, uri, _) in &planned {
        content.push_str(&format!("{service}:{uri}\n"));
    }
    write_store(&path, &content)?;
    for (service, _, who) in &planned {
        eprintln!("otp: added {service} ({who})");
    }
    Ok(())
}

/// Copy text to the system clipboard via the first available helper command.
fn copy_to_clipboard(text: &str) -> Result<()> {
    // pbcopy: macOS, wl-copy: Wayland, xclip: X11, clip.exe: WSL/Windows.
    let candidates: [(&str, &[&str]); 4] = [
        ("pbcopy", &[]),
        ("wl-copy", &[]),
        ("xclip", &["-selection", "clipboard"]),
        ("clip.exe", &[]),
    ];
    for (program, args) in candidates {
        match Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .spawn()
        {
            Ok(mut child) => {
                child
                    .stdin
                    .take()
                    .ok_or_else(|| anyhow!("failed to open {program} stdin"))?
                    .write_all(text.as_bytes())?;
                let status = child.wait()?;
                if status.success() {
                    return Ok(());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e).with_context(|| format!("failed to run {program}")),
        }
    }
    bail!("no clipboard tool found (install pbcopy/wl-copy/xclip)")
}
