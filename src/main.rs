//! Command-line entry point for otp.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};

use otp::{
    find_entry, parse_store, resolve_secret, seconds_remaining, totp_at, validate_service_name,
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
    Add { service: String, secret: String },
    /// Remove a service.
    Rm { service: String },
    /// List available services.
    Ls,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(Command_::Add { service, secret }) => cmd_add(&service, &secret),
        Some(Command_::Rm { service }) => cmd_rm(&service),
        Some(Command_::Ls) => cmd_list(),
        None => match cli.generate.service.clone() {
            Some(service) => cmd_generate(&service, &cli.generate),
            None => cmd_list(),
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

/// Write the store with owner-only (0600) permissions.
fn write_store(path: &PathBuf, content: &str) -> Result<()> {
    std::fs::write(path, content).with_context(|| format!("failed to write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to set permissions on {}", path.display()))?;
    }
    Ok(())
}

fn unix_now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before 1970")?
        .as_secs())
}

fn cmd_generate(service: &str, opts: &GenerateArgs) -> Result<()> {
    let path = secrets_path()?;
    let entries = parse_store(&read_store(&path)?);
    let entry = find_entry(&entries, service)
        .ok_or_else(|| anyhow!("service {service:?} not found (see: otp ls)"))?;

    let params = resolve_secret(&entry.value)
        .with_context(|| format!("invalid secret for service {service:?}"))?;
    let now = unix_now()?;
    let code = totp_at(&params, now);
    let remaining = seconds_remaining(&params, now);

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
        println!("OTP: {code} (copied to clipboard, valid {remaining}s)");
    } else {
        println!("OTP: {code} (valid {remaining}s)");
    }
    Ok(())
}

fn cmd_add(service: &str, secret_arg: &str) -> Result<()> {
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

fn cmd_list() -> Result<()> {
    let path = secrets_path()?;
    let entries = parse_store(&read_store(&path)?);
    if entries.is_empty() {
        println!("No services yet. Add one with: otp add <service> <secret>");
        return Ok(());
    }
    println!("Usage: otp <service>");
    println!("Available services:");
    for entry in &entries {
        println!("  - {}", entry.service);
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
