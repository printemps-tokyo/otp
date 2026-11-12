//! otp — generate TOTP one-time passwords from a local secrets file.
//!
//! This library implements the RFC 4226 (HOTP) and RFC 6238 (TOTP) algorithms
//! directly on top of HMAC, so the tool needs no external `oathtool` binary.
//! Everything here is pure: the time and the secrets file are passed in by the
//! caller, which keeps the code easy to test against the RFC test vectors.

use anyhow::{anyhow, bail, Context, Result};
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

/// The HMAC hash used by a TOTP secret. SHA-1 is the near-universal default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl Algorithm {
    /// Parse an algorithm name (`SHA1` / `SHA256` / `SHA512`, case-insensitive).
    pub fn parse(name: &str) -> Result<Algorithm> {
        match name.trim().to_ascii_uppercase().as_str() {
            "SHA1" => Ok(Algorithm::Sha1),
            "SHA256" => Ok(Algorithm::Sha256),
            "SHA512" => Ok(Algorithm::Sha512),
            other => Err(anyhow!(
                "unsupported algorithm {other:?} (use SHA1/SHA256/SHA512)"
            )),
        }
    }
}

/// A fully resolved TOTP configuration: the decoded key plus its parameters.
#[derive(Debug, Clone)]
pub struct TotpParams {
    pub key: Vec<u8>,
    pub digits: u32,
    pub period: u64,
    pub algorithm: Algorithm,
    /// For an HOTP (counter-based, RFC 4226) secret, the counter of the next
    /// code; None for TOTP.
    pub hotp_counter: Option<u64>,
}

impl TotpParams {
    /// Build parameters from a base32-encoded secret, validating the ranges.
    pub fn from_base32(
        secret: &str,
        digits: u32,
        period: u64,
        algorithm: Algorithm,
    ) -> Result<Self> {
        if !(1..=9).contains(&digits) {
            bail!("digits must be between 1 and 9 (got {digits})");
        }
        if period == 0 {
            bail!("period must be greater than zero");
        }
        let key = decode_base32(secret)?;
        if key.is_empty() {
            bail!("secret decodes to an empty key");
        }
        Ok(Self {
            key,
            digits,
            period,
            algorithm,
            hotp_counter: None,
        })
    }
}

/// Decode a base32 (RFC 4648) secret, ignoring spaces, padding, and case.
pub fn decode_base32(secret: &str) -> Result<Vec<u8>> {
    let cleaned: String = secret
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .collect::<String>()
        .to_ascii_uppercase();
    if cleaned.is_empty() {
        bail!("empty secret");
    }
    data_encoding::BASE32_NOPAD
        .decode(cleaned.as_bytes())
        .map_err(|e| anyhow!("invalid base32 secret: {e}"))
}

fn hmac_digest(algorithm: Algorithm, key: &[u8], message: &[u8]) -> Vec<u8> {
    // HMAC accepts a key of any length, so `new_from_slice` cannot fail here.
    match algorithm {
        Algorithm::Sha1 => {
            let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC accepts any key length");
            mac.update(message);
            mac.finalize().into_bytes().to_vec()
        }
        Algorithm::Sha256 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
            mac.update(message);
            mac.finalize().into_bytes().to_vec()
        }
        Algorithm::Sha512 => {
            let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("HMAC accepts any key length");
            mac.update(message);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

/// Compute an HOTP value (RFC 4226) for a counter. `digits` must be 1..=9.
pub fn hotp(key: &[u8], counter: u64, digits: u32, algorithm: Algorithm) -> u32 {
    let digest = hmac_digest(algorithm, key, &counter.to_be_bytes());
    // Dynamic truncation: the low nibble of the last byte selects the offset.
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let bin = ((digest[offset] as u32 & 0x7f) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | (digest[offset + 3] as u32);
    bin % 10u32.pow(digits)
}

/// Compute the TOTP code (RFC 6238) for a given Unix time, zero-padded.
pub fn totp_at(params: &TotpParams, unix_secs: u64) -> String {
    let counter = unix_secs / params.period;
    let code = hotp(&params.key, counter, params.digits, params.algorithm);
    format!("{code:0width$}", width = params.digits as usize)
}

/// Seconds until the current TOTP step ends (1..=period).
pub fn seconds_remaining(params: &TotpParams, unix_secs: u64) -> u64 {
    params.period - (unix_secs % params.period)
}

/// Parse an `otpauth://totp/...` or `otpauth://hotp/...` URI. Missing query
/// fields fall back to the standard defaults (SHA1, 6 digits, 30s period);
/// an HOTP URI must carry its `counter`, as the Key URI Format requires.
pub fn parse_otpauth(uri: &str) -> Result<TotpParams> {
    let (rest, is_hotp) = if let Some(r) = uri.strip_prefix("otpauth://totp/") {
        (r, false)
    } else if let Some(r) = uri.strip_prefix("otpauth://hotp/") {
        (r, true)
    } else {
        bail!("not a TOTP or HOTP otpauth URI: {}", redact_uri(uri));
    };
    let query = rest.split_once('?').map(|(_, q)| q).unwrap_or("");

    let mut secret: Option<String> = None;
    let mut digits: u32 = 6;
    let mut period: u64 = 30;
    let mut algorithm = Algorithm::Sha1;
    let mut counter: Option<u64> = None;

    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let value = percent_decode(value);
        match key.to_ascii_lowercase().as_str() {
            "secret" => secret = Some(value),
            "digits" => {
                digits = value
                    .parse()
                    .map_err(|_| anyhow!("invalid digits: {value:?}"))?
            }
            "period" => {
                period = value
                    .parse()
                    .map_err(|_| anyhow!("invalid period: {value:?}"))?
            }
            "algorithm" => algorithm = Algorithm::parse(&value)?,
            "counter" => {
                counter = Some(
                    value
                        .parse()
                        .map_err(|_| anyhow!("invalid counter: {value:?}"))?,
                )
            }
            _ => {}
        }
    }

    let secret = secret.ok_or_else(|| anyhow!("otpauth URI is missing the secret parameter"))?;
    let mut params = TotpParams::from_base32(&secret, digits, period, algorithm)?;
    if is_hotp {
        params.hotp_counter =
            Some(counter.ok_or_else(|| anyhow!("an HOTP otpauth URI needs a counter parameter"))?);
    }
    Ok(params)
}

/// A URI shown in a message without its secret.
fn redact_uri(uri: &str) -> String {
    match uri.split_once('?') {
        Some((head, _)) => format!("{head}?..."),
        None => uri.to_string(),
    }
}

/// The code for these parameters now: TOTP from the time, or HOTP from the
/// stored counter (the caller advances the counter after using it).
pub fn code_at(params: &TotpParams, unix_secs: u64) -> String {
    match params.hotp_counter {
        Some(counter) => {
            let code = hotp(&params.key, counter, params.digits, params.algorithm);
            format!("{code:0width$}", width = params.digits as usize)
        }
        None => totp_at(params, unix_secs),
    }
}

/// An `otpauth://hotp/` URI for a bare base32 secret and a counter.
pub fn hotp_uri(label: &str, secret: &str, counter: u64) -> String {
    format!(
        "otpauth://hotp/{}?secret={}&counter={counter}",
        percent_encode(label),
        secret.trim().replace(' ', "").to_ascii_uppercase()
    )
}

/// The same otpauth URI with its `counter` parameter set to `counter`.
pub fn set_counter(uri: &str, counter: u64) -> String {
    let (head, query) = uri.split_once('?').unwrap_or((uri, ""));
    let mut pairs: Vec<String> = query
        .split('&')
        .filter(|p| !p.is_empty() && !p.to_ascii_lowercase().starts_with("counter="))
        .map(str::to_string)
        .collect();
    pairs.push(format!("counter={counter}"));
    format!("{head}?{}", pairs.join("&"))
}

/// Percent-encode everything but unreserved characters (RFC 3986).
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// One account found in an imported QR payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Imported {
    /// The account part of the label (e.g. an e-mail address).
    pub account: String,
    pub issuer: String,
    /// An otpauth URI carrying the secret and its parameters.
    pub uri: String,
}

/// The accounts in a scanned QR payload: an `otpauth://` URI, or a Google
/// Authenticator export (`otpauth-migration://offline?data=...`), which can
/// hold several.
pub fn import_payload(text: &str) -> Result<Vec<Imported>> {
    let t = text.trim();
    if t.starts_with("otpauth-migration://") {
        return parse_migration(t);
    }
    if t.starts_with("otpauth://") {
        parse_otpauth(t).context("the QR code holds an otpauth URI that is not valid")?;
        let (head, query) = t.split_once('?').unwrap_or((t, ""));
        let label = percent_decode(head.splitn(4, '/').nth(3).unwrap_or(""));
        let (label_issuer, account) = match label.split_once(':') {
            Some((i, a)) => (i.trim().to_string(), a.trim().to_string()),
            None => (String::new(), label.trim().to_string()),
        };
        let issuer = query
            .split('&')
            .filter_map(|p| p.split_once('='))
            .find(|(k, _)| k.eq_ignore_ascii_case("issuer"))
            .map(|(_, v)| percent_decode(v))
            .unwrap_or(label_issuer);
        return Ok(vec![Imported {
            account,
            issuer,
            uri: t.to_string(),
        }]);
    }
    bail!("the QR code does not hold an otpauth:// or otpauth-migration:// payload");
}

/// Read a protobuf varint at `*at`.
fn varint(buf: &[u8], at: &mut usize) -> Result<u64> {
    let mut v: u64 = 0;
    for shift in (0..64).step_by(7) {
        let b = *buf
            .get(*at)
            .ok_or_else(|| anyhow!("export data is cut short"))?;
        *at += 1;
        v |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Ok(v);
        }
    }
    bail!("export data has a varint that is too long")
}

/// A protobuf field value: a varint, or length-delimited bytes.
enum Proto {
    Varint(u64),
    Bytes(Vec<u8>),
}

/// The fields of one protobuf message: (field number, value).
fn proto_fields(buf: &[u8]) -> Result<Vec<(u64, Proto)>> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < buf.len() {
        let key = varint(buf, &mut at)?;
        let (field, wire) = (key >> 3, key & 7);
        match wire {
            0 => out.push((field, Proto::Varint(varint(buf, &mut at)?))),
            2 => {
                let len = usize::try_from(varint(buf, &mut at)?)?;
                let end = at
                    .checked_add(len)
                    .filter(|&e| e <= buf.len())
                    .ok_or_else(|| anyhow!("export data is cut short"))?;
                out.push((field, Proto::Bytes(buf[at..end].to_vec())));
                at = end;
            }
            1 => at += 8,
            5 => at += 4,
            _ => bail!("export data uses an unknown protobuf wire type {wire}"),
        }
    }
    Ok(out)
}

/// Decode a Google Authenticator export: base64 protobuf in `data`, as the
/// widely used reconstruction of its schema describes (MigrationPayload with
/// repeated OtpParameters: secret, name, issuer, algorithm, digits, type,
/// counter).
pub fn parse_migration(uri: &str) -> Result<Vec<Imported>> {
    let query = uri
        .strip_prefix("otpauth-migration://offline?")
        .ok_or_else(|| anyhow!("not an otpauth-migration://offline URI"))?;
    let data = query
        .split('&')
        .filter_map(|p| p.split_once('='))
        .find(|(k, _)| *k == "data")
        .map(|(_, v)| percent_decode(v).replace(' ', "+"))
        .ok_or_else(|| anyhow!("the export URI has no data parameter"))?;
    let bytes = data_encoding::BASE64
        .decode(data.as_bytes())
        .or_else(|_| data_encoding::BASE64_NOPAD.decode(data.trim_end_matches('=').as_bytes()))
        .map_err(|_| anyhow!("the export data is not base64"))?;
    let mut out = Vec::new();
    for (field, value) in proto_fields(&bytes)? {
        let (1, Proto::Bytes(msg)) = (field, value) else {
            continue;
        };
        let mut secret = Vec::new();
        let (mut name, mut issuer) = (String::new(), String::new());
        let (mut algorithm, mut digits, mut kind, mut counter) = (0u64, 0u64, 0u64, 0u64);
        for (f, v) in proto_fields(&msg)? {
            match (f, v) {
                (1, Proto::Bytes(b)) => secret = b,
                (2, Proto::Bytes(b)) => name = String::from_utf8_lossy(&b).into_owned(),
                (3, Proto::Bytes(b)) => issuer = String::from_utf8_lossy(&b).into_owned(),
                (4, Proto::Varint(n)) => algorithm = n,
                (5, Proto::Varint(n)) => digits = n,
                (6, Proto::Varint(n)) => kind = n,
                (7, Proto::Varint(n)) => counter = n,
                _ => {}
            }
        }
        if secret.is_empty() {
            bail!("an exported account has no secret");
        }
        let algorithm = match algorithm {
            0 | 1 => "SHA1",
            2 => "SHA256",
            3 => "SHA512",
            _ => bail!("an exported account uses an algorithm otp does not support (MD5)"),
        };
        let digits = if digits == 2 { 8 } else { 6 };
        // The name may already be "issuer:account".
        let account = match name.split_once(':') {
            Some((i, a)) if !issuer.is_empty() && i.trim() == issuer => a.trim().to_string(),
            _ => name.clone(),
        };
        let label = if issuer.is_empty() {
            account.clone()
        } else {
            format!("{issuer}:{account}")
        };
        let mut uri = format!(
            "otpauth://{}/{}?secret={}&algorithm={algorithm}&digits={digits}",
            if kind == 1 { "hotp" } else { "totp" },
            percent_encode(&label),
            data_encoding::BASE32_NOPAD.encode(&secret)
        );
        if !issuer.is_empty() {
            uri.push_str(&format!("&issuer={}", percent_encode(&issuer)));
        }
        if kind == 1 {
            uri.push_str(&format!("&counter={counter}"));
        }
        out.push(Imported {
            account,
            issuer,
            uri,
        });
    }
    if out.is_empty() {
        bail!("the export holds no accounts");
    }
    Ok(out)
}

/// A service name for an imported account: the issuer (or else the account),
/// lowercased, with whitespace and colons turned into dashes.
pub fn suggest_service_name(item: &Imported) -> String {
    let base = if item.issuer.trim().is_empty() {
        &item.account
    } else {
        &item.issuer
    };
    let mut name = String::new();
    for c in base.trim().chars() {
        if c.is_whitespace() || c == ':' {
            if !name.ends_with('-') {
                name.push('-');
            }
        } else {
            name.extend(c.to_lowercase());
        }
    }
    let name = name.trim_matches('-').to_string();
    if name.is_empty() {
        "imported".to_string()
    } else {
        name
    }
}

/// Resolve a stored secret value: either a bare base32 secret (with the
/// standard defaults) or a full `otpauth://` URI carrying its own parameters.
pub fn resolve_secret(value: &str) -> Result<TotpParams> {
    let v = value.trim();
    if v.starts_with("otpauth://") {
        parse_otpauth(v)
    } else {
        TotpParams::from_base32(v, 6, 30, Algorithm::Sha1)
    }
}

/// Minimal percent-decoding for otpauth query values (`%XX` and `+`).
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
                match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(byte) => {
                        out.push(byte);
                        i += 3;
                    }
                    None => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// One `service:value` line from the secrets store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub service: String,
    pub value: String,
}

/// Parse the secrets file. Blank lines and `#` comments are ignored. Each entry
/// is `service:value`, split at the first colon so `otpauth://` values survive.
pub fn parse_store(text: &str) -> Vec<Entry> {
    text.lines()
        .filter_map(|line| {
            let l = line.trim();
            if l.is_empty() || l.starts_with('#') {
                return None;
            }
            let (service, value) = l.split_once(':')?;
            let service = service.trim();
            if service.is_empty() {
                return None;
            }
            Some(Entry {
                service: service.to_string(),
                value: value.trim().to_string(),
            })
        })
        .collect()
}

/// Find the entry whose service name matches exactly.
pub fn find_entry<'a>(entries: &'a [Entry], service: &str) -> Option<&'a Entry> {
    entries.iter().find(|e| e.service == service)
}

/// Maximum edit distance for a name to appear in "did you mean" suggestions.
const SUGGESTION_MAX_DISTANCE: usize = 3;

/// Maximum number of "did you mean" suggestions to return.
const SUGGESTION_LIMIT: usize = 3;

/// Result of resolving a user-supplied service query against the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution<'a> {
    /// Exactly one entry matched: an exact name, a unique case-insensitive
    /// prefix, or a unique case-insensitive substring (in that order).
    Unique(&'a Entry),
    /// Several entries matched equally well; the caller must not guess.
    Ambiguous(Vec<&'a str>),
    /// Nothing matched; carries the closest names for a "did you mean" hint
    /// (possibly empty). Ranked by edit distance, ties broken by name.
    NotFound(Vec<&'a str>),
}

/// Resolve a service query to an entry. An exact name always wins (an entry
/// literally named "githu" beats prefix-expanding "githu" to "github"). Then a
/// unique case-insensitive prefix match, then a unique case-insensitive
/// substring match. Multiple equally good matches are reported as ambiguous
/// rather than guessed at.
pub fn resolve_entry<'a>(entries: &'a [Entry], query: &str) -> Resolution<'a> {
    if let Some(entry) = find_entry(entries, query) {
        return Resolution::Unique(entry);
    }

    let q = query.to_ascii_lowercase();
    let collect = |pred: fn(&str, &str) -> bool| -> Vec<&'a Entry> {
        entries
            .iter()
            .filter(|e| pred(&e.service.to_ascii_lowercase(), &q))
            .collect()
    };
    let by_prefix = collect(|name, q| name.starts_with(q));
    let by_substring = collect(|name, q| name.contains(q));
    for matches in [by_prefix, by_substring] {
        match matches.as_slice() {
            [] => continue,
            [single] => return Resolution::Unique(single),
            many => {
                return Resolution::Ambiguous(many.iter().map(|e| e.service.as_str()).collect())
            }
        }
    }

    // No prefix or substring match: suggest the closest names by edit distance.
    let mut scored: Vec<(usize, &str)> = entries
        .iter()
        .map(|e| {
            (
                edit_distance(&q, &e.service.to_ascii_lowercase()),
                e.service.as_str(),
            )
        })
        .filter(|(distance, _)| *distance <= SUGGESTION_MAX_DISTANCE)
        .collect();
    scored.sort();
    Resolution::NotFound(
        scored
            .into_iter()
            .take(SUGGESTION_LIMIT)
            .map(|(_, name)| name)
            .collect(),
    )
}

/// Levenshtein edit distance between two strings, over Unicode scalar values.
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut curr: Vec<usize> = vec![0; b.len() + 1];
    for (i, &ca) in a.iter().enumerate() {
        curr[0] = i + 1;
        for (j, &cb) in b.iter().enumerate() {
            let substitution = prev[j] + usize::from(ca != cb);
            curr[j + 1] = substitution.min(prev[j + 1] + 1).min(curr[j] + 1);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b.len()]
}

/// Validate a service name for `add`: non-empty, no colon or whitespace.
pub fn validate_service_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("service name must not be empty");
    }
    if name.contains(':') || name.chars().any(char::is_whitespace) {
        bail!("service name must not contain a colon or whitespace: {name:?}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4226 Appendix D: key = ASCII "12345678901234567890".
    const RFC_KEY: &[u8] = b"12345678901234567890";

    #[test]
    fn hotp_matches_rfc4226_vectors() {
        let expected = [
            755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
        ];
        for (counter, &want) in expected.iter().enumerate() {
            assert_eq!(
                hotp(RFC_KEY, counter as u64, 6, Algorithm::Sha1),
                want,
                "counter {counter}"
            );
        }
    }

    #[test]
    fn totp_matches_rfc6238_sha1_vectors() {
        let params = TotpParams {
            hotp_counter: None,
            key: RFC_KEY.to_vec(),
            digits: 8,
            period: 30,
            algorithm: Algorithm::Sha1,
        };
        assert_eq!(totp_at(&params, 59), "94287082");
        assert_eq!(totp_at(&params, 1111111109), "07081804");
        assert_eq!(totp_at(&params, 1234567890), "89005924");
        assert_eq!(totp_at(&params, 2000000000), "69279037");
    }

    #[test]
    fn decode_base32_handles_case_spaces_and_padding() {
        assert_eq!(decode_base32("JBSWY3DP").unwrap(), b"Hello");
        assert_eq!(decode_base32("jbsw y3dp").unwrap(), b"Hello");
        assert_eq!(decode_base32("JBSWY3DP====").unwrap(), b"Hello");
        assert!(decode_base32("1188!!").is_err());
    }

    #[test]
    fn seconds_remaining_counts_down_within_the_step() {
        let p = TotpParams {
            hotp_counter: None,
            key: RFC_KEY.to_vec(),
            digits: 6,
            period: 30,
            algorithm: Algorithm::Sha1,
        };
        assert_eq!(seconds_remaining(&p, 0), 30);
        assert_eq!(seconds_remaining(&p, 1), 29);
        assert_eq!(seconds_remaining(&p, 29), 1);
        assert_eq!(seconds_remaining(&p, 30), 30);
    }

    #[test]
    fn parse_otpauth_reads_parameters_with_defaults() {
        let p = parse_otpauth(
            "otpauth://totp/ACME:alice?secret=JBSWY3DPEHPK3PXP&digits=8&period=60&algorithm=SHA256",
        )
        .unwrap();
        assert_eq!(p.digits, 8);
        assert_eq!(p.period, 60);
        assert_eq!(p.algorithm, Algorithm::Sha256);

        let d = parse_otpauth("otpauth://totp/x?secret=JBSWY3DP").unwrap();
        assert_eq!((d.digits, d.period, d.algorithm), (6, 30, Algorithm::Sha1));

        assert!(parse_otpauth("otpauth://totp/x?digits=6").is_err()); // no secret
        assert!(parse_otpauth("https://example.com").is_err());
    }

    #[test]
    fn resolve_secret_accepts_bare_and_uri() {
        assert_eq!(resolve_secret("JBSWY3DP").unwrap().digits, 6);
        assert_eq!(
            resolve_secret("otpauth://totp/x?secret=JBSWY3DP&digits=7")
                .unwrap()
                .digits,
            7
        );
    }

    #[test]
    fn parse_store_ignores_comments_and_keeps_uri_values() {
        let text = "# header\n\ngithub: JBSWY3DP\nwork:otpauth://totp/x?secret=JBSWY3DP\n";
        let entries = parse_store(text);
        assert_eq!(entries.len(), 2);
        assert_eq!(find_entry(&entries, "github").unwrap().value, "JBSWY3DP");
        assert_eq!(
            find_entry(&entries, "work").unwrap().value,
            "otpauth://totp/x?secret=JBSWY3DP"
        );
        assert!(find_entry(&entries, "missing").is_none());
    }

    fn store(names: &[&str]) -> Vec<Entry> {
        names
            .iter()
            .map(|name| Entry {
                service: name.to_string(),
                value: "JBSWY3DP".to_string(),
            })
            .collect()
    }

    fn service_of(resolution: Resolution<'_>) -> String {
        match resolution {
            Resolution::Unique(entry) => entry.service.clone(),
            other => panic!("expected a unique match, got {other:?}"),
        }
    }

    #[test]
    fn resolve_entry_exact_match_beats_prefix_expansion() {
        let entries = store(&["githu", "github"]);
        assert_eq!(service_of(resolve_entry(&entries, "githu")), "githu");
    }

    #[test]
    fn resolve_entry_unique_prefix_resolves_case_insensitively() {
        let entries = store(&["github", "gitlab", "aws"]);
        assert_eq!(service_of(resolve_entry(&entries, "gith")), "github");
        assert_eq!(service_of(resolve_entry(&entries, "GITH")), "github");
        assert_eq!(service_of(resolve_entry(&entries, "aws")), "aws");
    }

    #[test]
    fn resolve_entry_ambiguous_prefix_lists_candidates() {
        let entries = store(&["github", "gitlab", "aws"]);
        assert_eq!(
            resolve_entry(&entries, "git"),
            Resolution::Ambiguous(vec!["github", "gitlab"])
        );
    }

    #[test]
    fn resolve_entry_falls_back_to_unique_substring() {
        let entries = store(&["github", "gitlab", "aws"]);
        assert_eq!(service_of(resolve_entry(&entries, "hub")), "github");
        // Multiple substring matches are ambiguous, never guessed.
        assert_eq!(
            resolve_entry(&entries, "it"),
            Resolution::Ambiguous(vec!["github", "gitlab"])
        );
    }

    #[test]
    fn resolve_entry_suggests_closest_names_when_nothing_matches() {
        let entries = store(&["github", "gitlab", "aws"]);
        // One typo away from "github": suggested, closest first.
        assert_eq!(
            resolve_entry(&entries, "guthub"),
            Resolution::NotFound(vec!["github", "gitlab"])
        );
        // Nothing anywhere near: no suggestions, still not found.
        assert_eq!(
            resolve_entry(&entries, "zzzzzzzz"),
            Resolution::NotFound(vec![])
        );
    }

    #[test]
    fn validate_service_name_rejects_bad_names() {
        assert!(validate_service_name("github").is_ok());
        assert!(validate_service_name("").is_err());
        assert!(validate_service_name("a:b").is_err());
        assert!(validate_service_name("a b").is_err());
    }

    #[test]
    fn hotp_uris_need_a_counter_and_give_rfc4226_codes() {
        // RFC 4226 key "12345678901234567890" in base32.
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        assert!(parse_otpauth(&format!("otpauth://hotp/x?secret={secret}")).is_err());
        let p = parse_otpauth(&format!("otpauth://hotp/x?secret={secret}&counter=1")).unwrap();
        assert_eq!(p.hotp_counter, Some(1));
        assert_eq!(code_at(&p, 0), "287082");
        let uri = hotp_uri("my svc", secret, 9);
        assert_eq!(
            uri,
            format!("otpauth://hotp/my%20svc?secret={secret}&counter=9")
        );
        assert_eq!(code_at(&resolve_secret(&uri).unwrap(), 0), "520489");
        let next = set_counter(&uri, 10);
        assert_eq!(
            next,
            format!("otpauth://hotp/my%20svc?secret={secret}&counter=10")
        );
        assert_eq!(resolve_secret(&next).unwrap().hotp_counter, Some(10));
    }

    #[test]
    fn a_secret_never_shows_in_an_error() {
        let err = parse_otpauth("otpauth://steam/x?secret=JBSWY3DPEHPK3PXP")
            .unwrap_err()
            .to_string();
        assert!(!err.contains("JBSWY3DP"), "{err}");
    }

    #[test]
    fn imports_a_single_otpauth_uri() {
        let items = import_payload(
            "otpauth://totp/ACME%20Co:jo@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co\n",
        )
        .unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].issuer, "ACME Co");
        assert_eq!(items[0].account, "jo@example.com");
        assert_eq!(suggest_service_name(&items[0]), "acme-co");
        assert!(import_payload("https://example.com").is_err());
    }

    #[test]
    fn imports_a_google_authenticator_export() {
        // The sample from dim13/otpauth's tests (no base64 padding): one TOTP
        // account, secret "Hello!\xde\xad\xbe\xef" = JBSWY3DPEHPK3PXP.
        let uri = "otpauth-migration://offline?data=CjEKCkhlbGxvId6tvu8SGEV4YW1wbGU6YWxpY2VAZ29vZ2xlLmNvbRoHRXhhbXBsZTAC";
        let items = import_payload(uri).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].issuer, "Example");
        assert_eq!(items[0].account, "alice@google.com");
        let p = resolve_secret(&items[0].uri).unwrap();
        assert_eq!(p.key, b"Hello!\xde\xad\xbe\xef");
        assert_eq!(p.hotp_counter, None);
        assert!(items[0].uri.contains("secret=JBSWY3DPEHPK3PXP"));
        assert_eq!(suggest_service_name(&items[0]), "example");
    }

    #[test]
    fn export_with_two_accounts_hotp_and_eight_digits() {
        // Hand-built payload: field 1 twice. The second is HOTP (type 1),
        // eight digits (2), SHA256 (2), counter 5.
        fn ld(field: u8, bytes: &[u8]) -> Vec<u8> {
            let mut v = vec![(field << 3) | 2, bytes.len() as u8];
            v.extend_from_slice(bytes);
            v
        }
        let mut a = ld(1, b"abcdefghij");
        a.extend(ld(2, b"first"));
        let mut b = ld(1, b"0123456789");
        b.extend(ld(2, b"bob"));
        b.extend(ld(3, b"Corp"));
        b.extend([4 << 3, 2, 5 << 3, 2, 6 << 3, 1, 7 << 3, 5]);
        let mut payload = ld(1, &a);
        payload.extend(ld(1, &b));
        payload.extend([2 << 3, 1]);
        let data = data_encoding::BASE64
            .encode(&payload)
            .replace('+', "%2B")
            .replace('/', "%2F")
            .replace('=', "%3D");
        let items = import_payload(&format!("otpauth-migration://offline?data={data}")).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(suggest_service_name(&items[0]), "first");
        let p = resolve_secret(&items[1].uri).unwrap();
        assert_eq!(
            (p.digits, p.algorithm, p.hotp_counter),
            (8, Algorithm::Sha256, Some(5))
        );
        assert_eq!(items[1].issuer, "Corp");
        assert!(import_payload("otpauth-migration://offline?data=CgA").is_err());
    }
}
