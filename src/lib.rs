//! otp — generate TOTP one-time passwords from a local secrets file.
//!
//! This library implements the RFC 4226 (HOTP) and RFC 6238 (TOTP) algorithms
//! directly on top of HMAC, so the tool needs no external `oathtool` binary.
//! Everything here is pure: the time and the secrets file are passed in by the
//! caller, which keeps the code easy to test against the RFC test vectors.

use anyhow::{anyhow, bail, Result};
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

/// Parse an `otpauth://totp/...` URI into TOTP parameters. Missing query
/// fields fall back to the standard defaults (SHA1, 6 digits, 30s period).
pub fn parse_otpauth(uri: &str) -> Result<TotpParams> {
    let rest = uri
        .strip_prefix("otpauth://totp/")
        .ok_or_else(|| anyhow!("not a TOTP otpauth URI: {uri:?}"))?;
    let query = rest.split_once('?').map(|(_, q)| q).unwrap_or("");

    let mut secret: Option<String> = None;
    let mut digits: u32 = 6;
    let mut period: u64 = 30;
    let mut algorithm = Algorithm::Sha1;

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
            _ => {}
        }
    }

    let secret = secret.ok_or_else(|| anyhow!("otpauth URI is missing the secret parameter"))?;
    TotpParams::from_base32(&secret, digits, period, algorithm)
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

    #[test]
    fn validate_service_name_rejects_bad_names() {
        assert!(validate_service_name("github").is_ok());
        assert!(validate_service_name("").is_err());
        assert!(validate_service_name("a:b").is_err());
        assert!(validate_service_name("a b").is_err());
    }
}
