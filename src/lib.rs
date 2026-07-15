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
    /// (possibly empty). Ranked by prefix, then substring, then edit distance.
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
}
