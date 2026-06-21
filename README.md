# otp

> Generate TOTP one-time passwords from a local secrets file and copy them to the clipboard. Fast, offline Rust CLI.

[![CI](https://github.com/printemps-tokyo/otp/actions/workflows/ci.yml/badge.svg)](https://github.com/printemps-tokyo/otp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)

`otp` turns a service name into its current 2FA code:

```console
$ otp github
OTP: 657914 (copied to clipboard, valid 21s)
```

It reads a simple `~/.otp_secrets` file, computes the TOTP code locally (RFC
6238), and copies it to your clipboard. There is no external `oathtool`
dependency and nothing ever leaves your machine.

## Why

A terminal `otp <service>` is faster than reaching for your phone. This started
as a small shell function wrapping `oathtool` and `pbcopy`; this version
reimplements the TOTP algorithm natively so it ships as a single binary, adds
cross-platform clipboard support and `otpauth://` import, and keeps the exact
same secrets-file format so there is nothing to migrate.

## Requirements

- A Rust toolchain (to build from source)
- A clipboard helper for the copy feature: `pbcopy` (macOS, built in),
  `wl-copy` (Wayland), `xclip` (X11), or `clip.exe` (WSL). Code generation works
  without one; use `--no-copy` or `-q` to skip copying.

## Install

```bash
cargo install --git https://github.com/printemps-tokyo/otp
# or, from a clone:
cargo install --path .
```

Prebuilt binaries will be attached to each [release](https://github.com/printemps-tokyo/otp/releases) once a version is tagged.

## Usage

```bash
otp <service>              # generate a code and copy it to the clipboard
otp                        # list available services (same as `otp ls`)
otp add <service> <secret> # add a service (base32 secret or otpauth:// URI)
otp rm <service>           # remove a service
otp ls                     # list services
```

| Option (on `otp <service>`) | Description |
| --- | --- |
| `-q, --quiet` | Print only the code (no label) and do not copy. Handy for scripts |
| `--no-copy` | Generate and print, but do not touch the clipboard |

### Adding services

```bash
otp add github JBSWY3DPEHPK3PXP                      # base32 secret
otp add aws "otpauth://totp/AWS:me?secret=JBSWY...&digits=6&period=30"
printf %s "$SECRET" | otp add work -                 # read secret from stdin
```

Passing the secret as `-` reads it from stdin so the secret stays out of your
shell history. A plain base32 secret uses the standard defaults (SHA-1, 6
digits, 30s); an `otpauth://` URI carries its own `digits`, `period`, and
`algorithm` (SHA1/SHA256/SHA512).

## Secrets file

By default `otp` reads and writes `~/.otp_secrets`. Set `OTP_SECRETS_FILE` to
use a different path. The format is one entry per line, split at the first
colon, with `#` comments allowed:

```
# work accounts
github: JBSWY3DPEHPK3PXP
aws: otpauth://totp/AWS:me?secret=JBSWY3DPEHPK3PXP&digits=6
```

`otp` creates and rewrites this file with owner-only permissions (`0600`).

## Security

- TOTP secrets are stored in plaintext, protected only by file permissions
  (`0600`). Anyone who can read the file can generate your codes, so keep it on
  an encrypted disk and never commit it to a repository or sync it unencrypted.
- Prefer `otp add <service> -` to keep secrets out of your shell history.
- Codes are computed entirely offline; no network requests are made.

See [SECURITY.md](./SECURITY.md) to report a vulnerability.

## Programmatic API

```rust
use otp::{resolve_secret, totp_at, seconds_remaining};

let params = resolve_secret("JBSWY3DPEHPK3PXP")?; // base32 or otpauth:// URI
let now = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)?
    .as_secs();
let code = totp_at(&params, now);
let left = seconds_remaining(&params, now);
```

The library implements HOTP (RFC 4226) and TOTP (RFC 6238) and is verified
against the published RFC test vectors.

## License

[MIT](./LICENSE) (c) printemps.tokyo
