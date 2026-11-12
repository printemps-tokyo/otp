# otp

> Generate TOTP and HOTP one-time passwords from a local secrets file and copy them to the clipboard. Fast, offline Rust CLI.

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
otp ls --codes             # every TOTP service's current code at once
otp import qr.png          # add the accounts in a QR code image
```

| Option (on `otp <service>`) | Description |
| --- | --- |
| `-q, --quiet` | Print only the code (no label) and do not copy. Handy for scripts |
| `--no-copy` | Generate and print, but do not touch the clipboard |

### Name matching

You do not have to type the full service name. `otp gith` resolves to `github`
when it is the only name with that prefix (case-insensitive); if no prefix
matches, a unique substring match is tried (`otp hub` also finds `github`). An
exact name always wins over expansion, and if several names match, `otp` lists
the candidates and exits non-zero instead of guessing -- including in `--quiet`
mode, so scripts never get a code for the wrong service. An unmatched name
prints a "did you mean" list of the closest entries.

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

### HOTP (counter-based) codes

```bash
otp add --hotp bank JBSWY3DPEHPK3PXP              # counter starts at 0
otp add --hotp --counter 12 token JBSWY3DPEHPK3PXP
otp add vpn "otpauth://hotp/VPN:me?secret=JBSWY3DPEHPK3PXP&counter=0"
```

An HOTP code (RFC 4226) is made from a counter instead of the time. Each
`otp <service>` shows the code for the stored counter and moves the counter on
in the secrets file first, so the same code is never shown twice. An
`otpauth://hotp/` URI must carry its `counter`. `otp ls --codes` does not show
HOTP codes, since showing one uses up a counter value.

### Importing from a QR code

```bash
otp import ~/Desktop/qr.png                # add what the code holds
otp import --dry-run export.jpg            # show the services, add nothing
otp import --name work qr.png              # choose the service name
pbpaste | otp import -                     # the QR's text instead of an image
```

`otp import` reads the QR codes in a PNG or JPEG image (a screenshot of a
site's 2FA setup page works). A code may hold an `otpauth://` URI or a Google
Authenticator export (`otpauth-migration://offline?data=...`), which can carry
several accounts; the export is decoded as described by the widely used
reconstruction of its format (dim13/otpauth), since Google does not publish
one. Service names come from each account's issuer (lowercased, spaces as
`-`), or from `--name` for a code with one account. If any name already exists
or comes up twice, nothing is added. Secrets are never printed.
## Secrets file

By default `otp` reads and writes `~/.otp_secrets`. Set `OTP_SECRETS_FILE` to
use a different path. The format is one entry per line, split at the first
colon, with `#` comments allowed:

```
# work accounts
github: JBSWY3DPEHPK3PXP
aws: otpauth://totp/AWS:me?secret=JBSWY3DPEHPK3PXP&digits=6
```

`otp` writes this file through a new file created with owner-only permissions
(`0600`) and renamed over the old one, so the secrets are never readable by
others, not even for a moment, and an interrupted write leaves the old file
whole.

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
