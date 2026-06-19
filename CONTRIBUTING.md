# Contributing

Thanks for your interest in contributing to placehold.

## Development

1. Fork / clone the repository
2. Install a stable Rust toolchain (https://rustup.rs)
3. Create a branch: `git switch -c feat/your-change`
4. Make your change and verify locally:
   ```bash
   cargo fmt --all -- --check
   cargo clippy --all-targets -- -D warnings
   cargo test --all
   ```
5. Commit and open a pull request

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/) are preferred
(`feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`).

## Pull requests

- Keep one PR focused on a single purpose
- CI (fmt / clippy / test / build) must be green
- Update the README and tests when behavior changes

## Bug reports and requests

Please open an [issue](../../issues) using the templates.
