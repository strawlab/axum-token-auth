# axum-token-auth

`axum-token-auth` is middleware to authenticate requests to axum.

[![Build status](https://github.com/strawlab/axum-token-auth/actions/workflows/CI.yml/badge.svg?branch=main)](https://github.com/strawlab/axum-token-auth/actions/workflows/CI.yml)
[![Crates.io](https://img.shields.io/crates/v/axum-token-auth)](https://crates.io/crates/axum-token-auth)
[![Documentation](https://docs.rs/axum-token-auth/badge.svg)](https://docs.rs/axum-token-auth)

More information about this crate can be found in the [crate documentation][docs].

## Releasing

Releases are automated with [release-plz](https://release-plz.dev) via GitHub
Actions (`.github/workflows/release-plz.yml`):

1. Push commits to `main` using
   [conventional commit](https://www.conventionalcommits.org) messages
   (`fix:`, `feat:`, `feat!:` / `BREAKING CHANGE:` for breaking changes, etc.).
2. release-plz opens (and keeps updated) a **release PR** that bumps the version
   in `Cargo.toml` and updates `CHANGELOG.md` based on those commits.
3. Merge the release PR. release-plz then publishes the new version to
   [crates.io](https://crates.io/crates/axum-token-auth) (via trusted
   publishing — no API token required), creates the `vX.Y.Z` git tag, and a
   GitHub release. [docs.rs](https://docs.rs/axum-token-auth) builds the docs
   automatically from the crates.io publish.

Because this is a `0.x` crate, `feat:` and `fix:` commits bump the patch
version; only a breaking change bumps the minor version.

## License

This project is licensed under the [MIT license][license].

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in `axum-token-auth` by you, shall be licensed as MIT, without any
additional terms or conditions.

[docs]: https://docs.rs/axum-token-auth
[license]: https://github.com/strawlab/axum-token-auth/blob/main/axum/LICENSE