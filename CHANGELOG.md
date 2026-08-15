# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.2](https://github.com/strawlab/axum-token-auth/compare/v0.3.1...v0.3.2) - 2026-08-15

### Added

- expose token_expiry to read a token's embedded expiry (Claude Opus 5)

## [0.3.1](https://github.com/strawlab/axum-token-auth/compare/v0.3.0...v0.3.1) - 2026-08-15

### Added

- authentication failures now emit specific diagnostic messages (Claude Opus 5)

### Miscellaneous

- bump actions/checkout to v6 in the release-plz workflow (Claude Opus 4.8)

### Added

- Authentication failures now emit specific diagnostic messages distinguishing no session cookie, invalid session signature, expired session, no access token, malformed token, invalid token signature, and expired access token. The `ValidationErrors` type carries all relevant error reasons, allowing clients to provide actionable feedback. (Claude Haiku 4.5)
- `token_expiry(&str)` reads the expiry embedded in a token so a server can tell an operator when a URL or QR code it handed out stops working, without callers re-deriving the token wire format. It does not verify the signature and must not be used to authorize anything. `OffsetDateTime` is re-exported for its return type. (Claude Opus 5)

## [0.3.0](https://github.com/strawlab/axum-token-auth/compare/v0.2.1...v0.3.0) - 2026-06-16

### Added

- [**breaking**] stateless tokens, configurable cookies, trusted networks, Rust 2024 (Claude Opus 4.8)

## [0.2.1](https://github.com/strawlab/axum-token-auth/compare/v0.2.0...v0.2.1) - 2026-06-16

### Fixed

- set HttpOnly and SameSite=Strict on the session cookie (Claude Opus 4.8)
- avoid panic on malformed session cookie (Claude Opus 4.8)

### Miscellaneous

- don't use rust-cache action
- *(deps)* bump if-addrs dev-dependency to 0.15 (Claude Opus 4.8)
- streamline CI workflow (Claude Opus 4.8)
- add release-plz workflow and config (Claude Opus 4.8)

### Other

- improve docs around 'trusted connection'
