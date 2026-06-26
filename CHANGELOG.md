# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.1](https://github.com/strawlab/axum-token-auth/compare/v0.3.0...v0.3.1) - 2026-06-26

### Miscellaneous

- bump actions/checkout to v6 in the release-plz workflow (Claude Opus 4.8)

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
