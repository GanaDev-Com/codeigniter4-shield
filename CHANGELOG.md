# Changelog

All notable changes to `ganadev/codeigniter4-shield` will be documented in this file.

## [1.0.0 - 2026-10-05]

### Added

- Initial release of CodeIgniter 4 adapter for Ganadev Shield.
- SecurityFirewallFilter implementing CI4 FilterInterface.
- Challenge system with Turnstile, reCAPTCHA, and NullTest drivers.
- Admin panel with bans, events, rules, and health endpoints.
- 6 spark commands: prune, release, health, report, rules:list, replay.
- Database migrations for security_ip_bans and security_events tables.
- CI4 Model-based repositories with caching layer.
- Trusted cookie system bound to IP and user-agent.
- DNS-based crawler verification with CIDR allowlist support.
