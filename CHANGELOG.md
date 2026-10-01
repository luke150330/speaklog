# Changelog

## 0.1.1 — 2026-10-01
- Fix partial redaction of Basic/Digest authentication and multi-value Cookies.
- Redact URL credentials and complete PEM private keys, retaining evidence lines.
- Add four regression tests; use the package version in JSON reports.
- Redaction remains best-effort and requires manual review before sharing.

## 0.1.0 — 2026-10-01
- First experimental offline analyzer and optional opt-in AI adapter.
- Synthetic examples, privacy documentation and automated tests.
- Not yet validated against a production log corpus or live AI provider.
