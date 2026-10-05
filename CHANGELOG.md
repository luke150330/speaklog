# Changelog

## 0.1.4 — 2026-10-05
- Show bilingual omission counts in Markdown when evidence or unclassified
  errors exceed display limits; no longer silently hide the truncation.
- Preserve existing JSON fields and accept older reports without omission fields.
- Add four regression tests; no new network calls or runtime dependencies.

## 0.1.3 — 2026-10-03
- Explain common Nginx upstream failures: no live upstreams, premature close,
  response-header failure and unresolved upstream host.
- Keep the report symptom-based and avoid claiming a confirmed root cause.
- Update the synthetic Nginx sample and usage documentation.

## 0.1.2 — 2026-10-02
- Preserve offline Markdown/JSON reports when optional AI fails, including
  timeouts and malformed HTTP transport; return exit code 1 with a safe warning.
- Add specific bilingual input error messages and document exit codes.
- Add --version and nine regression/success-path tests.
- No live-provider compatibility or diagnosis-quality claims are added.

## 0.1.1 — 2026-10-01
- Fix partial redaction of Basic/Digest authentication and multi-value Cookies.
- Redact URL credentials and complete PEM private keys, retaining evidence lines.
- Add four regression tests; use the package version in JSON reports.
- Redaction remains best-effort and requires manual review before sharing.

## 0.1.0 — 2026-10-01
- First experimental offline analyzer and optional opt-in AI adapter.
- Synthetic examples, privacy documentation and automated tests.
- Not yet validated against a production log corpus or live AI provider.
