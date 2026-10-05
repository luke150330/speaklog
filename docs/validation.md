# v0.1.0 validation

## v0.1.4 regression validation — 2026-10-05

- Four new tests reproduced four failing bilingual assertions before the fix:
  Markdown omitted evidence/unknown-error counts without disclosing truncation.
- All 34 tests pass locally after the fix, including exact display limits,
  original evidence counts and compatibility with older report dictionaries.
- Only synthetic logs and mocked providers were used; no production logs,
  production credentials or live AI requests were read or transmitted.
- GitHub CI outcome is recorded separately in the maintainer project state.

Local validation date: 2026-10-01. Python 3.12.9 on macOS.

- 17 unit tests pass: six known symptoms, counts/line references, unknown errors,
  bilingual output, bounded input, common-secret redaction, CLI JSON, offline
  network isolation, explicit AI consent, endpoint restrictions, redirects,
  AI input limit and a mocked provider request.
- Synthetic Nginx example emits port-conflict, refused-connection and timeout
  findings with original evidence lines.
- No real production logs were read or uploaded.
- No real AI request was made. Mock tests do not establish model compatibility,
  model reasoning accuracy or network latency.
- Linux/Python matrix CI is configured but has not run on GitHub yet.
- A clean temporary virtual environment successfully built and installed the
  wheel; the installed `speaklog` entry point ran the systemd example outside
  the source directory.

This is a correctness smoke test, not an accuracy benchmark or privacy audit.

## v0.1.1 regression validation — 2026-10-01

- Four added tests reproduced six failing assertions on 0.1.0: partially
  exposed authentication/Cookie values, URL credentials and PEM content.
- All 21 tests pass after the fixes, including original evidence line numbers
  after multiline private-key redaction and headers on preceding lines.
- The v0.1.0 GitHub matrix run passed on Python 3.10, 3.12 and 3.13:
  https://github.com/luke150330/speaklog/actions/runs/36734847561
- No production logs or live AI providers were used for this update.

## v0.1.2 validation — 2026-10-02

- Reproduced report loss after optional-provider failure and unhandled
  incomplete HTTP reads in the previous CLI.
- All 30 unit tests pass locally, covering AI-failure JSON/Markdown retention,
  missing configuration without network access, mocked successful responses,
  credential-safe warnings, version output, encoding, size and file errors.
- No real provider call or production log was used.
- Built and installed the 0.1.2 wheel in a temporary virtual environment;
  outside the source directory, the real CLI reported the correct version and
  retained a parseable JSON report with exit code 1 when no provider was configured.
