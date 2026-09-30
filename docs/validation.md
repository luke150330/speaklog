# v0.1.0 validation

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
