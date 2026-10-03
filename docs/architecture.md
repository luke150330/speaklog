# Architecture

Bounded UTF-8 input → local redaction → symptom rule matching → evidence-linked report.
Optional: explicit consent → bounded redacted log → user-configured HTTPS provider
→ unverified plain-text advice. No automatic commands.

Rule evidence keeps original line numbers; duplicate symptoms are grouped by
rule, not by proven shared incident. Each rule has Chinese/English descriptions
and a safe diagnostic suggestion. Unknown error lines are reported separately.
No database, persistent server, production access or telemetry.

Optional-provider failures are isolated from offline analysis: the CLI retains
the rule report, adds a fixed localized warning, and returns 1. Invalid local
input returns 2. Neither code claims the target service is healthy or unhealthy.

Tests mock network transport; live-provider performance and diagnosis quality
still require evaluation with consented, sanitized examples.

The symptom catalog includes common Nginx upstream failures such as an empty
healthy-upstream set, premature connection close and upstream-name resolution
failure. These are reported as observations, not confirmed causes.
