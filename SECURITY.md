# Security

This is an experimental release, not a certified log scrubber.
Do not publish sensitive samples. Offline analysis reads user-selected input;
it does not run commands, follow URLs in logs or contact servers.
AI is opt-in and sends redacted text to a user-selected HTTPS provider.
A provider can still return misleading advice or be influenced by log content.
No automatic remediation is provided.

Report suspected leaks privately to the repository maintainer, using GitHub
private vulnerability reporting if enabled. If unavailable, request a private
contact without attaching exploit secrets or sensitive logs to a public issue.
Do not consider best-effort regex redaction sufficient for highly sensitive logs.
