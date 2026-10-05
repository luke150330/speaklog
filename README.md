# SpeakLog

[![Tests](https://github.com/luke150330/speaklog/actions/workflows/tests.yml/badge.svg)](https://github.com/luke150330/speaklog/actions/workflows/tests.yml)

Turn server logs into plain-language explanations with evidence.

**v0.1.4 — experimental.** Local-first, zero runtime dependencies, Python 3.10+.
Chinese and English reports. No telemetry, account or shared API key.

## Quick start

From this source directory:

Download or clone [the repository](https://github.com/luke150330/speaklog),
then change into its directory before running the commands below.

```sh
python3 -m speaklog examples/nginx.log
python3 -m speaklog examples/systemd.log --lang en
python3 -m speaklog examples/nginx.log --format json
python3 -m speaklog --version
```

Install in an isolated environment:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
speaklog examples/nginx.log
```

For a service excerpt (read-only collection, run yourself):

```sh
journalctl -u nginx --no-pager -n 200 | speaklog -
```

## What you get

- Port conflict, permission, storage, refused connection, timeout, unavailable Nginx upstream and service failure explanations.
- Repeated symptoms grouped with occurrence counts and up to five original evidence lines.
- Suggested checks and explicit uncertainty; no automatic repair or shell execution.
- Unknown errors shown instead of inventing an explanation.
- Markdown explicitly reports omitted evidence and unknown-error counts when
  display limits are reached (five evidence lines per symptom, 20 unknown errors).
  Counts and original line references remain available in JSON; its redacted log
  is still sensitive and should be reviewed locally before sharing.
- Best-effort redaction of common credentials, email addresses and IPv4 addresses.
- Full Authorization/Cookie header values, URL credentials and complete PEM
  private-key blocks are redacted; original evidence line numbering is retained.

For example, `Address already in use` becomes:
“Port is already in use. The log reports a listening-port conflict;
the owning process is not confirmed. Inspect listening ports before changing anything.”

## Optional AI advice

Offline rules are the default. AI mode is a generic Chat Completions-compatible
HTTP adapter; compatibility depends on your provider and model. No provider
has been live-validated for this release. You supply your own key and pay any
provider charges. SpeakLog never uses LukeTeam production keys.

1. Inspect `speaklog your-file --redact-only` locally.
2. Set `SPEAKLOG_API_URL` to your trusted HTTPS chat-completions endpoint.
3. Set `SPEAKLOG_MODEL` and `SPEAKLOG_API_KEY` privately in your shell.
4. Run `speaklog your-file --ai --consent-send`.

Do not put secrets in command arguments, GitHub issues or committed files.
AI requests are limited to 24,000 redacted bytes; offline input to 2 MiB.
Redirects are rejected. No URL in a log is visited.
Provider advice is unverified, displayed as text and never executed.

If AI configuration, network or response handling fails, SpeakLog still prints
the offline report and a safe warning. JSON adds an `ai_error` field; raw provider
errors and response bodies are not displayed.

## Exit codes and troubleshooting

- `0`: requested processing completed, including when no known symptom matches.
- `1`: offline report produced, but requested AI advice is unavailable.
- `2`: invalid arguments, missing consent, unreadable file, invalid UTF-8,
  oversized input or an output error.

An exit code is not a service health verdict. When redirecting output in a script,
keep the report even if the exit code is `1`. Missing files, encoding and size
errors include specific Chinese/English guidance without exposing input data.

## Privacy and limitations

Redaction is **not a security guarantee**. IPv6 addresses, personal names,
paths and unknown secret formats may remain. Review before sharing.
Unquoted sensitive headers are removed through the end of their line, so adjacent
diagnostic fields on that line may also be omitted. Incomplete PEM blocks are not
guaranteed to be redacted. This release is still not a comprehensive secret scanner.
No root-cause confirmation, timestamp correlation, continuous monitoring or
full log-format parser is claimed. A report with no findings does not prove health.
Remote AI may retain data according to its own policies. Offline mode makes no network calls.
JSON includes the redacted input: treat generated reports as sensitive.

## Development

```sh
python3 -m unittest discover -s tests -v
```

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md),
[architecture](docs/architecture.md) and [roadmap](docs/roadmap.md).
All example logs are synthetic. MIT license.

## 中文

SpeakLog 把服务器日志整理成“发生了什么、证据在哪、下一步检查什么”。
默认离线运行；AI 模式需要用户自行配置服务、密钥并明确同意发送日志。
脱敏是尽力处理，不保证覆盖全部敏感数据；结论是症状解释，不是已确认根因。
