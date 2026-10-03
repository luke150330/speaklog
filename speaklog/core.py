"""Deterministic explanations with original line references. No network."""
import re
from . import __version__

MAX_BYTES = 2 * 1024 * 1024
RULES = [
    ("port_busy", r"address already in use|bind\(\).*failed.*98", "端口已被占用", "Port is already in use", "日志报告监听端口冲突；占用进程尚未确认。", "The log reports a listening-port conflict; the owning process is not confirmed.", "查看 ss -ltnp 或 lsof -i 的结果，确认占用者后再决定处理方式。", "Inspect ss -ltnp or lsof -i to identify the owner before changing anything."),
    ("permission", r"permission denied|operation not permitted", "操作被权限拒绝", "Operation denied by permissions", "进程被拒绝访问资源；可能涉及文件权限、运行用户或安全策略。", "Access was denied; filesystem permissions, service identity or security policy may be involved.", "检查日志所指资源的权限和服务运行用户，不要直接 chmod 777。", "Check resource permissions and service identity; do not blindly chmod 777."),
    ("disk_full", r"no space left on device", "存储空间或 inode 可能耗尽", "Storage capacity or inodes may be exhausted", "写入失败，日志报告设备没有可用空间。", "A write failed because the device reports no available space.", "检查 df -h 和 df -i，不要未经确认删除文件。", "Inspect df -h and df -i; do not delete files without review."),
    ("upstream", r"connect\(\) failed.*connection refused|connection refused", "目标连接被拒绝", "Target connection was refused", "连接未建立；目标服务未监听、地址配置错误或网络拒绝均有可能。", "The connection was not established; missing listener, wrong address or network rejection are possible.", "确认 upstream 地址和服务状态，检查监听端口。", "Verify upstream address, service status and listening port."),
    ("upstream_unavailable", r"no live upstreams|upstream prematurely closed connection|upstream sent .* while reading response header|host not found in upstream", "上游服务未能提供可用响应", "Upstream did not provide a usable response", "代理日志显示没有可用上游，或上游在返回完整响应前关闭；单凭这一行不能确定根因。", "The proxy reports no usable upstream or a connection closed before a complete response; this line alone does not establish the cause.", "检查上游实例健康状态、名称解析和应用日志，并核对代理目标配置。", "Check upstream instance health, name resolution and application logs; verify the proxy target configuration."),
    ("timeout", r"upstream timed out|connection timed out|read timed out", "请求超时", "Request timed out", "请求超过等待时间；仅凭此日志无法确定是服务慢还是网络问题。", "The request exceeded its wait limit; this alone does not distinguish slow service from network issues.", "对照服务日志、耗时和资源使用情况；不要直接无限延长超时。", "Compare service logs, latency and resource usage before changing timeouts."),
    ("service_exit", r"main process exited|failed with result|failed to start", "服务启动或运行失败", "Service failed to start or run", "这是失败结果记录，根因可能出现在此前日志。", "This records a failure outcome; the underlying cause may appear in earlier logs.", "查看同一服务此前日志和退出代码。", "Inspect earlier logs for the same service and its exit code."),
]
# Keep punctuation and technical signals while replacing common sensitive values.
SECRET = re.compile(r"""(?ix)(\b(?:password|passwd|pwd|api[_-]?key|access[_-]?token|token|secret|cookie|authorization)\b["']?\s*[:=]\s*)(?:["'][^"'\r\n]*["']|[^\s,;&]+)""")
BEARER = re.compile(r"(?i)\bBearer\s+[^\s,;]+")
KEY = re.compile(r"\b(?:sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9_]{8,}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b")
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
HEADER = re.compile(r"""(?im)(\b(?:proxy-authorization|authorization|set-cookie|cookie)\b["']?[ \t]*[:=][ \t]*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\r\n]+)""")
URL_CREDENTIALS = re.compile(r"""(?i)(\b[a-z][a-z0-9+.-]*://)[^/\s@"']+@""")
PRIVATE_KEY = re.compile(r"-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----.*?-----END \1-----", re.S)

def redact(text):
    text = ANSI.sub("", text)
    # Preserve newlines so evidence continues to refer to original input lines.
    text = PRIVATE_KEY.sub(lambda m: "[PRIVATE KEY REDACTED]" + "\n" * m[0].count("\n"), text)
    text = URL_CREDENTIALS.sub(lambda m: m[1] + "[CREDENTIALS]@", text)
    # Unquoted headers are conservatively redacted through end-of-line.
    text = HEADER.sub(lambda m: m[1] + "[REDACTED]", text)
    text = BEARER.sub("Bearer [REDACTED]", text)
    text = SECRET.sub(lambda m: m[1] + "[REDACTED]", text)
    text = KEY.sub("[SECRET]", text)
    text = EMAIL.sub("[EMAIL]", text)
    text = IPV4.sub("[IP]", text)
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)

def analyze(text, lang="zh"):
    if lang not in ("zh", "en"):
        raise ValueError("unsupported language")
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise ValueError("input exceeds 2 MiB")
    safe = redact(text)
    lines = safe.splitlines()
    findings = []
    for key, pattern, zh_title, en_title, zh_desc, en_desc, zh_next, en_next in RULES:
        matches = [(i, line) for i, line in enumerate(lines, 1) if re.search(pattern, line, re.I)]
        if matches:
            findings.append(dict(code=key, title=zh_title if lang == "zh" else en_title,
                explanation=zh_desc if lang == "zh" else en_desc,
                next_step=zh_next if lang == "zh" else en_next,
                occurrences=len(matches), evidence=[dict(line=i, text=line) for i, line in matches[:5]],
                evidence_omitted=max(0, len(matches)-5), certainty="observed-symptom"))
    known_lines = {i for _, pattern, *_ in RULES for i, line in enumerate(lines, 1) if re.search(pattern, line, re.I)}
    unknown = [dict(line=i, text=line) for i, line in enumerate(lines, 1)
               if i not in known_lines and re.search(r"\berror\b|\bfatal\b|exception|traceback", line, re.I)]
    return dict(version=__version__, language=lang, line_count=len(lines), findings=findings,
                unclassified=unknown[:20], unclassified_omitted=max(0,len(unknown)-20),
                warning="Heuristic explanations are not verified root causes. Redaction is best-effort; review before sharing.",
                redacted_log=safe)

def markdown(report):
    zh = report["language"] == "zh"
    out = ["# SpeakLog", "", "规则解释，不代表已确认根因。脱敏不是绝对保证，请检查后再分享。" if zh else report["warning"], ""]
    if not report["findings"]:
        out += ["未匹配已知错误；不能据此断言服务正常。" if zh else "No known error matched; this does not prove the service is healthy.", ""]
    for f in report["findings"]:
        out += ["## " + f["title"], "", f["explanation"], "", ("出现次数：" if zh else "Occurrences: ") + str(f["occurrences"]), "", f["next_step"], ""]
        for e in f["evidence"]:
            # Indented code avoids a log closing a Markdown fence.
            out += [("证据行 " if zh else "Evidence line ") + str(e["line"]) + ":", "",
                    *["    " + line for line in e["text"].splitlines()], ""]
    if report["unclassified"]:
        out += ["## " + ("尚未解释的错误" if zh else "Unclassified errors"), ""]
        for e in report["unclassified"]:
            out += [str(e["line"]) + ":", "", "    " + e["text"], ""]
    return "\n".join(out)
