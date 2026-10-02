import argparse
import http.client
import json
import os
import sys
from .core import MAX_BYTES, analyze, markdown, redact
from .ai import explain
from . import __version__

MESSAGES = {
    "consent": ("AI 模式需要 --consent-send；请先用 --redact-only 检查脱敏结果。",
                "AI requires --consent-send; preview redaction with --redact-only first."),
    "missing": ("找不到日志文件，请检查路径。", "Log file not found; check the path."),
    "access": ("无法读取日志文件，请检查权限和路径。", "Cannot read the log file; check permissions and path."),
    "size": ("日志超过 2 MiB，请选择较小的日志片段。", "Log exceeds 2 MiB; select a smaller excerpt."),
    "encoding": ("日志不是有效 UTF-8，请转换编码后重试。", "Log is not valid UTF-8; convert its encoding and retry."),
    "ai": ("AI 不可用（配置、网络或响应异常）；已保留离线分析，请检查服务配置后重试。",
           "AI unavailable (configuration, network or response problem); offline analysis is retained. Check provider settings and retry."),
    "output": ("无法写入报告，请检查输出目标。", "Cannot write the report; check the output destination."),
}

def message(code, lang):
    return MESSAGES[code][0 if lang == "zh" else 1]

class InputError(Exception):
    """Contains only a fixed error code, never raw log or provider data."""

def read_input(path):
    try:
        if path == "-":
            data = sys.stdin.buffer.read(MAX_BYTES + 1)
        else:
            with open(path, "rb") as stream:
                data = stream.read(MAX_BYTES + 1)
    except FileNotFoundError:
        raise InputError("missing") from None
    except OSError:
        raise InputError("access") from None
    if len(data) > MAX_BYTES:
        raise InputError("size")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise InputError("encoding") from None

def main(argv=None):
    parser = argparse.ArgumentParser(description="Explain server logs locally; no network unless --ai is used.")
    parser.add_argument("--version", action="version", version="SpeakLog " + __version__)
    parser.add_argument("file", nargs="?", default="-", help="UTF-8 log file, or - for stdin")
    parser.add_argument("--lang", choices=["zh","en"], default="zh")
    parser.add_argument("--format", choices=["markdown","json"], default="markdown")
    parser.add_argument("--redact-only", action="store_true")
    parser.add_argument("--ai", action="store_true", help="send redacted logs to your configured provider")
    parser.add_argument("--consent-send", action="store_true", help="acknowledge best-effort redaction and external log transmission")
    args = parser.parse_args(argv)
    try:
        if args.ai and not args.consent_send and not args.redact_only:
            raise InputError("consent")
        text = read_input(args.file)
        report = analyze(text,args.lang)
        if args.redact_only:
            print(report["redacted_log"])
            return 0
        exit_code = 0
        if args.ai:
            try:
                result = explain(report,os.environ.get("SPEAKLOG_API_URL",""),
                                 os.environ.get("SPEAKLOG_MODEL",""),os.environ.get("SPEAKLOG_API_KEY",""))
                report["ai_advice_unverified"] = redact(result)
            except (OSError, ValueError, KeyError, IndexError, TypeError, http.client.HTTPException):
                # Never display provider response bodies, URLs or raw exception details.
                report["ai_error"] = message("ai", args.lang)
                print("SpeakLog: " + report["ai_error"], file=sys.stderr)
                exit_code = 1
        if args.format=="json":
            print(json.dumps(report,ensure_ascii=False,indent=2))
        else:
            print(markdown(report))
            if "ai_advice_unverified" in report:
                print("\n## AI advice (unverified)\n")
                print("\n".join("    "+line for line in report["ai_advice_unverified"].splitlines()))
            if "ai_error" in report:
                print("\n> " + report["ai_error"])
        return exit_code
    except InputError as error:
        print("SpeakLog: " + message(error.args[0], args.lang), file=sys.stderr)
        return 2
    except OSError:
        print("SpeakLog: " + message("output", args.lang), file=sys.stderr)
        return 2
