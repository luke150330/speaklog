import argparse
import json
import os
import sys
from .core import MAX_BYTES, analyze, markdown, redact
from .ai import explain

def main(argv=None):
    parser = argparse.ArgumentParser(description="Explain server logs locally; no network unless --ai is used.")
    parser.add_argument("file", nargs="?", default="-", help="UTF-8 log file, or - for stdin")
    parser.add_argument("--lang", choices=["zh","en"], default="zh")
    parser.add_argument("--format", choices=["markdown","json"], default="markdown")
    parser.add_argument("--redact-only", action="store_true")
    parser.add_argument("--ai", action="store_true", help="send redacted logs to your configured provider")
    parser.add_argument("--consent-send", action="store_true", help="acknowledge best-effort redaction and external log transmission")
    args = parser.parse_args(argv)
    try:
        if args.file == "-":
            data = sys.stdin.buffer.read(MAX_BYTES+1)
        else:
            with open(args.file,"rb") as stream:
                data = stream.read(MAX_BYTES+1)
        if len(data)>MAX_BYTES:
            raise ValueError("input exceeds 2 MiB; select a smaller excerpt")
        text = data.decode("utf-8")
        report = analyze(text,args.lang)
        if args.redact_only:
            print(report["redacted_log"])
            return 0
        if args.ai:
            if not args.consent_send:
                raise ValueError("--ai requires --consent-send; preview with --redact-only first")
            result = explain(report,os.environ.get("SPEAKLOG_API_URL",""),
                             os.environ.get("SPEAKLOG_MODEL",""),os.environ.get("SPEAKLOG_API_KEY",""))
            report["ai_advice_unverified"] = redact(result)
        if args.format=="json":
            print(json.dumps(report,ensure_ascii=False,indent=2))
        else:
            print(markdown(report))
            if "ai_advice_unverified" in report:
                print("\n## AI advice (unverified)\n")
                print("\n".join("    "+line for line in report["ai_advice_unverified"].splitlines()))
        return 0
    except (OSError,ValueError,KeyError,IndexError,TypeError):
        # Provider bodies/URLs may contain credentials; never print exception payloads.
        print("SpeakLog: cannot analyze input or provider request. Check UTF-8, size, consent and provider settings. No repair was performed.",file=sys.stderr)
        return 2
