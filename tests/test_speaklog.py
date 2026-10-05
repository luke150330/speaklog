import contextlib
import io
import json
import http.client
import os
import tempfile
import unittest
from unittest.mock import patch
from speaklog.core import MAX_BYTES, analyze, redact, markdown
from speaklog.cli import main
from speaklog.ai import explain, NoRedirect

class CoreTests(unittest.TestCase):
    def test_each_rule(self):
        for text, code in [("Address already in use","port_busy"),
                           ("Permission denied","permission"),
                           ("No space left on device","disk_full"),
                           ("Connection refused","upstream"),
                           ("upstream timed out","timeout"),
                           ("Main process exited","service_exit")]:
            with self.subTest(code=code):
                self.assertEqual(analyze(text)["findings"][0]["code"],code)

    def test_counts_original_lines_and_cap(self):
        report = analyze("startup\n" + "\n".join(["Permission denied"]*9))
        f = report["findings"][0]
        self.assertEqual(f["occurrences"],9)
        self.assertEqual(f["evidence"][0]["line"],2)
        self.assertEqual(len(f["evidence"]),5)
        self.assertEqual(f["evidence_omitted"],4)

    def test_no_health_claim(self):
        report = analyze("service started successfully","en")
        self.assertEqual(report["findings"],[])
        self.assertIn("does not prove",markdown(report))

    def test_unknown_error(self):
        self.assertEqual(analyze("hello\nERROR strange problem")["unclassified"][0]["line"],2)

    def test_markdown_reports_omitted_evidence_bilingually(self):
        for lang, notice in [("zh", "另有 4 条证据未展示"),
                             ("en", "4 additional evidence lines not shown")]:
            with self.subTest(lang=lang):
                output = markdown(analyze("\n".join(["Permission denied"] * 9), lang))
                self.assertIn(notice, output)
                self.assertEqual(output.count("    Permission denied"), 5)

    def test_markdown_reports_omitted_unknown_errors(self):
        text = "\n".join(f"ERROR unfamiliar-{n}" for n in range(23))
        for lang, notice in [("zh", "另有 3 条尚未解释的错误未展示"),
                             ("en", "3 additional unclassified error lines not shown")]:
            with self.subTest(lang=lang):
                output = markdown(analyze(text, lang))
                self.assertIn(notice, output)
                self.assertNotIn("unfamiliar-22", output)

    def test_markdown_does_not_claim_omissions_at_limits(self):
        report = analyze("\n".join(["Permission denied"] * 5 + ["ERROR unknown"] * 20), "en")
        self.assertNotIn("not shown", markdown(report))
        self.assertEqual(report["findings"][0]["evidence_omitted"], 0)
        self.assertEqual(report["unclassified_omitted"], 0)

    def test_markdown_handles_older_report_without_omission_fields(self):
        report = analyze("Permission denied\nERROR unknown", "en")
        report.pop("unclassified_omitted")
        report["findings"][0].pop("evidence_omitted")
        self.assertIn("Operation denied", markdown(report))
        self.assertNotIn("not shown", markdown(report))

    def test_secret_redaction(self):
        samples = ['password=hunter2', 'token=abc123', '"api_key": "abcdef"',
                   'Authorization: Bearer supersecret', 'Cookie: session=abcdef',
                   'contact person@example.com at 192.0.2.5',
                   'sk-123456789abcdef', 'ghp_123456789abcdef',
                   'https://example.com/?token=secretvalue&next=ok']
        for sample in samples:
            output = redact(sample)
            for secret in ["hunter2","abc123","abcdef","supersecret","person@example.com",
                           "192.0.2.5","123456789abcdef","secretvalue"]:
                self.assertNotIn(secret, output)

    def test_input_limit(self):
        with self.assertRaises(ValueError):
            analyze("a"*(MAX_BYTES+1))

    def test_language(self):
        self.assertEqual(analyze("Permission denied","en")["findings"][0]["title"],
                         "Operation denied by permissions")

    def test_json_is_safe(self):
        self.assertNotIn("hunter2",json.dumps(analyze("ERROR password=hunter2")))

    def test_complete_auth_and_cookie_headers(self):
        for sample in ['Authorization: Basic dXNlcjpwYXNz',
                       'Proxy-Authorization: Digest username="privateuser", response="privatehash"',
                       'Cookie: session=firstvalue; refresh=secondvalue',
                       'Set-Cookie: session=thirdvalue; Path=/; HttpOnly',
                       '"Authorization": "Basic fourthvalue", "status": 401']:
            with self.subTest(sample=sample):
                output = redact(sample)
                for secret in ["dXNlcjpwYXNz", "privateuser", "privatehash",
                               "firstvalue", "secondvalue", "thirdvalue", "fourthvalue"]:
                    self.assertNotIn(secret, output)

    def test_url_credentials(self):
        output = redact("ERROR postgresql://dbuser:dbpass@example.org:5432/db")
        self.assertNotIn("dbuser", output)
        self.assertNotIn("dbpass", output)
        self.assertIn("example.org:5432/db", output)

    def test_pem_preserves_evidence_line_numbers(self):
        text = ("start\n-----BEGIN RSA PRIVATE KEY-----\n"
                "privatebody\n-----END RSA PRIVATE KEY-----\nPermission denied")
        report = analyze(text)
        self.assertNotIn("privatebody", report["redacted_log"])
        self.assertEqual(report["line_count"], 5)
        self.assertEqual(report["findings"][0]["evidence"][0]["line"], 5)

    def test_header_redaction_preserves_following_line(self):
        report = analyze("Cookie: session=one; refresh=two\nPermission denied")
        self.assertEqual(report["findings"][0]["evidence"][0]["line"], 2)
        self.assertNotIn("one", report["redacted_log"])
        self.assertNotIn("two", report["redacted_log"])

class CliTests(unittest.TestCase):
    def run_file(self,text,args):
        with tempfile.NamedTemporaryFile() as stream:
            stream.write(text if isinstance(text, bytes) else text.encode())
            stream.flush()
            out,err=io.StringIO(),io.StringIO()
            with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
                code=main([stream.name]+args)
            return code,out.getvalue(),err.getvalue()

    def test_json(self):
        code,out,_=self.run_file("Permission denied",["--format","json"])
        self.assertEqual(code,0)
        self.assertEqual(json.loads(out)["line_count"],1)

    def test_offline_never_calls_ai(self):
        with patch("speaklog.cli.explain",side_effect=AssertionError("network")):
            self.assertEqual(self.run_file("ERROR hello",[])[0],0)

    def test_requires_consent(self):
        with patch("speaklog.cli.explain") as provider:
            self.assertEqual(self.run_file("ERROR hello",["--ai"])[0],2)
            provider.assert_not_called()

    def test_provider_error_not_exposed(self):
        with patch("speaklog.cli.explain",side_effect=ValueError("private-key-secret")):
            code,out,err=self.run_file("ERROR hello",["--ai","--consent-send"])
        self.assertEqual(code,1)
        self.assertNotIn("private-key-secret",out+err)
        self.assertIn("SpeakLog", out)

    def test_ai_failure_keeps_json_report(self):
        with patch("speaklog.cli.explain",side_effect=ValueError("private-provider-detail")):
            code,out,err=self.run_file("Permission denied",["--ai","--consent-send","--format","json"])
        self.assertEqual(code,1)
        report = json.loads(out)
        self.assertEqual(report["findings"][0]["code"],"permission")
        self.assertIn("ai_error",report)
        self.assertNotIn("private-provider-detail",out+err)

    def test_ai_timeout_keeps_markdown(self):
        with patch("speaklog.cli.explain",side_effect=TimeoutError("private-detail")):
            code,out,err=self.run_file("Permission denied",["--ai","--consent-send","--lang","en"])
        self.assertEqual(code,1)
        self.assertIn("Operation denied",out)
        self.assertIn("offline",out+err)
        self.assertNotIn("private-detail",out+err)

    def test_malformed_transport_keeps_report(self):
        with patch("speaklog.cli.explain",side_effect=http.client.IncompleteRead(b"secret")):
            code,out,err=self.run_file("Permission denied",["--ai","--consent-send"])
        self.assertEqual(code,1)
        self.assertIn("SpeakLog",out)
        self.assertNotIn("secret",out+err)

    def test_missing_ai_configuration_does_not_open_network(self):
        with patch.dict(os.environ, {}, clear=True), patch("urllib.request.build_opener") as network:
            code,out,_=self.run_file("Permission denied",["--ai","--consent-send","--format","json"])
        self.assertEqual(code,1)
        self.assertIn("ai_error",json.loads(out))
        network.assert_not_called()

    def test_successful_ai_is_zero_and_redacted(self):
        with patch("speaklog.cli.explain",return_value="Check service. token=syntheticreply"):
            code,out,_=self.run_file("Permission denied",["--ai","--consent-send","--format","json"])
        self.assertEqual(code,0)
        report=json.loads(out)
        self.assertIn("ai_advice_unverified",report)
        self.assertNotIn("ai_error",report)
        self.assertNotIn("syntheticreply",out)

    def test_missing_file_help(self):
        with tempfile.TemporaryDirectory() as folder:
            out,err=io.StringIO(),io.StringIO()
            with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
                code=main([folder+"/missing.log","--lang","en"])
        self.assertEqual(code,2)
        self.assertIn("file",err.getvalue())
        self.assertIn("not found",err.getvalue())
        self.assertEqual(out.getvalue(),"")

    def test_encoding_help(self):
        code,out,err=self.run_file(b"\xff\xfe",["--lang","en"])
        self.assertEqual(code,2)
        self.assertIn("UTF-8",err)
        self.assertEqual(out,"")

    def test_size_help(self):
        code,out,err=self.run_file(b"x"*(MAX_BYTES+1),["--lang","en"])
        self.assertEqual(code,2)
        self.assertIn("2 MiB",err)
        self.assertEqual(out,"")

    def test_version(self):
        out=io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as raised:
            main(["--version"])
        self.assertEqual(raised.exception.code,0)
        from speaklog import __version__
        self.assertIn(__version__,out.getvalue())

    def test_preview(self):
        code,out,_=self.run_file("token=hide123",["--redact-only"])
        self.assertEqual(code,0)
        self.assertNotIn("hide123",out)

class AiTests(unittest.TestCase):
    def test_bad_endpoints(self):
        for url in ["http://example.com","https://user:pass@example.com",
                    "https://example.com?token=x","https://example.com/#x"]:
            with self.assertRaises(ValueError):
                explain(analyze("test"),url,"model","key")

    def test_redirect_rejected(self):
        with self.assertRaises(ValueError):
            NoRedirect().redirect_request(None,None,302,"",{},"https://other.example")

    def test_size_limit(self):
        with self.assertRaises(ValueError):
            explain(analyze("a"*24001),"https://example.com/chat","model","key")

    def test_mock_request_only_sends_redacted_text(self):
        response = unittest.mock.MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps(
            {"choices":[{"message":{"content":"Possible cause"}}]}).encode()
        opener = unittest.mock.MagicMock()
        opener.open.return_value = response
        with patch("urllib.request.build_opener",return_value=opener):
            result = explain(analyze("ERROR token=private123"),
                             "https://example.com/chat","model","key")
        self.assertEqual(result,"Possible cause")
        body = opener.open.call_args.args[0].data.decode()
        self.assertNotIn("private123",body)
        self.assertIn("REDACTED",body)

if __name__ == "__main__":
    unittest.main()
