import contextlib
import io
import json
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

class CliTests(unittest.TestCase):
    def run_file(self,text,args):
        with tempfile.NamedTemporaryFile() as stream:
            stream.write(text.encode())
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
        self.assertEqual(code,2)
        self.assertNotIn("private-key-secret",out+err)

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
