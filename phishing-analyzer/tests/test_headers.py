import unittest
from email import policy
from email.parser import BytesParser
from pathlib import Path
from analyzer.headers import get_sender_addresses
from analyzer.loader import load_eml
from analyzer.headers import get_auth_results, get_sender_addresses

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "sample_01.eml"

class TestGetSenderAddresses(unittest.TestCase):
    def test_reads_all_sender_headers(self):
        result = get_sender_addresses(load_eml(SAMPLE))
        self.assertEqual(
            result["From"],
            {"address": "support@secure-bank.invalid", "domain": "secure-bank.invalid"},
        )
        self.assertEqual(
            result["Reply-To"],
            {"address": "help.desk@other-domain.invalid", "domain": "other-domain.invalid"},
        )
        self.assertEqual(
            result["Return-Path"],
            {"address": "bounce@mailer-xyz.invalid", "domain": "mailer-xyz.invalid"},
        )

    def test_missing_headers_are_none(self):
        msg = BytesParser(policy=policy.default).parsebytes(
            b"From: someone@example.invalid\n\nbody\n"
        )
        result = get_sender_addresses(msg)
        self.assertEqual(result["From"]["domain"], "example.invalid")
        self.assertIsNone(result["Reply-To"])
        self.assertIsNone(result["Return-Path"])

    def test_header_without_address_is_none(self):
        msg = BytesParser(policy=policy.default).parsebytes(
            b"From: Bank Support\n\nbody\n"
        )
        result=get_sender_addresses(msg)
        self.assertIsNone(result["From"])

class TestGetAuthResults(unittest.TestCase):
    def test_reads_results_from_sample(self):
        result = get_auth_results(load_eml(SAMPLE))
        self.assertEqual(result, {"spf": "pass", "dkim": "none", "dmarc": "fail"})

    def test_missing_header_gives_none(self):
        msg = BytesParser(policy=policy.default).parsebytes(
            b"From: someone@example.invalid\n\nbody\n"
        )
        self.assertEqual(
            get_auth_results(msg), {"spf": None, "dkim": None, "dmarc": None}
        )

    def test_only_topmost_header_is_used(self):
        msg = BytesParser(policy=policy.default).parsebytes(
            b"Authentication-Results: mx.example.invalid; spf=fail\n"
            b"Authentication-Results: fake.invalid; spf=pass; dkim=pass; dmarc=pass\n"
            b"From: someone@example.invalid\n\nbody\n"
        )
        self.assertEqual(
            get_auth_results(msg), {"spf": "fail", "dkim": None, "dmarc": None}
        )

if __name__ == "__main__":
    unittest.main()