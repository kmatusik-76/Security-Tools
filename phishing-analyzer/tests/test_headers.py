import unittest
from email import policy
from email.parser import BytesParser
from pathlib import Path
from analyzer.headers import get_sender_addresses
from analyzer.loader import load_eml

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

if __name__ == "__main__":
    unittest.main()