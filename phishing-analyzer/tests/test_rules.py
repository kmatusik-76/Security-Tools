import unittest

from analyzer.rules import rule_reply_to_mismatch


def addr(address):
    return {"address": address, "domain": address.rpartition("@")[2]}


class TestRuleReplyToMismatch(unittest.TestCase):
    def test_different_domains_are_reported(self):
        finding = rule_reply_to_mismatch(
            {
                "From": addr("support@secure-bank.invalid"),
                "Reply-To": addr("help.desk@other-domain.invalid"),
                "Return-Path": None,
            }
        )
        self.assertEqual(finding["rule"], "reply_to_mismatch")
        self.assertEqual(finding["score"], 20)
        self.assertIn("other-domain.invalid", finding["detail"])

    def test_same_domain_is_not_reported(self):
        self.assertIsNone(
            rule_reply_to_mismatch(
                {"From": addr("a@bank.invalid"), "Reply-To": addr("b@bank.invalid")}
            )
        )

    def test_subdomain_is_not_reported(self):
        self.assertIsNone(
            rule_reply_to_mismatch(
                {"From": addr("a@bank.invalid"), "Reply-To": addr("b@support.bank.invalid")}
            )
        )

    def test_lookalike_suffix_is_reported(self):
        self.assertIsNotNone(
            rule_reply_to_mismatch(
                {"From": addr("a@bank.invalid"), "Reply-To": addr("b@evilbank.invalid")}
            )
        )

    def test_missing_reply_to_is_not_reported(self):
        self.assertIsNone(
            rule_reply_to_mismatch({"From": addr("a@bank.invalid"), "Reply-To": None})
        )


if __name__ == "__main__":
    unittest.main()
