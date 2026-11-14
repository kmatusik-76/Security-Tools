import unittest

from analyzer.rules import rule_reply_to_mismatch
from analyzer.rules import rule_reply_to_mismatch, rule_return_path_mismatch
from analyzer.rules import (
    rule_auth_failed,
    rule_reply_to_mismatch,
    rule_return_path_mismatch,
)


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

class TestRuleReturnPathMismatch(unittest.TestCase):
    def test_different_domains_are_reported(self):
        finding = rule_return_path_mismatch(
            {
                "From": addr("support@secure-bank.invalid"),
                "Reply-To": None,
                "Return-Path": addr("bounce@mailer-xyz.invalid"),
            }
        )
        self.assertEqual(finding["rule"], "return_path_mismatch")
        self.assertEqual(finding["score"], 10)
        self.assertIn("mailer-xyz.invalid", finding["detail"])

    def test_subdomain_is_not_reported(self):
        self.assertIsNone(
            rule_return_path_mismatch(
                {"From": addr("a@bank.invalid"), "Return-Path": addr("bounce@mail.bank.invalid")}
            )
        )

    def test_missing_return_path_is_not_reported(self):
        self.assertIsNone(
            rule_return_path_mismatch({"From": addr("a@bank.invalid"), "Return-Path": None})
        )

class TestRuleAuthFailed(unittest.TestCase):
    def test_dmarc_fail_is_reported(self):
        finding = rule_auth_failed({"spf": "pass", "dkim": "none", "dmarc": "fail"})
        self.assertEqual(finding["rule"], "auth_failed")
        self.assertEqual(finding["score"], 30)
        self.assertIn("dmarc=fail", finding["detail"])

    def test_scores_of_several_failures_are_added(self):
        finding = rule_auth_failed({"spf": "softfail", "dkim": "fail", "dmarc": "fail"})
        self.assertEqual(finding["score"], 30 + 5 + 15)
        self.assertIn("spf=softfail", finding["detail"])
        self.assertIn("dkim=fail", finding["detail"])

    def test_all_pass_is_not_reported(self):
        self.assertIsNone(rule_auth_failed({"spf": "pass", "dkim": "pass", "dmarc": "pass"}))

    def test_missing_results_are_not_reported(self):
        self.assertIsNone(rule_auth_failed({"spf": None, "dkim": None, "dmarc": None}))


if __name__ == "__main__":
    unittest.main()
