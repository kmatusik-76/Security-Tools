import unittest
from email import policy
from email.parser import BytesParser
from pathlib import Path

from analyzer.links import get_links
from analyzer.loader import load_eml
from analyzer.links import get_link_host, get_links

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "sample_01.eml"


def parse(raw):
    return BytesParser(policy=policy.default).parsebytes(raw)


class TestGetLinks(unittest.TestCase):
    def test_reads_link_from_sample(self):
        self.assertEqual(
            get_links(load_eml(SAMPLE)),
            ["http://secure-bank.invalid.login-check.invalid/verify?id=12345"],
        )

    def test_no_links_gives_empty_list(self):
        msg = parse(b"From: a@example.invalid\n\nNo links here.\n")
        self.assertEqual(get_links(msg), [])

    def test_reads_html_part_and_removes_duplicates(self):
        msg = parse(
            b"From: a@example.invalid\n"
            b"MIME-Version: 1.0\n"
            b'Content-Type: multipart/alternative; boundary="XYZ"\n'
            b"\n"
            b"--XYZ\n"
            b"Content-Type: text/plain\n"
            b"\n"
            b"Go to https://one.invalid/a\n"
            b"--XYZ\n"
            b"Content-Type: text/html\n"
            b"\n"
            b'<a href="https://one.invalid/a">click</a> <a href="https://two.invalid/b">more</a>\n'
            b"--XYZ--\n"
        )
        self.assertEqual(get_links(msg), ["https://one.invalid/a", "https://two.invalid/b"])

class TestGetLinkHost(unittest.TestCase):
    def test_host_of_sample_link(self):
        url = "http://secure-bank.invalid.login-check.invalid/verify?id=12345"
        self.assertEqual(get_link_host(url), "secure-bank.invalid.login-check.invalid")

    def test_user_info_trick(self):
        self.assertEqual(get_link_host("https://bank.invalid@evil.invalid/login"), "evil.invalid")

    def test_lowercase_and_no_port(self):
        self.assertEqual(get_link_host("HTTPS://Bank.INVALID:8443/x"), "bank.invalid")

    def test_ip_address(self):
        self.assertEqual(get_link_host("http://192.0.2.10/a"), "192.0.2.10")

    def test_unparsable_url_gives_none(self):
        self.assertIsNone(get_link_host("http://[::1/x"))


if __name__ == "__main__":
    unittest.main()