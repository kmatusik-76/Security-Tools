import unittest
from email import policy
from email.parser import BytesParser
from pathlib import Path

from analyzer.links import get_links
from analyzer.loader import load_eml

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


if __name__ == "__main__":
    unittest.main()