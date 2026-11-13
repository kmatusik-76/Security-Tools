import unittest
from email import policy
from email.parser import BytesParser
from pathlib import Path

from analyzer.attachments import get_attachments
from analyzer.loader import load_eml

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "sample_01.eml"


def parse(raw):
    return BytesParser(policy=policy.default).parsebytes(raw)


class TestGetAttachments(unittest.TestCase):
    def test_sample_has_no_attachments(self):
        self.assertEqual(get_attachments(load_eml(SAMPLE)), [])

    def test_reads_attachment_metadata(self):
        msg = parse(
            b"From: a@example.invalid\n"
            b"MIME-Version: 1.0\n"
            b'Content-Type: multipart/mixed; boundary="XYZ"\n'
            b"\n"
            b"--XYZ\n"
            b"Content-Type: text/plain\n"
            b"\n"
            b"See the invoice.\n"
            b"--XYZ\n"
            b'Content-Type: application/pdf; name="invoice.pdf"\n'
            b'Content-Disposition: attachment; filename="invoice.pdf"\n'
            b"Content-Transfer-Encoding: base64\n"
            b"\n"
            b"JVBERi0=\n"
            b"--XYZ--\n"
        )
        self.assertEqual(
            get_attachments(msg),
            [{"filename": "invoice.pdf", "content_type": "application/pdf", "size": 5}],
        )

    def test_attachment_without_name(self):
        msg = parse(
            b"From: a@example.invalid\n"
            b"MIME-Version: 1.0\n"
            b'Content-Type: multipart/mixed; boundary="XYZ"\n'
            b"\n"
            b"--XYZ\n"
            b"Content-Type: text/plain\n"
            b"\n"
            b"Body.\n"
            b"--XYZ\n"
            b"Content-Type: application/octet-stream\n"
            b"Content-Disposition: attachment\n"
            b"\n"
            b"abc\n"
            b"--XYZ--\n"
        )
        result = get_attachments(msg)
        self.assertEqual(len(result), 1)
        self.assertIsNone(result[0]["filename"])
        self.assertEqual(result[0]["content_type"], "application/octet-stream")

    def test_finds_nested_attachment(self):
        msg = parse(
            b"From: a@example.invalid\n"
            b"MIME-Version: 1.0\n"
            b'Content-Type: multipart/mixed; boundary="OUT"\n'
            b"\n"
            b"--OUT\n"
            b'Content-Type: multipart/mixed; boundary="IN"\n'
            b"\n"
            b"--IN\n"
            b"Content-Type: text/plain\n"
            b"\n"
            b"Body.\n"
            b"--IN\n"
            b'Content-Type: application/zip; name="docs.zip"\n'
            b'Content-Disposition: attachment; filename="docs.zip"\n'
            b"\n"
            b"abc\n"
            b"--IN--\n"
            b"--OUT--\n"
        )
        self.assertEqual([a["filename"] for a in get_attachments(msg)], ["docs.zip"])


if __name__ == "__main__":
    unittest.main()