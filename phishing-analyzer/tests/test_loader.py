import unittest
from pathlib import Path
from analyzer.loader import load_eml

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "sample_01.eml"

class TestLoadEml(unittest.TestCase):
    def test_reads_from_and_subject(self):
        msg=load_eml(SAMPLE)
        sender = msg["FROM"].addresses[0]
        self.assertEqual(sender.display_name, "Bank Support")
        self.assertEqual(sender.addr_spec, "support@secure-bank.invalid")
        self.assertEqual(msg["Subject"], "Urgent: confirm your account")

if __name__=="__main__":
    unittest.main()