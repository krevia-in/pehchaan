"""Redaction. Every identifier here is synthetic."""

import tempfile
import unittest
from pathlib import Path

from pehchaan import Kind, redact, scan_text, verhoeff_digit
from pehchaan.cli import main

AADHAAR = "36420577201" + str(verhoeff_digit("36420577201"))
PAN = "ABCPN1234F"
GSTIN = "29ABCPN1234F1ZY"
UPI = "ravi.k@okhdfcbank"
IFSC = "HDFC0001234"


class Redact(unittest.TestCase):
    def test_aadhaar_is_hidden_except_last_four(self):
        out = redact(f"uid {AADHAAR} ok")
        self.assertNotIn(AADHAAR, out)
        self.assertNotIn(AADHAAR[:8], out)
        self.assertEqual(out, f"uid XXXX XXXX {AADHAAR[-4:]} ok")

    def test_spaced_aadhaar_is_hidden(self):
        spaced = f"{AADHAAR[:4]} {AADHAAR[4:8]} {AADHAAR[8:]}"
        self.assertNotIn(AADHAAR[:4] + " " + AADHAAR[4:8], redact(spaced))

    def test_every_default_kind_is_hidden_and_the_rest_is_untouched(self):
        text = f"pan={PAN}, gst={GSTIN}, upi={UPI}, ifsc={IFSC}, name=Priya"
        out = redact(text)
        for secret in (PAN, GSTIN, UPI):
            self.assertNotIn(secret, out)
        self.assertIn(f"ifsc={IFSC}, name=Priya", out)   # public, left alone
        self.assertTrue(out.startswith("pan=ABCXXXXX4F, gst="))

    def test_ifsc_only_when_asked(self):
        self.assertEqual(redact(IFSC, kinds=[Kind.IFSC], style="label"), "[IFSC]")

    def test_label_style(self):
        self.assertEqual(redact(f"PAN {PAN}", style="label"), "PAN [PAN]")

    def test_full_style_keeps_length_and_separators(self):
        out = redact(f"{AADHAAR[:4]}-{AADHAAR[4:8]}-{AADHAAR[8:]}", style="full")
        self.assertEqual(out, "XXXX-XXXX-XXXX")

    def test_text_without_identifiers_is_unchanged(self):
        text = "order 123456789012 shipped\r\nphone 919876543210\n"
        self.assertEqual(redact(text), text)

    def test_bad_style_is_rejected(self):
        with self.assertRaises(ValueError):
            redact(PAN, style="blur")

    def test_characters_that_grow_when_uppercased_do_not_shift_positions(self):
        # German sharp s upper-cases to two characters
        self.assertEqual(redact(f"straße PAN {PAN}"), "straße PAN ABCXXXXX4F")


class Positions(unittest.TestCase):
    def test_scan_text_positions_survive_long_blank_runs(self):
        text = f"intro\n\n\n \n\nPAN {PAN}\n\n\n\nmore"
        (f,) = scan_text(text)
        self.assertEqual(text[f.hit.start:f.hit.end], PAN)


class Cli(unittest.TestCase):
    def test_redact_writes_a_copy_and_leaves_the_original(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "customers.csv"
            original = f"name,pan_no\r\nPriya Nair,{PAN}\r\n"
            src.write_bytes(original.encode())
            self.assertEqual(main(["--redact", str(src)]), 0)
            self.assertEqual(src.read_bytes(), original.encode())
            out = (Path(d) / "customers.redacted.csv").read_bytes().decode()
            self.assertEqual(out, "name,pan_no\r\nPriya Nair,ABCXXXXX4F\r\n")


if __name__ == "__main__":
    unittest.main()
