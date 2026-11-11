"""Every identifier here is synthetic, built to satisfy its own checksum."""

import unittest

from pehchaan import Kind, Scope, gstin_check_char, scan, scan_rows, scan_text, verhoeff_digit, verhoeff_ok


def make_aadhaar(prefix11="36420577201"):
    return prefix11 + str(verhoeff_digit(prefix11))


def make_gstin(state="29", pan="ABCPN1234F", entity="1"):
    head = f"{state}{pan}{entity}Z"
    return head + gstin_check_char(head)


AADHAAR = make_aadhaar()
PAN = "ABCPN1234F"
GSTIN = make_gstin()


class Checksums(unittest.TestCase):
    def test_verhoeff_accepts_what_it_generates(self):
        self.assertTrue(verhoeff_ok(AADHAAR))

    def test_verhoeff_catches_a_single_digit_change(self):
        broken = AADHAAR[:-1] + str((int(AADHAAR[-1]) + 1) % 10)
        self.assertFalse(verhoeff_ok(broken))

    def test_verhoeff_catches_transposition(self):
        swapped = AADHAAR[:4] + AADHAAR[5] + AADHAAR[4] + AADHAAR[6:]
        if swapped != AADHAAR:
            self.assertFalse(verhoeff_ok(swapped))

    def test_gstin_check_char_round_trips(self):
        self.assertEqual(gstin_check_char(GSTIN[:14]), GSTIN[14])

    def test_bad_gstin_check_char_is_dropped(self):
        bad = GSTIN[:14] + ("A" if GSTIN[14] != "A" else "B")
        self.assertEqual(scan(f"gstin {bad}"), [])


class FalsePositives(unittest.TestCase):
    """The failure mode that kills these tools in production."""

    def test_order_ids_and_timestamps_are_not_aadhaar(self):
        noise = "order 491230000123 ref 300412009988 epoch 173847561234"
        self.assertEqual([f for f in scan(noise) if f.hit.kind is Kind.AADHAAR], [])

    def test_plain_email_is_not_upi(self):
        self.assertEqual(scan("mail priya.nair@gmail.com"), [])

    def test_psp_handle_is_upi(self):
        self.assertEqual([f.hit.kind for f in scan("upi priya@okhdfcbank")], [Kind.UPI])

    def test_bad_holder_code_is_not_pan(self):
        self.assertEqual(scan("ref ABCXN1234F"), [])   # X is not a holder type

    def test_eleven_digits_is_not_aadhaar(self):
        self.assertEqual(scan("36420577201"), [])


class AadhaarNeverLeaks(unittest.TestCase):
    def test_value_is_absent_from_every_field(self):
        f = scan(f"uid {AADHAAR}", Scope(field="aadhaar_no"))[0]
        blob = repr(f) + str(f)
        self.assertNotIn(AADHAAR, blob)
        self.assertNotIn(AADHAAR[:8], blob)
        self.assertIn(AADHAAR[-4:], blob)   # last four, as UIDAI allows


class Scoring(unittest.TestCase):
    def test_column_name_beats_bare_text(self):
        bare = scan(PAN)[0].score
        named = scan(PAN, Scope(field="CUST_PAN_NO"))[0].score
        self.assertGreater(named - bare, 25)

    def test_inline_label_counts_when_there_is_no_column(self):
        self.assertGreater(scan(f"PAN: {PAN}")[0].score, scan(PAN)[0].score)

    def test_uat_is_discounted(self):
        prod = scan(f"customer pan {PAN}", Scope(environment="prod"))[0].score
        uat = scan(f"customer pan {PAN}", Scope(environment="uat"))[0].score
        self.assertGreater(prod - uat, 35)

    def test_nonprod_path_is_discounted(self):
        live = scan(PAN, Scope(source="oracle://PRD/CRM"))[0].score
        dev = scan(PAN, Scope(source="oracle://DEV/CRM"))[0].score
        self.assertGreater(live - dev, 35)

    def test_a_fixture_does_not_suppress_a_live_record(self):
        """Regression: a sliding window used to let this happen."""
        doc = (f"Customer: Priya Nair\nAddress: Bengaluru\nPAN: {PAN}\n"
               "\n\n-- test fixture below --\nsample pan: AAAPA1111A\n")
        found = scan_text(doc)
        live = [f for f in found if f.hit.masked.startswith("ABC")]
        fake = [f for f in found if f.hit.masked.startswith("AAA")]
        self.assertEqual((len(live), len(fake)), (1, 1))
        self.assertGreater(live[0].score, 55)
        self.assertLess(fake[0].score, 20)


class Rows(unittest.TestCase):
    def test_ranking_puts_prod_pan_column_on_top(self):
        rows = [
            (PAN, Scope(source="oracle://PRD/CRM", container="CUSTOMER",
                        field="PAN_NO", environment="prod")),
            (PAN, Scope(source="oracle://UAT/CRM", container="CUSTOMER",
                        field="PAN_NO", environment="uat")),
            (PAN, Scope(source="oracle://PRD/CRM", container="ORDERS",
                        field="EXT_REF_03", environment="prod")),
        ]
        ranked = scan_rows(rows)
        self.assertEqual(ranked[0].scope.field, "PAN_NO")
        self.assertEqual(ranked[0].scope.environment, "prod")
        self.assertEqual(ranked[-1].scope.environment, "uat")


if __name__ == "__main__":
    unittest.main()
