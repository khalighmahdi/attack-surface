# IDN / punycode tests — internationalized domain names must survive
# sanitisation (they are how most phishing lookalikes are spelled).
import unittest
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.utils import sanitize_domain


class TestIDN(unittest.TestCase):
    """Non-ASCII (IDN) domains must be accepted and converted to punycode."""

    def test_unicode_passthrough(self):
        # a Persian-label domain must not be rejected outright
        d = sanitize_domain("فروشگاه.example")
        self.assertTrue(d)

    def test_unicode_with_scheme(self):
        # scheme + unicode label + path must come back as punycode host
        d = sanitize_domain("https://فروشگاه.example/صفحه")
        self.assertEqual(d, "xn--mgbtj4c7ad63e.example")

    def test_punycode(self):
        # an already-punycoded host passes through unchanged
        d = sanitize_domain("xn--mgbaam7a.example")
        self.assertEqual(d, "xn--mgbaam7a.example")


if __name__ == "__main__":
    unittest.main()
