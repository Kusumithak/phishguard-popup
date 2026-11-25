"""URL-only feature checks. These tests use hand-written edge-case strings."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "training"))

from url_pipeline import BASELINE, extract  # noqa: E402


URLS = [
    "http://192.0.2.10:8080/login",
    "https://example.com:8443/path",
    "https://user:pw@example.com/login",
    "HTTPS://EXAMPLE.COM/Account",
    "https://xn--pple-43d.com/signin",
    "https://a.b.example.co.uk/login",
    "https://a.b.example.co.in/login",
    "example.com/login",
    "example.com/path//double",
    "https://example.com/a%2Fb?q=%2520",
    "https://exämple.com/pé?café=1",
    "https://example.com./login",
    "https://example.com/#fragment-only",
    "https://paypal-login.xyz/verify",
    "https://paypal.com/login",
    "https://amazonaws.com/login",
    "https://www.example.com/",
    "https://login.example.com/",
    "https://example.com?next=%2Flogin&x=1",
    "http://example.net:80/",
    "https://:pw@example.net/",
    "https://@example.net/",
    "https://one.two.three.example.org/secure",
    "https://www.google.co.in/",
    "https://accounts.google.com/",
    "https://paypa1-login-secure.xyz/account",
    "https://foo.example.com./path#x",
    "//example.org/path",
]


class UrlFeatureTests(unittest.TestCase):
    def test_edge_case_features(self):
        self.assertGreaterEqual(len(URLS), 20)
        results = [extract(url) for url in URLS]
        self.assertEqual(results[0]["is_ip"], 1)
        self.assertEqual(results[1]["has_port"], 1)
        self.assertEqual(results[2]["has_userinfo"], 1)
        self.assertEqual(results[2]["has_at"], 1)
        self.assertEqual(results[3]["host_length"], len("example.com"))
        self.assertEqual(results[4]["has_punycode"], 1)
        self.assertEqual(results[5]["deep_subdomain_count"], 1)
        self.assertEqual(results[6]["deep_subdomain_count"], 1)
        self.assertEqual(results[8]["double_slash"], 1)
        self.assertGreater(results[9]["n_pct"], 0)
        self.assertEqual(results[11]["host_length"], len("example.com"))
        self.assertEqual(results[12]["path_len"], 1)  # slash, fragment excluded
        self.assertEqual(results[13]["brand_mismatch_host"], 1)
        self.assertEqual(results[14]["brand_mismatch_host"], 0)
        self.assertEqual(results[15]["brand_mismatch_host"], 0)
        self.assertEqual(results[20]["has_userinfo"], 1)
        self.assertEqual(results[21]["has_userinfo"], 0)

    def test_scheme_is_not_a_feature(self):
        http = extract("http://example.com/login?q=1")
        https = extract("https://example.com/login?q=1")
        self.assertEqual(http, https)
        self.assertNotIn("has_https", http)
        self.assertNotIn("has_https", BASELINE)


if __name__ == "__main__":
    unittest.main()
