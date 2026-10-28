"""
Unit Tests for PhishGuard Threat Analyzer Engine.
Executable using: python3 -m unittest backend/tests/test_analyzer.py
or using: pytest backend/tests/
"""

import unittest
from backend.app.services.analyzer import analyze_content, get_risk_band
from backend.app.services.url_engine import analyze_url_lexical, looks_like_url
from backend.app.services.message_engine import analyze_message_heuristics

class TestPhishGuardAnalyzer(unittest.TestCase):

    def test_01_empty_input(self):
        """Test handling of empty or blank input."""
        res = analyze_content("")
        self.assertEqual(res["riskBand"], "Unknown")
        self.assertEqual(res["riskScore"], 0)
        self.assertEqual(res["primaryCategory"], "unknown")
        self.assertIn("Insufficient", res["summary"])

    def test_02_short_unsupported_input(self):
        """Test handling of very short strings (< 3 chars)."""
        res = analyze_content("hi")
        self.assertEqual(res["riskBand"], "Unknown")
        self.assertEqual(res["riskScore"], 0)

    def test_03_valid_legitimate_url_parsing(self):
        """Test parsing of verified academic/government URLs."""
        url = "https://www.stanford.edu/research/publications"
        res = analyze_content(url, input_type="url")
        self.assertEqual(res["detectedType"], "url")
        self.assertLessEqual(res["riskScore"], 30)
        self.assertEqual(res["riskBand"], "Low Risk")
        self.assertIsNotNone(res["urlMetrics"])
        self.assertEqual(res["urlMetrics"]["tldRiskLevel"], "low")

    def test_04_ip_based_url(self):
        """Test detection of IP-based hostnames bypassing DNS."""
        url = "http://192.168.1.100/secure-login/update.html"
        res = analyze_content(url, input_type="url")
        self.assertTrue(res["urlMetrics"]["isIpAddress"])
        self.assertGreaterEqual(res["riskScore"], 61)
        self.assertIn(res["riskBand"], ["High Risk", "Critical Risk"])
        indicator_ids = [i["id"] for i in res["indicators"]]
        self.assertIn("url_ip_hostname", indicator_ids)

    def test_05_malformed_url(self):
        """Test resilience against malformed URLs."""
        url = "http:///invalid..url::99999"
        res = analyze_content(url, input_type="url")
        self.assertIsNotNone(res)
        self.assertIn("riskScore", res)

    def test_06_suspicious_otp_request(self):
        """Test detection of urgent OTP / 2FA interception."""
        msg = "URGENT: Suspicious activity on your account. Send your one-time password (OTP) immediately within 24 hours to prevent permanent account lock."
        res = analyze_content(msg, input_type="sms")
        self.assertGreaterEqual(res["riskScore"], 61)
        self.assertIn(res["riskBand"], ["High Risk", "Critical Risk"])
        self.assertEqual(res["primaryCategory"], "credential_harvesting")
        # Check compound threat detection
        indicator_titles = [i["title"] for i in res["indicators"]]
        self.assertTrue(any("Credential" in t or "OTP" in t for t in indicator_titles))

    def test_07_recruitment_scam(self):
        """Test detection of upfront employment equipment fraud."""
        msg = "Congratulations! You are hired as a Remote Operations Assistant earning $500/day. No interview needed! Please wire $150 for your background check fee and onboarding starter kit via Western Union."
        res = analyze_content(msg, input_type="email")
        self.assertGreaterEqual(res["riskScore"], 61)
        self.assertIn(res["primaryCategory"], ["recruitment_scam", "advance_fee_scam"])

    def test_08_investment_scam(self):
        """Test detection of guaranteed returns and crypto fraud."""
        msg = "Guaranteed 300% return on your investment in 24 hours! 100% risk-free automated crypto trading bot. Double your bitcoin today."
        res = analyze_content(msg, input_type="other")
        self.assertGreaterEqual(res["riskScore"], 61)
        self.assertEqual(res["primaryCategory"], "investment_fraud")

    def test_09_legitimate_business_text(self):
        """Test benign email message receives low risk score."""
        msg = "Hi Team, please find attached the meeting agenda and quarterly project review slide deck for tomorrow's call at 10 AM. Sincerely, Alex."
        res = analyze_content(msg, input_type="email")
        self.assertLessEqual(res["riskScore"], 30)
        self.assertEqual(res["riskBand"], "Low Risk")
        self.assertEqual(res["primaryCategory"], "legitimate")

    def test_10_risk_score_boundaries(self):
        """Test risk score boundary mappings strictly conform to specifications."""
        self.assertEqual(get_risk_band(0), "Low Risk")
        self.assertEqual(get_risk_band(30), "Low Risk")
        self.assertEqual(get_risk_band(31), "Medium Risk")
        self.assertEqual(get_risk_band(60), "Medium Risk")
        self.assertEqual(get_risk_band(61), "High Risk")
        self.assertEqual(get_risk_band(80), "High Risk")
        self.assertEqual(get_risk_band(81), "Critical Risk")
        self.assertEqual(get_risk_band(100), "Critical Risk")
        self.assertEqual(get_risk_band(50, is_unknown=True), "Unknown")

    def test_11_explanation_generation(self):
        """Verify explainability fields are fully populated."""
        msg = "Security Alert: Verify your password now or account suspended within 24 hours."
        res = analyze_content(msg)
        self.assertTrue(len(res["summary"]) > 10)
        self.assertTrue(len(res["detailedExplanation"]) > 20)
        self.assertTrue(len(res["differenceExplanation"]) > 20)
        self.assertTrue(len(res["recommendations"]) >= 1)
        self.assertTrue(len(res["limitations"]) >= 1)

    def test_12_url_detection_heuristics(self):
        """Test URL pattern detection helper."""
        self.assertTrue(looks_like_url("https://google.com"))
        self.assertTrue(looks_like_url("http://192.168.0.1/login"))
        self.assertTrue(looks_like_url("subdomain.example.xyz/path"))
        self.assertFalse(looks_like_url("Hello this is a regular sentence with no link."))

if __name__ == "__main__":
    unittest.main()
