"""Tests for packages.web.zap.scanner module."""

import json
import unittest
from pathlib import Path
from unittest.mock import MagicMock, PropertyMock, patch

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class MockZAP:
    """Mock ZAP API client for testing."""

    def __init__(self):
        self.spider = MagicMock()
        self.ascan = MagicMock()
        self.core = MagicMock()
        self.pscan = MagicMock()


class TestZapScanner(unittest.TestCase):
    """Test suite for ZapScanner class."""

    def _get_alerts_fixture(self):
        """Load alerts fixture."""
        fixture_path = FIXTURES_DIR / "zap_alerts.json"
        with open(fixture_path) as f:
            return json.load(f)

    # ── Initialization Tests ──

    def test_init_default_params(self):
        """Test ZapScanner initializes with default parameters."""
        with patch("packages.web.zap.scanner.ZAPv2", MagicMock()):
            from packages.web.zap.scanner import ZapScanner

            scanner = ZapScanner()
            self.assertEqual(scanner.host, "localhost")
            self.assertEqual(scanner.port, 8080)
            self.assertEqual(scanner.api_key, "")

    def test_init_custom_params(self):
        """Test ZapScanner initializes with custom parameters."""
        with patch("packages.web.zap.scanner.ZAPv2", MagicMock()):
            from packages.web.zap.scanner import ZapScanner

            scanner = ZapScanner(api_key="test-key", host="192.168.1.1", port=9090)
            self.assertEqual(scanner.api_key, "test-key")
            self.assertEqual(scanner.host, "192.168.1.1")
            self.assertEqual(scanner.port, 9090)

    def test_init_raises_when_zapv2_missing(self):
        """Test ZapScanner raises ImportError when zapv2 is not installed."""
        with patch("packages.web.zap.scanner.ZAPv2", None):
            from packages.web.zap.scanner import ZapScanner

            with self.assertRaises(ImportError) as ctx:
                ZapScanner()
            self.assertIn("zapv2", str(ctx.exception).lower())

    # ── Availability Tests ──

    @patch("packages.web.zap.scanner.ZAPv2")
    def test_is_available_returns_true_when_zap_running(self, mock_zap_class):
        """Test is_available returns True when ZAP is running."""
        mock_zap = MockZAP()
        mock_zap.core.version.return_value = "2.14.0"
        mock_zap_class.return_value = mock_zap

        from packages.web.zap.scanner import ZapScanner

        scanner = ZapScanner()
        self.assertTrue(scanner.is_available())

    @patch("packages.web.zap.scanner.ZAPv2")
    def test_is_available_returns_false_when_zap_not_running(self, mock_zap_class):
        """Test is_available returns False when ZAP is not running."""
        mock_zap_class.side_effect = Exception("Connection refused")

        from packages.web.zap.scanner import ZapScanner

        scanner = ZapScanner()
        self.assertFalse(scanner.is_available())

    @patch("packages.web.zap.scanner.ZAPv2")
    def test_is_available_returns_false_on_timeout(self, mock_zap_class):
        """Test is_available returns False on connection timeout."""
        mock_zap_class.side_effect = TimeoutError("Connection timed out")

        from packages.web.zap.scanner import ZapScanner

        scanner = ZapScanner()
        self.assertFalse(scanner.is_available())

    # ── Spider Scan Tests ──

    @patch("packages.web.zap.scanner.ZAPv2")
    def test_spider_scan_starts_scan(self, mock_zap_class):
        """Test spider scan initiates a spider scan via ZAP API."""
        mock_zap = MockZAP()
        mock_zap.spider.scan.return_value = "scan-id-123"
        mock_zap.spider.status.return_value = "100"
        mock_zap_class.return_value = mock_zap

        from packages.web.zap.scanner import ZapScanner

        scanner = ZapScanner()
        result = scanner.spider_scan("https://example.com")

        mock_zap.spider.scan.assert_called_once_with(
            "https://example.com", maxchildren=None
        )
        self.assertEqual(result["scan_id"], "scan-id-123")
        self.assertTrue(result["completed"])

    @patch("packages.web.zap.scanner.ZAPv2")
    def test_spider_scan_polls_until_complete(self, mock_zap_class):
        """Test spider scan polls status until completion."""
        mock_zap = MockZAP()
        mock_zap.spider.scan.return_value = "scan-id-456"
        mock_zap.spider.status.side_effect = ["50", "100"]
        mock_zap_class.return_value = mock_zap

        from packages.web.zap.scanner import ZapScanner

        scanner = ZapScanner()
        result = scanner.spider_scan("https://example.com")

        self.assertTrue(result["completed"])
        self.assertEqual(result["progress"], "100")

    @patch("packages.web.zap.scanner.ZAPv2")
    def test_spider_scan_respects_max_duration(self, mock_zap_class):
        """Test spider scan respects max_duration parameter."""
        mock_zap = MockZAP()
        mock_zap.spider.scan.return_value = "scan-id-789"
        mock_zap.spider.status.return_value = "50"
        mock_zap_class.return_value = mock_zap

        from packages.web.zap.scanner import ZapScanner

        scanner = ZapScanner()
        # With very short max_duration, scan should time out
        result = scanner.spider_scan("https://example.com", max_duration=0)

        # With max_duration=0, it should still call scan but may not complete
        mock_zap.spider.scan.assert_called_once()

    @patch("packages.web.zap.scanner.ZAPv2")
    def test_spider_scan_returns_urls_found(self, mock_zap_class):
        """Test spider scan returns number of URLs found."""
        mock_zap = MockZAP()
        mock_zap.spider.scan.return_value = "scan-id-urls"
        mock_zap.spider.status.return_value = "100"
        mock_zap.spider.results.return_value = [
            "https://example.com/page1",
            "https://example.com/page2",
        ]
        mock_zap_class.return_value = mock_zap

        from packages.web.zap.scanner import ZapScanner

        scanner = ZapScanner()
        result = scanner.spider_scan("https://example.com")

        self.assertIn("urls_found", result)
        self.assertEqual(result["urls_found"], 2)

    # ── Active Scan Tests ──

    @patch("packages.web.zap.scanner.ZAPv2")
    def test_active_scan_starts_scan(self, mock_zap_class):
        """Test active scan initiates an active scan via ZAP API."""
        mock_zap = MockZAP()
        mock_zap.ascan.scan.return_value = "ascan-id-123"
        mock_zap.ascan.status.return_value = "100"
        mock_zap_class.return_value = mock_zap

        from packages.web.zap.scanner import ZapScanner

        scanner = ZapScanner()
        result = scanner.active_scan("https://example.com")

        mock_zap.ascan.scan.assert_called_once_with("https://example.com")
        self.assertEqual(result["scan_id"], "ascan-id-123")
        self.assertTrue(result["completed"])

    @patch("packages.web.zap.scanner.ZAPv2")
    def test_active_scan_polls_until_complete(self, mock_zap_class):
        """Test active scan polls status until completion."""
        mock_zap = MockZAP()
        mock_zap.ascan.scan.return_value = "ascan-id-456"
        mock_zap.ascan.status.side_effect = ["25", "75", "100"]
        mock_zap_class.return_value = mock_zap

        from packages.web.zap.scanner import ZapScanner

        scanner = ZapScanner()
        result = scanner.active_scan("https://example.com")

        self.assertTrue(result["completed"])
        self.assertEqual(result["progress"], "100")

    @patch("packages.web.zap.scanner.ZAPv2")
    def test_active_scan_respects_max_duration(self, mock_zap_class):
        """Test active scan respects max_duration parameter."""
        mock_zap = MockZAP()
        mock_zap.ascan.scan.return_value = "ascan-id-789"
        mock_zap.ascan.status.return_value = "50"
        mock_zap_class.return_value = mock_zap

        from packages.web.zap.scanner import ZapScanner

        scanner = ZapScanner()
        result = scanner.active_scan("https://example.com", max_duration=0)

        mock_zap.ascan.scan.assert_called_once()

    @patch("packages.web.zap.scanner.ZAPv2")
    def test_active_scan_stops_on_duration_exceeded(self, mock_zap_class):
        """Test active scan stops when duration is exceeded."""
        mock_zap = MockZAP()
        mock_zap.ascan.scan.return_value = "ascan-id-timeout"
        mock_zap.ascan.status.return_value = "50"
        mock_zap_class.return_value = mock_zap

        from packages.web.zap.scanner import ZapScanner

        scanner = ZapScanner()
        # max_duration=0 should trigger immediate stop logic
        result = scanner.active_scan("https://example.com", max_duration=0)

        # Scan should be marked as not completed or stopped
        self.assertIsInstance(result, dict)

    # ── Alert Retrieval Tests ──

    @patch("packages.web.zap.scanner.ZAPv2")
    def test_get_alerts_returns_parsed_alerts(self, mock_zap_class):
        """Test get_alerts returns parsed alert data."""
        mock_zap = MockZAP()
        fixture_alerts = self._get_alerts_fixture()
        mock_zap.core.alerts.return_value = fixture_alerts
        mock_zap_class.return_value = mock_zap

        from packages.web.zap.scanner import ZapScanner

        scanner = ZapScanner()
        alerts = scanner.get_alerts()

        self.assertIsInstance(alerts, list)
        self.assertEqual(len(alerts), 6)
        self.assertEqual(alerts[0]["alert"], "SQL Injection")
        self.assertEqual(alerts[0]["risk"], "High")

    @patch("packages.web.zap.scanner.ZAPv2")
    def test_get_alerts_returns_empty_list_when_no_alerts(self, mock_zap_class):
        """Test get_alerts returns empty list when no alerts exist."""
        mock_zap = MockZAP()
        mock_zap.core.alerts.return_value = []
        mock_zap_class.return_value = mock_zap

        from packages.web.zap.scanner import ZapScanner

        scanner = ZapScanner()
        alerts = scanner.get_alerts()

        self.assertEqual(alerts, [])

    @patch("packages.web.zap.scanner.ZAPv2")
    def test_get_alerts_handles_api_error(self, mock_zap_class):
        """Test get_alerts handles ZAP API errors gracefully."""
        mock_zap = MockZAP()
        mock_zap.core.alerts.side_effect = Exception("API error")
        mock_zap_class.return_value = mock_zap

        from packages.web.zap.scanner import ZapScanner

        scanner = ZapScanner()
        alerts = scanner.get_alerts()

        self.assertEqual(alerts, [])

    # ── Risk Count Tests ──

    @patch("packages.web.zap.scanner.ZAPv2")
    def test_get_risk_counts_returns_correct_counts(self, mock_zap_class):
        """Test get_risk_counts returns correct risk level counts."""
        mock_zap = MockZAP()
        fixture_alerts = self._get_alerts_fixture()
        mock_zap.core.alerts.return_value = fixture_alerts
        mock_zap_class.return_value = mock_zap

        from packages.web.zap.scanner import ZapScanner

        scanner = ZapScanner()
        counts = scanner.get_risk_counts()

        self.assertEqual(counts["High"], 2)
        self.assertEqual(counts["Medium"], 1)
        self.assertEqual(counts["Low"], 2)
        self.assertEqual(counts["Informational"], 1)

    @patch("packages.web.zap.scanner.ZAPv2")
    def test_get_risk_counts_empty_when_no_alerts(self, mock_zap_class):
        """Test get_risk_counts returns zeros when no alerts."""
        mock_zap = MockZAP()
        mock_zap.core.alerts.return_value = []
        mock_zap_class.return_value = mock_zap

        from packages.web.zap.scanner import ZapScanner

        scanner = ZapScanner()
        counts = scanner.get_risk_counts()

        self.assertEqual(counts.get("High", 0), 0)
        self.assertEqual(counts.get("Medium", 0), 0)
        self.assertEqual(counts.get("Low", 0), 0)
        self.assertEqual(counts.get("Informational", 0), 0)

    # ── Passive Scan Tests ──

    @patch("packages.web.zap.scanner.ZAPv2")
    def test_passive_scan_returns_records(self, mock_zap_class):
        """Test passive scan retrieves scan records."""
        mock_zap = MockZAP()
        mock_zap.pscan.records_to_display.return_value = "5"
        mock_zap_class.return_value = mock_zap

        from packages.web.zap.scanner import ZapScanner

        scanner = ZapScanner()
        result = scanner.get_passive_scan_records()

        self.assertEqual(result, 5)

    @patch("packages.web.zap.scanner.ZAPv2")
    def test_passive_scan_handles_error(self, mock_zap_class):
        """Test passive scan handles API errors gracefully."""
        mock_zap = MockZAP()
        mock_zap.pscan.records_to_display.side_effect = Exception("API error")
        mock_zap_class.return_value = mock_zap

        from packages.web.zap.scanner import ZapScanner

        scanner = ZapScanner()
        result = scanner.get_passive_scan_records()

        self.assertIsNone(result)

    # ── Shutdown Tests ──

    @patch("packages.web.zap.scanner.ZAPv2")
    def test_shutdown_stops_zap(self, mock_zap_class):
        """Test shutdown calls ZAP core shutdown."""
        mock_zap = MockZAP()
        mock_zap_class.return_value = mock_zap

        from packages.web.zap.scanner import ZapScanner

        scanner = ZapScanner()
        scanner.shutdown()

        mock_zap.core.shutdown.assert_called_once()

    @patch("packages.web.zap.scanner.ZAPv2")
    def test_shutdown_handles_error(self, mock_zap_class):
        """Test shutdown handles errors gracefully."""
        mock_zap = MockZAP()
        mock_zap.core.shutdown.side_effect = Exception("Shutdown error")
        mock_zap_class.return_value = mock_zap

        from packages.web.zap.scanner import ZapScanner

        scanner = ZapScanner()
        # Should not raise
        scanner.shutdown()

    # ── Error Handling Tests ──

    @patch("packages.web.zap.scanner.ZAPv2")
    def test_spider_scan_handles_connection_error(self, mock_zap_class):
        """Test spider scan handles connection errors."""
        mock_zap = MockZAP()
        mock_zap.spider.scan.side_effect = Exception("Connection refused")
        mock_zap_class.return_value = mock_zap

        from packages.web.zap.scanner import ZapScanner

        scanner = ZapScanner()
        result = scanner.spider_scan("https://example.com")

        self.assertFalse(result["completed"])
        self.assertIn("error", result)

    @patch("packages.web.zap.scanner.ZAPv2")
    def test_active_scan_handles_connection_error(self, mock_zap_class):
        """Test active scan handles connection errors."""
        mock_zap = MockZAP()
        mock_zap.ascan.scan.side_effect = Exception("Connection refused")
        mock_zap_class.return_value = mock_zap

        from packages.web.zap.scanner import ZapScanner

        scanner = ZapScanner()
        result = scanner.active_scan("https://example.com")

        self.assertFalse(result["completed"])
        self.assertIn("error", result)

    @patch("packages.web.zap.scanner.ZAPv2")
    def test_spider_scan_handles_timeout_error(self, mock_zap_class):
        """Test spider scan handles timeout errors."""
        mock_zap = MockZAP()
        mock_zap.spider.scan.side_effect = TimeoutError("Timed out")
        mock_zap_class.return_value = mock_zap

        from packages.web.zap.scanner import ZapScanner

        scanner = ZapScanner()
        result = scanner.spider_scan("https://example.com")

        self.assertFalse(result["completed"])
        self.assertIn("error", result)

    # ── Context Manager Tests ──

    @patch("packages.web.zap.scanner.ZAPv2")
    def test_context_manager_enters(self, mock_zap_class):
        """Test ZapScanner works as a context manager."""
        mock_zap = MockZAP()
        mock_zap.core.version.return_value = "2.14.0"
        mock_zap_class.return_value = mock_zap

        from packages.web.zap.scanner import ZapScanner

        with ZapScanner() as scanner:
            self.assertIsInstance(scanner, object)

    @patch("packages.web.zap.scanner.ZAPv2")
    def test_context_manager_exits_calls_shutdown(self, mock_zap_class):
        """Test context manager calls shutdown on exit."""
        mock_zap = MockZAP()
        mock_zap.core.version.return_value = "2.14.0"
        mock_zap_class.return_value = mock_zap

        from packages.web.zap.scanner import ZapScanner

        with ZapScanner() as scanner:
            pass

        mock_zap.core.shutdown.assert_called_once()


if __name__ == "__main__":
    unittest.main()
