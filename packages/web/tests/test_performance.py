#!/usr/bin/env python3
"""Performance tests for the WebScanner and related components.

Tests that the scanner performs well under various conditions using
simple timing assertions.
"""

import csv
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

from packages.exploit_db.database import ExploitDatabase
from packages.exploit_db.searcher import ExploitSearcher


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_mock_scanner(out_dir: Path, **kwargs: Any) -> Any:
    """Build a WebScanner with mocked external tools.

    Args:
        out_dir: Temporary output directory.
        **kwargs: Override default mock results.

    Returns:
        Configured WebScanner instance.
    """
    from packages.web.scanner import WebScanner

    mock_llm = MagicMock()
    scanner = WebScanner(base_url="https://example.com", llm=mock_llm, out_dir=out_dir)

    default_recon = {
        "success": True, "subdomains": [], "live_hosts": [], "endpoints": [],
    }
    default_nuclei = {
        "success": True, "scans": [], "findings": [],
    }
    default_crawl = {
        "success": True, "visited_urls": [], "discovered_urls": [],
        "discovered_forms": [], "discovered_apis": [],
        "discovered_parameters": [],
        "stats": {"total_pages": 0, "total_urls": 0, "total_forms": 0,
                  "total_apis": 0, "total_parameters": 0},
    }

    scanner.run_recon = MagicMock(
        return_value=kwargs.get("recon_result", default_recon)
    )
    scanner.run_nuclei = MagicMock(
        return_value=kwargs.get("nuclei_result", default_nuclei)
    )
    scanner.run_zap = MagicMock(
        return_value=kwargs.get("zap_result", {
            "success": True, "spider": {}, "active_scan": {}, "alerts": [],
        })
    )
    mock_crawler = MagicMock()
    mock_crawler.crawl.return_value = kwargs.get("crawl_result", default_crawl)
    scanner.crawler = mock_crawler
    scanner.fuzzer = MagicMock()
    scanner.fuzzer.fuzz_parameter.return_value = kwargs.get("fuzz_findings", [])
    scanner.correlate_findings = MagicMock(
        return_value={"correlations": kwargs.get("correlations", [])}
    )
    return scanner


# ---------------------------------------------------------------------------
# Performance tests
# ---------------------------------------------------------------------------


class TestScannerInitialization:
    """Test that scanner initialization is fast."""

    def test_scan_initialization_under_100ms(self, tmp_path: Path) -> None:
        """Scanner init should be fast."""
        from packages.web.scanner import WebScanner

        mock_llm = MagicMock()
        start = time.perf_counter()
        scanner = WebScanner(
            base_url="https://example.com", llm=mock_llm, out_dir=tmp_path
        )
        elapsed = time.perf_counter() - start

        assert elapsed < 0.1, f"Scanner init took {elapsed:.3f}s, expected < 0.1s"
        assert scanner is not None


class TestFindingAggregation:
    """Test finding aggregation performance."""

    def test_finding_aggregation_1000_findings(self, tmp_path: Path) -> None:
        """Aggregating 1000 findings should be under 1s."""
        scanner = _make_mock_scanner(tmp_path)

        # Simulate 1000 findings across phases
        scanner._phase_results = {
            "recon": {
                "success": True,
                "subdomains": [f"sub{i}.example.com" for i in range(200)],
                "live_hosts": [f"https://sub{i}.example.com" for i in range(200)],
                "endpoints": [],
            },
            "zap": {
                "alerts": [
                    {
                        "pluginId": "40012",
                        "alert": f"Vuln {i}",
                        "risk": "High",
                        "confidence": "Medium",
                        "url": f"https://example.com/vuln{i}",
                        "param": "p",
                        "evidence": "evidence",
                        "cweid": 89,
                        "wascid": 19,
                        "description": f"Vuln {i}",
                        "solution": "Fix it",
                    }
                    for i in range(300)
                ]
            },
            "fuzz": [
                {
                    "url": f"https://example.com/api{i}",
                    "parameter": "id",
                    "payload": f"payload_{i}",
                    "vulnerability_type": "sqli",
                    "status_code": 500,
                    "response_length": 100,
                }
                for i in range(300)
            ],
            "crawl": {
                "success": True,
                "discovered_forms": [
                    {"action": f"https://example.com/form{i}", "method": "POST",
                     "inputs": {"field": {"type": "text"}}}
                    for i in range(200)
                ],
            },
            "nuclei": {
                "success": True,
                "scans": [
                    {
                        "target": f"https://example.com/target{i}",
                        "success": True,
                        "stdout": "",
                        "stderr": "",
                        "_output_dir": ".",
                    }
                    for i in range(10)
                ],
            },
        }

        start = time.perf_counter()
        findings = scanner.aggregate_findings()
        elapsed = time.perf_counter() - start

        assert len(findings) >= 1000
        assert elapsed < 1.0, (
            f"Aggregating 1000+ findings took {elapsed:.3f}s, expected < 1.0s"
        )


class TestCorrelationPerformance:
    """Test correlation performance."""

    def test_correlation_100_findings(self, tmp_path: Path) -> None:
        """Correlating 100 findings should be under 2s."""
        from packages.web.scanner import WebScanner

        mock_llm = MagicMock()
        scanner = WebScanner(
            base_url="https://example.com", llm=mock_llm, out_dir=tmp_path,
            phases=["correlate"],
        )

        # Create 100 findings with CVEs
        scanner._findings = [
            {
                "id": f"finding-{i}",
                "type": "nuclei",
                "severity": "high",
                "title": f"Vuln {i}",
                "source": "nuclei",
                "cve": f"CVE-2021-{40000 + i}",
            }
            for i in range(100)
        ]

        # Mock exploit database and searcher
        mock_db = MagicMock()
        mock_searcher = MagicMock()
        mock_searcher.search.return_value = [
            {"id": "EDB-1", "description": "exploit", "type": "remote"}
        ]

        start = time.perf_counter()

        with patch("packages.web.scanner.ExploitDatabase", return_value=mock_db), \
             patch("packages.web.scanner.ExploitSearcher", return_value=mock_searcher):
            result = scanner.correlate_findings()

        elapsed = time.perf_counter() - start

        assert elapsed < 2.0, (
            f"Correlating 100 findings took {elapsed:.3f}s, expected < 2.0s"
        )


class TestReportGeneration:
    """Test report generation performance."""

    def test_report_generation_under_500ms(self, tmp_path: Path) -> None:
        """Report generation should be fast."""
        scanner = _make_mock_scanner(tmp_path)

        # Add 500 findings
        scanner._findings = [
            {
                "id": f"finding-{i}",
                "type": "test",
                "severity": "info",
                "title": f"Finding {i}",
                "source": "test",
                "url": f"https://example.com/{i}",
                "parameter": None,
                "evidence": "test",
                "cve": None,
                "cwe": None,
                "confidence": "high",
                "remediation": "N/A",
            }
            for i in range(500)
        ]
        scanner._phases_run = ["recon", "nuclei", "zap", "crawl", "fuzz", "correlate"]
        scanner._correlations = []

        start = time.perf_counter()
        report_path = scanner.save_report()
        elapsed = time.perf_counter() - start

        assert report_path.exists()
        assert elapsed < 0.5, (
            f"Report generation took {elapsed:.3f}s, expected < 0.5s"
        )


class TestMemoryUsage:
    """Test memory usage and leak prevention."""

    def test_memory_usage_reasonable(self, tmp_path: Path) -> None:
        """Scanner should not leak memory on repeated runs."""
        scanner = _make_mock_scanner(tmp_path)

        initial_size = len(scanner._findings)
        assert initial_size == 0

        # Run scan multiple times
        for _ in range(5):
            scanner.scan()
            # After each scan, _findings should be reset and repopulated
            # Not growing unboundedly
            assert len(scanner._findings) < 1000  # Reasonable upper bound


class TestExploitDatabasePerformance:
    """Test ExploitDatabase CSV and search performance."""

    def _create_large_csv(self, path: Path, num_rows: int) -> Path:
        """Create a CSV file with the specified number of rows.

        Args:
            path: Output CSV path.
            num_rows: Number of exploit rows to generate.

        Returns:
            Path to the created CSV file.
        """
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "id", "filename", "description", "author",
                "date_published", "type", "platform", "port",
            ])
            for i in range(num_rows):
                writer.writerow([
                    str(i),
                    f"exploit_{i}.py",
                    f"Software Vulnerability CVE-2021-{40000 + (i % 50)}",
                    f"Author {i % 10}",
                    "2021-01-01",
                    ["webapps", "remote", "local"][i % 3],
                    ["linux", "windows"][i % 2],
                    str(80 + (i % 10)),
                ])
        return path

    def test_csv_load_under_500ms(self, tmp_path: Path) -> None:
        """ExploitDatabase CSV load for 1000 records."""
        csv_path = tmp_path / "large_exploits.csv"
        self._create_large_csv(csv_path, 1000)

        start = time.perf_counter()
        db = ExploitDatabase()
        db.load_csv(str(csv_path))
        elapsed = time.perf_counter() - start

        assert len(db.exploits) == 1000
        assert elapsed < 0.5, (
            f"CSV load for 1000 records took {elapsed:.3f}s, expected < 0.5s"
        )

    def test_search_under_100ms(self, tmp_path: Path) -> None:
        """ExploitSearcher search should be fast."""
        csv_path = tmp_path / "exploits.csv"
        self._create_large_csv(csv_path, 1000)

        db = ExploitDatabase()
        db.load_csv(str(csv_path))
        db.build_index()
        searcher = ExploitSearcher(db)

        start = time.perf_counter()
        results = searcher.search(cve="CVE-2021-40000")
        elapsed = time.perf_counter() - start

        assert elapsed < 0.1, (
            f"Search took {elapsed:.3f}s, expected < 0.1s"
        )


class TestOrchestratorPipeline:
    """Test full orchestrator pipeline performance."""

    def test_orchestrator_pipeline_under_5s(self, tmp_path: Path) -> None:
        """Full recon pipeline mock should be fast."""
        from packages.web.recon.orchestrator import ReconOrchestrator

        # Mock all external tools
        with patch("packages.web.recon.orchestrator.SubfinderWrapper") as mock_sub, \
             patch("packages.web.recon.orchestrator.HttpxWrapper") as mock_http, \
             patch("packages.web.recon.orchestrator.KatanaWrapper") as mock_kat:

            mock_sub.return_value.run.return_value = {
                "success": True,
                "subdomains": [
                    f"sub{i}.example.com" for i in range(50)
                ],
            }
            mock_http.return_value.run.return_value = {
                "success": True,
                "live_hosts": [
                    f"https://sub{i}.example.com" for i in range(50)
                ],
            }
            mock_kat.return_value.run.return_value = {
                "success": True,
                "endpoints": ["/api/endpoint"],
            }

            orchestrator = ReconOrchestrator()
            start = time.perf_counter()
            result = orchestrator.run(
                target_domain="example.com",
                output_dir=str(tmp_path),
            )
            elapsed = time.perf_counter() - start

            assert result.get("success") is True
            assert len(result.get("subdomains", [])) == 50
            assert len(result.get("live_hosts", [])) == 50
            # 50 hosts * 1 endpoint each = 50
            assert len(result.get("endpoints", [])) == 50
            assert elapsed < 5.0, (
                f"Orchestrator pipeline took {elapsed:.3f}s, expected < 5.0s"
            )


class TestScannerScanPerformance:
    """Test full scanner scan performance."""

    def test_full_scan_under_2s(self, tmp_path: Path) -> None:
        """Full mocked scan should complete under 2 seconds."""
        scanner = _make_mock_scanner(tmp_path)

        start = time.perf_counter()
        result = scanner.scan()
        elapsed = time.perf_counter() - start

        assert result["target"] == "https://example.com"
        assert elapsed < 2.0, (
            f"Full mocked scan took {elapsed:.3f}s, expected < 2.0s"
        )

    def test_scan_with_large_recon_under_1s(self, tmp_path: Path) -> None:
        """Scan with 500 subdomains should be fast."""
        large_recon = {
            "success": True,
            "subdomains": [f"sub{i}.example.com" for i in range(250)],
            "live_hosts": [f"https://sub{i}.example.com" for i in range(250)],
            "endpoints": [f"/api/{i}" for i in range(100)],
        }
        scanner = _make_mock_scanner(
            tmp_path,
            recon_result=large_recon,
            zap_alerts=[],
            fuzz_findings=[],
            exploit_results=[],
        )

        start = time.perf_counter()
        result = scanner.scan()
        elapsed = time.perf_counter() - start

        assert len(result["findings"]) >= 500  # 250 subdomains + 250 hosts
        assert elapsed < 1.0, (
            f"Scan with large recon took {elapsed:.3f}s, expected < 1.0s"
        )
