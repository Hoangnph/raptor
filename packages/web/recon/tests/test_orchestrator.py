"""Tests for packages.web.recon.orchestrator module."""

import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch, MagicMock

from packages.web.recon.orchestrator import ReconOrchestrator


class TestOrchestratorInit(unittest.TestCase):
    """Test suite for ReconOrchestrator initialization."""

    def test_init_stores_results(self):
        """Test ReconOrchestrator initializes with empty results."""
        orchestrator = ReconOrchestrator()
        self.assertIsInstance(orchestrator._results, dict)

    def test_init_has_tool_instances(self):
        """Test ReconOrchestrator initializes tool wrappers."""
        orchestrator = ReconOrchestrator()
        self.assertIsNotNone(orchestrator._subfinder)
        self.assertIsNotNone(orchestrator._httpx)
        self.assertIsNotNone(orchestrator._katana)


class TestOrchestratorRun(unittest.TestCase):
    """Test suite for run method."""

    @patch("packages.web.recon.orchestrator.save_json")
    @patch("packages.web.recon.orchestrator.KatanaWrapper")
    @patch("packages.web.recon.orchestrator.HttpxWrapper")
    @patch("packages.web.recon.orchestrator.SubfinderWrapper")
    def test_full_pipeline_success(
        self,
        mock_subfinder_cls: Mock,
        mock_httpx_cls: Mock,
        mock_katana_cls: Mock,
        mock_save_json: Mock,
    ):
        """Test full pipeline: subfinder -> httpx -> katana."""
        mock_subfinder = MagicMock()
        mock_subfinder.is_available.return_value = True
        mock_subfinder.run.return_value = {
            "success": True,
            "subdomains": ["sub1.example.com", "sub2.example.com"],
            "stdout": "sub1.example.com\nsub2.example.com\n",
        }
        mock_subfinder_cls.return_value = mock_subfinder

        mock_httpx = MagicMock()
        mock_httpx.is_available.return_value = True
        mock_httpx.run.return_value = {
            "success": True,
            "live_hosts": ["https://sub1.example.com"],
        }
        mock_httpx_cls.return_value = mock_httpx

        mock_katana = MagicMock()
        mock_katana.is_available.return_value = True
        mock_katana.run.return_value = {"success": True, "endpoints": ["/api/users"]}
        mock_katana_cls.return_value = mock_katana

        with TemporaryDirectory() as tmpdir:
            orchestrator = ReconOrchestrator()
            result = orchestrator.run(target_domain="example.com", output_dir=tmpdir)

        self.assertTrue(result["success"])
        self.assertIn("subdomains", result)
        self.assertIn("live_hosts", result)

    @patch("packages.web.recon.orchestrator.save_json")
    @patch("packages.web.recon.orchestrator.KatanaWrapper")
    @patch("packages.web.recon.orchestrator.HttpxWrapper")
    @patch("packages.web.recon.orchestrator.SubfinderWrapper")
    def test_partial_failure_subfinder_fails(
        self,
        mock_subfinder_cls: Mock,
        mock_httpx_cls: Mock,
        mock_katana_cls: Mock,
        mock_save_json: Mock,
    ):
        """Test pipeline handles subfinder failure."""
        mock_subfinder = MagicMock()
        mock_subfinder.is_available.return_value = True
        mock_subfinder.run.return_value = {"success": False, "error": "subfinder error"}
        mock_subfinder_cls.return_value = mock_subfinder

        mock_httpx = MagicMock()
        mock_httpx.is_available.return_value = True
        mock_httpx.run.return_value = {"success": True, "live_hosts": []}
        mock_httpx_cls.return_value = mock_httpx

        mock_katana = MagicMock()
        mock_katana.is_available.return_value = True
        mock_katana.run.return_value = {"success": True, "endpoints": []}
        mock_katana_cls.return_value = mock_katana

        with TemporaryDirectory() as tmpdir:
            orchestrator = ReconOrchestrator()
            result = orchestrator.run(target_domain="example.com", output_dir=tmpdir)

        # Pipeline should continue despite partial failure
        self.assertIn("live_hosts", result)
        self.assertIn("endpoints", result)

    @patch("packages.web.recon.orchestrator.save_json")
    @patch("packages.web.recon.orchestrator.KatanaWrapper")
    @patch("packages.web.recon.orchestrator.HttpxWrapper")
    @patch("packages.web.recon.orchestrator.SubfinderWrapper")
    def test_partial_failure_httpx_fails(
        self,
        mock_subfinder_cls: Mock,
        mock_httpx_cls: Mock,
        mock_katana_cls: Mock,
        mock_save_json: Mock,
    ):
        """Test pipeline handles httpx failure."""
        mock_subfinder = MagicMock()
        mock_subfinder.is_available.return_value = True
        mock_subfinder.run.return_value = {
            "success": True,
            "subdomains": ["sub1.example.com"],
        }
        mock_subfinder_cls.return_value = mock_subfinder

        mock_httpx = MagicMock()
        mock_httpx.is_available.return_value = True
        mock_httpx.run.return_value = {"success": False, "error": "httpx error"}
        mock_httpx_cls.return_value = mock_httpx

        mock_katana = MagicMock()
        mock_katana.is_available.return_value = True
        mock_katana.run.return_value = {"success": True, "endpoints": []}
        mock_katana_cls.return_value = mock_katana

        with TemporaryDirectory() as tmpdir:
            orchestrator = ReconOrchestrator()
            result = orchestrator.run(target_domain="example.com", output_dir=tmpdir)

        self.assertIn("subdomains", result)
        self.assertIn("endpoints", result)

    @patch("packages.web.recon.orchestrator.save_json")
    @patch("packages.web.recon.orchestrator.KatanaWrapper")
    @patch("packages.web.recon.orchestrator.HttpxWrapper")
    @patch("packages.web.recon.orchestrator.SubfinderWrapper")
    def test_result_saving(
        self,
        mock_subfinder_cls: Mock,
        mock_httpx_cls: Mock,
        mock_katana_cls: Mock,
        mock_save_json: Mock,
    ):
        """Test results are saved with save_json."""
        mock_subfinder = MagicMock()
        mock_subfinder.is_available.return_value = True
        mock_subfinder.run.return_value = {"success": True, "subdomains": ["sub1.example.com"]}
        mock_subfinder_cls.return_value = mock_subfinder

        mock_httpx = MagicMock()
        mock_httpx.is_available.return_value = True
        mock_httpx.run.return_value = {"success": True, "live_hosts": []}
        mock_httpx_cls.return_value = mock_httpx

        mock_katana = MagicMock()
        mock_katana.is_available.return_value = True
        mock_katana.run.return_value = {"success": True, "endpoints": []}
        mock_katana_cls.return_value = mock_katana

        with TemporaryDirectory() as tmpdir:
            orchestrator = ReconOrchestrator()
            orchestrator.run(target_domain="example.com", output_dir=tmpdir)

        mock_save_json.assert_called_once()

    @patch("packages.web.recon.orchestrator.KatanaWrapper")
    @patch("packages.web.recon.orchestrator.HttpxWrapper")
    @patch("packages.web.recon.orchestrator.SubfinderWrapper")
    def test_result_aggregation(
        self,
        mock_subfinder_cls: Mock,
        mock_httpx_cls: Mock,
        mock_katana_cls: Mock,
    ):
        """Test results are properly aggregated."""
        mock_subfinder = MagicMock()
        mock_subfinder.is_available.return_value = True
        mock_subfinder.run.return_value = {
            "success": True,
            "subdomains": ["sub1.example.com"],
        }
        mock_subfinder_cls.return_value = mock_subfinder

        mock_httpx = MagicMock()
        mock_httpx.is_available.return_value = True
        mock_httpx.run.return_value = {
            "success": True,
            "live_hosts": ["https://sub1.example.com"],
        }
        mock_httpx_cls.return_value = mock_httpx

        mock_katana = MagicMock()
        mock_katana.is_available.return_value = True
        mock_katana.run.return_value = {"success": True, "endpoints": ["/api"]}
        mock_katana_cls.return_value = mock_katana

        with TemporaryDirectory() as tmpdir:
            orchestrator = ReconOrchestrator()
            result = orchestrator.run(target_domain="example.com", output_dir=tmpdir)

        self.assertIn("subdomains", result)
        self.assertIn("live_hosts", result)
        self.assertIn("endpoints", result)

    @patch("packages.web.recon.orchestrator.save_json")
    @patch("packages.web.recon.orchestrator.KatanaWrapper")
    @patch("packages.web.recon.orchestrator.HttpxWrapper")
    @patch("packages.web.recon.orchestrator.SubfinderWrapper")
    def test_run_uses_logger(
        self,
        mock_subfinder_cls: Mock,
        mock_httpx_cls: Mock,
        mock_katana_cls: Mock,
        mock_save_json: Mock,
    ):
        """Test run uses the logger from core.logging."""
        mock_subfinder = MagicMock()
        mock_subfinder.is_available.return_value = True
        mock_subfinder.run.return_value = {"success": True, "subdomains": []}
        mock_subfinder_cls.return_value = mock_subfinder

        mock_httpx = MagicMock()
        mock_httpx.is_available.return_value = True
        mock_httpx.run.return_value = {"success": True, "live_hosts": []}
        mock_httpx_cls.return_value = mock_httpx

        mock_katana = MagicMock()
        mock_katana.is_available.return_value = True
        mock_katana.run.return_value = {"success": True, "endpoints": []}
        mock_katana_cls.return_value = mock_katana

        with TemporaryDirectory() as tmpdir:
            with patch("packages.web.recon.orchestrator.get_logger") as mock_get_logger:
                mock_logger = MagicMock()
                mock_get_logger.return_value = mock_logger

                orchestrator = ReconOrchestrator()
                orchestrator.run(target_domain="example.com", output_dir=tmpdir)

                mock_get_logger.assert_called()


class TestOrchestratorGetResults(unittest.TestCase):
    """Test suite for get_results method."""

    def test_get_results_returns_results(self):
        """Test get_results returns the aggregated results."""
        orchestrator = ReconOrchestrator()
        orchestrator._results = {"subdomains": ["sub1.example.com"], "live_hosts": []}

        result = orchestrator.get_results()

        self.assertIsInstance(result, dict)
        self.assertIn("subdomains", result)
        self.assertEqual(result["subdomains"], ["sub1.example.com"])

    def test_get_results_empty_before_run(self):
        """Test get_results returns empty dict before run."""
        orchestrator = ReconOrchestrator()

        result = orchestrator.get_results()

        self.assertIsInstance(result, dict)
        self.assertEqual(result, {})


if __name__ == "__main__":
    unittest.main()
