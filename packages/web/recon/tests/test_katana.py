"""Tests for packages.web.recon.katana module."""

import subprocess
import unittest
from unittest.mock import Mock, patch, MagicMock

from packages.web.recon.katana import KatanaWrapper


FIXTURES_DIR = __import__("pathlib").Path(__file__).parent / "fixtures"


class TestKatanaInit(unittest.TestCase):
    """Test suite for KatanaWrapper initialization."""

    def test_init_default_params(self):
        """Test KatanaWrapper initializes with default parameters."""
        wrapper = KatanaWrapper()
        self.assertEqual(wrapper.katana_path, "katana")

    def test_init_custom_path(self):
        """Test KatanaWrapper initializes with custom katana path."""
        wrapper = KatanaWrapper(katana_path="/usr/local/bin/katana")
        self.assertEqual(wrapper.katana_path, "/usr/local/bin/katana")


class TestKatanaIsAvailable(unittest.TestCase):
    """Test suite for is_available method."""

    @patch("packages.web.recon.katana.subprocess.run")
    def test_is_available_returns_true(self, mock_run: Mock):
        """Test is_available returns True when katana is installed."""
        mock_run.return_value = MagicMock(returncode=0, stdout="katana version")

        wrapper = KatanaWrapper()
        result = wrapper.is_available()

        self.assertTrue(result)

    @patch("packages.web.recon.katana.subprocess.run")
    def test_is_available_returns_false_when_not_found(self, mock_run: Mock):
        """Test is_available returns False when katana is not installed."""
        mock_run.side_effect = FileNotFoundError("katana not found")

        wrapper = KatanaWrapper()
        result = wrapper.is_available()

        self.assertFalse(result)

    @patch("packages.web.recon.katana.subprocess.run")
    def test_is_available_returns_false_on_nonzero(self, mock_run: Mock):
        """Test is_available returns False when katana returns nonzero."""
        mock_run.return_value = MagicMock(returncode=1, stdout="")

        wrapper = KatanaWrapper()
        result = wrapper.is_available()

        self.assertFalse(result)

    @patch("packages.web.recon.katana.subprocess.run")
    def test_is_available_returns_false_on_timeout(self, mock_run: Mock):
        """Test is_available returns False on subprocess timeout."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="katana", timeout=10)

        wrapper = KatanaWrapper()
        result = wrapper.is_available()

        self.assertFalse(result)


class TestKatanaRun(unittest.TestCase):
    """Test suite for run method."""

    @patch("packages.web.recon.katana.subprocess.run")
    def test_run_success(self, mock_run: Mock):
        """Test run executes katana with url."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"endpoint": "/api/users", "method": "GET"}',
            stderr="",
        )

        wrapper = KatanaWrapper()
        result = wrapper.run(url="https://example.com")

        mock_run.assert_called_once()
        call_args = mock_run.call_args
        cmd = call_args[1]["args"] if "args" in call_args[1] else call_args[0][0]
        self.assertIn("katana", cmd)
        self.assertIn("-u", cmd)
        self.assertIn("https://example.com", cmd)
        self.assertTrue(result["success"])

    @patch("packages.web.recon.katana.subprocess.run")
    def test_run_with_output_file(self, mock_run: Mock):
        """Test run executes with output file."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        wrapper = KatanaWrapper()
        result = wrapper.run(url="https://example.com", output_file="/tmp/output.json")

        call_args = mock_run.call_args
        cmd = call_args[1]["args"] if "args" in call_args[1] else call_args[0][0]
        self.assertIn("-o", cmd)
        self.assertIn("/tmp/output.json", cmd)
        self.assertTrue(result["success"])

    @patch("packages.web.recon.katana.subprocess.run")
    def test_run_with_js_render_true(self, mock_run: Mock):
        """Test run executes with JS rendering enabled."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        wrapper = KatanaWrapper()
        result = wrapper.run(url="https://example.com", js_render=True)

        call_args = mock_run.call_args
        cmd = call_args[1]["args"] if "args" in call_args[1] else call_args[0][0]
        self.assertIn("-js-render", cmd)
        self.assertTrue(result["success"])

    @patch("packages.web.recon.katana.subprocess.run")
    def test_run_with_js_render_false(self, mock_run: Mock):
        """Test run executes without JS rendering flag."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        wrapper = KatanaWrapper()
        result = wrapper.run(url="https://example.com", js_render=False)

        call_args = mock_run.call_args
        cmd = call_args[1]["args"] if "args" in call_args[1] else call_args[0][0]
        self.assertNotIn("-js-render", cmd)
        self.assertTrue(result["success"])

    @patch("packages.web.recon.katana.subprocess.run")
    def test_run_with_custom_timeout(self, mock_run: Mock):
        """Test run respects custom timeout."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        wrapper = KatanaWrapper()
        wrapper.run(url="https://example.com", timeout=120)

        call_kwargs = mock_run.call_args[1]
        self.assertEqual(call_kwargs.get("timeout"), 120)

    @patch("packages.web.recon.katana.subprocess.run")
    def test_run_default_timeout(self, mock_run: Mock):
        """Test run uses default timeout of 300."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        wrapper = KatanaWrapper()
        wrapper.run(url="https://example.com")

        call_kwargs = mock_run.call_args[1]
        self.assertEqual(call_kwargs.get("timeout"), 300)

    @patch("packages.web.recon.katana.subprocess.run")
    def test_run_timeout(self, mock_run: Mock):
        """Test run handles subprocess timeout."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="katana", timeout=300)

        wrapper = KatanaWrapper()
        result = wrapper.run(url="https://example.com")

        self.assertFalse(result["success"])
        self.assertIn("timeout", result.get("error", "").lower())

    @patch("packages.web.recon.katana.subprocess.run")
    def test_run_tool_missing(self, mock_run: Mock):
        """Test run handles katana not found."""
        mock_run.side_effect = FileNotFoundError("katana not found")

        wrapper = KatanaWrapper()
        result = wrapper.run(url="https://example.com")

        self.assertFalse(result["success"])
        self.assertIn("not found", result.get("error", "").lower())

    @patch("packages.web.recon.katana.subprocess.run")
    def test_run_failure(self, mock_run: Mock):
        """Test run handles katana failure."""
        mock_run.return_value = MagicMock(
            returncode=1, stdout="", stderr="error occurred"
        )

        wrapper = KatanaWrapper()
        result = wrapper.run(url="https://example.com")

        self.assertFalse(result["success"])

    @patch("packages.web.recon.katana.subprocess.run")
    def test_run_uses_subprocess_run(self, mock_run: Mock):
        """Test run uses subprocess.run."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        wrapper = KatanaWrapper()
        wrapper.run(url="https://example.com")

        mock_run.assert_called_once()

    @patch("packages.web.recon.katana.subprocess.run")
    def test_run_uses_logger(self, mock_run: Mock):
        """Test run uses the logger from core.logging."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        with patch("packages.web.recon.katana.get_logger") as mock_get_logger:
            mock_logger = MagicMock()
            mock_get_logger.return_value = mock_logger

            wrapper = KatanaWrapper()
            wrapper.run(url="https://example.com")

            mock_get_logger.assert_called()


class TestKatanaGetPaths(unittest.TestCase):
    """Test suite for get_paths method."""

    def test_get_paths_extraction(self):
        """Test get_paths extracts paths from results."""
        wrapper = KatanaWrapper()
        wrapper._results = [
            {"endpoint": "/api/users", "method": "GET"},
            {"endpoint": "/api/posts", "method": "POST"},
            {"endpoint": "/login", "method": "GET"},
        ]

        result = wrapper.get_paths()

        self.assertIsInstance(result, list)
        self.assertIn("/api/users", result)
        self.assertIn("/api/posts", result)
        self.assertIn("/login", result)

    def test_get_paths_empty_results(self):
        """Test get_paths returns empty list when no results."""
        wrapper = KatanaWrapper()

        result = wrapper.get_paths()

        self.assertIsInstance(result, list)
        self.assertEqual(result, [])

    def test_get_paths_no_endpoint_field(self):
        """Test get_paths handles results without endpoint field."""
        wrapper = KatanaWrapper()
        wrapper._results = [{"url": "https://example.com"}, {"path": "/other"}]

        result = wrapper.get_paths()

        self.assertIsInstance(result, list)
        self.assertEqual(result, [])


class TestKatanaGetParameters(unittest.TestCase):
    """Test suite for get_parameters method."""

    def test_get_parameters_extraction(self):
        """Test get_parameters extracts parameters from results."""
        wrapper = KatanaWrapper()
        wrapper._results = [
            {"endpoint": "/api/users", "parameters": ["id", "name"]},
            {"endpoint": "/api/posts", "parameters": ["page"]},
        ]

        result = wrapper.get_parameters()

        self.assertIsInstance(result, list)
        self.assertIn("id", result)
        self.assertIn("name", result)
        self.assertIn("page", result)

    def test_get_parameters_empty_results(self):
        """Test get_parameters returns empty list when no results."""
        wrapper = KatanaWrapper()

        result = wrapper.get_parameters()

        self.assertIsInstance(result, list)
        self.assertEqual(result, [])

    def test_get_parameters_no_parameters_field(self):
        """Test get_parameters handles results without parameters field."""
        wrapper = KatanaWrapper()
        wrapper._results = [{"endpoint": "/api/users"}, {"endpoint": "/login"}]

        result = wrapper.get_parameters()

        self.assertIsInstance(result, list)
        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()
