"""Tests for packages.web.recon.httpx_tool module."""

import subprocess
import unittest
from unittest.mock import Mock, patch, MagicMock

from packages.web.recon.httpx_tool import HttpxWrapper


FIXTURES_DIR = __import__("pathlib").Path(__file__).parent / "fixtures"


class TestHttpxInit(unittest.TestCase):
    """Test suite for HttpxWrapper initialization."""

    def test_init_default_params(self):
        """Test HttpxWrapper initializes with default parameters."""
        wrapper = HttpxWrapper()
        self.assertEqual(wrapper.httpx_path, "httpx")

    def test_init_custom_path(self):
        """Test HttpxWrapper initializes with custom httpx path."""
        wrapper = HttpxWrapper(httpx_path="/usr/local/bin/httpx")
        self.assertEqual(wrapper.httpx_path, "/usr/local/bin/httpx")


class TestHttpxIsAvailable(unittest.TestCase):
    """Test suite for is_available method."""

    @patch("packages.web.recon.httpx_tool.subprocess.run")
    def test_is_available_returns_true(self, mock_run: Mock):
        """Test is_available returns True when httpx is installed."""
        mock_run.return_value = MagicMock(returncode=0, stdout="httpx version")

        wrapper = HttpxWrapper()
        result = wrapper.is_available()

        self.assertTrue(result)

    @patch("packages.web.recon.httpx_tool.subprocess.run")
    def test_is_available_returns_false_when_not_found(self, mock_run: Mock):
        """Test is_available returns False when httpx is not installed."""
        mock_run.side_effect = FileNotFoundError("httpx not found")

        wrapper = HttpxWrapper()
        result = wrapper.is_available()

        self.assertFalse(result)

    @patch("packages.web.recon.httpx_tool.subprocess.run")
    def test_is_available_returns_false_on_nonzero(self, mock_run: Mock):
        """Test is_available returns False when httpx returns nonzero."""
        mock_run.return_value = MagicMock(returncode=1, stdout="")

        wrapper = HttpxWrapper()
        result = wrapper.is_available()

        self.assertFalse(result)

    @patch("packages.web.recon.httpx_tool.subprocess.run")
    def test_is_available_returns_false_on_timeout(self, mock_run: Mock):
        """Test is_available returns False on subprocess timeout."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="httpx", timeout=10)

        wrapper = HttpxWrapper()
        result = wrapper.is_available()

        self.assertFalse(result)


class TestHttpxRun(unittest.TestCase):
    """Test suite for run method."""

    @patch("packages.web.recon.httpx_tool.subprocess.run")
    def test_run_success_single_target(self, mock_run: Mock):
        """Test run executes httpx with single target."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"url": "https://example.com", "status_code": 200}',
            stderr="",
        )

        wrapper = HttpxWrapper()
        result = wrapper.run(targets="https://example.com")

        mock_run.assert_called_once()
        call_args = mock_run.call_args
        cmd = call_args[1]["args"] if "args" in call_args[1] else call_args[0][0]
        self.assertIn("httpx", cmd)
        self.assertIn("-u", cmd)
        self.assertIn("https://example.com", cmd)
        self.assertTrue(result["success"])

    @patch("packages.web.recon.httpx_tool.subprocess.run")
    def test_run_with_multiple_targets(self, mock_run: Mock):
        """Test run executes httpx with multiple targets."""
        mock_run.return_value = MagicMock(
            returncode=0, stdout="", stderr=""
        )

        wrapper = HttpxWrapper()
        result = wrapper.run(targets=["https://a.com", "https://b.com"])

        call_args = mock_run.call_args
        cmd = call_args[1]["args"] if "args" in call_args[1] else call_args[0][0]
        self.assertIn("-l", cmd)
        self.assertTrue(result["success"])

    @patch("packages.web.recon.httpx_tool.subprocess.run")
    def test_run_with_output_file(self, mock_run: Mock):
        """Test run executes with output file."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        wrapper = HttpxWrapper()
        result = wrapper.run(targets="https://example.com", output_file="/tmp/output.json")

        call_args = mock_run.call_args
        cmd = call_args[1]["args"] if "args" in call_args[1] else call_args[0][0]
        self.assertIn("-o", cmd)
        self.assertIn("/tmp/output.json", cmd)
        self.assertTrue(result["success"])

    @patch("packages.web.recon.httpx_tool.subprocess.run")
    def test_run_with_custom_timeout(self, mock_run: Mock):
        """Test run respects custom timeout."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        wrapper = HttpxWrapper()
        wrapper.run(targets="https://example.com", timeout=120)

        call_kwargs = mock_run.call_args[1]
        self.assertEqual(call_kwargs.get("timeout"), 120)

    @patch("packages.web.recon.httpx_tool.subprocess.run")
    def test_run_default_timeout(self, mock_run: Mock):
        """Test run uses default timeout of 300."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        wrapper = HttpxWrapper()
        wrapper.run(targets="https://example.com")

        call_kwargs = mock_run.call_args[1]
        self.assertEqual(call_kwargs.get("timeout"), 300)

    @patch("packages.web.recon.httpx_tool.subprocess.run")
    def test_run_timeout(self, mock_run: Mock):
        """Test run handles subprocess timeout."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="httpx", timeout=300)

        wrapper = HttpxWrapper()
        result = wrapper.run(targets="https://example.com")

        self.assertFalse(result["success"])
        self.assertIn("timeout", result.get("error", "").lower())

    @patch("packages.web.recon.httpx_tool.subprocess.run")
    def test_run_tool_missing(self, mock_run: Mock):
        """Test run handles httpx not found."""
        mock_run.side_effect = FileNotFoundError("httpx not found")

        wrapper = HttpxWrapper()
        result = wrapper.run(targets="https://example.com")

        self.assertFalse(result["success"])
        self.assertIn("not found", result.get("error", "").lower())

    @patch("packages.web.recon.httpx_tool.subprocess.run")
    def test_run_failure(self, mock_run: Mock):
        """Test run handles httpx failure."""
        mock_run.return_value = MagicMock(
            returncode=1, stdout="", stderr="error occurred"
        )

        wrapper = HttpxWrapper()
        result = wrapper.run(targets="https://example.com")

        self.assertFalse(result["success"])

    @patch("packages.web.recon.httpx_tool.subprocess.run")
    def test_run_uses_subprocess_run(self, mock_run: Mock):
        """Test run uses subprocess.run."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        wrapper = HttpxWrapper()
        wrapper.run(targets="https://example.com")

        mock_run.assert_called_once()

    @patch("packages.web.recon.httpx_tool.subprocess.run")
    def test_run_uses_logger(self, mock_run: Mock):
        """Test run uses the logger from core.logging."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        with patch("packages.web.recon.httpx_tool.get_logger") as mock_get_logger:
            mock_logger = MagicMock()
            mock_get_logger.return_value = mock_logger

            wrapper = HttpxWrapper()
            wrapper.run(targets="https://example.com")

            mock_get_logger.assert_called()


class TestHttpxParseTechnology(unittest.TestCase):
    """Test suite for parse_technology method."""

    def test_parse_technology_valid_json(self):
        """Test parse_technology parses valid JSON output."""
        wrapper = HttpxWrapper()
        output = '{"url": "https://example.com", "tech": ["Nginx", "React"]}'

        result = wrapper.parse_technology(output)

        self.assertIsInstance(result, list)
        self.assertIn("Nginx", result)
        self.assertIn("React", result)

    def test_parse_technology_invalid_json(self):
        """Test parse_technology handles invalid JSON."""
        wrapper = HttpxWrapper()
        output = "not valid json"

        result = wrapper.parse_technology(output)

        self.assertIsInstance(result, list)
        self.assertEqual(result, [])

    def test_parse_technology_no_tech_field(self):
        """Test parse_technology handles JSON without tech field."""
        wrapper = HttpxWrapper()
        output = '{"url": "https://example.com", "status_code": 200}'

        result = wrapper.parse_technology(output)

        self.assertIsInstance(result, list)
        self.assertEqual(result, [])

    def test_parse_technology_empty_output(self):
        """Test parse_technology handles empty output."""
        wrapper = HttpxWrapper()

        result = wrapper.parse_technology("")

        self.assertIsInstance(result, list)
        self.assertEqual(result, [])

    def test_parse_technology_multiple_lines(self):
        """Test parse_technology parses multiple JSON lines."""
        wrapper = HttpxWrapper()
        output = '{"tech": ["Nginx"]}\n{"tech": ["Apache"]}'

        result = wrapper.parse_technology(output)

        self.assertIsInstance(result, list)
        self.assertIn("Nginx", result)
        self.assertIn("Apache", result)

    def test_parse_technology_filters_by_status_code(self):
        """Test parse_technology can filter entries by status code."""
        wrapper = HttpxWrapper()
        output = (
            '{"url": "https://a.com", "status_code": 200, "tech": ["Nginx"]}\n'
            '{"url": "https://b.com", "status_code": 404, "tech": ["Apache"]}'
        )

        result = wrapper.parse_technology(output, min_status=200, max_status=299)

        self.assertIsInstance(result, list)
        self.assertIn("Nginx", result)
        self.assertNotIn("Apache", result)


if __name__ == "__main__":
    unittest.main()
