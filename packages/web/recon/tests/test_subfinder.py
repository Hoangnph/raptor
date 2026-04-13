"""Tests for packages.web.recon.subfinder module."""

import subprocess
import unittest
from unittest.mock import Mock, patch, MagicMock

from packages.web.recon.subfinder import SubfinderWrapper


FIXTURES_DIR = __import__("pathlib").Path(__file__).parent / "fixtures"


class TestSubfinderInit(unittest.TestCase):
    """Test suite for SubfinderWrapper initialization."""

    def test_init_default_params(self):
        """Test SubfinderWrapper initializes with default parameters."""
        wrapper = SubfinderWrapper()
        self.assertEqual(wrapper.subfinder_path, "subfinder")

    def test_init_custom_path(self):
        """Test SubfinderWrapper initializes with custom subfinder path."""
        wrapper = SubfinderWrapper(subfinder_path="/usr/local/bin/subfinder")
        self.assertEqual(wrapper.subfinder_path, "/usr/local/bin/subfinder")


class TestSubfinderIsAvailable(unittest.TestCase):
    """Test suite for is_available method."""

    @patch("packages.web.recon.subfinder.subprocess.run")
    def test_is_available_returns_true(self, mock_run: Mock):
        """Test is_available returns True when subfinder is installed."""
        mock_run.return_value = MagicMock(returncode=0, stdout="subfinder version")

        wrapper = SubfinderWrapper()
        result = wrapper.is_available()

        self.assertTrue(result)

    @patch("packages.web.recon.subfinder.subprocess.run")
    def test_is_available_returns_false_when_not_found(self, mock_run: Mock):
        """Test is_available returns False when subfinder is not installed."""
        mock_run.side_effect = FileNotFoundError("subfinder not found")

        wrapper = SubfinderWrapper()
        result = wrapper.is_available()

        self.assertFalse(result)

    @patch("packages.web.recon.subfinder.subprocess.run")
    def test_is_available_returns_false_on_nonzero(self, mock_run: Mock):
        """Test is_available returns False when subfinder returns nonzero."""
        mock_run.return_value = MagicMock(returncode=1, stdout="")

        wrapper = SubfinderWrapper()
        result = wrapper.is_available()

        self.assertFalse(result)

    @patch("packages.web.recon.subfinder.subprocess.run")
    def test_is_available_returns_false_on_timeout(self, mock_run: Mock):
        """Test is_available returns False on subprocess timeout."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="subfinder", timeout=10)

        wrapper = SubfinderWrapper()
        result = wrapper.is_available()

        self.assertFalse(result)


class TestSubfinderRun(unittest.TestCase):
    """Test suite for run method."""

    @patch("packages.web.recon.subfinder.subprocess.run")
    def test_run_success(self, mock_run: Mock):
        """Test run executes subfinder with domain."""
        mock_run.return_value = MagicMock(
            returncode=0, stdout="sub1.example.com\nsub2.example.com\n", stderr=""
        )

        wrapper = SubfinderWrapper()
        result = wrapper.run(domain="example.com")

        mock_run.assert_called_once()
        call_args = mock_run.call_args
        cmd = call_args[1]["args"] if "args" in call_args[1] else call_args[0][0]
        self.assertIn("subfinder", cmd)
        self.assertIn("-d", cmd)
        self.assertIn("example.com", cmd)
        self.assertTrue(result["success"])
        self.assertIn("sub1.example.com", result.get("stdout", ""))

    @patch("packages.web.recon.subfinder.subprocess.run")
    def test_run_with_output_file(self, mock_run: Mock):
        """Test run executes with output file."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        wrapper = SubfinderWrapper()
        result = wrapper.run(domain="example.com", output_file="/tmp/output.json")

        call_args = mock_run.call_args
        cmd = call_args[1]["args"] if "args" in call_args[1] else call_args[0][0]
        self.assertIn("-o", cmd)
        self.assertIn("/tmp/output.json", cmd)
        self.assertTrue(result["success"])

    @patch("packages.web.recon.subfinder.subprocess.run")
    def test_run_with_custom_timeout(self, mock_run: Mock):
        """Test run respects custom timeout."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        wrapper = SubfinderWrapper()
        wrapper.run(domain="example.com", timeout=120)

        call_kwargs = mock_run.call_args[1]
        self.assertEqual(call_kwargs.get("timeout"), 120)

    @patch("packages.web.recon.subfinder.subprocess.run")
    def test_run_timeout(self, mock_run: Mock):
        """Test run handles subprocess timeout."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="subfinder", timeout=300)

        wrapper = SubfinderWrapper()
        result = wrapper.run(domain="example.com")

        self.assertFalse(result["success"])
        self.assertIn("timeout", result.get("error", "").lower())

    @patch("packages.web.recon.subfinder.subprocess.run")
    def test_run_tool_missing(self, mock_run: Mock):
        """Test run handles subfinder not found."""
        mock_run.side_effect = FileNotFoundError("subfinder not found")

        wrapper = SubfinderWrapper()
        result = wrapper.run(domain="example.com")

        self.assertFalse(result["success"])
        self.assertIn("not found", result.get("error", "").lower())

    @patch("packages.web.recon.subfinder.subprocess.run")
    def test_run_failure(self, mock_run: Mock):
        """Test run handles subfinder failure."""
        mock_run.return_value = MagicMock(
            returncode=1, stdout="", stderr="error occurred"
        )

        wrapper = SubfinderWrapper()
        result = wrapper.run(domain="example.com")

        self.assertFalse(result["success"])
        self.assertIn("error", result.get("stderr", "").lower())

    @patch("packages.web.recon.subfinder.subprocess.run")
    def test_run_uses_subprocess_run(self, mock_run: Mock):
        """Test run uses subprocess.run."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        wrapper = SubfinderWrapper()
        wrapper.run(domain="example.com")

        mock_run.assert_called_once()

    @patch("packages.web.recon.subfinder.subprocess.run")
    def test_run_default_timeout(self, mock_run: Mock):
        """Test run uses default timeout of 300."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        wrapper = SubfinderWrapper()
        wrapper.run(domain="example.com")

        call_kwargs = mock_run.call_args[1]
        self.assertEqual(call_kwargs.get("timeout"), 300)

    @patch("packages.web.recon.subfinder.subprocess.run")
    def test_run_parses_subdomains_from_stdout(self, mock_run: Mock):
        """Test run parses subdomains from stdout."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="sub1.example.com\nsub2.example.com\nsub3.example.com\n",
            stderr="",
        )

        wrapper = SubfinderWrapper()
        result = wrapper.run(domain="example.com")

        self.assertIn("subdomains", result)
        self.assertEqual(len(result["subdomains"]), 3)
        self.assertIn("sub1.example.com", result["subdomains"])

    @patch("packages.web.recon.subfinder.subprocess.run")
    def test_run_handles_empty_stdout(self, mock_run: Mock):
        """Test run handles empty stdout."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        wrapper = SubfinderWrapper()
        result = wrapper.run(domain="example.com")

        self.assertIn("subdomains", result)
        self.assertEqual(result["subdomains"], [])

    @patch("packages.web.recon.subfinder.subprocess.run")
    def test_run_uses_logger(self, mock_run: Mock):
        """Test run uses the logger from core.logging."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        with patch("packages.web.recon.subfinder.get_logger") as mock_get_logger:
            mock_logger = MagicMock()
            mock_get_logger.return_value = mock_logger

            wrapper = SubfinderWrapper()
            wrapper.run(domain="example.com")

            mock_get_logger.assert_called()


if __name__ == "__main__":
    unittest.main()
