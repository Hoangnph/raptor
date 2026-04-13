"""Tests for packages.web.nuclei.runner module."""

import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestNucleiRunnerInit(unittest.TestCase):
    """Test suite for NucleiRunner initialization."""

    def test_init_default_params(self):
        """Test NucleiRunner initializes with default parameters."""
        from packages.web.nuclei.runner import NucleiRunner

        runner = NucleiRunner()
        self.assertEqual(runner.nuclei_path, "nuclei")
        self.assertIsNone(runner.output_dir)
        self.assertEqual(runner.timeout, 300)

    def test_init_custom_params(self):
        """Test NucleiRunner initializes with custom parameters."""
        from packages.web.nuclei.runner import NucleiRunner

        runner = NucleiRunner(
            nuclei_path="/usr/local/bin/nuclei",
            output_dir="/tmp/nuclei_output",
            timeout=600,
        )
        self.assertEqual(runner.nuclei_path, "/usr/local/bin/nuclei")
        self.assertEqual(runner.output_dir, "/tmp/nuclei_output")
        self.assertEqual(runner.timeout, 600)

    def test_init_with_templates(self):
        """Test NucleiRunner initializes with template list."""
        from packages.web.nuclei.runner import NucleiRunner

        templates = ["cve-2021-44228", "xss-reflected"]
        runner = NucleiRunner(templates=templates)
        self.assertEqual(runner.templates, templates)


class TestNucleiRunnerIsAvailable(unittest.TestCase):
    """Test suite for tool availability checking."""

    @patch("packages.web.nuclei.runner.subprocess.run")
    def test_is_available_returns_true(self, mock_run):
        """Test is_available returns True when nuclei is installed."""
        mock_run.return_value = MagicMock(returncode=0, stdout="nuclei version 3.1.0")

        from packages.web.nuclei.runner import NucleiRunner

        runner = NucleiRunner()
        self.assertTrue(runner.is_available())

    @patch("packages.web.nuclei.runner.subprocess.run")
    def test_is_available_returns_false_when_not_found(self, mock_run):
        """Test is_available returns False when nuclei is not installed."""
        mock_run.side_effect = FileNotFoundError("nuclei not found")

        from packages.web.nuclei.runner import NucleiRunner

        runner = NucleiRunner()
        self.assertFalse(runner.is_available())

    @patch("packages.web.nuclei.runner.subprocess.run")
    def test_is_available_returns_false_on_nonzero(self, mock_run):
        """Test is_available returns False when nuclei returns nonzero."""
        mock_run.return_value = MagicMock(returncode=1, stdout="")

        from packages.web.nuclei.runner import NucleiRunner

        runner = NucleiRunner()
        self.assertFalse(runner.is_available())

    @patch("packages.web.nuclei.runner.subprocess.run")
    def test_is_available_returns_false_on_timeout(self, mock_run):
        """Test is_available returns False on subprocess timeout."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="nuclei", timeout=10)

        from packages.web.nuclei.runner import NucleiRunner

        runner = NucleiRunner()
        self.assertFalse(runner.is_available())


class TestNucleiRunnerRun(unittest.TestCase):
    """Test suite for nuclei execution."""

    @patch("packages.web.nuclei.runner.subprocess.run")
    def test_run_basic_target(self, mock_run):
        """Test run executes nuclei with basic target."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        from packages.web.nuclei.runner import NucleiRunner

        runner = NucleiRunner()
        result = runner.run(target="https://example.com")

        mock_run.assert_called_once()
        call_args = mock_run.call_args
        cmd = call_args[1]["args"] if "args" in call_args[1] else call_args[0][0]
        self.assertIn("nuclei", cmd)
        self.assertIn("-u", cmd)
        self.assertIn("https://example.com", cmd)
        self.assertTrue(result["success"])

    @patch("packages.web.nuclei.runner.subprocess.run")
    def test_run_with_severity_filter(self, mock_run):
        """Test run executes with severity filter."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        from packages.web.nuclei.runner import NucleiRunner

        runner = NucleiRunner()
        result = runner.run(target="https://example.com", severity="critical")

        call_args = mock_run.call_args
        cmd = call_args[1]["args"] if "args" in call_args[1] else call_args[0][0]
        self.assertIn("-severity", cmd)
        self.assertIn("critical", cmd)
        self.assertTrue(result["success"])

    @patch("packages.web.nuclei.runner.subprocess.run")
    def test_run_with_templates(self, mock_run):
        """Test run executes with template filter."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        from packages.web.nuclei.runner import NucleiRunner

        runner = NucleiRunner(templates=["cve-2021-44228"])
        result = runner.run(target="https://example.com")

        call_args = mock_run.call_args
        cmd = call_args[1]["args"] if "args" in call_args[1] else call_args[0][0]
        self.assertIn("-t", cmd)
        self.assertIn("cve-2021-44228", cmd)

    @patch("packages.web.nuclei.runner.subprocess.run")
    def test_run_with_tags(self, mock_run):
        """Test run executes with tag filter."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        from packages.web.nuclei.runner import NucleiRunner

        runner = NucleiRunner()
        result = runner.run(target="https://example.com", tags=["cve", "rce"])

        call_args = mock_run.call_args
        cmd = call_args[1]["args"] if "args" in call_args[1] else call_args[0][0]
        self.assertIn("-tags", cmd)
        self.assertIn("cve,rce", cmd)

    @patch("packages.web.nuclei.runner.subprocess.run")
    def test_run_with_sarif_output(self, mock_run):
        """Test run executes with SARIF output enabled."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        from packages.web.nuclei.runner import NucleiRunner

        runner = NucleiRunner(output_dir="/tmp/output")
        result = runner.run(target="https://example.com", sarif_output=True)

        call_args = mock_run.call_args
        cmd = call_args[1]["args"] if "args" in call_args[1] else call_args[0][0]
        self.assertIn("-se", cmd)
        self.assertIn("-sarif", cmd)

    @patch("packages.web.nuclei.runner.subprocess.run")
    def test_run_with_technology_filter(self, mock_run):
        """Test run executes with technology filter."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        from packages.web.nuclei.runner import NucleiRunner

        runner = NucleiRunner()
        result = runner.run(target="https://example.com", technology="java")

        call_args = mock_run.call_args
        cmd = call_args[1]["args"] if "args" in call_args[1] else call_args[0][0]
        self.assertIn("-tech", cmd)
        self.assertIn("java", cmd)

    @patch("packages.web.nuclei.runner.subprocess.run")
    def test_run_with_custom_timeout(self, mock_run):
        """Test run respects custom timeout."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        from packages.web.nuclei.runner import NucleiRunner

        runner = NucleiRunner(timeout=120)
        runner.run(target="https://example.com")

        call_kwargs = mock_run.call_args[1]
        self.assertEqual(call_kwargs.get("timeout"), 120)

    @patch("packages.web.nuclei.runner.subprocess.run")
    def test_run_failure(self, mock_run):
        """Test run handles nuclei failure."""
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error occurred")

        from packages.web.nuclei.runner import NucleiRunner

        runner = NucleiRunner()
        result = runner.run(target="https://example.com")

        self.assertFalse(result["success"])
        self.assertIn("error", result.get("stderr", "").lower() if result.get("stderr") else True)

    @patch("packages.web.nuclei.runner.subprocess.run")
    def test_run_timeout(self, mock_run):
        """Test run handles subprocess timeout."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="nuclei", timeout=300)

        from packages.web.nuclei.runner import NucleiRunner

        runner = NucleiRunner()
        result = runner.run(target="https://example.com")

        self.assertFalse(result["success"])
        self.assertIn("timeout", result.get("error", "").lower())

    @patch("packages.web.nuclei.runner.subprocess.run")
    def test_run_file_not_found(self, mock_run):
        """Test run handles nuclei not found."""
        mock_run.side_effect = FileNotFoundError("nuclei not found")

        from packages.web.nuclei.runner import NucleiRunner

        runner = NucleiRunner()
        result = runner.run(target="https://example.com")

        self.assertFalse(result["success"])
        self.assertIn("not found", result.get("error", "").lower())

    @patch("packages.web.nuclei.runner.subprocess.run")
    def test_run_with_target_list(self, mock_run):
        """Test run with multiple targets using target list."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        from packages.web.nuclei.runner import NucleiRunner

        runner = NucleiRunner()
        result = runner.run(target_list="/tmp/targets.txt")

        call_args = mock_run.call_args
        cmd = call_args[1]["args"] if "args" in call_args[1] else call_args[0][0]
        self.assertIn("-l", cmd)
        self.assertIn("/tmp/targets.txt", cmd)
        self.assertTrue(result["success"])

    @patch("packages.web.nuclei.runner.subprocess.run")
    def test_run_with_rate_limit(self, mock_run):
        """Test run with rate limiting."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        from packages.web.nuclei.runner import NucleiRunner

        runner = NucleiRunner()
        result = runner.run(target="https://example.com", rate_limit=100)

        call_args = mock_run.call_args
        cmd = call_args[1]["args"] if "args" in call_args[1] else call_args[0][0]
        self.assertIn("-rl", cmd)
        self.assertIn("100", cmd)


class TestNucleiRunnerParseResults(unittest.TestCase):
    """Test suite for SARIF result parsing."""

    def test_parse_results_valid_sarif(self):
        """Test parse_results parses valid SARIF file."""
        from packages.web.nuclei.runner import NucleiRunner
        from core.sarif.parser import parse_sarif_findings

        fixture_path = FIXTURES_DIR / "sample_sarif.json"

        runner = NucleiRunner()
        results = runner.parse_results(str(fixture_path))

        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)

    def test_parse_results_missing_file(self):
        """Test parse_results handles missing file."""
        from packages.web.nuclei.runner import NucleiRunner

        runner = NucleiRunner()
        results = runner.parse_results("/nonexistent/file.json")

        self.assertEqual(results, [])

    def test_parse_results_invalid_json(self):
        """Test parse_results handles invalid JSON."""
        from packages.web.nuclei.runner import NucleiRunner

        runner = NucleiRunner()
        with patch("builtins.open", mock_open(read_data="not json")):
            with patch("pathlib.Path.exists", return_value=True):
                results = runner.parse_results("/tmp/bad.json")

        self.assertEqual(results, [])


class TestNucleiRunnerGetFindings(unittest.TestCase):
    """Test suite for get_findings functionality."""

    def test_get_findings_from_sarif(self):
        """Test get_findings returns parsed findings from SARIF."""
        from packages.web.nuclei.runner import NucleiRunner

        fixture_path = FIXTURES_DIR / "sample_sarif.json"

        runner = NucleiRunner()
        findings = runner.get_findings(str(fixture_path))

        self.assertIsInstance(findings, list)
        self.assertGreater(len(findings), 0)

    def test_get_findings_with_severity_filter(self):
        """Test get_findings with severity filter."""
        from packages.web.nuclei.runner import NucleiRunner

        fixture_path = FIXTURES_DIR / "sample_sarif.json"

        runner = NucleiRunner()
        findings = runner.get_findings(str(fixture_path), severity="critical")

        self.assertIsInstance(findings, list)
        # All findings should be critical or have critical level
        for finding in findings:
            level = finding.get("level", "")
            self.assertIn(level, ["error", "critical"])

    def test_get_findings_empty_when_no_file(self):
        """Test get_findings returns empty list for missing file."""
        from packages.web.nuclei.runner import NucleiRunner

        runner = NucleiRunner()
        findings = runner.get_findings("/nonexistent/sarif.json")

        self.assertEqual(findings, [])

    def test_get_findings_count(self):
        """Test get_findings returns correct count of findings."""
        from packages.web.nuclei.runner import NucleiRunner

        fixture_path = FIXTURES_DIR / "sample_sarif.json"

        runner = NucleiRunner()
        findings = runner.get_findings(str(fixture_path))

        # Should have 6 results from our fixture
        self.assertEqual(len(findings), 6)


class TestNucleiRunnerBuildCommand(unittest.TestCase):
    """Test suite for command building."""

    def test_build_command_basic(self):
        """Test build_command with basic target."""
        from packages.web.nuclei.runner import NucleiRunner

        runner = NucleiRunner()
        cmd = runner._build_command(target="https://example.com")

        self.assertIn("nuclei", cmd)
        self.assertIn("-u", cmd)
        self.assertIn("https://example.com", cmd)

    def test_build_command_with_sarif(self):
        """Test build_command includes SARIF flags."""
        from packages.web.nuclei.runner import NucleiRunner

        runner = NucleiRunner(output_dir="/tmp/out")
        cmd = runner._build_command(target="https://example.com", sarif_output=True)

        self.assertIn("-se", cmd)
        self.assertIn("-sarif", cmd)
        self.assertTrue(any("/tmp/out" in arg for arg in cmd))

    def test_build_command_with_all_options(self):
        """Test build_command with all options."""
        from packages.web.nuclei.runner import NucleiRunner

        runner = NucleiRunner(templates=["cve-2021-44228"])
        cmd = runner._build_command(
            target="https://example.com",
            severity="high",
            tags=["cve", "rce"],
            technology="java",
            rate_limit=50,
        )

        self.assertIn("-severity", cmd)
        self.assertIn("high", cmd)
        self.assertIn("-tags", cmd)
        self.assertIn("-tech", cmd)
        self.assertIn("java", cmd)
        self.assertIn("-rl", cmd)
        self.assertIn("50", cmd)

    def test_build_command_with_target_list(self):
        """Test build_command with target list file."""
        from packages.web.nuclei.runner import NucleiRunner

        runner = NucleiRunner()
        cmd = runner._build_command(target_list="/tmp/targets.txt")

        self.assertIn("-l", cmd)
        self.assertIn("/tmp/targets.txt", cmd)
        self.assertNotIn("-u", cmd)

    def test_build_command_custom_nuclei_path(self):
        """Test build_command uses custom nuclei path."""
        from packages.web.nuclei.runner import NucleiRunner

        runner = NucleiRunner(nuclei_path="/custom/nuclei")
        cmd = runner._build_command(target="https://example.com")

        self.assertEqual(cmd[0], "/custom/nuclei")


if __name__ == "__main__":
    unittest.main()
