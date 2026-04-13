"""Tests for packages.web.zap.automation module."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import mock_open, patch

import yaml

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestZapAutomation(unittest.TestCase):
    """Test suite for ZapAutomation class."""

    def setUp(self):
        """Set up test fixtures."""
        from packages.web.zap.automation import ZapAutomation

        self.automation = ZapAutomation()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up temporary directories."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # ── Initialization Tests ──

    def test_init_creates_instance(self):
        """Test ZapAutomation initializes correctly."""
        from packages.web.zap.automation import ZapAutomation

        automation = ZapAutomation()
        self.assertIsInstance(automation, ZapAutomation)

    # ── Baseline Plan Tests ──

    def test_create_baseline_plan_returns_dict(self):
        """Test create_baseline_plan returns a dictionary."""
        plan = self.automation.create_baseline_plan(
            target="https://example.com",
            output_dir=self.temp_dir,
        )
        self.assertIsInstance(plan, dict)

    def test_create_baseline_plan_has_correct_structure(self):
        """Test baseline plan has required top-level keys."""
        plan = self.automation.create_baseline_plan(
            target="https://example.com",
            output_dir=self.temp_dir,
        )
        self.assertIn("env", plan)
        self.assertIn("jobs", plan)

    def test_create_baseline_plan_has_context(self):
        """Test baseline plan contains context with target URL."""
        plan = self.automation.create_baseline_plan(
            target="https://example.com",
            output_dir=self.temp_dir,
        )
        contexts = plan["env"]["contexts"]
        self.assertTrue(len(contexts) > 0)
        self.assertIn("https://example.com", contexts[0].get("urls", []))

    def test_create_baseline_plan_has_spider_job(self):
        """Test baseline plan includes a spider job."""
        plan = self.automation.create_baseline_plan(
            target="https://example.com",
            output_dir=self.temp_dir,
        )
        job_types = [job.get("type") for job in plan["jobs"]]
        self.assertIn("spider", job_types)

    def test_create_baseline_plan_has_passive_scan_job(self):
        """Test baseline plan includes a passive scan job."""
        plan = self.automation.create_baseline_plan(
            target="https://example.com",
            output_dir=self.temp_dir,
        )
        job_types = [job.get("type") for job in plan["jobs"]]
        self.assertIn("passiveScan", job_types)

    def test_create_baseline_plan_has_report_job(self):
        """Test baseline plan includes a report generation job."""
        plan = self.automation.create_baseline_plan(
            target="https://example.com",
            output_dir=self.temp_dir,
        )
        job_types = [job.get("type") for job in plan["jobs"]]
        self.assertIn("report", job_types)

    def test_create_baseline_plan_with_custom_context_name(self):
        """Test baseline plan accepts custom context name."""
        plan = self.automation.create_baseline_plan(
            target="https://example.com",
            output_dir=self.temp_dir,
            context_name="MyTestContext",
        )
        contexts = plan["env"]["contexts"]
        self.assertEqual(contexts[0]["name"], "MyTestContext")

    # ── Full Scan Plan Tests ──

    def test_create_full_scan_plan_returns_dict(self):
        """Test create_full_scan_plan returns a dictionary."""
        plan = self.automation.create_full_scan_plan(
            target="https://example.com",
            output_dir=self.temp_dir,
        )
        self.assertIsInstance(plan, dict)

    def test_create_full_scan_plan_has_active_scan(self):
        """Test full scan plan includes active scan job."""
        plan = self.automation.create_full_scan_plan(
            target="https://example.com",
            output_dir=self.temp_dir,
        )
        job_types = [job.get("type") for job in plan["jobs"]]
        self.assertIn("activeScan", job_types)

    def test_create_full_scan_plan_has_spider(self):
        """Test full scan plan includes spider job."""
        plan = self.automation.create_full_scan_plan(
            target="https://example.com",
            output_dir=self.temp_dir,
        )
        job_types = [job.get("type") for job in plan["jobs"]]
        self.assertIn("spider", job_types)

    def test_create_full_scan_plan_has_more_jobs_than_baseline(self):
        """Test full scan plan has more jobs than baseline."""
        baseline = self.automation.create_baseline_plan(
            target="https://example.com",
            output_dir=self.temp_dir,
        )
        full = self.automation.create_full_scan_plan(
            target="https://example.com",
            output_dir=self.temp_dir,
        )
        self.assertTrue(len(full["jobs"]) > len(baseline["jobs"]))

    def test_create_full_scan_plan_accepts_policy(self):
        """Test full scan plan accepts scan policy parameter."""
        plan = self.automation.create_full_scan_plan(
            target="https://example.com",
            output_dir=self.temp_dir,
            scan_policy="default",
        )
        self.assertIsInstance(plan, dict)

    # ── API Scan Plan Tests ──

    def test_create_api_scan_plan_returns_dict(self):
        """Test create_api_scan_plan returns a dictionary."""
        plan = self.automation.create_api_scan_plan(
            target="https://api.example.com",
            api_spec="/path/to/openapi.yaml",
            output_dir=self.temp_dir,
        )
        self.assertIsInstance(plan, dict)

    def test_create_api_scan_plan_has_api_import_job(self):
        """Test API scan plan includes API import job."""
        plan = self.automation.create_api_scan_plan(
            target="https://api.example.com",
            api_spec="/path/to/openapi.yaml",
            output_dir=self.temp_dir,
        )
        job_types = [job.get("type") for job in plan["jobs"]]
        self.assertIn("openapi", job_types)

    def test_create_api_scan_plan_has_active_scan(self):
        """Test API scan plan includes active scan."""
        plan = self.automation.create_api_scan_plan(
            target="https://api.example.com",
            api_spec="/path/to/openapi.yaml",
            output_dir=self.temp_dir,
        )
        job_types = [job.get("type") for job in plan["jobs"]]
        self.assertIn("activeScan", job_types)

    def test_create_api_scan_plan_accepts_format(self):
        """Test API scan plan accepts API format parameter."""
        for fmt in ["openapi", "graphql"]:
            plan = self.automation.create_api_scan_plan(
                target="https://api.example.com",
                api_spec="/path/to/spec.yaml",
                output_dir=self.temp_dir,
                api_format=fmt,
            )
            self.assertIsInstance(plan, dict)

    # ── Authentication Tests ──

    def test_add_authentication_adds_users_to_context(self):
        """Test add_authentication adds users to plan context."""
        plan = self.automation.create_baseline_plan(
            target="https://example.com",
            output_dir=self.temp_dir,
        )
        plan = self.automation.add_authentication(
            plan=plan,
            login_url="https://example.com/login",
            username="admin",
            password="secret",
        )
        contexts = plan["env"]["contexts"]
        self.assertIn("users", contexts[0])
        self.assertEqual(contexts[0]["users"][0]["name"], "admin")

    def test_add_authentication_adds_form_based_auth(self):
        """Test add_authentication configures form-based authentication."""
        plan = self.automation.create_baseline_plan(
            target="https://example.com",
            output_dir=self.temp_dir,
        )
        plan = self.automation.add_authentication(
            plan=plan,
            login_url="https://example.com/login",
            username="admin",
            password="secret",
        )
        contexts = plan["env"]["contexts"]
        self.assertEqual(contexts[0]["authentication"]["method"], "formBased")

    def test_add_authentication_configures_login_url(self):
        """Test add_authentication sets login URL correctly."""
        plan = self.automation.create_baseline_plan(
            target="https://example.com",
            output_dir=self.temp_dir,
        )
        plan = self.automation.add_authentication(
            plan=plan,
            login_url="https://example.com/login",
            username="admin",
            password="secret",
        )
        contexts = plan["env"]["contexts"]
        auth_config = contexts[0]["authentication"]["parameters"]
        self.assertEqual(auth_config["loginPageUrl"], "https://example.com/login")
        self.assertEqual(auth_config["loginRequestUrl"], "https://example.com/login")

    def test_add_authentication_adds_verification_strategy(self):
        """Test add_authentication adds logged in/out indicators."""
        plan = self.automation.create_baseline_plan(
            target="https://example.com",
            output_dir=self.temp_dir,
        )
        plan = self.automation.add_authentication(
            plan=plan,
            login_url="https://example.com/login",
            username="admin",
            password="secret",
        )
        contexts = plan["env"]["contexts"]
        self.assertIn("verificationStrategy", contexts[0])

    # ── YAML Export Tests ──

    def test_export_yaml_creates_file(self):
        """Test export_yaml creates the output file."""
        plan = self.automation.create_baseline_plan(
            target="https://example.com",
            output_dir=self.temp_dir,
        )
        output_file = Path(self.temp_dir) / "test_plan.yaml"
        self.automation.export_yaml(plan, str(output_file))
        self.assertTrue(output_file.exists())

    def test_export_yaml_contains_valid_yaml(self):
        """Test export_yaml produces valid YAML content."""
        plan = self.automation.create_baseline_plan(
            target="https://example.com",
            output_dir=self.temp_dir,
        )
        output_file = Path(self.temp_dir) / "valid_plan.yaml"
        self.automation.export_yaml(plan, str(output_file))

        with open(output_file) as f:
            content = yaml.safe_load(f)

        self.assertIn("env", content)
        self.assertIn("jobs", content)

    def test_export_yaml_creates_parent_dirs(self):
        """Test export_yaml creates parent directories if needed."""
        plan = self.automation.create_baseline_plan(
            target="https://example.com",
            output_dir=self.temp_dir,
        )
        nested_dir = Path(self.temp_dir) / "nested" / "deep"
        output_file = nested_dir / "plan.yaml"
        self.automation.export_yaml(plan, str(output_file))
        self.assertTrue(output_file.exists())

    def test_export_yaml_handles_permission_error(self):
        """Test export_yaml handles permission errors gracefully."""
        plan = self.automation.create_baseline_plan(
            target="https://example.com",
            output_dir=self.temp_dir,
        )
        # Try to write to a non-existent root path
        result = self.automation.export_yaml(plan, "/nonexistent/path/plan.yaml")
        self.assertFalse(result)

    # ── Plan Merging Tests ──

    def test_merge_plans_combines_jobs(self):
        """Test merge_plans combines jobs from both plans."""
        plan1 = self.automation.create_baseline_plan(
            target="https://example.com",
            output_dir=self.temp_dir,
        )
        plan2 = self.automation.create_full_scan_plan(
            target="https://example.com",
            output_dir=self.temp_dir,
        )
        merged = self.automation.merge_plans(plan1, plan2)
        self.assertIsInstance(merged, dict)
        self.assertIn("jobs", merged)

    def test_merge_plans_preserves_env(self):
        """Test merge_plans preserves environment configuration."""
        plan1 = self.automation.create_baseline_plan(
            target="https://example.com",
            output_dir=self.temp_dir,
        )
        plan2 = self.automation.create_full_scan_plan(
            target="https://example2.com",
            output_dir=self.temp_dir,
        )
        merged = self.automation.merge_plans(plan1, plan2)
        self.assertIn("env", merged)

    # ── Error Handling Tests ──

    def test_create_baseline_plan_invalid_output_dir(self):
        """Test baseline plan handles invalid output directory."""
        # The method should still return a plan even if output_dir doesn't exist
        plan = self.automation.create_baseline_plan(
            target="https://example.com",
            output_dir="/nonexistent/dir",
        )
        self.assertIsInstance(plan, dict)

    def test_export_yaml_with_invalid_plan(self):
        """Test export_yaml handles invalid plan gracefully."""
        output_file = Path(self.temp_dir) / "invalid.yaml"
        result = self.automation.export_yaml(None, str(output_file))
        self.assertFalse(result)

    def test_export_yaml_with_empty_plan(self):
        """Test export_yaml handles empty plan."""
        output_file = Path(self.temp_dir) / "empty.yaml"
        result = self.automation.export_yaml({}, str(output_file))
        self.assertTrue(result)
        self.assertTrue(output_file.exists())


if __name__ == "__main__":
    unittest.main()
