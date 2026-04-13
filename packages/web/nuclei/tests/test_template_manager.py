"""Tests for packages.web.nuclei.template_manager module."""

import json
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestTemplateManagerInit(unittest.TestCase):
    """Test suite for TemplateManager initialization."""

    def test_init_default_params(self):
        """Test TemplateManager initializes with default parameters."""
        from packages.web.nuclei.template_manager import TemplateManager

        manager = TemplateManager()
        self.assertEqual(manager.template_dir, "nuclei-templates")
        self.assertIsInstance(manager.templates, list)
        self.assertEqual(len(manager.templates), 0)

    def test_init_custom_template_dir(self):
        """Test TemplateManager initializes with custom template directory."""
        from packages.web.nuclei.template_manager import TemplateManager

        manager = TemplateManager(template_dir="/custom/path")
        self.assertEqual(manager.template_dir, "/custom/path")

    def test_init_with_templates_list(self):
        """Test TemplateManager initializes with provided templates list."""
        from packages.web.nuclei.template_manager import TemplateManager

        templates = [{"id": "test-1", "severity": "high"}]
        manager = TemplateManager(templates=templates)
        self.assertEqual(len(manager.templates), 1)
        self.assertEqual(manager.templates[0]["id"], "test-1")


class TestTemplateManagerLoad(unittest.TestCase):
    """Test suite for template loading functionality."""

    @patch("packages.web.nuclei.template_manager.load_json")
    @patch("packages.web.nuclei.template_manager.Path")
    def test_load_default_templates_from_json(self, mock_path_class, mock_load_json):
        """Test loading default templates from a JSON file."""
        mock_path = MagicMock()
        mock_path.exists.return_value = True
        mock_path_class.return_value = mock_path
        mock_path.__truediv__.return_value = mock_path

        mock_load_json.return_value = [
            {"id": "cve-2021-44228", "severity": "critical", "tags": ["cve", "rce"]},
            {"id": "xss-basic", "severity": "medium", "tags": ["xss"]},
        ]

        from packages.web.nuclei.template_manager import TemplateManager

        manager = TemplateManager()
        result = manager.load_default_templates()

        self.assertTrue(result)
        self.assertEqual(len(manager.templates), 2)
        self.assertEqual(manager.templates[0]["id"], "cve-2021-44228")

    @patch("packages.web.nuclei.template_manager.Path")
    def test_load_default_templates_file_not_found(self, mock_path_class):
        """Test load_default_templates handles missing file gracefully."""
        mock_path = MagicMock()
        mock_path.exists.return_value = False
        mock_path_class.return_value = mock_path

        from packages.web.nuclei.template_manager import TemplateManager

        manager = TemplateManager()
        result = manager.load_default_templates()

        self.assertFalse(result)
        self.assertEqual(len(manager.templates), 0)

    @patch("packages.web.nuclei.template_manager.load_json")
    @patch("packages.web.nuclei.template_manager.Path")
    def test_load_default_templates_invalid_json(self, mock_path_class, mock_load_json):
        """Test load_default_templates handles invalid JSON gracefully."""
        mock_path = MagicMock()
        mock_path.exists.return_value = True
        mock_path_class.return_value = mock_path
        mock_path.__truediv__.return_value = mock_path

        mock_load_json.return_value = None

        from packages.web.nuclei.template_manager import TemplateManager

        manager = TemplateManager()
        result = manager.load_default_templates()

        self.assertFalse(result)
        self.assertEqual(len(manager.templates), 0)

    @patch("packages.web.nuclei.template_manager.load_json")
    @patch("packages.web.nuclei.template_manager.Path")
    def test_load_default_templates_empty_file(self, mock_path_class, mock_load_json):
        """Test load_default_templates handles empty file gracefully."""
        mock_path = MagicMock()
        mock_path.exists.return_value = True
        mock_path_class.return_value = mock_path
        mock_path.__truediv__.return_value = mock_path

        mock_load_json.return_value = None

        from packages.web.nuclei.template_manager import TemplateManager

        manager = TemplateManager()
        result = manager.load_default_templates()

        self.assertFalse(result)

    def test_load_custom_templates_from_file(self):
        """Test loading custom templates from a specified file."""
        fixture_path = FIXTURES_DIR / "custom_templates.json"

        from packages.web.nuclei.template_manager import TemplateManager

        manager = TemplateManager()
        # load_custom_templates should parse the file
        result = manager.load_custom_templates(str(fixture_path))

        self.assertTrue(result)
        self.assertEqual(len(manager.templates), 3)

    @patch("packages.web.nuclei.template_manager.Path")
    def test_load_custom_templates_missing_file(self, mock_path_class):
        """Test load_custom_templates handles missing file."""
        mock_path = MagicMock()
        mock_path.exists.return_value = False
        mock_path_class.return_value = mock_path

        from packages.web.nuclei.template_manager import TemplateManager

        manager = TemplateManager()
        result = manager.load_custom_templates("/nonexistent/file.json")

        self.assertFalse(result)


class TestTemplateManagerSeverityFilter(unittest.TestCase):
    """Test suite for severity filtering functionality."""

    def setUp(self):
        """Set up test fixtures."""
        from packages.web.nuclei.template_manager import TemplateManager

        self.templates = [
            {"id": "cve-2021-44228", "severity": "critical", "tags": ["cve", "rce"]},
            {"id": "cve-2023-44487", "severity": "high", "tags": ["cve", "dos"]},
            {"id": "xss-reflected", "severity": "medium", "tags": ["xss"]},
            {"id": "missing-headers", "severity": "info", "tags": ["misconfig"]},
            {"id": "sqli-error", "severity": "critical", "tags": ["sqli"]},
            {"id": "csrf-basic", "severity": "low", "tags": ["csrf"]},
        ]
        self.manager = TemplateManager(templates=self.templates)

    def test_filter_by_severity_critical(self):
        """Test filtering by critical severity."""
        results = self.manager.filter_by_severity("critical")
        self.assertEqual(len(results), 2)
        self.assertTrue(all(t["severity"] == "critical" for t in results))

    def test_filter_by_severity_high(self):
        """Test filtering by high severity."""
        results = self.manager.filter_by_severity("high")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["id"], "cve-2023-44487")

    def test_filter_by_severity_medium(self):
        """Test filtering by medium severity."""
        results = self.manager.filter_by_severity("medium")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["id"], "xss-reflected")

    def test_filter_by_severity_low(self):
        """Test filtering by low severity."""
        results = self.manager.filter_by_severity("low")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["id"], "csrf-basic")

    def test_filter_by_severity_info(self):
        """Test filtering by info severity."""
        results = self.manager.filter_by_severity("info")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["id"], "missing-headers")

    def test_filter_by_severity_case_insensitive(self):
        """Test filtering is case insensitive."""
        results_critical = self.manager.filter_by_severity("critical")
        results_upper = self.manager.filter_by_severity("CRITICAL")
        results_mixed = self.manager.filter_by_severity("CrItIcAl")

        self.assertEqual(len(results_critical), len(results_upper))
        self.assertEqual(len(results_critical), len(results_mixed))

    def test_filter_by_severity_no_matches(self):
        """Test filtering with no matching severity."""
        results = self.manager.filter_by_severity("unknown")
        self.assertEqual(len(results), 0)

    def test_filter_by_severity_empty_templates(self):
        """Test filtering with empty templates list."""
        from packages.web.nuclei.template_manager import TemplateManager

        manager = TemplateManager(templates=[])
        results = manager.filter_by_severity("critical")
        self.assertEqual(len(results), 0)

    def test_filter_by_severity_min_and_above(self):
        """Test filtering by minimum severity (critical and high)."""
        results = self.manager.filter_by_severity("high", min_severity=True)
        self.assertEqual(len(results), 3)  # critical (2) + high (1)

    def test_filter_by_severity_medium_and_above(self):
        """Test filtering by medium severity and above."""
        results = self.manager.filter_by_severity("medium", min_severity=True)
        self.assertEqual(len(results), 4)  # critical (2) + high (1) + medium (1)

    def test_filter_by_severity_multiple_values(self):
        """Test filtering by multiple severity values."""
        results = self.manager.filter_by_severity(["critical", "high"])
        self.assertEqual(len(results), 3)


class TestTemplateManagerTagFilter(unittest.TestCase):
    """Test suite for tag filtering functionality."""

    def setUp(self):
        """Set up test fixtures."""
        from packages.web.nuclei.template_manager import TemplateManager

        self.templates = [
            {"id": "cve-2021-44228", "severity": "critical", "tags": ["cve", "rce", "log4j"]},
            {"id": "cve-2023-44487", "severity": "high", "tags": ["cve", "dos", "http2"]},
            {"id": "xss-reflected", "severity": "medium", "tags": ["xss", "owasp"]},
            {"id": "sqli-error", "severity": "critical", "tags": ["sqli", "owasp", "database"]},
            {"id": "missing-headers", "severity": "info", "tags": ["misconfig", "headers"]},
        ]
        self.manager = TemplateManager(templates=self.templates)

    def test_filter_by_single_tag(self):
        """Test filtering by a single tag."""
        results = self.manager.filter_by_tag("cve")
        self.assertEqual(len(results), 2)

    def test_filter_by_tag_xss(self):
        """Test filtering by xss tag."""
        results = self.manager.filter_by_tag("xss")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["id"], "xss-reflected")

    def test_filter_by_tag_owasp(self):
        """Test filtering by owasp tag."""
        results = self.manager.filter_by_tag("owasp")
        self.assertEqual(len(results), 2)

    def test_filter_by_tag_no_matches(self):
        """Test filtering by tag with no matches."""
        results = self.manager.filter_by_tag("nonexistent")
        self.assertEqual(len(results), 0)

    def test_filter_by_tag_case_insensitive(self):
        """Test filtering by tag is case insensitive."""
        results_lower = self.manager.filter_by_tag("cve")
        results_upper = self.manager.filter_by_tag("CVE")
        self.assertEqual(len(results_lower), len(results_upper))

    def test_filter_by_tag_empty_templates(self):
        """Test filtering by tag with empty templates."""
        from packages.web.nuclei.template_manager import TemplateManager

        manager = TemplateManager(templates=[])
        results = manager.filter_by_tag("cve")
        self.assertEqual(len(results), 0)

    def test_filter_by_tag_missing_tags_field(self):
        """Test filtering when template has no tags field."""
        from packages.web.nuclei.template_manager import TemplateManager

        templates_no_tags = [
            {"id": "test-1", "severity": "high"},
            {"id": "test-2", "severity": "medium", "tags": ["xss"]},
        ]
        manager = TemplateManager(templates=templates_no_tags)
        results = manager.filter_by_tag("xss")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["id"], "test-2")


class TestTemplateManagerTechnologyFilter(unittest.TestCase):
    """Test suite for technology filtering functionality."""

    def setUp(self):
        """Set up test fixtures."""
        from packages.web.nuclei.template_manager import TemplateManager

        self.templates = [
            {"id": "cve-2021-44228", "severity": "critical", "technologies": ["java", "log4j"]},
            {"id": "cve-2023-44487", "severity": "high", "technologies": ["http2", "nginx"]},
            {"id": "xss-reflected", "severity": "medium", "technologies": ["php", "apache"]},
            {"id": "sqli-error", "severity": "critical", "technologies": ["mysql", "php"]},
            {"id": "missing-headers", "severity": "info", "technologies": ["nginx"]},
        ]
        self.manager = TemplateManager(templates=self.templates)

    def test_filter_by_technology_java(self):
        """Test filtering by java technology."""
        results = self.manager.filter_by_technology("java")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["id"], "cve-2021-44228")

    def test_filter_by_technology_nginx(self):
        """Test filtering by nginx technology."""
        results = self.manager.filter_by_technology("nginx")
        self.assertEqual(len(results), 2)

    def test_filter_by_technology_php(self):
        """Test filtering by php technology."""
        results = self.manager.filter_by_technology("php")
        self.assertEqual(len(results), 2)

    def test_filter_by_technology_no_matches(self):
        """Test filtering by technology with no matches."""
        results = self.manager.filter_by_technology("ruby")
        self.assertEqual(len(results), 0)

    def test_filter_by_technology_case_insensitive(self):
        """Test filtering by technology is case insensitive."""
        results_lower = self.manager.filter_by_technology("nginx")
        results_upper = self.manager.filter_by_technology("NGINX")
        self.assertEqual(len(results_lower), len(results_upper))

    def test_filter_by_technology_empty_templates(self):
        """Test filtering by technology with empty templates."""
        from packages.web.nuclei.template_manager import TemplateManager

        manager = TemplateManager(templates=[])
        results = manager.filter_by_technology("java")
        self.assertEqual(len(results), 0)

    def test_filter_by_technology_missing_field(self):
        """Test filtering when template has no technologies field."""
        from packages.web.nuclei.template_manager import TemplateManager

        templates_no_tech = [
            {"id": "test-1", "severity": "high"},
            {"id": "test-2", "severity": "medium", "technologies": ["php"]},
        ]
        manager = TemplateManager(templates=templates_no_tech)
        results = manager.filter_by_technology("php")
        self.assertEqual(len(results), 1)


class TestTemplateManagerGetList(unittest.TestCase):
    """Test suite for get_template_list functionality."""

    def test_get_template_list_returns_ids(self):
        """Test get_template_list returns template IDs."""
        from packages.web.nuclei.template_manager import TemplateManager

        templates = [
            {"id": "cve-2021-44228", "severity": "critical"},
            {"id": "xss-basic", "severity": "medium"},
        ]
        manager = TemplateManager(templates=templates)
        result = manager.get_template_list()

        self.assertIn("cve-2021-44228", result)
        self.assertIn("xss-basic", result)

    def test_get_template_list_empty(self):
        """Test get_template_list with empty templates."""
        from packages.web.nuclei.template_manager import TemplateManager

        manager = TemplateManager(templates=[])
        result = manager.get_template_list()

        self.assertEqual(len(result), 0)

    def test_get_template_list_count(self):
        """Test get_template_list returns correct count."""
        from packages.web.nuclei.template_manager import TemplateManager

        templates = [{"id": f"template-{i}", "severity": "high"} for i in range(5)]
        manager = TemplateManager(templates=templates)
        result = manager.get_template_list()

        self.assertEqual(len(result), 5)

    def test_get_template_list_with_details(self):
        """Test get_template_list with details=True."""
        from packages.web.nuclei.template_manager import TemplateManager

        templates = [
            {"id": "cve-2021-44228", "severity": "critical", "tags": ["cve"]},
        ]
        manager = TemplateManager(templates=templates)
        result = manager.get_template_list(details=True)

        self.assertIn("cve-2021-44228", result)
        self.assertEqual(result["cve-2021-44228"]["severity"], "critical")


class TestTemplateManagerCombinedFilters(unittest.TestCase):
    """Test suite for combined filtering functionality."""

    def setUp(self):
        """Set up test fixtures."""
        from packages.web.nuclei.template_manager import TemplateManager

        self.templates = [
            {"id": "cve-2021-44228", "severity": "critical", "tags": ["cve", "rce"], "technologies": ["java"]},
            {"id": "cve-2023-44487", "severity": "high", "tags": ["cve", "dos"], "technologies": ["nginx"]},
            {"id": "xss-reflected", "severity": "medium", "tags": ["xss"], "technologies": ["php"]},
            {"id": "sqli-error", "severity": "critical", "tags": ["sqli"], "technologies": ["mysql"]},
        ]
        self.manager = TemplateManager(templates=self.templates)

    def test_filter_by_severity_and_tag(self):
        """Test combined severity and tag filtering."""
        results = self.manager.filter_by_severity("critical")
        cve_results = [t for t in results if "cve" in [tag.lower() for tag in t.get("tags", [])]]
        self.assertEqual(len(cve_results), 1)
        self.assertEqual(cve_results[0]["id"], "cve-2021-44228")

    def test_filter_by_severity_and_technology(self):
        """Test combined severity and technology filtering."""
        results = self.manager.filter_by_severity("critical")
        java_results = [t for t in results if "java" in [t.lower() for t in t.get("technologies", [])]]
        self.assertEqual(len(java_results), 1)

    def test_filter_chain(self):
        """Test chaining multiple filters."""
        high_and_above = self.manager.filter_by_severity("high", min_severity=True)
        cve_only = [t for t in high_and_above if "cve" in [tag.lower() for tag in t.get("tags", [])]]
        self.assertEqual(len(cve_only), 2)


if __name__ == "__main__":
    unittest.main()
