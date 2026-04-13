#!/usr/bin/env python3
"""
Nuclei Template Manager

Manages Nuclei vulnerability scanning templates including loading,
filtering by severity/tags/technology, and custom template lists.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from core.json.utils import load_json, save_json

logger = logging.getLogger(__name__)

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


class TemplateManager:
    """
    Manages Nuclei templates for vulnerability scanning.

    Provides functionality to load, filter, and select templates
    based on severity, tags, technology, and custom criteria.

    Attributes:
        template_dir: Base directory for Nuclei templates.
        templates: List of loaded template dictionaries.
    """

    def __init__(
        self,
        template_dir: str = "nuclei-templates",
        templates: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        """
        Initialize the TemplateManager.

        Args:
            template_dir: Base directory for Nuclei templates.
            templates: Optional pre-loaded templates list.
        """
        self.template_dir: str = template_dir
        self.templates: List[Dict[str, Any]] = templates if templates is not None else []

    def load_default_templates(self) -> bool:
        """
        Load default templates from the template directory.

        Attempts to load templates from a templates.json file
        in the configured template directory.

        Returns:
            True if templates were loaded successfully, False otherwise.
        """
        templates_file = Path(self.template_dir) / "templates.json"

        if not templates_file.exists():
            logger.warning("Default templates file not found: %s", templates_file)
            return False

        try:
            data = load_json(templates_file)
            if data is None:
                logger.warning("Failed to parse templates file: %s", templates_file)
                return False

            if isinstance(data, list):
                self.templates = data
            elif isinstance(data, dict) and "templates" in data:
                self.templates = data["templates"]
            else:
                logger.warning("Unexpected templates format in %s", templates_file)
                return False

            logger.info("Loaded %d default templates", len(self.templates))
            return True

        except (OSError, json.JSONDecodeError) as e:
            logger.error("Error loading default templates: %s", e)
            return False

    def load_custom_templates(self, file_path: str) -> bool:
        """
        Load custom templates from a specified JSON file.

        Args:
            file_path: Path to the custom templates JSON file.

        Returns:
            True if templates were loaded successfully, False otherwise.
        """
        path = Path(file_path)

        if not path.exists():
            logger.warning("Custom templates file not found: %s", file_path)
            return False

        try:
            data = load_json(path)
            if data is None:
                logger.warning("Failed to parse custom templates file: %s", file_path)
                return False

            if isinstance(data, list):
                self.templates.extend(data)
            elif isinstance(data, dict) and "templates" in data:
                self.templates.extend(data["templates"])
            else:
                logger.warning("Unexpected format in custom templates: %s", file_path)
                return False

            logger.info("Loaded custom templates from %s", file_path)
            return True

        except (OSError, json.JSONDecodeError) as e:
            logger.error("Error loading custom templates: %s", e)
            return False

    def filter_by_severity(
        self,
        severity: Union[str, List[str]],
        min_severity: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        Filter templates by severity level.

        Args:
            severity: Severity level(s) to filter by (e.g., "critical", "high").
            min_severity: If True, filter by minimum severity (includes higher levels).

        Returns:
            List of templates matching the severity criteria.
        """
        if isinstance(severity, str):
            severities = [severity.lower()]
        else:
            severities = [s.lower() for s in severity]

        if min_severity and len(severities) == 1:
            target = severities[0]
            if target in SEVERITY_ORDER:
                idx = SEVERITY_ORDER.index(target)
                severities = SEVERITY_ORDER[idx:]

        results = []
        for template in self.templates:
            tmpl_severity = template.get("severity", "").lower()
            if tmpl_severity in severities:
                results.append(template)

        return results

    def filter_by_tag(self, tag: str) -> List[Dict[str, Any]]:
        """
        Filter templates by tag.

        Args:
            tag: Tag to filter by (case insensitive).

        Returns:
            List of templates containing the specified tag.
        """
        tag_lower = tag.lower()
        results = []

        for template in self.templates:
            tags = template.get("tags", [])
            if tag_lower in [t.lower() for t in tags]:
                results.append(template)

        return results

    def filter_by_technology(self, technology: str) -> List[Dict[str, Any]]:
        """
        Filter templates by technology.

        Args:
            technology: Technology to filter by (case insensitive).

        Returns:
            List of templates targeting the specified technology.
        """
        tech_lower = technology.lower()
        results = []

        for template in self.templates:
            technologies = template.get("technologies", [])
            if tech_lower in [t.lower() for t in technologies]:
                results.append(template)

        return results

    def get_template_list(self, details: bool = False) -> Union[List[str], Dict[str, Dict[str, Any]]]:
        """
        Get a list of loaded template IDs.

        Args:
            details: If True, return a dict with template details.
                     If False, return a list of template IDs.

        Returns:
            List of template IDs or dict of template details keyed by ID.
        """
        if not details:
            return [t.get("id", "unknown") for t in self.templates]

        result: Dict[str, Dict[str, Any]] = {}
        for template in self.templates:
            tmpl_id = template.get("id", "unknown")
            result[tmpl_id] = template

        return result
