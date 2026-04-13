#!/usr/bin/env python3
"""
Nuclei Runner

Executes Nuclei vulnerability scanner with various options,
handles SARIF output, and parses results.
"""

import logging
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.sarif.parser import load_sarif, parse_sarif_findings

logger = logging.getLogger(__name__)


class NucleiRunner:
    """
    Executes Nuclei CLI with various options and parses results.

    Supports SARIF output, severity/tag/technology filtering,
    and graceful handling of missing tool.

    Attributes:
        nuclei_path: Path to the nuclei binary.
        output_dir: Directory for output files.
        timeout: Subprocess timeout in seconds.
        templates: List of template IDs to use.
    """

    def __init__(
        self,
        nuclei_path: str = "nuclei",
        output_dir: Optional[str] = None,
        timeout: int = 300,
        templates: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize the NucleiRunner.

        Args:
            nuclei_path: Path to the nuclei binary.
            output_dir: Directory for output files.
            timeout: Subprocess timeout in seconds.
            templates: Optional list of template IDs to use.
        """
        self.nuclei_path: str = nuclei_path
        self.output_dir: Optional[str] = output_dir
        self.timeout: int = timeout
        self.templates: Optional[List[str]] = templates

    def is_available(self) -> bool:
        """
        Check if Nuclei is available on the system.

        Returns:
            True if Nuclei is installed and accessible, False otherwise.
        """
        try:
            result = subprocess.run(
                [self.nuclei_path, "-version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
            logger.debug("Nuclei not available: %s", e)
            return False

    def _build_command(
        self,
        target: Optional[str] = None,
        target_list: Optional[str] = None,
        severity: Optional[str] = None,
        tags: Optional[List[str]] = None,
        technology: Optional[str] = None,
        sarif_output: bool = False,
        rate_limit: Optional[int] = None,
    ) -> List[str]:
        """
        Build the Nuclei command line arguments.

        Args:
            target: Single target URL.
            target_list: Path to file containing target list.
            severity: Severity filter (e.g., "critical", "high").
            tags: List of tags to filter by.
            technology: Technology filter.
            sarif_output: Whether to enable SARIF output.
            rate_limit: Requests per second limit.

        Returns:
            List of command line arguments.
        """
        cmd: List[str] = [self.nuclei_path]

        # Target specification
        if target_list:
            cmd.extend(["-l", target_list])
        elif target:
            cmd.extend(["-u", target])

        # Severity filter
        if severity:
            cmd.extend(["-severity", severity])

        # Tags filter
        if tags:
            cmd.extend(["-tags", ",".join(tags)])

        # Technology filter
        if technology:
            cmd.extend(["-tech", technology])

        # Template selection
        if self.templates:
            cmd.extend(["-t"] + self.templates)

        # Rate limiting
        if rate_limit is not None:
            cmd.extend(["-rl", str(rate_limit)])

        # SARIF output
        if sarif_output:
            cmd.append("-se")
            if self.output_dir:
                sarif_path = str(Path(self.output_dir) / "results.sarif")
                cmd.extend(["-sarif", sarif_path])
            else:
                cmd.extend(["-sarif", "results.sarif"])

        return cmd

    def run(
        self,
        target: Optional[str] = None,
        target_list: Optional[str] = None,
        severity: Optional[str] = None,
        tags: Optional[List[str]] = None,
        technology: Optional[str] = None,
        sarif_output: bool = False,
        rate_limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Execute Nuclei with the specified options.

        Args:
            target: Single target URL to scan.
            target_list: Path to file containing list of targets.
            severity: Severity filter for templates.
            tags: List of tags to filter templates.
            technology: Technology filter for templates.
            sarif_output: Whether to enable SARIF output format.
            rate_limit: Maximum requests per second.

        Returns:
            Dictionary with scan results including success status,
            stdout, stderr, and any error messages.
        """
        cmd = self._build_command(
            target=target,
            target_list=target_list,
            severity=severity,
            tags=tags,
            technology=technology,
            sarif_output=sarif_output,
            rate_limit=rate_limit,
        )

        logger.info("Running Nuclei: %s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            success = result.returncode == 0

            if not success:
                logger.warning("Nuclei exited with code %d: %s", result.returncode, result.stderr)

            return {
                "success": success,
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }

        except subprocess.TimeoutExpired as e:
            logger.error("Nuclei timed out after %d seconds", self.timeout)
            return {
                "success": False,
                "error": f"timeout after {self.timeout} seconds",
                "stdout": str(e.stdout) if e.stdout else "",
                "stderr": str(e.stderr) if e.stderr else "",
            }

        except FileNotFoundError as e:
            logger.error("Nuclei binary not found: %s", e)
            return {
                "success": False,
                "error": f"nuclei not found: {e}",
            }

        except OSError as e:
            logger.error("OS error running Nuclei: %s", e)
            return {
                "success": False,
                "error": str(e),
            }

    def parse_results(self, sarif_path: str) -> List[Dict[str, Any]]:
        """
        Parse SARIF output from a Nuclei scan.

        Args:
            sarif_path: Path to the SARIF output file.

        Returns:
            List of parsed findings, or empty list on error.
        """
        path = Path(sarif_path)

        if not path.exists():
            logger.warning("SARIF file not found: %s", sarif_path)
            return []

        try:
            sarif_data = load_sarif(path)
            if sarif_data is None:
                logger.warning("Failed to load SARIF file: %s", sarif_path)
                return []

            findings = parse_sarif_findings(path)
            logger.info("Parsed %d findings from SARIF", len(findings))
            return findings

        except (OSError, ValueError) as e:
            logger.error("Error parsing SARIF results: %s", e)
            return []

    def get_findings(
        self, sarif_path: str, severity: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get findings from SARIF output, optionally filtered by severity.

        Args:
            sarif_path: Path to the SARIF output file.
            severity: Optional severity filter for findings.

        Returns:
            List of findings, filtered by severity if specified.
        """
        findings = self.parse_results(sarif_path)

        if severity and findings:
            severity_map = {
                "critical": "error",
                "high": "error",
                "medium": "warning",
                "low": "note",
                "info": "note",
            }
            target_level = severity_map.get(severity.lower(), severity.lower())
            findings = [f for f in findings if f.get("level") == target_level]

        return findings
