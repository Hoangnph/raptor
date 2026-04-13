"""Katana wrapper for web crawling and endpoint discovery.

Wraps the katana CLI subprocess for crawling web applications and
discovering endpoints, parameters, and paths.
"""

import json
import subprocess
from typing import Any, Dict, List, Optional

from core.logging import get_logger


class KatanaWrapper:
    """Wrapper around the katana CLI tool for web crawling.

    Provides methods to run katana against a target URL, check tool
    availability, and extract discovered paths and parameters.
    """

    def __init__(self, katana_path: str = "katana") -> None:
        """Initialize the KatanaWrapper.

        Args:
            katana_path: Path to the katana binary. Defaults to "katana".
        """
        self.katana_path: str = katana_path
        self._results: List[Dict[str, Any]] = []
        self._logger = get_logger()

    def is_available(self) -> bool:
        """Check if katana is available on the system.

        Returns:
            True if katana is installed and executable, False otherwise.
        """
        try:
            result = subprocess.run(
                [self.katana_path, "-version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return False

    def run(
        self,
        url: str,
        output_file: Optional[str] = None,
        js_render: bool = True,
        timeout: int = 300,
    ) -> Dict[str, object]:
        """Run katana against a target URL.

        Args:
            url: The target URL to crawl.
            output_file: Optional path to save results to.
            js_render: Whether to enable JavaScript rendering. Defaults to True.
            timeout: Timeout in seconds for the subprocess. Defaults to 300.

        Returns:
            Dictionary with 'success' boolean and either crawl results
            on success, or 'error' string on failure.
        """
        cmd: List[str] = [self.katana_path, "-u", url, "-silent", "-jsonl"]

        if js_render:
            cmd.append("-js-render")

        if output_file:
            cmd.extend(["-o", output_file])

        self._logger.debug(f"Running katana against URL: {url}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            if result.returncode != 0:
                self._logger.warning(
                    f"Katana failed for {url}: {result.stderr}"
                )
                return {
                    "success": False,
                    "error": f"katana exited with code {result.returncode}",
                    "stderr": result.stderr,
                }

            endpoints = self._parse_endpoints(result.stdout)
            self._logger.info(
                f"Katana discovered {len(endpoints)} endpoint(s) for {url}"
            )

            return {
                "success": True,
                "endpoints": endpoints,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }

        except subprocess.TimeoutExpired:
            self._logger.warning(f"Katana timed out for {url}")
            return {
                "success": False,
                "error": "katana timeout",
            }
        except FileNotFoundError:
            self._logger.error("Katana not found")
            return {
                "success": False,
                "error": "katana not found",
            }
        except OSError as exc:
            self._logger.error(f"Katana OS error: {exc}")
            return {
                "success": False,
                "error": str(exc),
            }

    def _parse_endpoints(self, stdout: str) -> List[Dict[str, Any]]:
        """Parse endpoint data from katana JSONL output.

        Args:
            stdout: Raw stdout output from katana.

        Returns:
            List of parsed endpoint dictionaries.
        """
        endpoints: List[Dict[str, Any]] = []
        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                endpoints.append(entry)
                self._results.append(entry)
            except json.JSONDecodeError:
                continue
        return endpoints

    def get_paths(self) -> List[str]:
        """Extract unique paths from katana results.

        Returns:
            List of unique endpoint paths discovered by katana.
        """
        paths: List[str] = []
        for entry in self._results:
            endpoint = entry.get("endpoint", "")
            if endpoint and endpoint not in paths:
                paths.append(endpoint)
        return paths

    def get_parameters(self) -> List[str]:
        """Extract unique parameters from katana results.

        Returns:
            List of unique parameter names discovered across all endpoints.
        """
        parameters: List[str] = []
        for entry in self._results:
            entry_params = entry.get("parameters", [])
            if isinstance(entry_params, list):
                for param in entry_params:
                    if param not in parameters:
                        parameters.append(param)
        return parameters
