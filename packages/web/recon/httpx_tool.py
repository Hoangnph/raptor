"""Httpx wrapper for HTTP probing and technology detection.

Wraps the httpx CLI (Go-based HTTP toolkit) subprocess for probing live hosts
and extracting technology fingerprints.
"""

import json
import subprocess
from typing import Dict, List, Optional, Union

from core.logging import get_logger


class HttpxWrapper:
    """Wrapper around the httpx CLI tool for HTTP probing.

    Provides methods to run httpx against targets, check tool availability,
    and parse technology detection results.
    """

    def __init__(self, httpx_path: str = "httpx") -> None:
        """Initialize the HttpxWrapper.

        Args:
            httpx_path: Path to the httpx binary. Defaults to "httpx".
        """
        self.httpx_path: str = httpx_path
        self._logger = get_logger()

    def is_available(self) -> bool:
        """Check if httpx is available on the system.

        Returns:
            True if httpx is installed and executable, False otherwise.
        """
        try:
            result = subprocess.run(
                [self.httpx_path, "-version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return False

    def run(
        self,
        targets: Union[str, List[str]],
        output_file: Optional[str] = None,
        timeout: int = 300,
    ) -> Dict[str, object]:
        """Run httpx against one or more targets.

        Args:
            targets: A single URL string or a list of URLs to probe.
                If a list is provided, it is written to a temp file and
                passed via -l flag.
            output_file: Optional path to save results to.
            timeout: Timeout in seconds for the subprocess. Defaults to 300.

        Returns:
            Dictionary with 'success' boolean and either probe results
            on success, or 'error' string on failure.
        """
        cmd: List[str] = [self.httpx_path, "-silent", "-json"]

        if isinstance(targets, list):
            # Write targets list to a temporary file for -l flag
            import tempfile
            tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
            tmp.write("\n".join(targets))
            tmp.close()
            cmd.extend(["-l", tmp.name])
        else:
            cmd.extend(["-u", targets])

        if output_file:
            cmd.extend(["-o", output_file])

        self._logger.debug(f"Running httpx against {len(targets) if isinstance(targets, list) else 1} target(s)")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            if result.returncode != 0:
                self._logger.warning(
                    f"Httpx failed: {result.stderr}"
                )
                return {
                    "success": False,
                    "error": f"httpx exited with code {result.returncode}",
                    "stderr": result.stderr,
                }

            live_hosts = self._parse_live_hosts(result.stdout)
            self._logger.info(
                f"Httpx found {len(live_hosts)} live host(s)"
            )

            return {
                "success": True,
                "live_hosts": live_hosts,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }

        except subprocess.TimeoutExpired:
            self._logger.warning("Httpx timed out")
            return {
                "success": False,
                "error": "httpx timeout",
            }
        except FileNotFoundError:
            self._logger.error("Httpx not found")
            return {
                "success": False,
                "error": "httpx not found",
            }
        except OSError as exc:
            self._logger.error(f"Httpx OS error: {exc}")
            return {
                "success": False,
                "error": str(exc),
            }

    def _parse_live_hosts(self, stdout: str) -> List[str]:
        """Parse live host URLs from httpx JSON output.

        Args:
            stdout: Raw stdout output from httpx.

        Returns:
            List of live host URLs.
        """
        hosts: List[str] = []
        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                url = entry.get("url", "")
                if url:
                    hosts.append(url)
            except json.JSONDecodeError:
                continue
        return hosts

    def parse_technology(
        self,
        output_text: str,
        min_status: Optional[int] = None,
        max_status: Optional[int] = None,
    ) -> List[str]:
        """Parse technology fingerprints from httpx JSON output.

        Each line of httpx JSON output may contain a 'tech' array.
        Optionally filter entries by HTTP status code range.

        Args:
            output_text: Raw stdout output from httpx (newline-delimited JSON).
            min_status: Minimum HTTP status code to include. None for no filter.
            max_status: Maximum HTTP status code to include. None for no filter.

        Returns:
            List of unique technology strings found across all matching entries.
        """
        technologies: List[str] = []
        for line in output_text.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            status_code = entry.get("status_code")
            if min_status is not None and status_code is not None:
                if status_code < min_status:
                    continue
            if max_status is not None and status_code is not None:
                if status_code > max_status:
                    continue

            tech_list = entry.get("tech", [])
            if isinstance(tech_list, list):
                technologies.extend(tech_list)

        return technologies
