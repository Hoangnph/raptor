"""Subfinder wrapper for subdomain discovery.

Wraps the subfinder CLI subprocess for enumerating subdomains of a target domain.
"""

import subprocess
from typing import Dict, List, Optional

from core.logging import get_logger


class SubfinderWrapper:
    """Wrapper around the subfinder CLI tool for subdomain enumeration.

    Provides methods to run subfinder against a target domain, check tool
    availability, and parse the resulting subdomains.
    """

    def __init__(self, subfinder_path: str = "subfinder") -> None:
        """Initialize the SubfinderWrapper.

        Args:
            subfinder_path: Path to the subfinder binary. Defaults to "subfinder".
        """
        self.subfinder_path: str = subfinder_path
        self._logger = get_logger()

    def is_available(self) -> bool:
        """Check if subfinder is available on the system.

        Returns:
            True if subfinder is installed and executable, False otherwise.
        """
        try:
            result = subprocess.run(
                [self.subfinder_path, "-version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return False

    def run(
        self,
        domain: str,
        output_file: Optional[str] = None,
        timeout: int = 300,
    ) -> Dict[str, object]:
        """Run subfinder against a target domain.

        Args:
            domain: The target domain to enumerate subdomains for.
            output_file: Optional path to save results to.
            timeout: Timeout in seconds for the subprocess. Defaults to 300.

        Returns:
            Dictionary with 'success' boolean and either 'subdomains' list
            on success, or 'error' string on failure.
        """
        cmd: List[str] = [self.subfinder_path, "-d", domain, "-silent"]

        if output_file:
            cmd.extend(["-o", output_file])

        self._logger.debug(f"Running subfinder for domain: {domain}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            if result.returncode != 0:
                self._logger.warning(
                    f"Subfinder failed for {domain}: {result.stderr}"
                )
                return {
                    "success": False,
                    "error": f"subfinder exited with code {result.returncode}",
                    "stderr": result.stderr,
                }

            subdomains = self._parse_subdomains(result.stdout)
            self._logger.info(
                f"Subfinder found {len(subdomains)} subdomains for {domain}"
            )

            return {
                "success": True,
                "subdomains": subdomains,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }

        except subprocess.TimeoutExpired:
            self._logger.warning(f"Subfinder timed out for {domain}")
            return {
                "success": False,
                "error": "subfinder timeout",
            }
        except FileNotFoundError:
            self._logger.error("Subfinder not found")
            return {
                "success": False,
                "error": "subfinder not found",
            }
        except OSError as exc:
            self._logger.error(f"Subfinder OS error: {exc}")
            return {
                "success": False,
                "error": str(exc),
            }

    def _parse_subdomains(self, stdout: str) -> List[str]:
        """Parse subdomain names from subfinder stdout.

        Args:
            stdout: Raw stdout output from subfinder.

        Returns:
            List of subdomain strings, one per non-empty line.
        """
        return [
            line.strip()
            for line in stdout.strip().splitlines()
            if line.strip()
        ]
