"""Recon orchestrator that chains subfinder, httpx, and katana.

Runs the full reconnaissance pipeline: subdomain discovery, HTTP probing,
and web crawling. Aggregates results into a unified structure.
"""

from pathlib import Path
from typing import Any, Dict

from core.json.utils import save_json
from core.logging import get_logger

from packages.web.recon.httpx_tool import HttpxWrapper
from packages.web.recon.katana import KatanaWrapper
from packages.web.recon.subfinder import SubfinderWrapper


class ReconOrchestrator:
    """Orchestrates the reconnaissance pipeline.

    Chains subfinder (subdomain discovery), httpx (HTTP probing), and
    katana (web crawling) to produce a unified set of reconnaissance
    results for a target domain.
    """

    def __init__(self) -> None:
        """Initialize the ReconOrchestrator with tool wrappers."""
        self._subfinder = SubfinderWrapper()
        self._httpx = HttpxWrapper()
        self._katana = KatanaWrapper()
        self._results: Dict[str, Any] = {}
        self._logger = get_logger()

    def run(self, target_domain: str, output_dir: str) -> Dict[str, Any]:
        """Run the full reconnaissance pipeline.

        Steps:
        1. Run subfinder to discover subdomains.
        2. Run httpx against discovered subdomains to find live hosts.
        3. Run katana against live hosts to discover endpoints.

        Results are saved to output_dir as recon_results.json.

        Args:
            target_domain: The target domain to recon.
            output_dir: Directory to save results.

        Returns:
            Unified dictionary with aggregated results from all tools.
        """
        self._logger.info(f"Starting recon pipeline for {target_domain}")
        self._results = {}

        # Step 1: Subdomain discovery
        subfinder_output_file = str(Path(output_dir) / "subfinder_output.json")
        subfinder_result = self._subfinder.run(
            domain=target_domain,
            output_file=subfinder_output_file,
        )

        if subfinder_result.get("success"):
            self._results["subdomains"] = subfinder_result.get("subdomains", [])
            self._logger.info(
                f"Subfinder found {len(self._results['subdomains'])} subdomains"
            )
        else:
            self._logger.warning(
                f"Subfinder failed: {subfinder_result.get('error', 'unknown')}"
            )
            self._results["subdomains"] = []

        # Step 2: HTTP probing
        subdomains = self._results.get("subdomains", [])
        if subdomains:
            httpx_output_file = str(Path(output_dir) / "httpx_output.json")
            httpx_result = self._httpx.run(
                targets=subdomains,
                output_file=httpx_output_file,
            )

            if httpx_result.get("success"):
                self._results["live_hosts"] = httpx_result.get("live_hosts", [])
                self._logger.info(
                    f"Httpx found {len(self._results['live_hosts'])} live hosts"
                )
            else:
                self._logger.warning(
                    f"Httpx failed: {httpx_result.get('error', 'unknown')}"
                )
                self._results["live_hosts"] = []
        else:
            self._results["live_hosts"] = []
            self._logger.info("No subdomains to probe")

        # Step 3: Web crawling
        live_hosts = self._results.get("live_hosts", [])
        if live_hosts:
            # Crawl each live host
            all_endpoints = []
            for host in live_hosts:
                katana_result = self._katana.run(url=host)
                if katana_result.get("success"):
                    endpoints = katana_result.get("endpoints", [])
                    all_endpoints.extend(endpoints)

            self._results["endpoints"] = all_endpoints
            self._logger.info(
                f"Katana discovered {len(all_endpoints)} total endpoints"
            )
        else:
            self._results["endpoints"] = []
            self._logger.info("No live hosts to crawl")

        # Save results
        output_path = str(Path(output_dir) / "recon_results.json")
        save_json(output_path, self._results)
        self._logger.info(f"Recon results saved to {output_path}")

        self._results["success"] = True
        return self._results

    def get_results(self) -> Dict[str, Any]:
        """Get the aggregated recon results.

        Returns:
            Dictionary containing subdomains, live_hosts, and endpoints
            from the most recent run.
        """
        return self._results
