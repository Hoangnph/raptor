#!/usr/bin/env python3
"""
Web Scanner Orchestrator

Coordinates multiple web security testing tools into a unified pipeline:
1. Recon (subfinder -> httpx -> katana) - discovery
2. Nuclei - known vulnerability scanning
3. ZAP - active DAST scanning
4. WebCrawler + WebFuzzer - deep analysis
5. Exploit-DB - exploit correlation

Backward compatible with the original WebScanner interface while supporting
configurable phase execution.
"""

import sys
from pathlib import Path

# Enable standalone execution: add repo root to path
_script_dir = Path(__file__).resolve().parents[2]
if str(_script_dir) not in sys.path:
    sys.path.insert(0, str(_script_dir))

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from core.json.utils import save_json
from core.logging import get_logger

from packages.web.client import WebClient
from packages.web.crawler import WebCrawler
from packages.web.fuzzer import WebFuzzer

# Graceful imports for external tools — fallback gracefully when unavailable
try:
    from packages.web.recon.orchestrator import ReconOrchestrator
except ImportError:
    ReconOrchestrator = None  # type: ignore[misc,assignment]

try:
    from packages.web.nuclei.runner import NucleiRunner
except ImportError:
    NucleiRunner = None  # type: ignore[misc,assignment]

try:
    from packages.web.zap.scanner import ZapScanner
except ImportError:
    ZapScanner = None  # type: ignore[misc,assignment]

try:
    from packages.exploit_db.searcher import ExploitSearcher
    from packages.exploit_db.database import ExploitDatabase
except ImportError:
    ExploitSearcher = None  # type: ignore[misc,assignment]
    ExploitDatabase = None  # type: ignore[misc,assignment]

logger = get_logger()

ALL_PHASES = ["recon", "nuclei", "zap", "crawl", "fuzz", "correlate"]


class WebScanner:
    """Fully autonomous web security scanner with configurable phases.

    Orchestrates reconnaissance, vulnerability scanning, DAST, crawling,
    fuzzing, and exploit correlation into a unified pipeline.

    Args:
        base_url: Target URL to scan.
        llm: Optional LLM provider for intelligent fuzzing.
        out_dir: Output directory for results.
        verify_ssl: Whether to verify SSL certificates.
        phases: List of phases to run. Defaults to all phases.
    """

    def __init__(
        self,
        base_url: str,
        llm: Optional[Any] = None,
        out_dir: Optional[Path] = None,
        verify_ssl: bool = True,
        phases: Optional[List[str]] = None,
    ) -> None:
        self.base_url: str = base_url
        self.llm: Optional[Any] = llm
        self.out_dir: Path = out_dir if out_dir is not None else Path("out/")
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.verify_ssl: bool = verify_ssl
        self.phases: List[str] = phases if phases is not None else list(ALL_PHASES)

        # Initialize core components
        self.client: WebClient = WebClient(base_url, verify_ssl=verify_ssl)
        self.crawler: WebCrawler = WebCrawler(self.client)
        self.fuzzer: Optional[WebFuzzer] = WebFuzzer(self.client, llm) if llm else None

        # Internal state
        self._phase_results: Dict[str, Any] = {}
        self._findings: List[Dict[str, Any]] = []
        self._correlations: List[Dict[str, Any]] = []
        self._phases_run: List[str] = []

        logger.info(
            f"Web scanner initialized for {base_url} "
            f"(verify_ssl={verify_ssl}, phases={self.phases})"
        )

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def scan(self) -> Dict[str, Any]:
        """Run all configured scanning phases.

        Executes phases in order: Recon -> Nuclei -> ZAP -> Crawl ->
        Fuzz -> Correlate. Each phase is wrapped in try/except so that
        a single failure does not abort the entire scan.

        Returns:
            Dictionary with target, findings, phase_results, phases_run,
            and correlations.
        """
        logger.info("Starting web security scan")
        self._phase_results = {}
        self._findings = []
        self._correlations = []
        self._phases_run = []

        for phase in self.phases:
            try:
                if phase == "recon":
                    domain = self._extract_domain(self.base_url)
                    result = self.run_recon(domain)
                    self._phase_results["recon"] = result
                    self._phases_run.append("recon")

                elif phase == "nuclei":
                    result = self.run_nuclei([self.base_url])
                    self._phase_results["nuclei"] = result
                    self._phases_run.append("nuclei")

                elif phase == "zap":
                    result = self.run_zap(self.base_url)
                    self._phase_results["zap"] = result
                    self._phases_run.append("zap")

                elif phase == "crawl":
                    result = self.run_crawl(self.base_url)
                    self._phase_results["crawl"] = result
                    self._phases_run.append("crawl")

                elif phase == "fuzz":
                    crawl_result = self._phase_results.get("crawl", {})
                    urls = crawl_result.get("visited_urls", [self.base_url])
                    parameters = crawl_result.get("discovered_parameters", [])
                    result = self.run_fuzz(urls, parameters)
                    self._phase_results["fuzz"] = result
                    self._phases_run.append("fuzz")

                elif phase == "correlate":
                    result = self.correlate_findings()
                    self._phase_results["correlate"] = result
                    self._correlations = result.get("correlations", [])
                    self._phases_run.append("correlate")

                else:
                    logger.warning(f"Unknown phase: {phase}")

            except Exception as exc:
                logger.error(f"Phase '{phase}' failed: {exc}", exc_info=True)
                self._phase_results[phase] = {"success": False, "error": str(exc)}

        # Aggregate findings into unified format
        self._findings = self.aggregate_findings()

        # Save report
        self.save_report()

        logger.info(
            f"Scan complete. Phases run: {self._phases_run}. "
            f"Findings: {len(self._findings)}"
        )

        return {
            "target": self.base_url,
            "findings": self._findings,
            "phase_results": self._phase_results,
            "phases_run": self._phases_run,
            "correlations": self._correlations,
            "total_vulnerabilities": len(self._findings),
        }

    # ------------------------------------------------------------------
    # Phase: Recon
    # ------------------------------------------------------------------

    def run_recon(self, domain: str) -> Dict[str, Any]:
        """Run reconnaissance phase (subfinder -> httpx -> katana).

        Args:
            domain: Target domain for reconnaissance.

        Returns:
            Recon results dictionary with subdomains, live_hosts, and
            endpoints. On failure, returns {"success": False, "error": ...}.
        """
        logger.info(f"Starting recon for domain: {domain}")

        if ReconOrchestrator is None:
            logger.warning("ReconOrchestrator not available — skipping recon")
            return {"success": False, "error": "ReconOrchestrator not available"}

        try:
            orchestrator = ReconOrchestrator()
            result = orchestrator.run(target_domain=domain, output_dir=str(self.out_dir))
            logger.info(f"Recon complete: {result.get('subdomains', [])}")
            return result
        except Exception as exc:
            logger.error(f"Recon failed: {exc}")
            return {"success": False, "error": str(exc)}

    # ------------------------------------------------------------------
    # Phase: Nuclei
    # ------------------------------------------------------------------

    def run_nuclei(self, targets: List[str]) -> Dict[str, Any]:
        """Run Nuclei vulnerability scanning.

        Args:
            targets: List of target URLs to scan.

        Returns:
            Nuclei scan results. On failure or when unavailable,
            returns {"success": False, "error": ...}.
        """
        logger.info(f"Starting Nuclei scan for {len(targets)} target(s)")

        if NucleiRunner is None:
            logger.warning("NucleiRunner not available — skipping nuclei")
            return {"success": False, "error": "NucleiRunner not available"}

        try:
            runner = NucleiRunner(output_dir=str(self.out_dir))
            if not runner.is_available():
                logger.warning("Nuclei binary not found — skipping")
                return {"success": False, "error": "Nuclei binary not found"}

            all_results: Dict[str, Any] = {
                "success": True,
                "scans": [],
                "findings": [],
            }

            for target in targets:
                result = runner.run(target=target, sarif_output=True)
                all_results["scans"].append({"target": target, **result})
                if not result.get("success"):
                    all_results["success"] = False

            return all_results
        except Exception as exc:
            logger.error(f"Nuclei scan failed: {exc}")
            return {"success": False, "error": str(exc)}

    # ------------------------------------------------------------------
    # Phase: ZAP
    # ------------------------------------------------------------------

    def run_zap(self, target: str) -> Dict[str, Any]:
        """Run ZAP DAST scanning (spider + active scan).

        Args:
            target: Target URL for ZAP scanning.

        Returns:
            ZAP scan results with alerts. On failure or when unavailable,
            returns {"success": False, "error": ...}.
        """
        logger.info(f"Starting ZAP scan for: {target}")

        if ZapScanner is None:
            logger.warning("ZapScanner not available — skipping ZAP")
            return {"success": False, "error": "ZapScanner not available"}

        try:
            scanner = ZapScanner()
            if not scanner.is_available():
                logger.warning("ZAP not running — skipping")
                return {"success": False, "error": "ZAP not running"}

            spider_result = scanner.spider_scan(target)
            active_result = scanner.active_scan(target)
            alerts = scanner.get_alerts()

            return {
                "success": True,
                "spider": spider_result,
                "active_scan": active_result,
                "alerts": alerts,
            }
        except Exception as exc:
            logger.error(f"ZAP scan failed: {exc}")
            return {"success": False, "error": str(exc)}

    # ------------------------------------------------------------------
    # Phase: Crawl
    # ------------------------------------------------------------------

    def run_crawl(self, start_url: str) -> Dict[str, Any]:
        """Run web crawler to discover pages, forms, and parameters.

        Args:
            start_url: URL to start crawling from.

        Returns:
            Crawl results with discovered resources. On failure,
            returns {"success": False, "error": ...}.
        """
        logger.info(f"Starting crawl from: {start_url}")

        try:
            result = self.crawler.crawl(start_url)
            logger.info(
                f"Crawl complete: {result.get('stats', {})}"
            )
            return result
        except Exception as exc:
            logger.error(f"Crawl failed: {exc}")
            return {"success": False, "error": str(exc)}

    # ------------------------------------------------------------------
    # Phase: Fuzz
    # ------------------------------------------------------------------

    def run_fuzz(
        self,
        urls: List[str],
        parameters: List[str],
    ) -> List[Dict[str, Any]]:
        """Run LLM-powered fuzzing on discovered parameters.

        Args:
            urls: List of URLs to fuzz.
            parameters: List of parameter names to test.

        Returns:
            List of fuzz findings. Empty list when no fuzzer is available.
        """
        logger.info(f"Starting fuzz: {len(urls)} URLs, {len(parameters)} parameters")

        if self.fuzzer is None:
            logger.warning("No fuzzer available (LLM not configured) — skipping fuzz")
            return []

        all_findings: List[Dict[str, Any]] = []

        for url in urls:
            for param in parameters:
                try:
                    findings = self.fuzzer.fuzz_parameter(
                        url,
                        param,
                        vulnerability_types=["sqli", "xss", "command_injection"],
                    )
                    all_findings.extend(findings)
                except Exception as exc:
                    logger.error(f"Fuzz failed for {param} at {url}: {exc}")

        logger.info(f"Fuzz complete: {len(all_findings)} findings")
        return all_findings

    # ------------------------------------------------------------------
    # Phase: Correlate
    # ------------------------------------------------------------------

    def correlate_findings(self) -> Dict[str, Any]:
        """Cross-reference findings with Exploit-DB.

        Looks up known exploits for any findings that have a CVE identifier.

        Returns:
            Dictionary with "correlations" list mapping CVEs to exploits.
        """
        logger.info("Starting exploit correlation")

        if ExploitSearcher is None or ExploitDatabase is None:
            logger.warning("ExploitSearcher not available — skipping correlation")
            return {"correlations": []}

        correlations: List[Dict[str, Any]] = []

        try:
            db = ExploitDatabase()
            searcher = ExploitSearcher(db)

            for finding in self._findings:
                cve = finding.get("cve")
                if cve:
                    try:
                        exploits = searcher.search(cve=cve)
                        if exploits:
                            correlations.append({
                                "finding_id": finding["id"],
                                "cve": cve,
                                "exploits": exploits,
                            })
                    except Exception as exc:
                        logger.warning(f"Exploit search failed for {cve}: {exc}")

        except Exception as exc:
            logger.error(f"Exploit correlation failed: {exc}")

        logger.info(f"Correlation complete: {len(correlations)} matches")
        return {"correlations": correlations}

    # ------------------------------------------------------------------
    # Aggregation
    # ------------------------------------------------------------------

    def aggregate_findings(self) -> List[Dict[str, Any]]:
        """Aggregate all phase results into a unified finding format.

        Converts raw tool output from recon, nuclei, zap, crawl, and fuzz
        into the standard finding schema.

        Returns:
            List of normalized finding dictionaries.
        """
        findings: List[Dict[str, Any]] = []

        results = self._phase_results

        # Recon findings
        recon = results.get("recon", {})
        if recon.get("success"):
            for subdomain in recon.get("subdomains", []):
                findings.append({
                    "id": f"recon-{uuid.uuid4().hex[:8]}",
                    "type": "recon",
                    "severity": "info",
                    "title": f"Subdomain discovered: {subdomain}",
                    "url": f"https://{subdomain}",
                    "parameter": None,
                    "evidence": "subfinder output",
                    "cve": None,
                    "cwe": None,
                    "confidence": "high",
                    "source": "recon",
                    "remediation": "N/A",
                })
            for host in recon.get("live_hosts", []):
                findings.append({
                    "id": f"recon-{uuid.uuid4().hex[:8]}",
                    "type": "recon",
                    "severity": "info",
                    "title": f"Live host discovered: {host}",
                    "url": host,
                    "parameter": None,
                    "evidence": "httpx probe",
                    "cve": None,
                    "cwe": None,
                    "confidence": "high",
                    "source": "recon",
                    "remediation": "N/A",
                })

        # Nuclei findings
        nuclei = results.get("nuclei", {})
        for scan in nuclei.get("scans", []):
            if scan.get("success"):
                # Parse SARIF if available
                output_dir = scan.get("_output_dir", str(self.out_dir))
                sarif_path = Path(output_dir) / "results.sarif"
                # For now extract from stdout/stderr
                findings.append({
                    "id": f"nuclei-{uuid.uuid4().hex[:8]}",
                    "type": "nuclei",
                    "severity": "info",
                    "title": f"Nuclei scan completed for {scan.get('target', 'unknown')}",
                    "url": scan.get("target", ""),
                    "parameter": None,
                    "evidence": scan.get("stdout", ""),
                    "cve": None,
                    "cwe": None,
                    "confidence": "medium",
                    "source": "nuclei",
                    "remediation": "Review Nuclei output for vulnerabilities.",
                })

        # ZAP findings
        zap = results.get("zap", {})
        for alert in zap.get("alerts", []):
            findings.append(self._normalize_zap_alert(alert))

        # Crawl findings
        crawl = results.get("crawl", {})
        if crawl.get("success") or "stats" in crawl:
            for form in crawl.get("discovered_forms", []):
                input_names = list(form.get("inputs", {}).keys())
                findings.append({
                    "id": f"crawl-{uuid.uuid4().hex[:8]}",
                    "type": "crawl",
                    "severity": "info",
                    "title": f"Discovered form at {form.get('action', 'unknown')}",
                    "url": form.get("action", ""),
                    "parameter": None,
                    "evidence": f"Form with inputs: {', '.join(input_names)}",
                    "cve": None,
                    "cwe": None,
                    "confidence": "high",
                    "source": "crawler",
                    "remediation": "Ensure form uses HTTPS and CSRF protection.",
                })

        # Fuzz findings
        fuzz_results = results.get("fuzz", [])
        for raw in fuzz_results:
            findings.append(self._normalize_fuzz_finding(raw))

        return findings

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------

    def save_report(self) -> Path:
        """Generate and save the final scan report.

        Saves findings, phase results, and correlations as JSON.

        Returns:
            Path to the saved report file.
        """
        report = {
            "target": self.base_url,
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "phases_run": self._phases_run,
            "findings": self._findings,
            "phase_results": self._phase_results,
            "exploit_correlations": self._correlations,
            "summary": {
                "total_findings": len(self._findings),
                "by_severity": self._count_by_severity(self._findings),
                "by_type": self._count_by_type(self._findings),
            },
        }

        report_path = self.out_dir / "scan_report.json"
        save_json(report_path, report)
        logger.info(f"Report saved to {report_path}")
        return report_path

    # ------------------------------------------------------------------
    # Normalization helpers
    # ------------------------------------------------------------------

    def _normalize_nuclei_finding(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a raw Nuclei finding to unified format.

        Args:
            raw: Raw Nuclei finding dictionary.

        Returns:
            Normalized finding dictionary.
        """
        info = raw.get("info", {})
        cve_ids = info.get("cve-id", [])
        cwe_ids = info.get("cwe-id", [])

        return {
            "id": f"nuclei-{uuid.uuid4().hex[:8]}",
            "type": "nuclei",
            "severity": info.get("severity", "info").lower(),
            "title": info.get("name", "Unknown Nuclei finding"),
            "url": raw.get("matched-at", ""),
            "parameter": None,
            "evidence": str(raw.get("extracted-results", "")),
            "cve": cve_ids[0] if cve_ids else None,
            "cwe": cwe_ids[0] if cwe_ids else None,
            "confidence": "high",
            "source": "nuclei",
            "remediation": f"Review and patch for {info.get('name', 'this vulnerability')}.",
        }

    def _normalize_zap_alert(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a raw ZAP alert to unified format.

        Args:
            raw: Raw ZAP alert dictionary.

        Returns:
            Normalized finding dictionary.
        """
        return {
            "id": f"zap-{uuid.uuid4().hex[:8]}",
            "type": "zap",
            "severity": self._risk_to_severity(raw.get("risk", "Unknown")),
            "title": raw.get("alert", "Unknown ZAP alert"),
            "url": raw.get("url", ""),
            "parameter": raw.get("param") or None,
            "evidence": raw.get("evidence", ""),
            "cve": None,
            "cwe": f"CWE-{raw['cweid']}" if raw.get("cweid") else None,
            "confidence": raw.get("confidence", "medium").lower(),
            "source": "zap",
            "remediation": raw.get("solution", "Review ZAP alert details."),
        }

    def _normalize_fuzz_finding(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a raw fuzz finding to unified format.

        Args:
            raw: Raw fuzz finding dictionary.

        Returns:
            Normalized finding dictionary.
        """
        vuln_type = raw.get("vulnerability_type", "unknown")
        payload = raw.get("payload", "")

        vuln_cwe_map = {
            "sqli": "CWE-89",
            "xss": "CWE-79",
            "command_injection": "CWE-78",
            "path_traversal": "CWE-22",
        }

        return {
            "id": f"fuzz-{uuid.uuid4().hex[:8]}",
            "type": "fuzz",
            "severity": "high" if raw.get("status_code") == 500 else "medium",
            "title": f"Potential {vuln_type} in parameter '{raw.get('parameter', 'unknown')}'",
            "url": raw.get("url", ""),
            "parameter": raw.get("parameter"),
            "evidence": f"Status {raw.get('status_code', '?')} with payload: {payload}",
            "cve": None,
            "cwe": vuln_cwe_map.get(vuln_type),
            "confidence": "medium",
            "source": "fuzzer",
            "remediation": "Use parameterized queries and input validation.",
        }

    @staticmethod
    def _risk_to_severity(risk: str) -> str:
        """Map ZAP risk level to standard severity.

        Args:
            risk: ZAP risk string (High, Medium, Low, Informational).

        Returns:
            Standard severity string.
        """
        mapping = {
            "High": "high",
            "Medium": "medium",
            "Low": "low",
            "Informational": "info",
        }
        return mapping.get(risk, "info")

    @staticmethod
    def _extract_domain(url: str) -> str:
        """Extract domain from a URL string.

        If the input is already a bare domain (no scheme), it is
        returned unchanged.

        Args:
            url: URL or domain string.

        Returns:
            Extracted domain name.
        """
        if not url.startswith(("http://", "https://")):
            return url
        parsed = urlparse(url)
        return parsed.hostname or url

    @staticmethod
    def _count_by_severity(findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count findings grouped by severity.

        Args:
            findings: List of finding dictionaries.

        Returns:
            Dict mapping severity to count.
        """
        counts: Dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "unknown")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    @staticmethod
    def _count_by_type(findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count findings grouped by type.

        Args:
            findings: List of finding dictionaries.

        Returns:
            Dict mapping type to count.
        """
        counts: Dict[str, int] = {}
        for f in findings:
            ftype = f.get("type", "unknown")
            counts[ftype] = counts.get(ftype, 0) + 1
        return counts


# ---------------------------------------------------------------------------
# CLI entry point (backward compatible)
# ---------------------------------------------------------------------------

def main() -> int:
    """CLI entry point for web scanner."""
    import argparse
    import time
    from core.config import RaptorConfig

    parser = argparse.ArgumentParser(
        description="RAPTOR Web Application Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a web application
  python3 scanner.py --url https://example.com

  # Scan with custom output directory
  python3 scanner.py --url http://localhost:3000 --out /path/to/output

  # Run only specific phases
  python3 scanner.py --url https://example.com --phases recon,crawl,fuzz
        """,
    )

    parser.add_argument("--url", required=True, help="Target web application URL")
    parser.add_argument("--out", help="Output directory for results")
    parser.add_argument("--max-depth", type=int, default=3, help="Maximum crawl depth (default: 3)")
    parser.add_argument("--max-pages", type=int, default=50, help="Maximum pages to crawl (default: 50)")
    parser.add_argument("--insecure", action="store_true", help="Skip SSL/TLS certificate verification")
    parser.add_argument("--phases", help="Comma-separated list of phases to run (default: all)")

    args = parser.parse_args()

    # Determine output directory
    if args.out:
        out_dir = Path(args.out)
    else:
        timestamp = int(time.time())
        out_dir = RaptorConfig.get_out_dir() / f"web_scan_{timestamp}"

    out_dir.mkdir(parents=True, exist_ok=True)

    # Parse phases
    phases = None
    if args.phases:
        phases = [p.strip() for p in args.phases.split(",")]

    print("\n" + "=" * 70)
    print("RAPTOR WEB APPLICATION SECURITY SCANNER")
    print("=" * 70)
    print(f"Target: {args.url}")
    print(f"Output: {out_dir}")
    if phases:
        print(f"Phases: {', '.join(phases)}")
    else:
        print("Phases: all (recon, nuclei, zap, crawl, fuzz, correlate)")
    print("=" * 70 + "\n")

    logger.info("=" * 70)
    logger.info("RAPTOR WEB SCAN STARTED")
    logger.info("=" * 70)
    logger.info(f"Target: {args.url}")
    logger.info(f"Output: {out_dir}")

    # Initialize LLM client with multi-model support, fallback, and retry
    from packages.llm_analysis import get_client
    llm = get_client()
    if llm:
        logger.info("LLM client initialized")
    else:
        print("\nWarning: Could not initialize LLM client")
        print("    Web scanning will work but fuzzing will be limited")

    # Run scan
    verify_ssl = not args.insecure
    scanner = WebScanner(args.url, llm, out_dir, verify_ssl=verify_ssl, phases=phases)
    scanner.crawler.max_depth = args.max_depth
    scanner.crawler.max_pages = args.max_pages

    try:
        results = scanner.scan()

        print("\n" + "=" * 70)
        print("SCAN COMPLETE")
        print("=" * 70)
        print(f"  Phases run: {', '.join(results['phases_run'])}")
        print(f"  Findings: {len(results['findings'])}")
        print(f"  Exploit correlations: {len(results.get('correlations', []))}")
        print(f"\n  Results saved to: {out_dir}")
        print(f"  - Report: {out_dir}/scan_report.json")
        print("=" * 70 + "\n")

        logger.info("=" * 70)
        logger.info("WEB SCAN COMPLETE")
        logger.info("=" * 70)
        logger.info(f"Findings: {len(results['findings'])}")

        return 0 if results["total_vulnerabilities"] == 0 else 1

    except KeyboardInterrupt:
        print("\n\n  Scan interrupted by user")
        logger.warning("Scan interrupted by user")
        return 130
    except Exception as e:
        print(f"\n  Scan failed: {e}")
        logger.error(f"Scan failed: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
