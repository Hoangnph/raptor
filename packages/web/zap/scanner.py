#!/usr/bin/env python3
"""
OWASP ZAP Scanner Integration

Provides integration with OWASP ZAP via the Python API client (zapv2).
Supports spider scanning, active scanning, passive scanning, and alert retrieval.
"""

import time
from typing import Any, Dict, List, Optional

from core.logging import get_logger

logger = get_logger()

# Graceful import of zapv2
try:
    from zapv2 import ZAPv2
except ImportError:
    ZAPv2 = None  # type: ignore[misc,assignment]


class ZapScanner:
    """Integration with OWASP ZAP dynamic analysis scanner.

    Wraps the ZAP Python API client to provide high-level scanning
    operations: spider, active scan, passive scan, and alert retrieval.

    Usage:
        scanner = ZapScanner(host='localhost', port=8080)
        if scanner.is_available():
            scanner.spider_scan('https://example.com')
            scanner.active_scan('https://example.com')
            alerts = scanner.get_alerts()
            scanner.shutdown()

    Or as a context manager:
        with ZapScanner() as scanner:
            scanner.spider_scan('https://example.com')
            alerts = scanner.get_alerts()
    """

    def __init__(
        self,
        api_key: str = "",
        host: str = "localhost",
        port: int = 8080,
    ) -> None:
        """Initialize the ZAP scanner.

        Args:
            api_key: ZAP API key (empty for local instances).
            host: ZAP proxy host.
            port: ZAP proxy port.

        Raises:
            ImportError: If the zapv2 package is not installed.
        """
        if ZAPv2 is None:
            raise ImportError(
                "The 'zapv2' package is required for ZAP integration. "
                "Install it with: pip install python-owasp-zap-v2.4"
            )

        self.api_key = api_key
        self.host = host
        self.port = port
        self.zap: Optional[ZAPv2] = None
        self._connect()

    def _connect(self) -> None:
        """Establish connection to ZAP API."""
        try:
            self.zap = ZAPv2(
                apikey=self.api_key,
                proxies={
                    "http": f"http://{self.host}:{self.port}",
                    "https": f"http://{self.host}:{self.port}",
                },
            )
            logger.debug(f"Connected to ZAP at {self.host}:{self.port}")
        except Exception as exc:
            logger.error(f"Failed to connect to ZAP: {exc}")
            self.zap = None

    def is_available(self) -> bool:
        """Check if ZAP is running and accessible.

        Returns:
            True if ZAP is available, False otherwise.
        """
        if self.zap is None:
            return False
        try:
            version = self.zap.core.version()
            logger.info(f"ZAP version: {version}")
            return True
        except Exception as exc:
            logger.warning(f"ZAP is not available: {exc}")
            return False

    def spider_scan(
        self,
        url: str,
        max_duration: int = 300,
    ) -> Dict[str, Any]:
        """Run a ZAP spider scan against the target URL.

        Args:
            url: Target URL to spider.
            max_duration: Maximum scan duration in seconds.

        Returns:
            Dictionary with scan_id, completed status, progress, and urls_found.
        """
        result: Dict[str, Any] = {
            "scan_id": None,
            "completed": False,
            "progress": "0",
            "urls_found": 0,
            "error": None,
        }

        if self.zap is None:
            result["error"] = "ZAP connection not available"
            logger.error(result["error"])
            return result

        try:
            logger.info(f"Starting spider scan on {url}")
            scan_id = self.zap.spider.scan(url, maxchildren=None)
            result["scan_id"] = scan_id

            # Poll until complete or timeout
            start_time = time.time()
            while True:
                elapsed = time.time() - start_time
                if elapsed > max_duration:
                    logger.warning(
                        f"Spider scan timed out after {max_duration}s"
                    )
                    break

                status = self.zap.spider.status(scan_id)
                result["progress"] = status

                if int(status) >= 100:
                    result["completed"] = True
                    break

                time.sleep(1)

            # Retrieve discovered URLs
            if result["completed"]:
                urls = self.zap.spider.results(scan_id)
                result["urls_found"] = len(urls) if urls else 0

            logger.info(
                f"Spider scan {'completed' if result['completed'] else 'timed out'}: "
                f"{result['progress']}%, {result['urls_found']} URLs found"
            )

        except Exception as exc:
            result["error"] = str(exc)
            logger.error(f"Spider scan failed: {exc}")

        return result

    def active_scan(
        self,
        url: str,
        max_duration: int = 600,
    ) -> Dict[str, Any]:
        """Run a ZAP active scan against the target URL.

        Args:
            url: Target URL to actively scan.
            max_duration: Maximum scan duration in seconds.

        Returns:
            Dictionary with scan_id, completed status, and progress.
        """
        result: Dict[str, Any] = {
            "scan_id": None,
            "completed": False,
            "progress": "0",
            "error": None,
        }

        if self.zap is None:
            result["error"] = "ZAP connection not available"
            logger.error(result["error"])
            return result

        try:
            logger.info(f"Starting active scan on {url}")
            scan_id = self.zap.ascan.scan(url)
            result["scan_id"] = scan_id

            # Poll until complete or timeout
            start_time = time.time()
            while True:
                elapsed = time.time() - start_time
                if elapsed > max_duration:
                    logger.warning(
                        f"Active scan timed out after {max_duration}s"
                    )
                    # Stop the scan on timeout
                    try:
                        self.zap.ascan.stop_scan()
                    except Exception:
                        pass
                    break

                status = self.zap.ascan.status(scan_id)
                result["progress"] = status

                if int(status) >= 100:
                    result["completed"] = True
                    break

                time.sleep(1)

            logger.info(
                f"Active scan {'completed' if result['completed'] else 'timed out'}: "
                f"{result['progress']}%"
            )

        except Exception as exc:
            result["error"] = str(exc)
            logger.error(f"Active scan failed: {exc}")

        return result

    def get_alerts(self) -> List[Dict[str, Any]]:
        """Retrieve and parse ZAP alerts.

        Returns:
            List of alert dictionaries with standardized fields.
        """
        if self.zap is None:
            logger.error("ZAP connection not available")
            return []

        try:
            alerts = self.zap.core.alerts()
            if not alerts:
                return []
            return alerts
        except Exception as exc:
            logger.error(f"Failed to retrieve alerts: {exc}")
            return []

    def get_risk_counts(self) -> Dict[str, int]:
        """Count alerts by risk level.

        Returns:
            Dictionary mapping risk level names to counts.
        """
        alerts = self.get_alerts()
        counts: Dict[str, int] = {}
        for alert in alerts:
            risk = alert.get("risk", "Unknown")
            counts[risk] = counts.get(risk, 0) + 1
        return counts

    def get_passive_scan_records(self) -> Optional[int]:
        """Get the number of passive scan records remaining.

        Returns:
            Number of records to display, or None on error.
        """
        if self.zap is None:
            logger.error("ZAP connection not available")
            return None

        try:
            records = self.zap.pscan.records_to_display()
            return int(records)
        except Exception as exc:
            logger.error(f"Failed to get passive scan records: {exc}")
            return None

    def shutdown(self) -> None:
        """Shut down the ZAP instance."""
        if self.zap is None:
            return
        try:
            self.zap.core.shutdown()
            logger.info("ZAP shutdown initiated")
        except Exception as exc:
            logger.warning(f"ZAP shutdown error (non-fatal): {exc}")

    def __enter__(self) -> "ZapScanner":
        """Support context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:  # type: ignore[no-untyped-def]
        """Support context manager exit - ensures shutdown."""
        self.shutdown()
        return None
