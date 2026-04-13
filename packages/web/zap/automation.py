#!/usr/bin/env python3
"""
ZAP Automation Framework Integration

Generates OWASP ZAP Automation Framework YAML plans for different scan types.
Supports baseline, full, and API scanning with authentication configuration.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from core.logging import get_logger

logger = get_logger()


class ZapAutomation:
    """Generate and manage ZAP Automation Framework YAML plans.

    The ZAP Automation Framework allows fully automated security scanning
    via YAML plan files. This class provides programmatic generation of
    those plans for different scanning scenarios.

    Usage:
        automation = ZapAutomation()
        plan = automation.create_baseline_plan(
            target="https://example.com",
            output_dir="/tmp/zap_results",
        )
        automation.export_yaml(plan, "/tmp/zap_results/baseline.yaml")
    """

    def __init__(self) -> None:
        """Initialize the ZAP automation plan generator."""
        pass

    def create_baseline_plan(
        self,
        target: str,
        output_dir: str,
        context_name: str = "Default Context",
    ) -> Dict[str, Any]:
        """Create a baseline scan plan (passive only, no active attacks).

        A baseline scan performs passive analysis without sending attack
        payloads. Suitable for production environments.

        Args:
            target: Target URL to scan.
            output_dir: Directory for scan output files.
            context_name: Name for the scan context.

        Returns:
            ZAP automation plan as a dictionary.
        """
        try:
            Path(output_dir).mkdir(parents=True, exist_ok=True)
        except OSError:
            logger.warning(f"Could not create output directory: {output_dir}")

        plan: Dict[str, Any] = {
            "env": {
                "contexts": [
                    {
                        "name": context_name,
                        "urls": [target],
                    }
                ],
                "parameters": {
                    "failOnError": True,
                },
            },
            "jobs": [
                {
                    "name": "spider",
                    "type": "spider",
                    "parameters": {
                        "url": target,
                        "maxDuration": 5,
                    },
                },
                {
                    "name": "passive-scan-wait",
                    "type": "passiveScan",
                    "parameters": {
                        "maxDuration": 5,
                    },
                },
                {
                    "name": "report",
                    "type": "report",
                    "parameters": {
                        "template": "traditional-html",
                        "reportDir": str(output_dir),
                        "reportFile": "baseline-report",
                        "reportTitle": f"Baseline Scan Report - {target}",
                    },
                },
            ],
        }

        logger.info(f"Created baseline scan plan for {target}")
        return plan

    def create_full_scan_plan(
        self,
        target: str,
        output_dir: str,
        context_name: str = "Default Context",
        scan_policy: str = "default",
    ) -> Dict[str, Any]:
        """Create a full scan plan (spider + active + passive).

        A full scan performs both passive analysis and active attack
        injection. Only use in test/staging environments.

        Args:
            target: Target URL to scan.
            output_dir: Directory for scan output files.
            context_name: Name for the scan context.
            scan_policy: ZAP scan policy name.

        Returns:
            ZAP automation plan as a dictionary.
        """
        try:
            Path(output_dir).mkdir(parents=True, exist_ok=True)
        except OSError:
            logger.warning(f"Could not create output directory: {output_dir}")

        plan: Dict[str, Any] = {
            "env": {
                "contexts": [
                    {
                        "name": context_name,
                        "urls": [target],
                    }
                ],
                "parameters": {
                    "failOnError": True,
                },
            },
            "jobs": [
                {
                    "name": "spider",
                    "type": "spider",
                    "parameters": {
                        "url": target,
                        "maxDuration": 10,
                    },
                },
                {
                    "name": "ajax-spider",
                    "type": "ajaxSpider",
                    "parameters": {
                        "url": target,
                        "maxDuration": 10,
                    },
                },
                {
                    "name": "passive-scan-wait",
                    "type": "passiveScan",
                    "parameters": {
                        "maxDuration": 10,
                    },
                },
                {
                    "name": "active-scan",
                    "type": "activeScan",
                    "parameters": {
                        "url": target,
                        "policy": scan_policy,
                        "maxDuration": 30,
                    },
                },
                {
                    "name": "passive-scan-wait-2",
                    "type": "passiveScan",
                    "parameters": {
                        "maxDuration": 10,
                    },
                },
                {
                    "name": "report",
                    "type": "report",
                    "parameters": {
                        "template": "traditional-html",
                        "reportDir": str(output_dir),
                        "reportFile": "full-scan-report",
                        "reportTitle": f"Full Scan Report - {target}",
                    },
                },
            ],
        }

        logger.info(f"Created full scan plan for {target}")
        return plan

    def create_api_scan_plan(
        self,
        target: str,
        api_spec: str,
        output_dir: str,
        api_format: str = "openapi",
        context_name: str = "API Context",
    ) -> Dict[str, Any]:
        """Create an API scan plan using OpenAPI or GraphQL specification.

        Args:
            target: Target API base URL.
            api_spec: Path to the API specification file.
            output_dir: Directory for scan output files.
            api_format: Format of the API spec ('openapi' or 'graphql').
            context_name: Name for the scan context.

        Returns:
            ZAP automation plan as a dictionary.
        """
        try:
            Path(output_dir).mkdir(parents=True, exist_ok=True)
        except OSError:
            logger.warning(f"Could not create output directory: {output_dir}")

        if api_format == "graphql":
            api_job: Dict[str, Any] = {
                "name": "graphql-import",
                "type": "graphql",
                "parameters": {
                    "url": target,
                    "schemaFile": api_spec,
                },
            }
        else:
            api_job = {
                "name": "openapi-import",
                "type": "openapi",
                "parameters": {
                    "url": target,
                    "apiFile": api_spec,
                },
            }

        plan: Dict[str, Any] = {
            "env": {
                "contexts": [
                    {
                        "name": context_name,
                        "urls": [target],
                    }
                ],
                "parameters": {
                    "failOnError": True,
                },
            },
            "jobs": [
                api_job,
                {
                    "name": "active-scan",
                    "type": "activeScan",
                    "parameters": {
                        "url": target,
                        "maxDuration": 30,
                    },
                },
                {
                    "name": "passive-scan-wait",
                    "type": "passiveScan",
                    "parameters": {
                        "maxDuration": 10,
                    },
                },
                {
                    "name": "report",
                    "type": "report",
                    "parameters": {
                        "template": "traditional-html",
                        "reportDir": str(output_dir),
                        "reportFile": "api-scan-report",
                        "reportTitle": f"API Scan Report - {target}",
                    },
                },
            ],
        }

        logger.info(f"Created API scan plan for {target} ({api_format})")
        return plan

    def add_authentication(
        self,
        plan: Dict[str, Any],
        login_url: str,
        username: str,
        password: str,
    ) -> Dict[str, Any]:
        """Add form-based authentication to a scan plan.

        Args:
            plan: Existing scan plan dictionary.
            login_url: URL of the login form.
            username: Login username.
            password: Login password.

        Returns:
            Updated plan with authentication configured.
        """
        if not plan or "env" not in plan:
            logger.error("Invalid plan: missing 'env' key")
            return plan

        contexts = plan["env"].setdefault("contexts", [])
        if not contexts:
            contexts.append({"name": "Default Context", "urls": []})

        context = contexts[0]

        # Configure form-based authentication
        context["authentication"] = {
            "method": "formBased",
            "parameters": {
                "loginPageUrl": login_url,
                "loginRequestUrl": login_url,
                "loginRequestBody": (
                    f"username={username}&password={password}"
                ),
            },
        }

        # Add user
        context["users"] = [
            {
                "name": username,
                "credentials": {
                    "username": username,
                    "password": password,
                },
            }
        ]

        # Set verification strategy
        context["verificationStrategy"] = "poll"
        context["verification"] = {
            "loggedInRegex": "logout|sign.?out",
            "loggedOutRegex": "login|sign.?in",
            "pollFrequency": 60,
            "pollUnits": "requests",
        }

        # Add authentication job to plan
        jobs = plan.setdefault("jobs", [])
        auth_job: Dict[str, Any] = {
            "name": "authentication",
            "type": "authentication",
            "parameters": {
                "context": context["name"],
                "user": username,
            },
        }
        # Insert authentication as first job
        jobs.insert(0, auth_job)

        logger.info(f"Added form-based authentication for user '{username}'")
        return plan

    def merge_plans(
        self,
        plan1: Dict[str, Any],
        plan2: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Merge two scan plans into one.

        Combines jobs from both plans and preserves environment
        configuration from the first plan.

        Args:
            plan1: First scan plan.
            plan2: Second scan plan.

        Returns:
            Merged scan plan.
        """
        merged: Dict[str, Any] = {
            "env": plan1.get("env", {}),
            "jobs": [],
        }

        # Combine jobs, deduplicating by type
        seen_types: List[str] = []
        for plan in [plan1, plan2]:
            for job in plan.get("jobs", []):
                job_type = job.get("type", "")
                if job_type not in seen_types:
                    merged["jobs"].append(job)
                    seen_types.append(job_type)

        # Merge context URLs
        urls1 = set()
        for ctx in merged["env"].get("contexts", []):
            urls1.update(ctx.get("urls", []))

        for ctx in plan2.get("env", {}).get("contexts", []):
            urls1.update(ctx.get("urls", []))

        if merged["env"].get("contexts"):
            merged["env"]["contexts"][0]["urls"] = list(urls1)

        logger.info(
            f"Merged plans: {len(merged['jobs'])} total jobs"
        )
        return merged

    def export_yaml(
        self,
        plan: Dict[str, Any],
        output_file: str,
    ) -> bool:
        """Export a scan plan as a YAML file.

        Args:
            plan: Scan plan dictionary.
            output_file: Path to the output YAML file.

        Returns:
            True if export succeeded, False otherwise.
        """
        if plan is None:
            logger.error("Cannot export None plan")
            return False

        try:
            path = Path(output_file)
            path.parent.mkdir(parents=True, exist_ok=True)

            with open(path, "w") as f:
                yaml.dump(
                    plan,
                    f,
                    default_flow_style=False,
                    sort_keys=False,
                    allow_unicode=True,
                )

            logger.info(f"Exported ZAP automation plan to {output_file}")
            return True

        except (OSError, yaml.YAMLError) as exc:
            logger.error(f"Failed to export YAML: {exc}")
            return False
