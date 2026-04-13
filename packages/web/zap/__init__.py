"""
RAPTOR OWASP ZAP Integration Package

Provides integration with OWASP ZAP for dynamic application security testing:
- ZapScanner: ZAP Python API integration for spider, active, and passive scanning
- ZapAutomation: ZAP Automation Framework YAML plan generation
"""

try:
    from .automation import ZapAutomation
    from .scanner import ZapScanner

    __all__ = [
        "ZapScanner",
        "ZapAutomation",
    ]
except ImportError:
    # zapv2 not installed
    __all__ = []
