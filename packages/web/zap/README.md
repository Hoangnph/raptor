# OWASP ZAP Integration

ZAP (Zed Attack Proxy) integration for RAPTOR via the Python API client and Automation Framework.

## Overview

This package provides:
- **ZapScanner**: Active/passive DAST scanning via ZAP Python API (`zapv2`)
- **ZapAutomation**: YAML-based automation plan generation for ZAP Automation Framework

## Installation

```bash
pip install python-owasp-zap-v2.4
```

Or run ZAP via Docker:
```bash
docker run -u zap -p 8080:8080 ghcr.io/zaproxy/zaproxy:stable zap.sh -daemon -host 0.0.0.0 -port 8080
```

## Usage

### ZapScanner — Active DAST Scanning

```python
from packages.web.zap.scanner import ZapScanner

# Connect to running ZAP instance
with ZapScanner(host='localhost', port=8080) as zap:
    # Spider scan (discovery)
    urls = zap.spider_scan('https://example.com', max_duration=120)
    print(f'Discovered {len(urls)} URLs')

    # Active Scan (attack)
    zap.active_scan('https://example.com', max_duration=300)

    # Retrieve findings
    alerts = zap.get_alerts()
    for alert in alerts:
        print(f'[{alert["risk"]}] {alert["alert"]} at {alert["url"]}')

    # Risk summary
    risks = zap.get_risk_counts()
    print(f'High: {risks["High"]}, Medium: {risks["Medium"]}, Low: {risks["Low"]}')
```

### ZapAutomation — YAML Plan Generation

```python
from packages.web.zap.automation import ZapAutomation
from pathlib import Path

auto = ZapAutomation()

# Baseline scan plan
plan = auto.create_baseline_plan('https://example.com', Path('out/'))
auto.export_yaml(plan, Path('out/baseline-plan.yaml'))

# Full scan plan with active scanning
plan = auto.create_full_scan_plan('https://example.com', Path('out/'))
auto.export_yaml(plan, Path('out/full-plan.yaml'))

# API scan plan (for REST APIs)
plan = auto.create_api_scan_plan('https://api.example.com', Path('out/api-spec.json'), Path('out/'))

# Add form-based authentication
auto.add_authentication(plan, 'https://example.com/login', 'admin', 'password')
auto.export_yaml(plan, Path('out/auth-plan.yaml'))
```

## API Reference

### ZapScanner

| Method | Description |
|--------|-------------|
| `__init__(api_key='', host='localhost', port=8080)` | Connect to ZAP instance |
| `is_available()` | Check if ZAP is running |
| `spider_scan(url, max_duration=300)` | Passive discovery of URLs |
| `active_scan(url, max_duration=600)` | Active vulnerability scanning |
| `passive_scan()` | Retrieve passive scan results |
| `get_alerts()` | Get all alerts as list of dicts |
| `get_risk_counts()` | Count alerts by risk level |
| `shutdown()` | Stop ZAP instance |

### ZapAutomation

| Method | Description |
|--------|-------------|
| `create_baseline_plan(target, output_dir)` | Generate passive scan plan |
| `create_full_scan_plan(target, output_dir)` | Generate full scan plan with active scanning |
| `create_api_scan_plan(target, api_spec, output_dir)` | Generate API-specific scan plan |
| `add_authentication(plan, login_url, username, password)` | Add form-based auth to plan |
| `export_yaml(plan, output_file)` | Export plan as YAML |
| `merge_plans(plans)` | Merge multiple plans, deduplicating jobs |

## Error Handling

- If `zapv2` is not installed, `ZapScanner.__init__()` raises `ImportError` with installation instructions
- Connection failures raise `ConnectionError`
- Timeout during scanning raises `TimeoutError`
- All methods log warnings/errors via `core.logging.get_logger`

## Output Format

Alerts are returned as:
```python
{
    "alert": "SQL Injection",
    "risk": "High",
    "confidence": "Medium",
    "url": "https://example.com/login",
    "parameter": "username",
    "evidence": "' OR 1=1 --",
    "cwe_id": "89",
    "wasc_id": "19",
    "description": "SQL injection may be possible",
    "solution": "Use parameterized queries"
}
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `ImportError: No module named 'zapv2'` | Run `pip install python-owasp-zap-v2.4` |
| Connection refused | Ensure ZAP is running: `docker run -p 8080:8080 ghcr.io/zaproxy/zaproxy:stable` |
| Scan timeout | Increase `max_duration` parameter |
| No alerts found | Check that target URL is accessible and spider found pages |

## Testing

```bash
# Run all ZAP tests
python3 -m pytest packages/web/zap/tests/ -v

# Run with coverage
python3 -m pytest packages/web/zap/tests/ --cov=packages.web.zap --cov-report=term-missing

# Run specific test modules
python3 -m pytest packages/web/zap/tests/test_scanner.py -v
python3 -m pytest packages/web/zap/tests/test_automation.py -v
```

All tests use mocked ZAP API calls -- no real ZAP instance required during testing.
