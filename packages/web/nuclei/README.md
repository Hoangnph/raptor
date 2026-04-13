# Nuclei Integration Package

Nuclei template management and vulnerability scanning integration for the RAPTOR web security testing framework.

## Overview

This package provides two main components:

- **NucleiRunner** -- Executes the Nuclei vulnerability scanner CLI, handles SARIF output, and parses results
- **TemplateManager** -- Manages Nuclei templates with filtering by severity, tags, and technology

Nuclei is a fast, template-based vulnerability scanner that sends requests across targets based on templates, enabling zero false positives and providing fast results.

## Installation / Prerequisites

### Nuclei Binary

Install Nuclei from ProjectDiscovery:

```bash
# Install via Go (recommended)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Or download pre-built binaries:
# https://github.com/projectdiscovery/nuclei/releases

# Update templates after install
nuclei -update-templates
```

Verify installation:
```bash
nuclei -version
```

### Python

No additional pip packages required. The package uses RAPTOR core modules:
- `core.sarif.parser` -- SARIF parsing
- `core.json.utils` -- JSON file utilities

## Quick Start

### NucleiRunner

```python
from packages.web.nuclei.runner import NucleiRunner

# Initialize
runner = NucleiRunner(
    nuclei_path="nuclei",
    output_dir="/tmp/nuclei_output",
    timeout=300,
)

# Check availability
if runner.is_available():
    # Run scan
    result = runner.run(
        target="https://example.com",
        severity="critical",
        tags=["cve", "rce"],
        technology="java",
        sarif_output=True,
    )

    # Parse results
    findings = runner.get_findings("/tmp/nuclei_output/results.sarif")
    critical_findings = runner.get_findings(
        "/tmp/nuclei_output/results.sarif",
        severity="critical",
    )
    print(f"Found {len(critical_findings)} critical vulnerabilities")
```

### TemplateManager

```python
from packages.web.nuclei.template_manager import TemplateManager

# Initialize with templates
manager = TemplateManager(templates=[
    {"id": "cve-2021-44228", "severity": "critical", "tags": ["cve", "rce"]},
    {"id": "xss-reflected", "severity": "medium", "tags": ["xss"]},
])

# Or load from file
manager = TemplateManager()
manager.load_custom_templates("/path/to/templates.json")

# Filter by severity
critical = manager.filter_by_severity("critical")
high_and_above = manager.filter_by_severity("high", min_severity=True)

# Filter by tag
cve_templates = manager.filter_by_tag("cve")

# Filter by technology
java_templates = manager.filter_by_technology("java")

# Get template list
ids = manager.get_template_list()
details = manager.get_template_list(details=True)
```

## API Reference

### NucleiRunner

| Method | Description |
|--------|-------------|
| `__init__(nuclei_path, output_dir, timeout=300)` | Initialize runner with Nuclei binary path |
| `is_available() -> bool` | Check if Nuclei is installed |
| `run(target, severity, tags, technology, sarif_output) -> dict` | Execute Nuclei scan |
| `get_findings(sarif_file, severity=None) -> list` | Parse and return findings from SARIF |
| `parse_results(sarif_path) -> dict` | Parse SARIF file into structured findings |

### TemplateManager

| Method | Description |
|--------|-------------|
| `__init__(templates=None)` | Initialize with optional template list |
| `load_custom_templates(path) -> list` | Load templates from JSON file |
| `filter_by_severity(severity, min_severity=False) -> list` | Filter templates by severity level |
| `filter_by_tag(tag) -> list` | Filter templates by tag |
| `filter_by_technology(tech) -> list` | Filter templates by technology |
| `get_template_list(details=False) -> list` | Get all template IDs or details |

## Error Handling and Troubleshooting

| Issue | Solution |
|-------|----------|
| `is_available()` returns `False` | Nuclei is not installed. Run `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`. |
| Scan timeout | Increase `timeout` parameter. Large targets may need 600s+. |
| SARIF file not found | Ensure `output_dir` exists and is writable. Check Nuclei stderr in result dict. |
| No findings returned | Target may have no known vulnerabilities for the selected templates. Try running without severity/tag filters. |
| Template load fails | Verify JSON format matches expected structure: `{"id", "severity", "tags", "technology"}`. |
| Nuclei process error | Check `result["stderr"]` in the run output for specific error messages. |

All methods log via `core.logging.get_logger`. Check RAPTOR logs for detailed diagnostics.

## Output Format

### Scan Result (raw)

```python
{
    "success": True,
    "stdout": "... nuclei output ...",
    "stderr": "... errors ...",
    "returncode": 0,
    "sarif_file": "/tmp/nuclei_output/results.sarif",
}
```

### Parsed Findings

```json
[
  {
    "id": "cve-2021-44228",
    "severity": "critical",
    "name": "Apache Log4j2 RCE",
    "url": "https://example.com/path",
    "matched_at": "https://example.com/path?input=${jndi:ldap://...}",
    "extracted_results": "vulnerable to log4shell",
    "cwe_id": "CWE-502",
    "cve_id": "CVE-2021-44228",
    "tags": ["cve", "rce", "java"],
    "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
  }
]
```

## Testing

```bash
# Run all nuclei tests
python3 -m pytest packages/web/nuclei/tests/ -v

# Run with coverage
python3 -m pytest packages/web/nuclei/tests/ --cov=packages.web.nuclei --cov-report=term-missing

# Run specific test files
python3 -m pytest packages/web/nuclei/tests/test_runner.py -v
python3 -m pytest packages/web/nuclei/tests/test_template_manager.py -v
```

72 tests total (31 runner + 41 template_manager), 96% coverage.

All tests use mocked external tool calls -- no real Nuclei invocations during testing.
