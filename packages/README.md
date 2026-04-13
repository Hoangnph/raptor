# RAPTOR Packages

RAPTOR security testing packages -- modular, extensible components for automated security research.

## Project Overview

This directory contains all RAPTOR testing packages, organized by capability. The two major additions in this release are:

1. **Exploit-DB Integration** (`exploit_db/`) -- Complete exploit database management with CSV parsing, indexing, multi-strategy search, CVE correlation, finding enrichment, and exploit validation.

2. **Web Scanning Framework** (`web/`) -- Full-stack web application security testing with reconnaissance, vulnerability scanning, DAST, crawling, LLM-powered fuzzing, and exploit correlation.

These packages integrate seamlessly with RAPTOR's core modules (`core/`) and can be used standalone or as part of the unified scanning pipeline.

## Architecture Summary

```
packages/
  exploit_db/          - Exploit database management and correlation
    database.py          - CSV parsing and indexing
    searcher.py          - Multi-strategy search with ranking
    correlator.py        - CVE/software-to-exploit correlation
    enricher.py          - Finding enrichment with exploit context
    validator.py         - Exploit-to-target validation
    cli.py               - Command-line interface

  web/                 - Web security testing framework
    scanner.py           - Main orchestrator (6-phase pipeline)
    client.py            - Secure HTTP client
    crawler.py           - Web crawler for form/API discovery
    fuzzer.py            - LLM-driven injection fuzzer
    recon/               - Reconnaissance toolkit
      subfinder.py         - Subdomain enumeration
      httpx_tool.py        - HTTP probing and tech detection
      katana.py            - Web crawling and endpoint discovery
      orchestrator.py      - Full recon pipeline
    nuclei/              - Nuclei vulnerability scanner
      runner.py            - Nuclei CLI execution and SARIF parsing
      template_manager.py  - Template filtering and management
    zap/                 - OWASP ZAP DAST integration
      scanner.py           - ZAP Python API integration
      automation.py        - ZAP Automation Framework YAML generation

  ... (other packages: autonomous, codeql, fuzzing, etc.)
```

### Data Flow

```
Target URL
  |
  v
[Recon] --> Subdomains, live hosts, endpoints
  |
  v
[Nuclei] --> Known CVE findings (SARIF)
  |
  v
[ZAP] --> DAST findings (spider + active scan)
  |
  v
[Crawl] --> Discovered forms, APIs, parameters
  |
  v
[Fuzz] --> Injection findings (SQLi, XSS, cmd injection)
  |
  v
[Correlate] --> CVE-to-exploit mappings from Exploit-DB
  |
  v
Unified Report (JSON with normalized findings)
```

## Package List

### New/Updated Packages

| Package | Description |
|---------|-------------|
| `exploit_db/` | Exploit database CSV parsing, indexing, search, and correlation |
| `web/` | Web security testing orchestrator (recon, nuclei, zap, crawl, fuzz) |
| `web/recon/` | Reconnaissance: subfinder, httpx, katana wrappers |
| `web/nuclei/` | Nuclei vulnerability scanner integration with SARIF support |
| `web/zap/` | OWASP ZAP DAST integration (API + Automation Framework) |

### Existing Packages

| Package | Description |
|---------|-------------|
| `autonomous/` | Autonomous security research agents |
| `binary_analysis/` | Binary analysis and reverse engineering utilities |
| `codeql/` | CodeQL static analysis integration |
| `cvss/` | CVSS score calculation and management |
| `diagram/` | Architecture diagram generation |
| `exploit_feasibility/` | Exploit feasibility analysis |
| `exploitability_validation/` | Exploitability validation pipeline |
| `exploitation/` | Exploit generation and proof-of-concept creation |
| `fuzzing/` | AFL++ binary fuzzing integration |
| `llm_analysis/` | LLM-powered vulnerability analysis |
| `recon/` | Legacy reconnaissance (superseded by `web/recon/`) |
| `sca/` | Software composition analysis |
| `static-analysis/` | Static code analysis (Semgrep integration) |

## Quick Start

### Exploit-DB

```python
from packages.exploit_db import ExploitDatabase, ExploitSearcher, ExploitCorrelator

db = ExploitDatabase()
db.load_csv("data/exploits.csv")
db.build_index()

searcher = ExploitSearcher(db)
results = searcher.search(software="apache", type="webapps")

correlator = ExploitCorrelator(db)
correlations = correlator.correlate_by_cve("CVE-2021-41773")
```

See [packages/exploit_db/README.md](exploit_db/README.md) for full documentation.

### Web Scanner

```python
from pathlib import Path
from packages.web.scanner import WebScanner

scanner = WebScanner(
    base_url="https://example.com",
    out_dir=Path("out/"),
)
results = scanner.scan()
```

See [packages/web/README.md](web/README.md) for full documentation.

### Recon Only

```python
from packages.web.recon.orchestrator import ReconOrchestrator

orchestrator = ReconOrchestrator()
results = orchestrator.run(
    target_domain="example.com",
    output_dir="/tmp/recon",
)
```

See [packages/web/recon/README.md](web/recon/README.md) for full documentation.

### Nuclei Only

```python
from packages.web.nuclei.runner import NucleiRunner

runner = NucleiRunner(output_dir="/tmp/nuclei")
result = runner.run(target="https://example.com")
findings = runner.get_findings(result["sarif_file"])
```

See [packages/web/nuclei/README.md](web/nuclei/README.md) for full documentation.

### ZAP Only

```python
from packages.web.zap.scanner import ZapScanner

with ZapScanner(host="localhost", port=8080) as zap:
    urls = zap.spider_scan("https://example.com")
    zap.active_scan("https://example.com")
    alerts = zap.get_alerts()
```

See [packages/web/zap/README.md](web/zap/README.md) for full documentation.

## External Dependencies

### Required for Web Scanning

| Tool | Purpose | Install |
|------|---------|---------|
| **subfinder** | Subdomain enumeration | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| **httpx** | HTTP probing, tech detection | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| **katana** | Web crawling, endpoint discovery | `go install -v github.com/projectdiscovery/katana/cmd/katana@latest` |
| **nuclei** | Template-based vulnerability scanning | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| **OWASP ZAP** | DAST (spider + active scanning) | `docker run -p 8080:8080 ghcr.io/zaproxy/zaproxy:stable zap.sh -daemon -host 0.0.0.0 -port 8080` |
| **python-owasp-zap-v2.4** | ZAP Python API client | `pip install python-owasp-zap-v2.4` |

### Python Dependencies

```bash
pip install requests beautifulsoup4
```

### Optional

| Dependency | Used By | Install |
|------------|---------|---------|
| LLM provider (OpenAI/Anthropic) | WebFuzzer, LLM analysis | Set `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` |

## Testing Guide

### Run All Package Tests

```bash
# Exploit-DB
pytest packages/exploit_db/tests/ -v --cov=packages.exploit_db

# Web Scanner (orchestrator)
pytest packages/web/tests/ -v --cov=packages.web.scanner

# Recon
pytest packages/web/recon/tests/ -v --cov=packages.web.recon

# Nuclei
pytest packages/web/nuclei/tests/ -v --cov=packages.web.nuclei

# ZAP
pytest packages/web/zap/tests/ -v --cov=packages.web.zap
```

### Test Design

- All tests use **mocked external tool calls** -- no real subfinder, httpx, katana, nuclei, or ZAP instances are invoked.
- Fixtures provide realistic sample data (SARIF files, exploit CSVs, tool outputs).
- Backward compatibility tests verify the `WebScanner` interface works without LLM.

### Coverage Targets

| Package | Tests | Coverage |
|---------|-------|----------|
| exploit_db | 106 | 99% |
| web (scanner) | varies | varies |
| web/recon | varies | varies |
| web/nuclei | 72 | 96% |
| web/zap | varies | varies |

## Integration Guide

### Integrating with RAPTOR Core

All packages use RAPTOR core utilities:

```python
from core.logging import get_logger  # Structured logging
from core.json.utils import save_json  # JSON file I/O
from core.sarif.parser import load_sarif, parse_sarif_findings  # SARIF parsing
```

### Integrating Exploit-DB with Custom Tools

```python
from packages.exploit_db import ExploitDatabase, ExploitCorrelator

# Load your exploit CSV
db = ExploitDatabase()
db.load_csv("path/to/your/exploits.csv")
db.build_index()

# Correlate your findings
correlator = ExploitCorrelator(db)
results = correlator.correlate_findings(your_findings)
# your_findings should be a list of dicts with 'cve' or 'software' keys
```

### Integrating Web Scanner into CI/CD

```python
from pathlib import Path
from packages.web.scanner import WebScanner

scanner = WebScanner(
    base_url="https://staging.example.com",
    out_dir=Path("ci_results/"),
    phases=["recon", "nuclei", "zap"],  # Skip fuzzing in CI
    verify_ssl=True,
)
results = scanner.scan()

# Check for critical findings
critical = [f for f in results["findings"] if f["severity"] == "critical"]
if critical:
    print(f"FAIL: {len(critical)} critical findings")
    exit(1)
```

### Using Individual Components

You do not need to run the full pipeline. Each component works standalone:

```python
# Just recon
from packages.web.recon.subfinder import SubfinderWrapper
subfinder = SubfinderWrapper()
result = subfinder.run(domain="example.com")

# Just Nuclei
from packages.web.nuclei.runner import NucleiRunner
runner = NucleiRunner(output_dir="/tmp/nuclei")
runner.run(target="https://example.com")

# Just ZAP
from packages.web.zap.automation import ZapAutomation
auto = ZapAutomation()
plan = auto.create_baseline_plan("https://example.com", Path("out/"))
auto.export_yaml(plan, Path("out/baseline.yaml"))
```
