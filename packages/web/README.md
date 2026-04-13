# RAPTOR Web Security Testing Package

Web application security testing tools for the RAPTOR framework.

## Overview

This package provides comprehensive web application security testing capabilities, organized as a multi-phase scanning pipeline:

1. **Recon** -- Subdomain discovery, HTTP probing, endpoint enumeration
2. **Nuclei** -- Known vulnerability scanning with template-based detection
3. **ZAP** -- Dynamic DAST scanning (spider + active scan)
4. **Crawl** -- Web crawling, form/API discovery, parameter identification
5. **Fuzz** -- LLM-powered injection testing on discovered parameters
6. **Correlate** -- Cross-reference findings with Exploit-DB for known exploits

The package is fully backward compatible with the original `WebScanner` interface while supporting configurable phase execution.

## Installation / Prerequisites

### Python Dependencies

```bash
pip install requests beautifulsoup4
```

### Optional External Tools

| Tool | Phase | Install Command |
|------|-------|----------------|
| subfinder | recon | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| httpx | recon | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| katana | recon | `go install -v github.com/projectdiscovery/katana/cmd/katana@latest` |
| nuclei | nuclei | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| OWASP ZAP | zap | `docker run -p 8080:8080 ghcr.io/zaproxy/zaproxy:stable zap.sh -daemon` |
| ZAP Python API | zap | `pip install python-owasp-zap-v2.4` |

The scanner gracefully skips phases whose tools are not available.

## Quick Start

### WebScanner Orchestrator

```python
from pathlib import Path
from packages.web.scanner import WebScanner

# Full scan with all phases
scanner = WebScanner(
    base_url="https://example.com",
    llm=llm_provider,       # Optional: LLM for intelligent fuzzing
    out_dir=Path("out/"),
    verify_ssl=True,
)
results = scanner.scan()

# Selective phases
scanner = WebScanner(
    base_url="https://example.com",
    out_dir=Path("out/"),
    phases=["recon", "nuclei", "crawl"],  # Skip ZAP, fuzz, correlate
)
results = scanner.scan()

# Without LLM (fuzzing disabled)
scanner = WebScanner(
    base_url="https://example.com",
    llm=None,
    out_dir=Path("out/"),
)
```

### CLI

```bash
# Full scan
python3 -m packages.web.scanner --url https://example.com

# Specific phases
python3 -m packages.web.scanner --url https://example.com --phases recon,crawl,fuzz

# Skip SSL verification
python3 -m packages.web.scanner --url https://example.com --insecure

# Custom output directory
python3 -m packages.web.scanner --url https://example.com --out ./results
```

## API Reference

### Core Modules

| Class | Module | Description |
|-------|--------|-------------|
| `WebScanner` | `scanner.py` | Main orchestrator coordinating all scan phases |
| `WebClient` | `client.py` | Secure HTTP client with session management, rate limiting, auth |
| `WebCrawler` | `crawler.py` | Web crawler for form/API discovery and parameter identification |
| `WebFuzzer` | `fuzzer.py` | LLM-driven fuzzer generating context-aware injection payloads |

### WebScanner Methods

| Method | Description |
|--------|-------------|
| `__init__(base_url, llm, out_dir, verify_ssl, phases)` | Initialize scanner |
| `scan() -> dict` | Run all configured phases, return unified results |
| `run_recon(domain) -> dict` | Run reconnaissance phase |
| `run_nuclei(targets) -> dict` | Run Nuclei vulnerability scan |
| `run_zap(url) -> dict` | Run ZAP DAST scan |
| `run_crawl() -> dict` | Run web crawler |
| `run_fuzz() -> dict` | Run LLM-powered fuzzer (requires LLM) |
| `run_correlate() -> dict` | Correlate findings with Exploit-DB |

### Sub-packages

| Package | Description | README |
|---------|-------------|--------|
| `recon/` | Subdomain discovery, HTTP probing, endpoint crawling | [recon/README.md](recon/README.md) |
| `nuclei/` | Nuclei vulnerability scanner with SARIF parsing | [nuclei/README.md](nuclei/README.md) |
| `zap/` | OWASP ZAP DAST integration | [zap/README.md](zap/README.md) |

## Scan Phases

| Phase | Description | Requirements |
|-------|-------------|--------------|
| `recon` | Subdomain discovery, HTTP probing, endpoint enumeration | subfinder, httpx, katana |
| `nuclei` | Known vulnerability scanning with template-based detection | nuclei binary |
| `zap` | Dynamic DAST scanning (spider + active scan) | OWASP ZAP running |
| `crawl` | Web crawling, form/API discovery, parameter identification | None (built-in) |
| `fuzz` | LLM-powered injection testing on discovered parameters | LLM provider |
| `correlate` | Cross-reference findings with Exploit-DB for known exploits | Exploit-DB |

## Error Handling and Troubleshooting

| Issue | Solution |
|-------|----------|
| Phase skipped with warning | Required tool not installed. Check prerequisites above. |
| SSL verification error | Use `verify_ssl=False` or `--insecure` CLI flag. |
| Fuzzing phase does nothing | LLM provider is required. Pass `llm=` to WebScanner. |
| Empty findings | Target may have no discoverable vulnerabilities. Try running individual phases. |
| Output directory not writable | Ensure `out_dir` exists and is writable. Default is `out/`. |

All phases are wrapped in try/except -- a single phase failure does not abort the entire scan. Errors are logged via `core.logging.get_logger` and included in `phase_results`.

## Output Format

Results are saved to `out_dir/scan_report.json`:

```json
{
    "target": "https://example.com",
    "scan_id": "uuid",
    "timestamp": "2026-04-13T10:00:00Z",
    "phases_run": ["recon", "nuclei", "zap", "crawl"],
    "findings": [
        {
            "id": "unique-id",
            "type": "nuclei",
            "severity": "critical",
            "title": "Apache Log4j2 RCE",
            "url": "https://example.com/path",
            "parameter": "input",
            "evidence": "vulnerable to log4shell",
            "cve": "CVE-2021-44228",
            "cwe": "CWE-502",
            "confidence": "high",
            "source": "nuclei",
            "remediation": "Upgrade Log4j to 2.17.0+"
        }
    ],
    "phase_results": { ... },
    "exploit_correlations": [ ... ],
    "summary": {
        "total_findings": 15,
        "by_severity": {"critical": 1, "high": 3, "medium": 5, "low": 4, "info": 2},
        "by_type": {"nuclei": 5, "zap": 7, "fuzz": 3}
    }
}
```

## Testing

```bash
# Run all web scanner tests
python3 -m pytest packages/web/tests/test_scanner.py -v

# Run with coverage
python3 -m pytest packages/web/tests/test_scanner.py --cov=packages.web.scanner --cov-report=term-missing

# Run backward-compatibility tests (no LLM mode)
python3 -m pytest packages/web/tests/test_scanner_none_llm.py -v

# Run sub-package tests
python3 -m pytest packages/web/recon/tests/ -v
python3 -m pytest packages/web/nuclei/tests/ -v
python3 -m pytest packages/web/zap/tests/ -v
```

All tests use mocked external tools -- no real tool calls are made during testing.
