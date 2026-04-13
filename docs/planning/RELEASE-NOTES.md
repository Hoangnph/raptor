# RAPTOR Release Notes -- Version 2.0

**Release Date:** 2026-04-13
**Repository:** https://github.com/gadievron/raptor

---

## Summary

RAPTOR v2.0 introduces a comprehensive web security testing framework and exploit database integration. This release adds five new packages with 585 tests at 97% coverage, providing automated reconnaissance, vulnerability scanning, DAST, LLM-powered fuzzing, and exploit correlation -- all unified into a single scanning pipeline.

## New Features

### Exploit-DB Integration (`packages/exploit_db/`)

A complete exploit database management system:

- **ExploitDatabase** -- Load, parse, index, and persist exploit data from CSV files. Supports fast lookups by CVE, software name, exploit type, and platform.
- **ExploitSearcher** -- Multi-strategy search engine with ranked results and fuzzy keyword matching. Combines exact-match, partial-match, and keyword-based search strategies.
- **ExploitCorrelator** -- Correlates vulnerability findings (by CVE or software name) with available exploits. Computes exploitability scores for risk prioritization.
- **FindingEnricher** -- Adds exploit context to security findings, including exploit counts, reference links, and historical exploit data.
- **ExploitValidator** -- Validates whether a specific exploit is applicable to a target based on platform and port matching.
- **CLI** -- Full command-line interface for all operations with argparse, supporting search, info lookup, and index management.

### Web Scanning Framework (`packages/web/`)

A multi-phase web security testing pipeline:

- **WebScanner** -- Orchestrates 6 scanning phases: Recon, Nuclei, ZAP, Crawl, Fuzz, Correlate. Configurable phases allow selective execution. Phase failures are isolated and do not abort the scan.
- **WebClient** -- Secure HTTP client with session management, rate limiting, and authentication support.
- **WebCrawler** -- Discovers pages, forms, APIs, and parameters on target web applications.
- **WebFuzzer** -- LLM-driven fuzzer that generates context-aware injection payloads for SQLi, XSS, command injection, and more.

### Reconnaissance Toolkit (`packages/web/recon/`)

Wraps three ProjectDiscovery tools into a unified recon pipeline:

- **SubfinderWrapper** -- Subdomain enumeration via `subfinder`
- **HttpxWrapper** -- HTTP probing and technology detection via `httpx`
- **KatanaWrapper** -- Web crawling and endpoint discovery via `katana`
- **ReconOrchestrator** -- Full pipeline chaining all three tools with aggregated results

### Nuclei Integration (`packages/web/nuclei/`)

Template-based vulnerability scanning:

- **NucleiRunner** -- Executes Nuclei scans with severity, tag, and technology filtering. Parses SARIF output into normalized findings.
- **TemplateManager** -- Manages and filters Nuclei templates by severity, tags, and technology. Supports loading custom templates from JSON.

### ZAP Integration (`packages/web/zap/`)

OWASP ZAP DAST scanning:

- **ZapScanner** -- Full ZAP Python API integration: spider scanning, active scanning, passive analysis, alert retrieval, risk counts.
- **ZapAutomation** -- YAML-based automation plan generation for ZAP Automation Framework. Supports baseline, full, and API scans with form-based authentication.

### Unified Output Format

All findings are normalized into a unified format:

```json
{
    "id": "unique-id",
    "type": "recon|nuclei|zap|crawl|fuzz",
    "severity": "critical|high|medium|low|info",
    "title": "Description",
    "url": "https://target/path",
    "parameter": "param_name",
    "evidence": "raw evidence",
    "cve": "CVE-XXXX-XXXX",
    "cwe": "CWE-XXX",
    "confidence": "high|medium|low",
    "source": "nuclei|zap|fuzzer|etc",
    "remediation": "fix suggestion"
}
```

### Backward Compatibility

The `WebScanner` class maintains full backward compatibility with the original interface. Existing scripts using `WebScanner` continue to work without modification.

## Breaking Changes

**None.** This release is fully backward compatible.

- The `WebScanner` API is unchanged.
- All existing RAPTOR commands (`/scan`, `/fuzz`, `/agentic`, etc.) work as before.
- New packages are additive -- they do not modify existing behavior.

## Performance Improvements

- **Indexed Exploit Lookups** -- ExploitDatabase builds in-memory indexes for O(1) lookups by CVE, software, type, and platform.
- **Isolated Phase Execution** -- Each scanning phase runs in a try/except block, so a single failure does not block remaining phases.
- **Graceful Degradation** -- Missing external tools cause phases to be skipped with a warning, not a crash.
- **SARIF Parsing** -- Nuclei results are parsed from SARIF format using the shared `core.sarif.parser`, avoiding duplicate parsing logic.
- **Optional LLM** -- The fuzzing phase only initializes when an LLM provider is available, avoiding unnecessary overhead.

## Test Results

| Package | Tests | Coverage |
|---------|-------|----------|
| `packages/exploit_db/` | 106 | 99% |
| `packages/web/nuclei/` | 72 | 96% |
| `packages/web/recon/` | -- | 90%+ |
| `packages/web/zap/` | -- | 88%+ |
| `packages/web/` (scanner) | -- | 92% |
| **Total** | **585** | **97%** |

All 585 tests pass. No failures.

## External Tool Dependencies

The following external tools are used by the new packages:

| Tool | Used By | Install Command |
|------|---------|----------------|
| **subfinder** | recon | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| **httpx** | recon | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| **katana** | recon | `go install -v github.com/projectdiscovery/katana/cmd/katana@latest` |
| **nuclei** | nuclei | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| **OWASP ZAP** | zap | `docker run -p 8080:8080 ghcr.io/zaproxy/zaproxy:stable zap.sh -daemon -host 0.0.0.0 -port 8080` |
| **python-owasp-zap-v2.4** | zap | `pip install python-owasp-zap-v2.4` |

All tools are optional. The scanner gracefully skips phases whose tools are not available.

## Known Limitations

- **Recon tools require Go** -- subfinder, httpx, katana, and nuclei are Go binaries. Pre-built binaries are available for systems without Go.
- **ZAP requires Docker or local install** -- ZAP must be running as a daemon process accessible on localhost.
- **LLM required for fuzzing** -- The fuzzing phase requires an LLM provider (OpenAI or Anthropic). Without it, fuzzing is skipped.
- **Exploit-DB CSV format** -- The exploit database expects a specific CSV format with columns: id, cve, type, platform, title, software, date_published, author, port.
- **Nuclei templates** -- TemplateManager requires manually provided template metadata. It does not auto-discover templates from the Nuclei template directory.
- **No parallel phase execution** -- Phases run sequentially. Future versions may parallelize independent phases.

## Migration Guide

### Upgrading from v1.x

1. **No configuration changes required.** Existing RAPTOR configuration (models.json, API keys) works as-is.
2. **No API changes.** The `WebScanner` class maintains its original interface.
3. **Install optional external tools** to enable full scanning capabilities (see External Tool Dependencies above).
4. **Review the UPGRADE-GUIDE** at `docs/UPGRADE-GUIDE.md` for a step-by-step walkthrough of new capabilities.

### Using New Packages

```python
# New: Exploit-DB standalone
from packages.exploit_db import ExploitDatabase
db = ExploitDatabase()
db.load_csv("exploits.csv")

# New: Recon standalone
from packages.web.recon.orchestrator import ReconOrchestrator
orchestrator = ReconOrchestrator()
results = orchestrator.run(target_domain="example.com", output_dir="/tmp/recon")

# Enhanced: WebScanner with all phases
from packages.web.scanner import WebScanner
scanner = WebScanner(base_url="https://example.com")
results = scanner.scan()  # Now includes recon, nuclei, zap, crawl, fuzz, correlate
```

## Documentation

New and updated documentation:

- `packages/README.md` -- Master documentation for all packages
- `packages/exploit_db/README.md` -- Exploit-DB integration guide
- `packages/web/README.md` -- Web security testing package documentation
- `packages/web/recon/README.md` -- Reconnaissance toolkit documentation
- `packages/web/nuclei/README.md` -- Nuclei integration documentation
- `packages/web/zap/README.md` -- ZAP integration documentation
- `docs/UPGRADE-GUIDE.md` -- Step-by-step upgrade guide from v1.x
