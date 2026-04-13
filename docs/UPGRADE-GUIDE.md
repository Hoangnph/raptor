# RAPTOR v2.0 Upgrade Guide

Step-by-step guide for upgrading from the original RAPTOR web scanning (STUB/alpha) to the new v2.0 web security testing framework.

---

## Step 1: Install Dependencies

### Python Packages

```bash
pip install requests beautifulsoup4
```

### External Tools (Optional but Recommended)

The new scanner uses external tools for maximum coverage. Install the ones you need:

```bash
# Reconnaissance tools (Go required)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# Vulnerability scanner
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates  # Download template database

# DAST (OWASP ZAP)
docker run -d -p 8080:8080 \
  ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -daemon -host 0.0.0.0 -port 8080

# ZAP Python API client
pip install python-owasp-zap-v2.4
```

**Note:** All tools are optional. The scanner gracefully skips phases whose tools are not available and logs a warning.

---

## Step 2: Configuration Changes

**No configuration changes are required.** The new packages use existing RAPTOR configuration:

- LLM providers (if using fuzzing): `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or `~/.config/raptor/models.json`
- Logging: Uses existing `core.logging` infrastructure
- Output: Defaults to `out/` directory (configurable)

### Optional: Exploit-DB CSV

If you want exploit correlation, prepare a CSV file with exploit data:

```csv
id,cve,type,platform,title,software,date_published,author,port
1,CVE-2021-41773,webapps,linux,"Apache HTTP Server 2.4.49 - Path Traversal",apache,2021-10-05,unknown,80
```

Place it at a known path (e.g., `data/exploits.csv`) and reference it when initializing the exploit database.

---

## Step 3: Running the New Scanner

### Full Scan (All Phases)

```python
from pathlib import Path
from packages.web.scanner import WebScanner

scanner = WebScanner(
    base_url="https://example.com",
    out_dir=Path("out/"),
    verify_ssl=True,
)
results = scanner.scan()

print(f"Found {len(results['findings'])} vulnerabilities")
for finding in results["findings"]:
    print(f"  [{finding['severity'].upper()}] {finding['title']}")
```

### Selective Phases

Skip phases you do not need. For example, recon + nuclei only:

```python
scanner = WebScanner(
    base_url="https://example.com",
    phases=["recon", "nuclei"],
    out_dir=Path("out/"),
)
results = scanner.scan()
```

### Without LLM (No Fuzzing)

```python
scanner = WebScanner(
    base_url="https://example.com",
    llm=None,  # Disables fuzzing phase
    out_dir=Path("out/"),
)
results = scanner.scan()
```

### CLI

```bash
# Full scan
python3 -m packages.web.scanner --url https://example.com

# Specific phases
python3 -m packages.web.scanner --url https://example.com --phases recon,nuclei,zap

# Skip SSL verification
python3 -m packages.web.scanner --url https://example.com --insecure

# Custom output
python3 -m packages.web.scanner --url https://example.com --out ./results
```

---

## Step 4: Understanding the New Output Format

### Old Format (STUB)

The original `/web` command was a stub with no structured output.

### New Format: Unified Findings

All results are normalized into a consistent format:

```json
{
    "target": "https://example.com",
    "scan_id": "a1b2c3d4-...",
    "timestamp": "2026-04-13T10:00:00Z",
    "phases_run": ["recon", "nuclei", "zap", "crawl"],
    "findings": [
        {
            "id": "nuclei-cve-2021-44228-001",
            "type": "nuclei",
            "severity": "critical",
            "title": "Apache Log4j2 Remote Code Execution",
            "url": "https://example.com/api",
            "parameter": "input",
            "evidence": "vulnerable to log4shell",
            "cve": "CVE-2021-44228",
            "cwe": "CWE-502",
            "confidence": "high",
            "source": "nuclei",
            "remediation": "Upgrade Log4j to 2.17.0+"
        }
    ],
    "phase_results": {
        "recon": { "subdomains": [...], "live_hosts": [...], "endpoints": [...] },
        "nuclei": { "findings": [...], "sarif_file": "..." },
        "zap": { "alerts": [...], "risk_counts": {...} }
    },
    "exploit_correlations": [
        {
            "cve": "CVE-2021-44228",
            "exploit_count": 3,
            "exploits": [...]
        }
    ],
    "summary": {
        "total_findings": 15,
        "by_severity": { "critical": 1, "high": 3, "medium": 5, "low": 4, "info": 2 },
        "by_type": { "nuclei": 5, "zap": 7, "fuzz": 3 }
    }
}
```

### Key Differences from Old STUB

| Aspect | Old (STUB) | New (v2.0) |
|--------|-----------|------------|
| Output | None/placeholder | Structured JSON report |
| Phases | Single monolithic | 6 configurable phases |
| Findings | N/A | Unified format with severity, CVE, CWE |
| Exploit correlation | N/A | Automatic via Exploit-DB |
| External tools | None | subfinder, httpx, katana, nuclei, ZAP |
| LLM integration | None | Fuzzing phase uses LLM for payload generation |

---

## Step 5: Using Individual Components

You do not need to run the full pipeline. Each component works standalone.

### Exploit-DB

```python
from packages.exploit_db import ExploitDatabase, ExploitSearcher, ExploitCorrelator

# Load and search
db = ExploitDatabase()
db.load_csv("data/exploits.csv")
db.build_index()

searcher = ExploitSearcher(db)
results = searcher.search(software="apache", type="webapps")

# Correlate findings
correlator = ExploitCorrelator(db)
correlations = correlator.correlate_by_cve("CVE-2021-41773")
```

CLI:
```bash
python -m packages.exploit_db.cli --csv exploits.csv search --cve CVE-2021-41773
python -m packages.exploit_db.cli --csv exploits.csv search --software apache --type webapps
```

### Recon Only

```python
from packages.web.recon.orchestrator import ReconOrchestrator

orchestrator = ReconOrchestrator()
results = orchestrator.run(
    target_domain="example.com",
    output_dir="/tmp/recon",
)
print(f"Found {len(results['subdomains'])} subdomains")
print(f"Found {len(results['live_hosts'])} live hosts")
```

### Nuclei Only

```python
from packages.web.nuclei.runner import NucleiRunner

runner = NucleiRunner(output_dir="/tmp/nuclei")
if runner.is_available():
    result = runner.run(target="https://example.com", severity="high")
    findings = runner.get_findings(result["sarif_file"])
    print(f"Found {len(findings)} high-severity vulnerabilities")
```

### ZAP Only

```python
from packages.web.zap.scanner import ZapScanner

with ZapScanner(host="localhost", port=8080) as zap:
    urls = zap.spider_scan("https://example.com", max_duration=120)
    print(f"Discovered {len(urls)} URLs")

    zap.active_scan("https://example.com", max_duration=300)
    alerts = zap.get_alerts()
    for alert in alerts:
        print(f"[{alert['risk']}] {alert['alert']}")
```

### ZAP Automation Plans

```python
from packages.web.zap.automation import ZapAutomation
from pathlib import Path

auto = ZapAutomation()
plan = auto.create_full_scan_plan("https://example.com", Path("out/"))
auto.export_yaml(plan, Path("out/full-scan-plan.yaml"))
```

---

## Step 6: CLI Reference

### Web Scanner CLI

```
python3 -m packages.web.scanner [OPTIONS]

Required:
  --url URL           Target URL to scan

Optional:
  --phases PHASES     Comma-separated phases: recon,nuclei,zap,crawl,fuzz,correlate
  --out DIR           Output directory (default: out/)
  --insecure          Skip SSL verification
  --help              Show help message
```

### Exploit-DB CLI

```
python -m packages.exploit_db.cli --csv FILE [COMMAND] [OPTIONS]

Commands:
  search              Search for exploits
    --cve CVE         Search by CVE ID
    --software NAME   Search by software name
    --type TYPE       Search by exploit type
    --keywords TEXT   Keyword search (fuzzy matching)
  info ID             Get exploit details by ID
  index               Index management
    build             Build index from CSV
    save              Save index to file
    load              Load index from file

Options:
  --csv FILE          Path to exploit CSV file (required)
  --index FILE        Path to index JSON file (optional)
  --help              Show help message
```

### Exit Codes

| Code | Meaning |
|------|--------|
| 0 | Success |
| 1 | Error (check stderr) |
| 130 | Interrupted (Ctrl+C) |

---

## Comparison: Old vs New Architecture

### Old (v1.x) -- STUB

```
/web command -> Placeholder, no real scanning
```

### New (v2.0) -- Full Pipeline

```
WebScanner.scan()
  |
  +-> Recon (subfinder -> httpx -> katana)
  |     Output: subdomains, live hosts, endpoints, technology
  |
  +-> Nuclei (template-based vulnerability scanning)
  |     Output: SARIF findings with CVE/CWE
  |
  +-> ZAP (DAST: spider + active scan)
  |     Output: alert findings with risk levels
  |
  +-> Crawl (form/API/parameter discovery)
  |     Output: discovered forms, APIs, parameters
  |
  +-> Fuzz (LLM-powered injection testing)
  |     Output: injection findings (SQLi, XSS, etc.)
  |
  +-> Correlate (Exploit-DB matching)
        Output: CVE-to-exploit mappings, exploitability scores
```

---

## Quick Reference Card

| Task | Command / Code |
|------|---------------|
| Full scan | `scanner = WebScanner(base_url="https://..."); scanner.scan()` |
| Recon only | `ReconOrchestrator().run("example.com", "/tmp/recon")` |
| Nuclei only | `NucleiRunner(output_dir="/tmp/n").run(target="https://...")` |
| ZAP only | `ZapScanner().spider_scan("https://...")` |
| Exploit search | `ExploitSearcher(db).search(software="apache")` |
| CLI full scan | `python3 -m packages.web.scanner --url https://...` |
| CLI exploit search | `python -m packages.exploit_db.cli --csv f.csv search --cve CVE-...` |
| Run tests | `pytest packages/exploit_db/tests/ packages/web/ -v` |
