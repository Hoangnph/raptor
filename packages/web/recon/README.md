# RAPTOR Recon Tools

Web reconnaissance toolkit wrapping CLI security tools: subfinder, httpx, and katana.

## Overview

This package provides automated web reconnaissance capabilities for the RAPTOR framework. It wraps three ProjectDiscovery tools into a cohesive pipeline:

- **SubfinderWrapper** -- Subdomain enumeration via `subfinder`
- **HttpxWrapper** -- HTTP probing and technology detection via `httpx`
- **KatanaWrapper** -- Web crawling and endpoint discovery via `katana`
- **ReconOrchestrator** -- Full pipeline chaining all three tools

The recon phase is the first step in the RAPTOR web scanning pipeline, discovering the attack surface before vulnerability scanning begins.

## Installation / Prerequisites

### External Tools

All tools are from [ProjectDiscovery](https://projectdiscovery.io/). Install via Go or download pre-built binaries:

```bash
# Install via Go (recommended)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# Or download from GitHub releases:
# https://github.com/projectdiscovery/subfinder/releases
# https://github.com/projectdiscovery/httpx/releases
# https://github.com/projectdiscovery/katana/releases
```

Verify installation:
```bash
subfinder -version
httpx -version
katana -version
```

### Python

No additional pip packages required. The package is included in RAPTOR.

## Quick Start

### Individual Tools

```python
from packages.web.recon.subfinder import SubfinderWrapper
from packages.web.recon.httpx_tool import HttpxWrapper
from packages.web.recon.katana import KatanaWrapper

# Check tool availability
subfinder = SubfinderWrapper()
if subfinder.is_available():
    result = subfinder.run(domain="example.com")
    print(result["subdomains"])

httpx = HttpxWrapper()
if httpx.is_available():
    result = httpx.run(targets=["https://sub1.example.com"])
    tech = httpx.parse_technology(result["stdout"])
    print(tech)

katana = KatanaWrapper()
if katana.is_available():
    result = katana.run(url="https://example.com")
    print(katana.get_paths())
    print(katana.get_parameters())
```

### Full Pipeline (Orchestrator)

```python
from packages.web.recon.orchestrator import ReconOrchestrator

orchestrator = ReconOrchestrator()
results = orchestrator.run(
    target_domain="example.com",
    output_dir="/tmp/recon_results",
)

print(results["subdomains"])   # Discovered subdomains
print(results["live_hosts"])   # Live HTTP hosts
print(results["endpoints"])    # Crawled endpoints
```

Results are saved to `output_dir/recon_results.json`.

## API Reference

### SubfinderWrapper

| Method | Description |
|--------|-------------|
| `is_available() -> bool` | Check if subfinder is installed |
| `run(domain, output_file=None, timeout=300) -> dict` | Enumerate subdomains for a domain |

### HttpxWrapper

| Method | Description |
|--------|-------------|
| `is_available() -> bool` | Check if httpx is installed |
| `run(targets, output_file=None, timeout=300) -> dict` | Probe HTTP targets for live hosts |
| `parse_technology(output_text, min_status=None, max_status=None) -> list` | Extract technology fingerprints from httpx output |

### KatanaWrapper

| Method | Description |
|--------|-------------|
| `is_available() -> bool` | Check if katana is installed |
| `run(url, output_file=None, js_render=True, timeout=300) -> dict` | Crawl a URL and discover endpoints |
| `get_paths() -> list` | Get discovered paths from results |
| `get_parameters() -> list` | Get discovered parameters from results |

### ReconOrchestrator

| Method | Description |
|--------|-------------|
| `run(target_domain, output_dir) -> dict` | Run full recon pipeline (subfinder -> httpx -> katana) |
| `get_results() -> dict` | Get aggregated results from last run |

## Error Handling and Troubleshooting

| Issue | Solution |
|-------|----------|
| `is_available()` returns `False` | Tool is not installed or not in PATH. Run `go install` commands above. |
| Timeout during recon | Increase `timeout` parameter (default 300s). Large domains may need 600s+. |
| Empty subdomain results | Domain may have limited subdomains; try with API keys for subfinder (Virustotal, SecurityTrails). |
| httpx returns no live hosts | Verify target URLs are correct and accessible. Check firewall rules. |
| Katana crawl returns few endpoints | Some sites require JavaScript rendering; try `js_render=True` (default). |
| Permission denied on output | Ensure `output_dir` exists and is writable. |

All tools log warnings/errors via `core.logging.get_logger`. Check RAPTOR logs for detailed error messages.

## Output Format

### Individual Tool Output

Each tool returns a dict with:
```python
{
    "success": True,
    "stdout": "... raw tool output ...",
    "stderr": "... errors ...",
    "returncode": 0,
}
```

### ReconOrchestrator Output

```json
{
  "subdomains": ["www.example.com", "api.example.com", "mail.example.com"],
  "live_hosts": ["https://www.example.com", "https://api.example.com"],
  "endpoints": [
    {"url": "https://example.com/login", "method": "POST"},
    {"url": "https://example.com/api/users", "method": "GET"}
  ],
  "technology": [
    {"url": "https://example.com", "tech": ["nginx", "php"]}
  ],
  "output_file": "/tmp/recon_results/recon_results.json"
}
```

## Testing

```bash
# Run all recon tests
python3 -m pytest packages/web/recon/tests/ -v

# Run with coverage
python3 -m pytest packages/web/recon/tests/ -v --cov=packages.web.recon

# Run specific test modules
python3 -m pytest packages/web/recon/tests/test_subfinder.py -v
python3 -m pytest packages/web/recon/tests/test_httpx.py -v
python3 -m pytest packages/web/recon/tests/test_katana.py -v
python3 -m pytest packages/web/recon/tests/test_orchestrator.py -v
```

All tests use mocked external tool calls -- no real tool invocations during testing.
