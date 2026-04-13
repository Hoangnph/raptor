# Hướng Dẫn Thực Hành RAPTOR

**Từ Cài Đặt Đến Sử Dụng Nâng Cao**

---

## Mục Lục

1. [Cài Đặt và Cấu Hình](#cài-đặt-và-cấu-hình)
2. [Sử Dụng Cơ Bản](#sử-dụng-cơ-bản)
3. [Workflows Nâng Cao](#workflows-nâng-cao)
4. [Tạo Custom Rules](#tạo-custom-rules)
5. [Mở Rộng RAPTOR](#mở-rộng-raptor)
6. [Troubleshooting](#troubleshooting)
7. [Cheatsheet](#cheatsheet)

---

## Cài Đặt và Cấu Hình

### Option 1: Cài Đặt Trực Tiếp

```bash
# 1. Clone repository
git clone https://github.com/gadievron/raptor.git
cd raptor

# 2. Cài đặt Python dependencies
pip install -r requirements.txt

# Sẽ cài: requests, pydantic, instructor, tabulate

# 3. Cài Semgrep
pip install semgrep

# 4. (Optional) Cài CodeQL
# Tải từ: https://github.com/github/codeql-cli-binaries
# Giải nén và thêm vào PATH

# 5. (Optional) Cài AFL++
# macOS:
brew install afl++
# Linux:
apt install afl++

# 6. Đặt API keys
export ANTHROPIC_API_KEY="sk-ant-..."
# hoặc
export OPENAI_API_KEY="sk-..."
# hoặc
export GEMINI_API_KEY="..."
```

### Option 2: Sử Dụng Dev Container (Recommended)

```bash
# Build dev container
docker build -f .devcontainer/Dockerfile -t raptor-devcontainer:latest .

# Hoặc mở trong VS Code
# Command Palette → Dev Containers: Open Folder in Container

# Lưu ý: Container ~6GB, cần --privileged flag cho rr debugger
```

### Verification

```bash
# Kiểm tra cài đặt
python3 raptor.py --help

# Kiểm tra LLM
python3 -c "
from packages.llm_analysis import detect_llm_availability
env = detect_llm_availability()
print(f'LLM available: {env.llm_available}')
print(f'Provider: {env.provider}')
"
```

### Cấu Hình Models (Optional)

Tạo file `~/.config/raptor/models.json`:

```json
{
  "models": [
    {
      "provider": "anthropic",
      "model": "claude-sonnet-4-20250514",
      "api_key": "sk-ant-...",
      "max_cost_per_scan": 1.0
    },
    {
      "provider": "openai", 
      "model": "gpt-4o",
      "api_key": "sk-...",
      "max_cost_per_scan": 1.0
    },
    {
      "provider": "ollama",
      "model": "llama3:70b",
      "ollama_host": "http://localhost:11434"
    }
  ]
}
```

---

## Sử Dụng Cơ Bản

### CLI Mode

**1. Full Autonomous Workflow:**
```bash
python3 raptor.py agentic --repo /path/to/code
```

**2. Static Analysis Only:**
```bash
python3 raptor.py scan --repo /path/to/code
# Với policy groups cụ thể:
python3 raptor.py scan --repo /path/to/code --policy-groups secrets,crypto
```

**3. CodeQL Analysis:**
```bash
python3 raptor.py codeql --repo /path/to/code
# Chỉ scan, không analyze:
python3 raptor.py codeql --repo /path/to/code --scan-only
```

**4. Binary Fuzzing:**
```bash
python3 raptor.py fuzz --binary /path/to/binary --duration 3600
```

### Claude Code Mode

```
/scan /path/to/code          # Static analysis
/agentic /path/to/code       # Full autonomous
/fuzz /path/to/binary        # Binary fuzzing
/codeql /path/to/code        # CodeQL analysis
/validate /path/to/code      # Exploitability validation
/understand /path/to/code    # Code comprehension
```

### Understanding Output

Tất cả outputs vào `out/<command>_<timestamp>/`:

```
out/agentic_20260411_120000/
├── .raptor-run.json          # Run metadata
├── semgrep_*.sarif           # Semgrep findings
├── codeql_*.sarif            # CodeQL findings  
├── combined.sarif            # Merged findings
├── scan_metrics.json         # Scan statistics
├── checklist.json            # Function inventory
├── findings.json             # Validated findings
├── analysis_report.json      # LLM analysis
└── validation-report.md      # Human-readable report
```

---

## Workflows Nâng Cao

### Workflow 1: CI/CD Security Gate

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.12'
      
      - name: Install RAPTOR
        run: |
          pip install -r requirements.txt
          pip install semgrep
      
      - name: Run RAPTOR Scan
        run: |
          python3 raptor.py scan --repo . \
            --policy-groups secrets,owasp,crypto \
            --out ./security-results
      
      - name: Check for Critical Findings
        run: |
          python3 -c "
          import json
          metrics = json.load(open('security-results/scan_metrics.json'))
          critical = metrics.get('findings_by_severity', {}).get('error', 0)
          if critical > 0:
              print(f'❌ {critical} critical findings found')
              exit(1)
          print('✅ No critical findings')
          "
```

### Workflow 2: Binary Vulnerability Research

```bash
# Step 1: Check exploit feasibility
python3 -c "
from packages.exploit_feasibility import analyze_binary, format_analysis_summary
result = analyze_binary('/path/to/binary')
print(format_analysis_summary(result, verbose=True))
"

# Step 2: If feasible, start fuzzing
python3 raptor.py fuzz \
  --binary /path/to/binary \
  --duration 7200 \
  --max-crashes 20 \
  --autonomous \
  --goal "find buffer overflow in parser"

# Step 3: Review results
cat out/fuzz_*/fuzzing_report.json
ls out/fuzz_*/analysis/exploits/
```

### Workflow 3: Deep Code Review với Validation

```bash
# Step 1: Scan with both Semgrep and CodeQL
python3 raptor.py agentic \
  --repo /path/to/code \
  --codeql \
  --languages python,javascript \
  --max-findings 50 \
  --no-exploits  # Skip exploit gen, just analysis

# Step 2: Validate findings
python3 -c "
from packages.exploitability_validation import run_validation_phase
from pathlib import Path

report, findings = run_validation_phase(
    repo_path='/path/to/code',
    out_dir=Path('out/validation'),
    sarif_files=list(Path('out').glob('**/*.sarif')),
    total_findings=50,
)

# Print summary
exploitable = [f for f in findings if f.get('status') == 'exploitable']
print(f'Exploitable: {len(exploitable)}')
for f in exploitable:
    print(f\"  - {f['rule_id']} at {f['file']}:{f['line']}\")
"

# Step 3: Generate patches for exploitable findings
python3 raptor.py agentic \
  --repo /path/to/code \
  --no-codeql \
  --max-findings 5 \
  --no-exploits  # Just patches
```

### Workflow 4: OSS Forensics Investigation

Trong Claude Code:

```
/oss-forensics Investigate suspicious commits in github.com/user/repo 
  between 2024-01-01 and 2024-06-01
```

Hoặc tìm investigation cụ thể:

```
/oss-forensics Find all deleted commits by user XYZ 
  and recover the deleted code
```

### Workflow 5: Multi-Model Consensus

```bash
# Cấu hình trong models.json nhiều providers
# RAPTOR sẽ tự động dùng consensus khi configured

python3 raptor.py agentic --repo /path/to/code --max-parallel 3
```

---

## Tạo Custom Rules

### Semgrep Custom Rule

Tạo file `engine/semgrep/rules/<category>/my-rule.yaml`:

```yaml
rules:
  - id: my-custom-rule
    pattern: |
      subprocess.Popen(..., shell=True, ...)
    message: |
      Sử dụng shell=True trong subprocess.Popen có thể dẫn đến command injection.
      Dùng shlex.quote() hoặc list arguments thay vì string concatenation.
    severity: ERROR
    languages: [python]
    metadata:
      owasp: "A03:2021 - Injection"
      cwe: "CWE-78: OS Command Injection"
      category: injection
```

### CodeQL Custom Query

Tạo file `engine/codeql/suites/my-query.ql`:

```ql
/**
 * @name My custom SQL injection query
 * @description Finds SQL injection via string concatenation
 * @kind path-problem
 * @problem.severity error
 */

import python
import DataFlow

class SqlInjectionConfig extends DataFlow::Configuration {
  SqlInjectionConfig() { this = "SqlInjectionConfig" }
  
  override predicate isSource(DataFlow::Node source) {
    source.asParameter().getName() = "user_input"
  }
  
  override predicate isSink(DataFlow::Node sink) {
    exists(Call call |
      call.getTarget().getName() = "execute" |
      sink.asExpr() = call.getArgument(_)
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, SqlInjectionConfig cfg
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "SQL injection vulnerability"
```

---

## Mở Rộng RAPTOR

### Adding a New Package

**1. Create package structure:**

```bash
mkdir -p packages/my-new-package/tests
touch packages/my-new-package/__init__.py
touch packages/my-new-package/main.py
touch packages/my-new-package/README.md
```

**2. Implement main.py:**

```python
#!/usr/bin/env python3
"""My new security package"""

import argparse
import sys
from pathlib import Path

# Chỉ import từ core, KHÔNG import từ packages khác
from core.config import RaptorConfig
from core.logging import get_logger

logger = get_logger()

def main():
    parser = argparse.ArgumentParser(description="My security package")
    parser.add_argument("--target", required=True, help="Target to analyze")
    parser.add_argument("--out", help="Output directory")
    args = parser.parse_args()
    
    # Do work
    logger.info(f"Analyzing {args.target}")
    results = analyze(args.target)
    
    # Save results
    out_dir = Path(args.out) if args.out else RaptorConfig.get_out_dir()
    save_results(results, out_dir)
    
    logger.info("Analysis complete")

if __name__ == "__main__":
    main()
```

**3. Add to launcher (raptor.py):**

```python
def mode_my_new_package(args: list) -> int:
    """Run my new package"""
    script_root = Path(__file__).parent
    script = script_root / "packages/my-new-package/main.py"
    return _run_with_lifecycle("my-new-package", script, args, "Running analysis...")

# Add to mode_handlers
mode_handlers = {
    # ... existing handlers
    'my-package': mode_my_new_package,
}
```

### Adding a New Claude Command

Tạo file `.claude/commands/my-command.md`:

```markdown
---
description: My custom command
---

# My Custom Command

## Usage
/my-command <target> [options]

## Implementation
Run: `python3 packages/my-new-package/main.py --target <target>`

## Output
Results saved to `$WORKDIR/my-command-results.json`
```

---

## Troubleshooting

### Problem: Semgrep fails with "no .git directory"

**Solution:**
```bash
cd /path/to/target
git init
git add .
git commit -m "Initial commit"
```

### Problem: CodeQL database creation fails

**Solutions:**
```bash
# Check if build is needed
python3 packages/codeql/agent.py --repo /path/to/code --languages python

# For compiled languages, provide build command
python3 packages/codeql/agent.py --repo /path/to/code \
  --languages java \
  --build-command "mvn clean compile -DskipTests"

# Force rebuild
python3 packages/codeql/agent.py --repo /path/to/code --force
```

### Problem: LLM analysis times out

**Solutions:**
```bash
# Check API key
echo $ANTHROPIC_API_KEY  # or $OPENAI_API_KEY

# Test LLM availability
python3 -c "
from packages.llm_analysis import detect_llm_availability
env = detect_llm_availability()
print(f'Available: {env.llm_available}')
print(f'Provider: {env.provider}')
print(f'External: {env.external_llm}')
"

# If using Ollama, check server
curl http://localhost:11434/api/tags
```

### Problem: Exploit generation produces non-compilable code

**Cause:** Local models (Ollama) thường không tốt bằng cloud models cho exploit generation

**Solutions:**
1. Use frontier models (Claude, GPT-4, Gemini)
2. Review and manually fix generated code
3. Check exploit validator output

### Problem: High memory usage during scanning

**Solution:**
```bash
# Limit parallel workers
# Edit core/config.py
MAX_SEMGREP_WORKERS = 2  # Default 4

# Or limit findings
python3 raptor.py agentic --repo /path/to/code --max-findings 20
```

---

## Cheatsheet

### Quick Commands

```bash
# Quick scan
python3 raptor.py scan --repo . 

# Deep analysis
python3 raptor.py agentic --repo .

# CodeQL only  
python3 raptor.py codeql --repo .

# Fuzz binary
python3 raptor.py fuzz --binary ./vuln --duration 3600

# Check exploit feasibility
python3 -c "from packages.exploit_feasibility import analyze_binary; print(analyze_binary('./vuln'))"
```

### Claude Code Commands

```
/raptor     - Overview
/scan       - Static analysis
/agentic    - Full autonomous
/fuzz       - Binary fuzzing
/codeql     - CodeQL analysis
/validate   - Validation pipeline
/understand - Code comprehension
/exploit    - Generate exploit
/patch      - Generate patch
/diagram    - Generate diagrams
/project    - Project management
```

### Output Locations

```
out/scan_*/           - Semgrep results
out/codeql_*/         - CodeQL results
out/agentic_*/        - Agentic workflow results
out/fuzz_*/           - Fuzzing results
out/validation_*/     - Validation results
```

### Environment Variables

```bash
# LLM Providers
ANTHROPIC_API_KEY="sk-ant-..."
OPENAI_API_KEY="sk-..."
GEMINI_API_KEY="..."
MISTRAL_API_KEY="..."
OLLAMA_HOST="http://localhost:11434"

# RAPTOR Config
RAPTOR_ROOT="/path/to/raptor"
RAPTOR_CALLER_DIR="/path/to/target"
RAPTOR_CONFIG="~/.config/raptor/models.json"
```

---

**End of Practical Guide**

For more details, see:
- [Exploit Feasibility Deep Dive](../05-EXPLOIT-ENGINEERING/01-exploit-feasibility-deep-dive.md)
- [Validation Pipeline Master](../06-VALIDATION-PIPELINE/01-validation-pipeline-master.md)
- [Core Foundation Master](../01-CORE-FOUNDATION/01-core-foundation-master.md)
- [Security Packages Master](../02-SECURITY-PACKAGES/01-security-packages-master.md)
