# Claude Code Integration - Tích Hợp Claude Code

**Phân Tích Từ Source Code Thực Tế**

---

## Mục Lục

1. [Kiến Trúc Tổng Quan](#kiến-trúc-tổng-quan)
2. [Commands (21 files)](#commands-21-files)
3. [Agents (16 files)](#agents-16-files)
4. [Skills Organization](#skills-organization)
5. [Persona System](#persona-system)
6. [Progressive Disclosure](#progressive-disclosure)
7. [Security Controls](#security-controls)

---

## Kiến Trúc Tổng Quan

RAPTOR tích hợp Claude Code qua **5 lớp**:

```
.claude/
├── commands/     (21 files)  → User-facing slash commands
├── agents/       (16 files)  → Autonomous agent definitions
├── skills/       (7 dirs)    → Reusable capabilities
└── CLAUDE.md                   → Root instructions (always loaded)

tiers/
├── personas/     (9 files)   → Expert personas (on-demand)
├── analysis-guidance.md       → Auto-load after scan
├── exploit-guidance.md        → Auto-load during exploit dev
├── recovery.md                → Auto-load on errors
└── validation-recovery.md     → Auto-load on validation failures
```

---

## Commands (21 files)

### Primary Commands

**1. `/scan`** - Static code analysis
- File: `.claude/commands/scan.md`
- Alias: `/raptor-scan`
- Implementation: `python3 raptor.py scan --repo <path>`

**2. `/agentic`** - Full autonomous workflow
- Runs: scan → dedup → prep → validate → analyze
- Python: `raptor_agentic.py`
- Options: `--codeql`, `--max-findings`, `--sequential`

**3. `/validate`** - Exploitability validation
- Most complex command
- 8 stages: 0→A→B→C→D→E→F→1
- Claude performs LLM stages directly (not via Python)

**4. `/codeql`** - CodeQL-only analysis
- Python: `raptor_codeql.py`
- Options: `--scan-only`, `--languages`, `--build-command`

**5. `/fuzz`** - Binary fuzzing
- Alias: `/raptor-fuzz`
- Python: `raptor_fuzzing.py`

**6. `/analyze`** - LLM analysis only
- 50% faster & cheaper
- No exploit/patch generation

**7. `/understand`** - Code comprehension
- Modes: `--map`, `--trace`, `--hunt`, `--teach`
- Output: `context-map.json`, `flow-trace-*.json`, `variants.json`

### Specialist Commands

**8. `/exploit`** - Generate exploit PoCs
- Pre-checks: validation data, feasibility analysis
- Output: Compilable C code

**9. `/patch`** - Generate security patches
- Input: Validated findings
- Output: Secure code fixes

**10. `/crash-analysis`** - Autonomous C/C++ crash analysis
- Spawns 4 sub-agents
- Uses rr debugger, ASAN, gcov

**11. `/oss-forensics`** - GitHub forensic investigation
- Spawns 10 sub-agents
- BigQuery, GitHub API, Wayback Machine

### Utility Commands

**12. `/project`** - Project management
- Subcommands: create, list, status, diff, merge, report, clean, export

**13. `/diagram`** - Generate Mermaid visualizations
- Input: JSON outputs from /understand or /validate
- Output: `diagrams.md`

**14. `/commands`** - List all available commands

**15. `/create-skill`** - Save custom approaches

### Internal Commands (not user-facing)

- `/raptor-scan` - Internal scan implementation
- `/raptor-fuzz` - Internal fuzz implementation
- `/raptor-web` - Internal web scan (STUB)

---

## Agents (16 files)

### Crash Analysis Agents (5)

**1. crash-analysis-agent**
- Main orchestrator
- Workflow: fetch report → clone repo → build with ASAN → reproduce → analyze

**2. crash-analyzer-agent**
- Deep root-cause analysis using rr traces
- Requires verifiable pointer chains

**3. crash-analyzer-checker-agent**
- Validates analysis quality
- Can reject and force re-analysis

**4. function-trace-generator-agent**
- Creates function execution traces (Perfetto)

**5. coverage-analysis-generator-agent**
- Generates gcov coverage data

### OSS Forensics Agents (10)

**6-15. oss-investigator-* agents**
- `gh-archive-agent` - BigQuery queries (immutable evidence)
- `gh-api-agent` - Live GitHub API
- `gh-recovery-agent` - Deleted content recovery
- `local-git-agent` - Dangling commits
- `ioc-extractor-agent` - IOC extraction
- `hypothesis-former-agent` - Evidence-backed hypotheses
- `evidence-verifier-agent` - Evidence verification
- `hypothesis-checker-agent` - Claim validation
- `report-generator-agent` - Final report

### Offensive Security

**16. offsec-specialist**
- General offensive security operations
- Uses SecOpsAgentKit

---

## Skills Organization

### 1. code-understanding/

**Files:**
- `SKILL.md` - Gates, config, output format
- `map.md` - Entry points, trust boundaries, sinks
- `trace.md` - Step-by-step data flow tracing
- `hunt.md` - Structural/semantic variant analysis
- `teach.md` - Framework/pattern explanation

**5 MUST-GATES (U1-U5):**
- U1: Read-first before analysis
- U2: Attacker-lens perspective
- U3: Full-flow coverage
- U4: Variant completeness
- U5: Evidence-only conclusions

### 2. exploitability-validation/

**Files:**
- `SKILL.md` - 8 MUST-GATES
- `PIPELINE.md` - Stage naming convention
- `stage-0-inventory.md` through `stage-f-review.md`

**8 MUST-GATES:**
- G1: Assume-exploit (treat findings as real until disproven)
- G2: Strict-sequence (stages must run in order)
- G3: Checklist compliance (all functions must be checked)
- G4: No-hedging (definite conclusions required)
- G5: Full-coverage (no skipped functions)
- G6: Proof-required (evidence for all claims)
- G7: Consistency (schemas must validate)
- G8: PoC-evidence (exploit code as evidence)

### 3. crash-analysis/

**Sub-directories:**
- `rr-debugger/` - Deterministic record-replay
- `function-tracing/` - `-finstrument-functions` instrumentation
- `gcov-coverage/` - Code coverage collection
- `line-execution-checker/` - Fast line execution queries

### 4. oss-forensics/

**Sub-directories:**
- `github-archive/` - GH Archive BigQuery
- `github-evidence-kit/` - Evidence store
- `github-commit-recovery/` - Commit recovery
- `github-wayback-recovery/` - Wayback Machine

---

## Persona System

**9 Expert Personas** (tiers/personas/):

| Persona | Expert Reference | Token Cost |
|---------|-----------------|------------|
| Exploit Developer | Mark Dowd | ~650t |
| Crash Analyst | Charlie Miller/Halvar Flake | ~700t |
| Security Researcher | 4-step framework | ~620t |
| Patch Engineer | Senior security engineer | ~400t |
| Penetration Tester | Senior pentester | ~350t |
| Fuzzing Strategist | Expert strategist | ~300t |
| Binary Exploitation Specialist | Binary expert | ~400t |
| CodeQL Dataflow Analyst | Dataflow expert | ~400t |
| CodeQL Finding Analyst | Mark Dowd methodology | ~350t |

**Load Method:** Explicit invocation only ("Use [persona name]")

---

## Progressive Disclosure

### Token Budget

| State | Files Loaded | Tokens |
|-------|-------------|--------|
| Core | CLAUDE.md | ~800t |
| After scan | CLAUDE.md + analysis-guidance.md | ~1,100t |
| During exploit | CLAUDE.md + exploit-guidance.md | ~1,400t |
| With persona | + persona file | ~2,000t |
| Skills loaded | + skill files | Variable |

### Auto-Load Triggers

| Trigger | File Loaded |
|---------|-------------|
| Scan completes | `tiers/analysis-guidance.md` |
| Exploit development | `tiers/exploit-guidance.md` |
| Error occurs | `tiers/recovery.md` |
| Validation failure | `tiers/validation-recovery.md` |
| User request | `tiers/personas/[name].md` |

---

## Security Controls

### 1. Repo Settings Check

Từ source code thực tế (`raptor_agentic.py`):

```python
def _check_repo_claude_settings(repo_path: str) -> bool:
    """Check for malicious .claude/settings.json"""
    dangerous_keys = [
        "apiKeyHelper", "awsAuthHelper", "awsAuthRefresh", "gcpAuthRefresh",
    ]

    claude_dir = Path(repo_path) / ".claude"
    settings_files = [claude_dir / name for name in ("settings.json", "settings.local.json")
                      if (claude_dir / name).exists()]

    for settings_path in settings_files:
        data = json.loads(settings_path.read_text())
        for key in dangerous_keys:
            if key in data and isinstance(data[key], str):
                return True  # Block dispatch
    return False
```

### 2. Sub-Agent Safety

```python
# RAPTOR uses --add-dir for sub-agents
# This means: file access ONLY, no settings loading
claude -p --add-dir /path/to/target
```

### 3. Environment Sanitization

Từ `core/config.py`:

```python
DANGEROUS_ENV_VARS = {
    "TERMINAL", "EDITOR", "VISUAL", "BROWSER", "PAGER",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"
}

def get_safe_env() -> dict:
    env = os.environ.copy()
    for var in DANGEROUS_ENV_VARS:
        env.pop(var, None)
    return env
```

---

**Tài liệu tiếp theo:** [07-SECURITY-ANALYSIS](../07-SECURITY-ANALYSIS/)
