# Kiến Trúc Hệ Thống RAPTOR

**Phân Tích Chi Tiết Từ Tổng Quan Đến Chi Tiết**

---

## Mục Lục

1. [Nguyên Tắc Thiết Kế](#nguyên-tắc-thiết-kế)
2. [Kiến Trúc Phân Lớp](#kiến-trúc-phân-lớp)
3. [Luồng Dữ Liệu](#luồng-dữ-liệu)
4. [Design Patterns](#design-patterns)
5. [Module Dependencies](#module-dependencies)
6. [Extension Points](#extension-points)
7. [Performance Considerations](#performance-considerations)
8. [Security Architecture](#security-architecture)

---

## Nguyên Tắc Thiết Kế

RAPTOR được xây dựng trên **6 nguyên tắc cốt lõi**:

### 1. Single Responsibility Principle

Mỗi package có **một và chỉ một** trách nhiệm:

```
✅ packages/static-analysis/  → Chỉ quét Semgrep
✅ packages/codeql/           → Chỉ CodeQL analysis
✅ packages/fuzzing/          → Chỉ AFL++ fuzzing
✅ packages/llm_analysis/     → Chỉ LLM reasoning

❌ KHÔNG có package nào làm nhiều việc
❌ KHÔNG có cross-package imports
```

### 2. No Cross-Package Dependencies

```python
# ✅ ĐÚNG: Package chỉ import từ core
from core.config import RaptorConfig
from core.logging import get_logger

# ❌ SAI: Package import từ package khác
from packages.codeql import something  # KHÔNG ALLOWED
from packages.fuzzing import something  # KHÔNG ALLOWED
```

**Lợi ích:**
- Mỗi package có thể chạy độc lập
- Dễ test, dễ debug
- Thay thế package dễ dàng
- Không có dependency hell

### 3. Standalone Executability

Mỗi package có thể chạy như một chương trình độc lập:

```bash
# Chạy trực tiếp
python3 packages/static-analysis/scanner.py --repo /path/to/code
python3 packages/codeql/agent.py --repo /path/to/code
python3 packages/fuzzing/afl_runner.py --binary /path/to/binary

# Hoặc qua unified launcher
python3 raptor.py scan --repo /path/to/code
python3 raptor.py codeql --repo /path/to/code
python3 raptor.py fuzz --binary /path/to/binary
```

### 4. Progressive Disclosure

Không load tất cả cùng lúc, mà load **theo nhu cầu**:

```
Level 0: CLAUDE.md                           (~800 tokens) - Luôn load
Level 1: analysis-guidance.md                (+300 tokens) - Sau scan
Level 2: exploit-guidance.md                 (+600 tokens) - Khi làm exploit
Level 3: personas/[name].md                  (+400-700 tokens) - Khi request
Level 4: skills/*                            (+500t each)   - Khi dùng command
```

**Token Budget:**
- Core session: ~800t
- After scan: ~1,100t
- During exploit: ~1,400t
- With persona: ~2,000t
- Maximum: ~2,500t+

### 5. Dual Interface Pattern

Mọi tính năng đều có **2 giao diện**:

**CLI Interface** (cho scripting/CI-CD):
```bash
python3 raptor.py agentic --repo /path/to/code
```

**Claude Code Interface** (cho interactive use):
```
/agentic /path/to/code
```

### 6. Security-First Design

Mọi quyết định đều ưu tiên bảo mật:

- Check malicious repo settings trước khi scan
- Strip dangerous env vars trước khi spawn subprocess
- List-based subprocess args (không string interpolation)
- Explicit confirmation cho dangerous operations

---

## Kiến Trúc Phân Lớp

### Layer 0: Entry Points

```
┌─────────────────────────────────────────────────┐
│                ENTRY POINTS                      │
├─────────────────────────────────────────────────┤
│                                                  │
│  bin/raptor          raptor.py                   │
│  (Bash wrapper)      (Python launcher)           │
│                                                  │
│  raptor_agentic.py   raptor_codeql.py            │
│  (Agentic workflow)  (CodeQL workflow)           │
│                                                  │
│  raptor_fuzzing.py                               │
│  (Fuzzing workflow)                              │
│                                                  │
└─────────────────────────────────────────────────┘
```

**bin/raptor** (Bash wrapper):
```bash
#!/usr/bin/env bash
# Resolve RAPTOR directory
RAPTOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Set caller's directory
export RAPTOR_CALLER_DIR="$PWD"
# Launch
cd "$RAPTOR_DIR"
exec python3 -m core.startup.launcher "$@"
```

**raptor.py** (Unified launcher):
- Route đến 6 modes: scan, fuzz, web, agentic, codeql, analyze
- Lifecycle wrapping (start → complete/fail)
- Output directory resolution
- Error handling và KeyboardInterrupt

### Layer 1: Core Foundation

```
┌─────────────────────────────────────────────────┐
│              CORE FOUNDATION                     │
├─────────────────────────────────────────────────┤
│                                                   │
│  config.py          logging.py                    │
│  ├─ Paths           ├─ JSONL audit trail          │
│  ├─ Env vars        ├─ Console output             │
│  └─ Safe env        └─ Security events            │
│                                                   │
│  progress.py        schema_constants.py           │
│  ├─ Progress bars   └─ Shared constants           │
│  └─ Status tracking                               │
│                                                   │
│  understand_bridge.py                             │
│  └─ Code understanding integration                │
│                                                   │
└─────────────────────────────────────────────────┘
```

**Sub-modules:**

```
core/inventory/          core/project/
├─ builder.py            ├─ clean.py
├─ coverage.py           ├─ cli.py
├─ diff.py               ├─ diff.py
├─ exclusions.py         ├─ export.py
├─ extractors.py         ├─ findings_utils.py
├─ languages.py          ├─ merge.py
└─ lookup.py             ├─ project.py
                           ├─ report.py
                           └─ schema.py

core/run/                core/reporting/
├─ __main__.py           ├─ console.py
├─ metadata.py           ├─ findings.py
└─ output.py             ├─ formatting.py
                           ├─ renderer.py
core/sarif/              └─ spec.py
├─ parser.py

core/json/
└─ utils.py

core/startup/
├─ banner.py
├─ init.py
└─ launcher.py
```

### Layer 2: Security Packages

```
┌─────────────────────────────────────────────────┐
│           SECURITY PACKAGES (15)                 │
├─────────────────────────────────────────────────┤
│                                                   │
│  SCANNING              ANALYSIS                   │
│  ├─ static-analysis/   ├─ llm_analysis/          │
│  │  └─ scanner.py      │  ├─ agent.py            │
│  │                     │  ├─ orchestrator.py      │
│  ├─ codeql/            │  └─ crash_agent.py       │
│  │  ├─ agent.py        │                          │
│  │  ├─ autonomous_     ├─ autonomous/             │
│  │  │  _analyzer.py    │  ├─ planner.py           │
│  │  ├─ build_detector  │  ├─ memory.py            │
│  │  ├─ database_       │  ├─ dialogue.py          │
│  │  │  _manager.py     │  ├─ exploit_validator.py  │
│  │  ├─ dataflow_       │  ├─ goal_planner.py      │
│  │  │  _validator.py   │  └─ corpus_generator.py  │
│  │  ├─ dataflow_       │                          │
│  │  │  _visualizer.py  ├─ recon/                  │
│  │  ├─ language_       ├─ sca/                    │
│  │  │  _detector.py    └─ web/                    │
│  │  └─ query_runner.py                            │
│  │                                               │
│  BINARY                VALIDATION                 │
│  ├─ fuzzing/           ├─ exploit_feasibility/    │
│  │  ├─ afl_runner.py   │  (24 files, 275+ tests) │
│  │  ├─ crash_collector ├─ exploitability_         │
│  │  └─ corpus_manager  │  _validation/            │
│  │                     │  (5 files, 207+ tests)   │
│  ├─ binary_analysis/   ├─ exploitation/           │
│  │  ├─ crash_analyser  │  ├─ bootstrap.py         │
│  │  └─ debugger.py     │  └─ reporting.py         │
│  │                     │                          │
│  VISUALIZATION         UTILITIES                  │
│  ├─ diagram/           ├─ cvss/                   │
│  │  ├─ attack_paths.py └─ calculator.py           │
│  │  ├─ attack_tree.py                             │
│  │  ├─ context_map.py                             │
│  │  ├─ flow_trace.py                              │
│  │  └─ renderer.py                                │
│                                                   │
└─────────────────────────────────────────────────┘
```

### Layer 3: Analysis Engines

```
┌─────────────────────────────────────────────────┐
│            ANALYSIS ENGINES                      │
├─────────────────────────────────────────────────┤
│                                                   │
│  engine/semgrep/         engine/codeql/           │
│  ├─ semgrep.yaml         ├─ suites/               │
│  ├─ rules/               │  ├─ codeql-config.yml  │
│  │  ├─ auth/             │  └─ custom queries     │
│  │  ├─ crypto/ (8 rules) │                        │
│  │  ├─ injection/        └─ (dùng GitHub official │
│  │  ├─ filesystem/           suites làm default)  │
│  │  ├─ logging/                                  │
│  │  ├─ secrets/                                  │
│  │  └─ sinks/                                    │
│  └─ tools/                                        │
│     └─ sarif_merge.py                             │
│                                                   │
└─────────────────────────────────────────────────┘
```

### Layer 4: Expert System

```
┌─────────────────────────────────────────────────┐
│           CLAUDE CODE EXPERT SYSTEM              │
├─────────────────────────────────────────────────┤
│                                                   │
│  .claude/commands/ (21 files)                    │
│  ├─ Primary: agentic, scan, fuzz, validate,      │
│  │          understand, codeql, analyze           │
│  ├─ Specialist: exploit, patch, crash-analysis,  │
│  │            oss-forensics                       │
│  └─ Utility: project, diagram, commands,         │
│              create-skill, test-workflows          │
│                                                   │
│  .claude/agents/ (16 files)                      │
│  ├─ Crash analysis agents (5)                    │
│  ├─ OSS forensics agents (10)                    │
│  └─ Offensive security specialist (1)            │
│                                                   │
│  .claude/skills/ (7 directories)                 │
│  ├─ code-understanding/    (map, trace, hunt)    │
│  ├─ exploitability-validation/ (stages 0-F)      │
│  ├─ crash-analysis/        (rr, tracing, gcov)   │
│  ├─ oss-forensics/         (archive, recovery)   │
│  ├─ exploitation/          (post-exploit)        │
│  ├─ exploit-dev/           (techniques)          │
│  └─ SecOpsAgentKit/        (offensive security)  │
│                                                   │
│  tiers/                                          │
│  ├─ analysis-guidance.md   (adversarial thinking)│
│  ├─ exploit-guidance.md    (constraint tables)   │
│  ├─ recovery.md            (error recovery)      │
│  ├─ validation-recovery.md (stage-specific)      │
│  └─ personas/ (9 files)                          │
│     ├─ binary_exploitation_specialist.md         │
│     ├─ codeql_analyst.md                         │
│     ├─ crash_analyst.md                          │
│     ├─ exploit_developer.md                      │
│     ├─ patch_engineer.md                         │
│     └─ ...                                       │
│                                                   │
└─────────────────────────────────────────────────┘
```

---

## Luồng Dữ Liệu

### Agentic Workflow (Full Pipeline)

```
User: python3 raptor.py agentic --repo /path/to/code
  │
  ├─ 1. Lifecycle: start_run("agentic")
  │    └─ Tạo out/agentic_<timestamp>/
  │    └─ Ghi .raptor-run.json {status: running}
  │
  ├─ 2. Pre-scan: Check repo Claude settings
  │    └─ Phát hiện malicious credential helpers
  │    └─ Block CC dispatch nếu dangerous
  │
  ├─ 3. Build inventory (core.inventory.builder)
  │    └─ Liệt kê files, checksums, SLOC
  │    └─ Ghi checklist.json
  │
  ├─ 4. Phase 1: PARALLEL SCANNING
  │    │
  │    ├─ Process A: Semgrep
  │    │  ├─ packages/static-analysis/scanner.py
  │    │  ├─ Map policy groups → rules + registry
  │    │  ├─ ThreadPoolExecutor (max 4 workers)
  │    │  ├─ Output: semgrep_*.sarif
  │    │  └─ Merge: combined.sarif
  │    │
  │    └─ Process B: CodeQL
  │       ├─ packages/codeql/agent.py
  │       ├─ LanguageDetector → BuildDetector
  │       ├─ DatabaseManager → QueryRunner
  │       ├─ Output: codeql_*.sarif
  │       └─ Report: codeql_report.json
  │
  ├─ 5. Phase 2: EXPLOITABILITY VALIDATION
  │    ├─ packages/exploitability_validation
  │    ├─ Deduplicate findings
  │    ├─ Classify vulnerability types
  │    └─ Output: validated_findings
  │
  ├─ 6. Phase 3: LLM ANALYSIS
  │    ├─ packages.llm_analysis.dispatch
  │    ├─ Parallel analysis per finding
  │    ├─ Read vulnerable code context
  │    ├─ Dataflow validation
  │    ├─ Exploitability scoring
  │    ├─ Patch generation
  │    └─ Output: analysis_report.json
  │
  ├─ 7. Phase 4-7: Advanced (optional)
  │    ├─ Cross-finding analysis
  │    ├─ Multi-model consensus
  │    └─ Exploit/patch generation
  │
  └─ 8. Lifecycle: complete_run()
     └─ Update .raptor-run.json {status: complete}
```

### Data Flow chi tiết cho một Finding

```
1. Semgrep phát hiện: command-taint
   ├─ Source: request.GET
   ├─ Sink: subprocess.call(shell=True)
   └─ SARIF: {ruleId: "command-taint", severity: "error"}

2. Validation Pipeline
   ├─ Stage 0: Inventory - function có trong checklist?
   ├─ Stage A: LLM đọc code, xác định vulnerability
   ├─ Stage B: Attack tree, hypotheses
   ├─ Stage C: Sanity check - verify code tại lines
   ├─ Stage D: Ruling - exploitable/confirmed/ruled_out
   ├─ Stage E: Feasibility - binary constraints (nếu có)
   └─ Stage F: Self-review - catch errors

3. LLM Analysis
   ├─ Read source files at vulnerable locations
   ├─ Validate dataflow (is sanitizer effective?)
   ├─ Assess exploitability (can attacker control input?)
   ├─ Generate patch (how to fix?)
   └─ (Optional) Generate exploit PoC

4. Output
   ├─ finding_id: "FIND-0001"
   ├─ status: "exploitable"
   ├─ cvss_score: 8.5
   ├─ exploit_code: "..." (nếu có)
   ├─ patch_code: "..." (nếu có)
   └─ confidence: 0.92
```

---

## Design Patterns

### 1. Lifecycle Pattern

Mọi operation đều theo lifecycle:

```python
from core.run import start_run, complete_run, fail_run

def run_workflow():
    out_dir = start_run("command_name", target_path="/path")
    try:
        # Do work
        do_scanning()
        do_analysis()
        complete_run(out_dir)
    except Exception as e:
        fail_run(out_dir, str(e))
        raise
```

### 2. Strategy Pattern

LLM providers được abstract hóa:

```python
# Provider interface
class LLMProvider:
    def generate(self, prompt: str) -> str: ...
    def generate_structured(self, prompt: str, schema: Type) -> Any: ...

# Implementations
class AnthropicProvider(LLMProvider): ...
class OpenAIProvider(LLMProvider): ...
class GeminiProvider(LLMProvider): ...
class OllamaProvider(LLMProvider): ...
```

### 3. Pipeline Pattern

Validation pipeline với stages:

```python
stages = [
    Stage0_Inventory(),    # Mechanical
    StageA_Discovery(),    # LLM
    StageB_Investigation(),# LLM
    StageC_Sanity(),       # LLM
    StageD_Ruling(),       # LLM
    StageE_Feasibility(),  # Mechanical
    StageF_Review(),       # LLM
]

for stage in stages:
    if not stage.execute(context):
        break  # Stop on failure
```

### 4. Factory Pattern

Output directory creation:

```python
def get_output_dir(command: str, target_path: str) -> Path:
    """Factory method tạo output directory"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = RaptorConfig.get_out_dir() / f"{command}_{target_path}_{timestamp}"
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir
```

### 5. Observer Pattern

Logging system:

```python
logger = get_logger()
logger.info("Scanning started")        # → Console + JSONL
logger.warning("High memory usage")     # → Console + JSONL
logger.error("Scan failed")             # → Console + JSONL
log_security_event("malicious_settings")# → Security audit trail
```

### 6. Adapter Pattern

SARIF parser adapts different formats:

```python
def parse_sarif_findings(sarif_path: Path) -> List[Finding]:
    """Adapt Semgrep SARIF và CodeQL SARIF về cùng format"""
    sarif = load_sarif(sarif_path)
    findings = []
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            finding = {
                "rule_id": result.get("ruleId"),
                "severity": get_severity(result),
                "message": extract_message(result),
                "locations": extract_locations(result),
            }
            findings.append(finding)
    return findings
```

---

## Module Dependencies

### Dependency Graph

```
raptor.py
├── core.run.*
├── raptor_agentic.py
│   ├── core.config
│   ├── core.logging
│   ├── core.inventory
│   ├── core.run
│   ├── packages.static-analysis
│   ├── packages.codeql
│   ├── packages.exploitability_validation
│   └── packages.llm_analysis
├── raptor_codeql.py
│   ├── core.config
│   ├── core.logging
│   ├── packages.codeql
│   └── packages.llm_analysis
└── raptor_fuzzing.py
    ├── core.config
    ├── core.logging
    ├── packages.fuzzing
    ├── packages.binary_analysis
    ├── packages.llm_analysis
    └── packages.autonomous
```

### Package Dependencies Map

```
static-analysis/  → core/*
codeql/           → core/*, llm_analysis/llm/*
llm_analysis/     → core/*
autonomous/       → core/*, llm_analysis/llm/*
fuzzing/          → core/*
binary_analysis/  → core/*
exploit_feasibility/ → core/* (NO external deps)
exploitability_validation/ → core/*, exploit_feasibility/
exploitation/     → core/*
recon/            → core/*
sca/              → core/*
web/              → core/*
diagram/          → core/*
cvss/             → core/*
```

---

## Extension Points

RAPTOR được thiết kế để dễ mở rộng:

### 1. Adding New Semgrep Rules

```
engine/semgrep/rules/<category>/new-rule.yaml
```

Rule tự động được include khi dùng policy group tương ứng.

### 2. Adding New CodeQL Queries

```
engine/codeql/suites/custom.ql
```

Custom queries được thêm vào suites.

### 3. Adding New Packages

```
packages/new-package/
├── __init__.py
├── main.py          # Main entry point
├── README.md        # Documentation
└── tests/
    └── test_main.py
```

Chỉ cần:
- Import từ `core/*` (không import packages khác)
- Có CLI interface với argparse
- Có thể chạy độc lập

### 4. Adding New Claude Commands

```
.claude/commands/new-command.md
```

File markdown với YAML frontmatter:
```yaml
---
description: Mô tả command
---
```

### 5. Adding New Skills

```
.claude/skills/new-skill/
├── SKILL.md
└── sub-modules/
```

### 6. Adding New Personas

```
tiers/personas/new-persona.md
```

---

## Performance Considerations

### Parallelism

**Semgrep Scanning:**
- ThreadPoolExecutor với max 4 workers
- Mỗi policy group chạy song song

**Agentic Workflow:**
- Semgrep và CodeQL chạy song song (Popen)
- LLM analysis có thể parallel (dispatch.py)

**CodeQL Database Creation:**
- Parallel database creation cho multi-language repos

### Caching

**CodeQL Database:**
- SHA256-based cache (git commit hash)
- Skip recreation nếu code không đổi

**Exploit Feasibility:**
- LRU caching cho expensive operations
- Context persistence (JSON files)

### Resource Limits

```python
# core/config.py
MAX_SEMGREP_WORKERS = 4
MAX_CODEQL_TIMEOUT = 1800  # 30 minutes
MAX_LLM_RETRIES = 3
MAX_COST_PER_SCAN = 1.0  # USD
```

---

## Security Architecture

### Defense in Depth

**Layer 1: Environment Sanitization**
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

**Layer 2: Repo Settings Check**
```python
def _check_repo_claude_settings(repo_path: str) -> bool:
    """Phát hiện malicious .claude/settings.json"""
    dangerous_keys = ["apiKeyHelper", "awsAuthHelper", ...]
    # Check và block CC dispatch nếu tìm thấy
```

**Layer 3: Subprocess Safety**
```python
# ✅ List-based args (không string interpolation)
subprocess.run(["semgrep", "--config", config_path, target])

# ❌ String interpolation (dễ injection)
subprocess.run(f"semgrep --config {config_path} {target}", shell=True)
```

### CVE Protection

**CVE-2026-21852** (Phoenix Security CWE-78):
- Check `.claude/settings.json` trước khi dispatch
- Block sub-agents nếu có dangerous credential helpers
- RAPTOR's own scanning dùng `--add-dir` (safe)

---

**Tài liệu tiếp theo:** [03-các-thành-phần-chính.md](03-các-thành-phần-chính.md) - Chi tiết từng component
