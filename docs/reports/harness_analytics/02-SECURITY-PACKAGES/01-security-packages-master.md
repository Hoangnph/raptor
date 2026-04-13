# Security Packages - Các Gói Bảo Mật

**Phân Tích Từ Source Code Thực Tế - 15 Packages**

---

## Tổng Quan

RAPTOR có **15 security packages**, mỗi package:
- ✅ Một trách nhiệm duy nhất
- ✅ Không import từ packages khác (chỉ từ core)
- ✅ Có thể chạy độc lập
- ✅ Có CLI interface riêng

---

## 1. static-analysis/

**File:** `packages/static-analysis/scanner.py`

**Mục Đích:** Quét Semgrep với custom rules + registry

**Implementation:**
```python
# Parallel scanning với ThreadPoolExecutor
with ThreadPoolExecutor(max_workers=RaptorConfig.MAX_SEMGREP_WORKERS) as executor:
    futures = {
        executor.submit(run_semgrep_config, config, repo_path): config
        for config in configs
    }
```

**Policy Groups:**
- `crypto` - Weak crypto detection (8 rules)
- `secrets` - Hardcoded secrets
- `injection` - Command/SQL injection
- `auth` - TLS skip verify
- `filesystem` - Path traversal
- `logging` - Logs secrets
- `sinks` - SSRF
- `flows` - Bad MAC order
- `deserialisation` - Unsafe Java deserialize

**Output:**
- `semgrep_<policy>.sarif`
- `combined.sarif` (merged)
- `scan_metrics.json`

---

## 2. codeql/

**Files:** 8 modules

**Pipeline:**
```
LanguageDetector → BuildDetector → DatabaseManager → QueryRunner → Report
```

**Key Modules:**
- `agent.py` - Main orchestrator
- `autonomous_analyzer.py` - LLM analysis
- `database_manager.py` - DB creation với SHA256 cache
- `dataflow_validator.py` - Validate dataflow paths
- `dataflow_visualizer.py` - HTML/Mermaid/ASCII/DOT visualizations

**Languages:** 10 languages (java, python, javascript, typescript, go, cpp, csharp, ruby, swift, kotlin)

---

## 3. llm_analysis/

**Files:** 12 modules

**Key Components:**
- `agent.py` - AutonomousSecurityAgentV2 (1277 lines)
- `crash_agent.py` - CrashAnalysisAgent
- `orchestrator.py` - Multi-agent coordination
- `dispatch.py` - Parallel dispatcher (DispatchTask base class)
- `llm/` - Client, config, detection, providers

**Capabilities:**
- Vulnerability context building
- Dataflow validation
- Exploitability scoring
- Exploit generation
- Patch generation

---

## 4. autonomous/

**Files:** 6 modules

**Components:**
- `planner.py` - FuzzingPlanner với intelligent decisions
- `memory.py` - FuzzingMemory persistent learning
- `dialogue.py` - MultiTurnAnalyser
- `exploit_validator.py` - ExploitValidator
- `goal_planner.py` - Goal-directed fuzzing
- `corpus_generator.py` - Intelligent seed corpus

---

## 5. fuzzing/

**Files:** 3 modules

**Components:**
- `afl_runner.py` - AFLRunner với parallel support
- `crash_collector.py` - CrashCollector deduplication
- `corpus_manager.py` - CorpusManager

**Features:**
- Parallel AFL instances
- Crash deduplication by signal
- QEMU mode support
- Coverage analysis với afl-showmap

---

## 6. binary_analysis/

**Files:** 2 modules

**Components:**
- `crash_analyser.py` - CrashAnalyser
- `debugger.py` - GDB wrapper

**Crash Types Detected:**
- Stack buffer overflows
- Heap corruption
- Use-after-free
- Integer overflows
- Format string vulnerabilities
- NULL pointer dereference

---

## 7. exploit_feasibility/

**Files:** 24 modules, **275+ tests**

**Xem chi tiết:** [05-EXPLOIT-ENGINEERING/01-exploit-feasibility-deep-dive.md](../05-EXPLOIT-ENGINEERING/01-exploit-feasibility-deep-dive.md)

---

## 8. exploitability_validation/

**Files:** 5 modules, **207+ tests**

**Xem chi tiết:** [06-VALIDATION-PIPELINE/01-validation-pipeline-master.md](../06-VALIDATION-PIPELINE/01-validation-pipeline-master.md)

---

## 9. exploitation/

**Files:** 2 modules

**Components:**
- `bootstrap.py` - Exploit bootstrapping
- `reporting.py` - Exploit reporting

---

## 10. recon/

**Files:** 1 module

**Purpose:** Technology stack enumeration

**Detects:**
- Programming languages
- Frameworks and libraries
- Dependencies
- Attack surface

**Output:** `recon_report.json`

---

## 11. sca/

**Files:** 1 module

**Purpose:** Dependency vulnerability scanning

**Detects:**
- requirements.txt (Python)
- package.json (Node.js)
- pom.xml (Java)
- Gemfile.lock (Ruby)
- Cargo.lock (Rust)
- go.mod (Go)

**Output:** `sca_report.json`, `dependencies.json`

---

## 12. web/

**Files:** 4 modules

**Status:** ⚠️ ALPHA/STUB

**Components:**
- `client.py` - HTTP client wrapper
- `crawler.py` - Web crawler
- `fuzzer.py` - Input fuzzing
- `scanner.py` - OWASP Top 10 checks

**Note:** Not production-ready

---

## 13. diagram/

**Files:** 8 modules

**Purpose:** Mermaid visualization generation

**Renders:**
- Context maps (entry points → trust boundaries → sinks)
- Flow traces (call chains)
- Attack trees (knowledge graphs)
- Attack paths (step chains với PROXIMITY scores)

**Usage:**
```python
from packages.diagram import render_and_write
render_and_write(Path(".out/code-understanding-20240101/"), target="myapp")
```

---

## 14. cvss/

**Files:** 1 module

**Purpose:** CVSS score calculation

**File:** `calculator.py`

---

## Testing Coverage

| Package | Tests | Status |
|---------|-------|--------|
| exploit_feasibility | 275+ | ✅ Excellent |
| exploitability_validation | 207+ | ✅ Excellent |
| Others | Varies | ⚠️ Needs improvement |

---

**Tài liệu tiếp theo:** Xem chi tiết từng package trong code source
