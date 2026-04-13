# RAPTOR Project Analysis Report

**Report Date:** April 11, 2026  
**Project:** RAPTOR - Autonomous Offensive/Defensive Security Research Framework  
**Version:** v1.0-beta (Modular Architecture v2.0)  
**Repository:** https://github.com/gadievron/raptor  

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Project Overview](#project-overview)
3. [Architecture & Design](#architecture--design)
4. [Core Components](#core-components)
5. [Security Packages](#security-packages)
6. [Analysis Engines](#analysis-engines)
7. [LLM Integration](#llm-integration)
8. [Key Features](#key-features)
9. [Technical Stack](#technical-stack)
10. [Project Statistics](#project-statistics)
11. [Strengths](#strengths)
12. [Areas for Improvement](#areas-for-improvement)
13. [Security Considerations](#security-considerations)
14. [Recommendations](#recommendations)
15. [Conclusion](#conclusion)

---

## Executive Summary

RAPTOR (Recursive Autonomous Penetration Testing and Observation Robot) is an advanced autonomous security research framework built on Claude Code and powered by LLM reasoning. The framework combines traditional security testing tools (Semgrep, CodeQL, AFL++) with AI-driven autonomous analysis to provide comprehensive vulnerability discovery, validation, exploit generation, and patching capabilities.

**Key Highlights:**
- Multi-layered autonomous security testing with progressive disclosure
- Integration with multiple LLM providers (Anthropic, OpenAI, Google Gemini, Mistral, Ollama)
- Comprehensive exploit feasibility analysis with empirical verification
- Multi-stage exploitability validation pipeline
- Advanced crash analysis with deterministic debugging (rr)
- OSS forensics capabilities for GitHub repository investigation
- Modular, extensible architecture with 15+ specialized packages
- Strong emphasis on cost management and budget enforcement

**Authors:** Gadi Evron, Daniel Cuthbert, Thomas Dullien (Halvar Flake), Michael Bargury, John Cartwright

**License:** MIT

---

## Project Overview

### Purpose

RAPTOR is designed to autonomously:
1. **Understand code** through adversarial code comprehension, attack surface mapping, and data flow tracing
2. **Scan code** with Semgrep and CodeQL with dataflow validation
3. **Fuzz binaries** using American Fuzzy Lop (AFL++)
4. **Analyze vulnerabilities** using advanced LLM reasoning
5. **Generate exploits** by creating proof-of-concepts
6. **Create patches** to fix vulnerabilities
7. **Conduct OSS forensics** for evidence-backed GitHub repository investigations
8. **Manage costs** with budget enforcement and real-time tracking
9. **Report findings** in structured formats

### Unique Value Proposition

- **Agentic Automation:** Combines traditional security tools with autonomous AI reasoning
- **Exploit Feasibility Analysis:** Determines if vulnerabilities are actually exploitable before wasting effort
- **Multi-Provider LLM Support:** Works with Anthropic Claude, OpenAI GPT, Google Gemini, Mistral, or local Ollama
- **Progressive Expert Loading:** Loads specialized personas and guidance only when needed
- **Cost-Aware Design:** Built-in budget enforcement and cost tracking per scan/analysis

---

## Architecture & Design

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    RAPTOR Framework                          │
├─────────────────────────────────────────────────────────────┤
│  Entry Points                                                │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐  │
│  │ raptor.py│ │raptor_   │ │raptor_   │ │raptor_       │  │
│  │(Launcher)│ │agentic.py│ │codeql.py │ │fuzzing.py    │  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────────┘  │
├─────────────────────────────────────────────────────────────┤
│  Core Layer (Shared Utilities)                               │
│  ┌─────────┐ ┌────────┐ ┌──────────┐ ┌─────────────────┐  │
│  │ config  │ │logging │ │ progress │ │ sarif/parser    │  │
│  └─────────┘ └────────┘ └──────────┘ └─────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ inventory/  │ json/  │ project/ │ reporting/ │ run/   │   │
│  └──────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│  Packages Layer (Security Capabilities)                      │
│  ┌─────────────┐ ┌──────────┐ ┌──────────────┐            │
│  │static-      │ │ codeql/  │ │ llm_         │            │
│  │analysis     │ │          │ │ analysis     │            │
│  └─────────────┘ └──────────┘ └──────────────┘            │
│  ┌─────────────┐ ┌──────────┐ ┌──────────────┐            │
│  │autonomous/  │ │ fuzzing/ │ │ binary_      │            │
│  │             │ │          │ │ analysis     │            │
│  └─────────────┘ └──────────┘ └──────────────┘            │
│  ┌─────────────┐ ┌──────────┐ ┌──────────────┐            │
│  │exploit_     │ │exploit-  │ │ diagram/     │            │
│  │feasibility  │ │ability_  │ │              │            │
│  │             │ │validation│ │              │            │
│  └─────────────┘ └──────────┘ └──────────────┘            │
│  ┌─────────────┐ ┌──────────┐ ┌──────────────┐            │
│  │exploita-    │ │ recon/   │ │ sca/         │            │
│  │tion         │ │          │ │              │            │
│  └─────────────┘ └──────────┘ └──────────────┘            │
│  ┌─────────────┐ ┌──────────┐                              │
│  │ web/        │ │ cvss/    │                              │
│  │             │ │          │                              │
│  └─────────────┘ └──────────┘                              │
├─────────────────────────────────────────────────────────────┤
│  Analysis Engines                                            │
│  ┌─────────────────────┐  ┌──────────────────────────┐     │
│  │ CodeQL Suites       │  │ Semgrep Rules            │     │
│  │ (custom queries)    │  │ (custom rules)           │     │
│  └─────────────────────┘  └──────────────────────────┘     │
├─────────────────────────────────────────────────────────────┤
│  Tiered Expertise System                                     │
│  ┌──────────────────────────────────────────────────┐       │
│  │ 9 Expert Personas + Recovery Protocols            │       │
│  └──────────────────────────────────────────────────┘       │
├─────────────────────────────────────────────────────────────┤
│  Claude Code Integration                                     │
│  ┌─────────────┐ ┌──────────┐ ┌─────────────────────┐      │
│  │ Commands    │ │ Agents   │ │ Skills              │      │
│  │ (21 files)  │ │(16 files)│ │ (multiple skills)   │      │
│  └─────────────┘ └──────────┘ └─────────────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

### Design Principles

1. **One responsibility per package** - Each package has a single, clear purpose
2. **No cross-package imports** - Packages only import from core, not from each other
3. **Standalone executability** - Each agent.py can run independently
4. **Clear CLI interface** - Every package has argparse-based CLI
5. **Progressive disclosure** - Load expertise only when needed (360t → 925t → 2,500t+ tokens)
6. **Modular and extensible** - Easy to add new capabilities

### Directory Structure

```
raptor/
├── core/                    # Shared utilities (14 subdirectories/modules)
│   ├── config.py           # Centralized configuration
│   ├── logging.py          # Structured JSONL logging
│   ├── progress.py         # Progress tracking
│   ├── schema_constants.py # Schema constants
│   ├── understand_bridge.py # Code understanding bridge
│   ├── inventory/          # Source inventory building
│   ├── json/               # JSON utilities
│   ├── project/            # Project management
│   ├── reporting/          # Reporting utilities
│   ├── run/                # Run lifecycle management
│   ├── sarif/              # SARIF parsing
│   ├── startup/            # Startup/banner initialization
│   └── tests/              # Core unit tests
├── packages/               # Security capabilities (15 packages)
├── engine/                 # Analysis engines
│   ├── codeql/suites/      # CodeQL query suites
│   └── semgrep/            # Semgrep rules and config
├── tiers/                  # Expert personas and guidance
│   ├── personas/           # 9 expert persona files
│   └── specialists/        # Specialist knowledge bases
├── docs/                   # Documentation
├── test/                   # Shell-based test scripts
├── tests/                  # Python unit tests
├── .claude/                # Claude Code integration
│   ├── commands/           # 21 slash commands
│   ├── agents/             # 16 agent definitions
│   └── skills/             # Multiple skill modules
├── .github/workflows/      # CI/CD pipelines
├── .devcontainer/          # VS Code dev container
├── raptor.py               # Main unified launcher
├── raptor_agentic.py       # Autonomous workflow (Semgrep + CodeQL)
├── raptor_codeql.py        # CodeQL-only analysis
└── raptor_fuzzing.py       # Binary fuzzing workflow
```

---

## Core Components

### 1. Configuration Management (`core/config.py`)

**Purpose:** Centralized configuration and path management

**Features:**
- Single source of truth for all paths
- Environment variable support (RAPTOR_ROOT)
- Safe environment variable handling (strips dangerous vars)
- Graceful fallback to auto-detection

**Key Methods:**
- `get_raptor_root()` - Get RAPTOR installation root
- `get_out_dir()` - Get output directory
- `get_logs_dir()` - Get logs directory
- `get_safe_env()` - Sanitized environment for subprocesses

### 2. Structured Logging (`core/logging.py`)

**Purpose:** Unified logging with audit trail

**Features:**
- JSONL format for structured logs (machine-readable)
- Console output for human readability
- Timestamped log files (raptor_<timestamp>.jsonl)
- Automatic log directory creation

### 3. SARIF Parser (`core/sarif/parser.py`)

**Purpose:** Parse and extract data from SARIF 2.1.0 files

**Key Functions:**
- `parse_sarif(sarif_path)` - Load and validate SARIF file
- `get_findings(sarif)` - Extract finding list
- `get_severity(result)` - Map SARIF levels to severity

### 4. Source Inventory (`core/inventory/`)

**Purpose:** Build and manage code inventories for analysis

**Components:**
- `builder.py` - build_inventory() with file enumeration + checksums
- `extractors.py` - Language-aware function extraction (12 languages)
- `languages.py` - LANGUAGE_MAP, detect_language
- `exclusions.py` - File exclusion logic + generated file detection
- `diff.py` - compare_inventories() with SHA-256 diffing
- `coverage.py` - checked_by tracking + coverage stats

### 5. Project Management (`core/project/`)

**Purpose:** Manage named workspaces for analysis runs

**Features:**
- Named project workspaces
- Shared directory for analysis runs
- Project status, diff, merge, report, export
- Run lifecycle tracking

### 6. Run Lifecycle (`core/run/`)

**Purpose:** Track analysis run status and metadata

**Features:**
- Output directory management
- Run status tracking (running, complete, failed)
- Metadata persistence (.raptor-run.json)

---

## Security Packages

### 1. Static Analysis (`packages/static-analysis/`)

**Purpose:** Static code analysis using Semgrep

**Entry Point:** `scanner.py`

**Features:**
- Semgrep scanning with configured policy groups
- SARIF output parsing and normalization
- Scan metrics generation (files scanned, findings, severities)
- Multiple policy group support (secrets, owasp, crypto, etc.)

**CLI:**
```bash
python3 packages/static-analysis/scanner.py --repo /path/to/code --policy_groups secrets,owasp
```

**Outputs:**
- `semgrep_<policy>.sarif` - SARIF 2.1.0 findings
- `scan_metrics.json` - Scan statistics

### 2. CodeQL Analysis (`packages/codeql/`)

**Purpose:** Deep CodeQL analysis with autonomous dataflow validation

**Components:**
- `agent.py` - Main CodeQL workflow orchestrator
- `autonomous_analyzer.py` - LLM-powered CodeQL analysis
- `build_detector.py` - Automatic build system detection
- `database_manager.py` - CodeQL database creation/management
- `dataflow_validator.py` - Validates dataflow paths
- `dataflow_visualizer.py` - Generates visual dataflow diagrams
- `language_detector.py` - Programming language detection
- `query_runner.py` - CodeQL query execution

**Features:**
- Automatic language and build system detection
- CodeQL database creation
- Query execution with custom suites
- Dataflow path validation and visualization
- LLM-powered exploitability assessment

**Supported Languages:** Python, Java, C/C++, JavaScript, Go, and more

**CLI:**
```bash
python3 packages/codeql/agent.py --repo /path/to/code --language python
```

**Outputs:**
- `codeql_*.sarif` - CodeQL findings
- `dataflow_*.json` - Validated dataflow paths
- `dataflow_*.svg` - Visual dataflow diagrams

### 3. LLM Analysis (`packages/llm_analysis/`)

**Purpose:** LLM-powered autonomous vulnerability analysis

**Entry Points:**
- `agent.py` - Standalone analysis (OpenAI/Anthropic compatible)
- `orchestrator.py` - Multi-agent coordination (requires Claude Code)
- `crash_agent.py` - Binary crash analysis

**LLM Abstraction:**
```
llm/
├── client.py       # Unified client interface
├── config.py       # API keys, model selection, cost tracking
├── detection.py    # LLM availability detection
├── model_data.py   # Model costs, limits, provider endpoints
└── providers.py    # Provider implementations (Anthropic, OpenAI, etc.)
```

**Features:**
- Provider-agnostic (swap OpenAI ↔ Anthropic ↔ Gemini)
- Configurable via environment variables
- Rate limiting and error handling
- Cost tracking with per-request breakdown
- Structured output with Pydantic validation
- Budget enforcement

**Supported Providers:**
- Anthropic Claude (native structured output)
- OpenAI GPT-4
- Google Gemini/Gemma
- Mistral
- Ollama (local)

**Cost Tracking Example:**
```python
from packages.llm_analysis.llm.config import LLMConfig

config = LLMConfig(
    max_cost_per_scan=1.0  # Prevent exceeding $1 per scan
)
```

### 4. Autonomous Capabilities (`packages/autonomous/`)

**Purpose:** Higher-level autonomous agent capabilities

**Components:**
- `corpus_generator.py` - Intelligent fuzzing corpus generation
- `dialogue.py` - Agent dialogue management (MultiTurnAnalyser)
- `exploit_validator.py` - Automated exploit code validation
- `goal_planner.py` - Goal-oriented task planning
- `memory.py` - Agent memory and context management
- `planner.py` - Task decomposition and planning (FuzzingPlanner)

**Features:**
- Autonomous task planning with LLM reasoning
- Exploit compilation and execution testing
- Context-aware corpus generation
- Persistent memory across interactions
- Multi-turn dialogue for deeper analysis
- Goal-directed operations

### 5. Binary Analysis (`packages/binary_analysis/`)

**Purpose:** Binary crash analysis and debugging using GDB

**Components:**
- `crash_analyser.py` - Main crash context extraction and classification
- `debugger.py` - GDB automation wrapper

**Crash Types Detected:**
- Stack buffer overflows (SIGSEGV with stack address)
- Heap corruption (SIGSEGV with heap address, malloc errors)
- Use-after-free (SIGSEGV on freed memory)
- Integer overflows (SIGFPE, wraparound detection)
- Format string vulnerabilities (SIGSEGV in printf family)
- NULL pointer dereference (SIGSEGV at low addresses)

**Analysis Process:**
1. Run binary under GDB with crash input
2. Capture crash signal and address
3. Extract stack trace and register dump
4. Disassemble crash location
5. Classify crash type based on signal and context

### 6. Fuzzing (`packages/fuzzing/`)

**Purpose:** Binary fuzzing orchestration using AFL++

**Components:**
- `afl_runner.py` - AFL++ process management and monitoring
- `crash_collector.py` - Crash triage, deduplication, and ranking
- `corpus_manager.py` - Seed corpus generation and management

**Features:**
- Parallel fuzzing support (multiple AFL instances)
- Automatic crash deduplication by signal
- Early termination on crash threshold
- Support for AFL-instrumented and QEMU mode binaries
- Coverage analysis with afl-showmap

**CLI:**
```bash
python3 raptor_fuzzing.py --binary /path/to/binary --duration 3600 --max-crashes 10
```

**Outputs:**
- `afl_output/` - AFL++ fuzzing results
- Crash inputs ranked by exploitability

### 7. Exploit Feasibility (`packages/exploit_feasibility/`)

**Purpose:** Analyze system and binary mitigations to determine if exploitation is actually feasible

**Key Innovation:** Answers "Can I actually exploit this?" before attempting exploit development

**Features:**
- Empirical verification (actually tests if techniques work)
- Constraint-aware analysis (null bytes, bad bytes, input handlers)
- Honest verdicts (Likely exploitable / Difficult / Unlikely)
- Context persistence (survives conversation context compaction)
- 275+ unit tests

**Key Questions Answered:**
- Can I actually write to that GOT entry? (Full RELRO blocks both GOT AND .fini_array)
- Will my ROP chain work with strcpy? (No - null bytes in x86_64 addresses)
- Does %n even work on this system? (glibc 2.38+ may block it)
- Are there enough usable gadgets? (Bad bytes may filter out most gadgets)

**API:**
```python
from packages.exploit_feasibility import analyze_binary, format_analysis_summary

result = analyze_binary('/path/to/binary')
print(format_analysis_summary(result, verbose=True))
```

**Output Example:**
```
EXPLOIT FEASIBILITY ANALYSIS
════════════════════════════════════════════════════════════════════════════════
Binary: /home/user/vuln
Verdict: Difficult

PROTECTIONS
────────────────────────────────────────
  PIE:        Yes (binary base randomized)
  NX:         Yes (no shellcode on stack)
  Canary:     Yes (stack smashing protection)
  RELRO:      Full (GOT and .fini_array read-only)

GLIBC MITIGATIONS (version 2.38)
────────────────────────────────────────
  __malloc_hook:     Removed (glibc 2.34+)
  __free_hook:       Removed (glibc 2.34+)
  %n specifier:      BLOCKED (tested empirically)

CHAIN BREAKS
────────────────────────────────────────
  ✗ GOT overwrite blocked by Full RELRO
  ✗ .fini_array blocked by Full RELRO
  ✗ Hook overwrite blocked (hooks removed in glibc 2.34+)
  ✗ Format string %n blocked by glibc
  ✗ Multi-gadget ROP blocked by null bytes in addresses
```

**Dependencies:**
- `pwntools` (binary analysis)
- `ROPgadget` (gadget enumeration)
- `one_gadget` (optional, one-gadget detection)
- `checksec` (optional, binary protection detection)

### 8. Exploitability Validation (`packages/exploitability_validation/`)

**Purpose:** Multi-stage pipeline for validating that vulnerability findings are real, reachable, and exploitable

**Pipeline Stages:**

| Stage | Name | Who | What |
|-------|------|-----|------|
| **0** | Inventory | Python | `build_checklist()` — extract all functions from source |
| **A** | Discovery | LLM | One-shot analysis — identify potential vulnerabilities |
| **B** | Investigation | LLM | Attack trees, hypotheses, systematic evidence gathering |
| **C** | Sanity | LLM | Verify findings against actual code (catch hallucinations) |
| **D** | Ruling | LLM | Final determination — exploitable, confirmed, or ruled out |
| **E** | Feasibility | Python | Binary constraint analysis (memory corruption only) |
| **F** | Review | LLM | Self-review — catch misclassifications, fix schema errors |

**Output Files:**
- `checklist.json` - Stage 0 inventory
- `findings.json` - Stages A-F with progressive enrichment
- `attack-surface.json` - Sources, sinks, trust boundaries
- `attack-tree.json` - Attack knowledge graph
- `hypotheses.json` - Testable predictions
- `disproven.json` - Failed approaches and why
- `attack-paths.json` - Paths tried, PROXIMITY scores, blockers
- `exploit-context.json` - Binary constraints (if binary provided)
- `validation-report.md` - Human-readable summary report

**Integration with exploit_feasibility:**
- Stage E calls `analyze_binary()` from exploit_feasibility package
- Stage E calls `map_findings_to_constraints()` for per-finding verdicts
- Web vulnerabilities (SQLi, XSS, SSRF) skip Stage E and proceed directly to F

### 9. Exploitation (`packages/exploitation/`)

**Purpose:** Exploit development and reporting

**Components:**
- `bootstrap.py` - Exploit bootstrapping
- `reporting.py` - Exploit reporting

### 10. Reconnaissance (`packages/recon/`)

**Purpose:** Reconnaissance and technology enumeration

**Features:**
- Detect programming languages
- Identify frameworks and libraries
- Enumerate dependencies
- Map attack surface
- Generate reconnaissance report

**Output:** `recon_report.json`

### 11. Software Composition Analysis (`packages/sca/`)

**Purpose:** Dependency vulnerability scanning

**Features:**
- Detect dependency files (requirements.txt, package.json, pom.xml, etc.)
- Query vulnerability databases (OSV, NVD, etc.)
- Generate dependency vulnerability reports
- Suggest remediation (version upgrades)

**Output:** `sca_report.json`, `dependencies.json`

### 12. Web Application Testing (`packages/web/`) ⚠️ ALPHA

**Purpose:** Web application security testing

**Components:**
- `client.py` - HTTP client wrapper (session management, headers)
- `crawler.py` - Web crawler (enumerate endpoints)
- `fuzzer.py` - Input fuzzing (injection testing)
- `scanner.py` - Main orchestrator (OWASP Top 10 checks)

**Note:** This is marked as STUB/ALPHA and should not be relied upon

### 13. Diagram Generation (`packages/diagram/`)

**Purpose:** Generate Mermaid visual maps from analysis outputs

**Features:**
- Context map visualization (entry points → trust boundaries → sinks)
- Flow trace visualization (call chains, tainted variables, attacker control)
- Attack tree visualization (knowledge graph with status)
- Attack paths visualization (step chains with proximity scores)

**Integration:** Auto-generated at end of `/validate` and `/understand` commands

**Programmatic Use:**
```python
from packages.diagram import render_and_write
from pathlib import Path

out_file = render_and_write(Path(".out/code-understanding-20240101/"), target="myapp")
```

### 14. CVSS Calculator (`packages/cvss/`)

**Purpose:** CVSS score calculation

**Component:** `calculator.py`

---

## Analysis Engines

### CodeQL Engine (`engine/codeql/`)

**Purpose:** CodeQL query suites and configurations

**Contents:**
- Custom CodeQL query suites for different languages
- Query configurations for taint tracking, security patterns, dataflow analysis

**Usage:** Consumed by `packages/codeql/` for automated CodeQL scanning

### Semgrep Engine (`engine/semgrep/`)

**Purpose:** Semgrep rules and configurations

**Custom Rules:**
- `auth/tls-skip-verify.yaml` - TLS verification bypass detection
- `crypto/` - 8 crypto-related rules (weak-hash, weak-block-modes, weak-kdf-*, etc.)
- `deserialisation/unsafe-java-deserialize.yaml` - Java deserialization vulnerabilities
- `filesystem/path-traversal.yaml` - Path traversal detection
- `flows/bad-mac-order.yaml` - MAC computation order issues
- `injection/command-taint.yaml`, `sql-concat.yaml` - Command injection, SQL injection
- `logging/logs-secrets.yaml` - Secrets in logs detection
- `secrets/hardcoded-api-key.yaml` - Hardcoded API keys
- `sinks/ssrf.yaml` - Server-Side Request Forgery

**Configuration:** `semgrep.yaml` - Main Semgrep configuration

**Usage:** Consumed by `packages/static-analysis/scanner.py` for Semgrep scanning

---

## LLM Integration

### Supported Providers

| Provider | Model Support | Cost | Structured Output |
|----------|--------------|------|-------------------|
| **Anthropic Claude** | claude-opus-4-6, etc. | ~$0.03/vuln | ✅ Native |
| **OpenAI GPT-4** | GPT-4, etc. | ~$0.03/vuln | ✅ Via Instructor |
| **Google Gemini** | Gemini 2.5, Gemma 4 | ~$0.03/vuln | ✅ Native SDK |
| **Mistral** | Various | Varies | ✅ Via OpenAI SDK |
| **Ollama (local)** | llama3:70b, etc. | FREE | ⚠️ Limited |

**Note:** Exploit generation requires frontier models (Claude, GPT, or Gemini). Local models work for analysis but may produce non-compilable exploit code.

### Cost Management

**Features:**
- Budget enforcement (prevents exceeding cost limits)
- Real-time cost tracking with detailed error messages
- Intelligent rate limit detection with provider-specific guidance
- Split input/output pricing with per-request breakdown
- Smart model selection from config or environment

**Configuration:**
```json
// ~/.config/raptor/models.json
{
  "models": [
    {"provider": "anthropic", "model": "claude-opus-4-6", "api_key": "sk-ant-..."},
    {"provider": "ollama", "model": "llama3:70b"}
  ]
}
```

**Environment Variables:**
- `ANTHROPIC_API_KEY` - Anthropic Claude API key
- `OPENAI_API_KEY` - OpenAI API key
- `GEMINI_API_KEY` - Google Gemini API key
- `MISTRAL_API_KEY` - Mistral API key
- `OLLAMA_HOST` - Ollama server URL (default: `http://localhost:11434`)
- `RAPTOR_CONFIG` - Path to RAPTOR models JSON configuration file

### Structured Output

**Implementation:** Instructor + Pydantic fallback for reliable JSON responses

**Benefits:**
- Consistent output format across providers
- Schema validation for critical data
- Graceful degradation when models don't support native structured output

---

## Key Features

### 1. Adversarial Code Understanding

**Command:** `/understand <target> [--map] [--trace <entry>] [--hunt <pattern>] [--teach <subject>]`

**Modes:**
- `--map` — Build context: entry points, trust boundaries, sinks → `context-map.json`
- `--trace <entry>` — Follow one data flow source → sink with full call chain → `flow-trace-<id>.json`
- `--hunt <pattern>` — Find all variants of a pattern across the codebase → `variants.json`
- `--teach <subject>` — Explain a framework, library, or pattern in depth (inline)

**Skills:**
- `map.md` — Entry point enumeration, trust boundary mapping, sink catalog
- `trace.md` — Step-by-step data flow tracing with branch coverage
- `hunt.md` — Structural, semantic, and root-cause variant analysis
- `teach.md` — Framework/pattern explanation with security conclusion

### 2. OSS Forensics Investigation

**Command:** `/oss-forensics <prompt> [--max-followups 3] [--max-retries 3]`

**Capabilities:**
- Evidence Collection: Multi-source evidence gathering (GH Archive, GitHub API, Wayback Machine, local git)
- BigQuery Integration: Query immutable GitHub event data via GH Archive
- Deleted Content Recovery: Recover deleted commits, issues, and repository content
- IOC Extraction: Automated extraction of indicators of compromise from vendor reports
- Evidence Verification: Rigorous evidence validation against original sources
- Hypothesis Formation: AI-powered evidence-backed hypothesis generation with iterative refinement
- Forensic Reporting: Detailed reports with timeline, attribution, and IOCs

**Agents:**
- `oss-forensics-agent` - Main orchestrator
- `oss-investigator-gh-archive-agent` - Queries GH Archive via BigQuery
- `oss-investigator-gh-api-agent` - Queries live GitHub API
- `oss-investigator-gh-recovery-agent` - Recovers deleted content
- `oss-investigator-local-git-agent` - Analyzes cloned repos for dangling commits
- `oss-investigator-ioc-extractor-agent` - Extracts IOCs from vendor reports
- `oss-hypothesis-former-agent` - Forms evidence-backed hypotheses
- `oss-evidence-verifier-agent` - Verifies evidence
- `oss-hypothesis-checker-agent` - Validates claims
- `oss-report-generator-agent` - Produces final forensic report

**Requirements:** `GOOGLE_APPLICATION_CREDENTIALS` for BigQuery

### 3. Crash Analysis

**Command:** `/crash-analysis <bug-tracker-url> <git-repo-url>`

**Capabilities:**
- Autonomous root-cause analysis for C/C++ crashes
- Deterministic record-replay debugging with rr
- Function execution traces
- Code coverage analysis with gcov
- Fast line execution queries

**Requirements:** rr, gcc/clang (with ASAN), gdb, gcov

### 4. Expert Personas (9 Total)

Load on-demand via "Use [persona name]":

1. **Mark Dowd** - Binary exploitation specialist
2. **Charlie Miller/Halvar Flake** - Security researcher
3. **Security Researcher** - General security research
4. **Patch Engineer** - Secure patch development
5. **Penetration Tester** - Penetration testing methodology
6. **Fuzzing Strategist** - Fuzzing strategy development
7. **Binary Exploitation Specialist** - Binary exploitation expertise
8. **CodeQL Dataflow Analyst** - CodeQL query development
9. **CodeQL Finding Analyst** - CodeQL finding analysis

### 5. Claude Code Integration

**Commands (21 total):**
- `/raptor` - RAPTOR security testing assistant (start here)
- `/scan` - Static code analysis (Semgrep + CodeQL + LLM)
- `/fuzz` - Binary fuzzing (AFL++ + crash analysis)
- `/web` - Web application security testing (STUB - treat as alpha)
- `/agentic` - Full autonomous workflow (analysis + exploit/patch generation)
- `/codeql` - CodeQL-only deep analysis with dataflow
- `/analyze` - LLM analysis only (no exploit/patch generation - 50% faster & cheaper)
- `/validate` - Exploitability validation pipeline
- `/exploit` - Generate exploit proof-of-concepts (beta)
- `/patch` - Generate security patches for vulnerabilities (beta)
- `/understand` - Adversarial code comprehension
- `/oss-forensics` - Evidence-backed forensic investigation
- `/crash-analysis` - Autonomous crash root-cause analysis
- `/diagram` - Generate Mermaid visual maps
- `/project` - Project management
- `/create-skill` - Save custom approaches (experimental)
- `/test-workflows` - Run comprehensive test suite (stub)
- `/commands` - Show all available commands

**Agents (16 total):**
- `crash-analysis-agent` - Main crash analysis orchestrator
- `crash-analyzer-agent` - Deep root-cause analysis using rr traces
- `crash-analyzer-checker-agent` - Validates analysis rigorously
- `function-trace-generator-agent` - Creates function execution traces
- `coverage-analysis-generator-agent` - Generates gcov coverage data
- `exploitability-validator-agent` - Validates exploitability
- `offsec-specialist` - Offensive security specialist with SecOpsAgentKit
- Various OSS investigation agents

### 6. Project Management

**Commands:**
```
/project create myapp --target /path/to/code -d "Description"
/project use myapp
/scan                          # output goes to project dir
/project status                # shows all runs and findings
/project report                # merged view across all runs
/project clean --keep 3        # delete old runs
```

**Features:**
- Opt-in named workspaces
- Shared directory for analysis runs
- Project status, diff, merge, report, export

### 7. Security: Untrusted Repos

**Protection Against:**
- Malicious `.claude/settings.json` files in repos
- Environment variable injection (TERMINAL, EDITOR, VISUAL, BROWSER, PAGER)
- File path injection from scanned repos

**Safeguards:**
- Blocks Claude Code sub-agent dispatch if malicious settings found
- `RaptorConfig.get_safe_env()` strips dangerous environment variables
- List-based subprocess arguments (no string interpolation)
- Uses `--add-dir` for sub-agents (file access only, no settings loading)

### 8. Run Lifecycle Management

**Before starting work:**
```bash
OUTPUT_DIR=$(python3 -m core.run start <command> --target <resolved_target>)
```

**After successful completion:**
```bash
python3 -m core.run complete "$OUTPUT_DIR"
```

**On failure:**
```bash
python3 -m core.run fail "$OUTPUT_DIR" "error description"
```

### 9. Multi-Model Consensus

When configured, RAPTOR can use multiple LLM models for consensus analysis, improving confidence in findings and reducing false positives.

### 10. Cross-Finding Analysis

Structural grouping of findings to identify shared root causes and systemic issues.

---

## Technical Stack

### Programming Languages

- **Python 3.9+** - Primary language for all orchestration and analysis
- **C/C++** - Test fixtures and crash analysis tools
- **JavaScript** - Test fixtures for web scanning
- **Shell (Bash)** - Test scripts

### Core Dependencies

**Required:**
- `requests>=2.31.0` - HTTP requests
- `pydantic>=2.9.2` - Data validation and structured output
- `instructor>=1.0.0` - Structured output for LLMs

**Optional:**
- `openai` - OpenAI, Gemini (via shim), Mistral, Ollama support
- `anthropic` - Anthropic Claude support (native structured output)
- `google-genai` - Google Gemini native SDK (accurate thinking token costs)
- `tabulate>=0.9.0` - Enhanced dataflow visualization
- `tree-sitter` + language grammars - Enhanced inventory metadata
- `beautifulsoup4>=4.12.0` - Web scanning
- `playwright>=1.40.0` - Web automation

### External Tools

**Required:**
- **Semgrep** (LGPL 2.1) - Static analysis scanner
  - Install: `pip install semgrep`

**Optional:**
- **AFL++** (Apache 2.0) - Binary fuzzer
  - Install: `brew install afl++` or `apt install afl++`
- **CodeQL** (GitHub Terms) - Semantic code analysis
  - Install: Download from GitHub
  - Note: Free for security research, restrictions on commercial use
- **Ollama** (MIT) - Local or remote model server
  - Install: Download from https://ollama.ai
- **rr** (MIT) - Record-replay debugger (Linux only, x86_64)
  - Install: `apt install rr` or build from source
- **gcov** (GPL) - Code coverage (bundled with gcc)
- **AddressSanitizer** (Apache 2.0) - Memory error detector (built into gcc >= 4.8, clang >= 3.1)
- **Google Cloud BigQuery** - For OSS forensics
  - Setup: Requires `GOOGLE_APPLICATION_CREDENTIALS`

**System Tools (pre-installed on most systems):**
- **LLDB** (Apache 2.0) - macOS debugger (Xcode Command Line Tools)
- **GDB** (GPL v3) - Linux debugger
- **GNU Binutils** (GPL v3) - nm, addr2line, objdump, file, strings

### Development Tools

**CI/CD:**
- GitHub Actions workflows for Python tests
- GitHub Actions workflows for Bash tests
- GitHub CodeQL scanning

**Dev Container:**
- VS Code Dev Container with all prerequisites pre-installed
- ~6GB Docker image based on Microsoft Python 3.12 devcontainer
- Includes: Semgrep, CodeQL v2.15.5, AFL++, rr, gcc, g++, clang, make, cmake, autotools, gdb, binutils
- Web testing: Playwright browser automation (Chromium, Firefox, Webkit)
- Note: Requires `--privileged` flag for rr debugger

**Testing:**
- Python unit tests with pytest
- Shell-based integration tests
- 275+ tests in exploit_feasibility package
- 207+ tests in exploitability_validation package

---

## Project Statistics

### Code Metrics

| Metric | Count |
|--------|-------|
| Python files (.py) | 258 |
| Markdown files (.md) | 105 |
| Shell scripts (.sh) | 7 |
| YAML configuration files | 13 |
| Total directories | ~80+ |

### Package Breakdown

| Package | Key Files | Tests | Purpose |
|---------|-----------|-------|---------|
| `static-analysis` | 2 | - | Semgrep scanning |
| `codeql` | 8 | - | CodeQL deep analysis |
| `llm_analysis` | 12 | - | LLM vulnerability analysis |
| `autonomous` | 6 | - | Autonomous planning & memory |
| `fuzzing` | 3 | - | AFL++ fuzzing orchestration |
| `binary_analysis` | 2 | - | GDB crash analysis |
| `exploit_feasibility` | 24 | 275+ | Binary exploit feasibility |
| `exploitability_validation` | 5 | 207+ | Multi-stage validation pipeline |
| `exploitation` | 2 | - | Exploit development & reporting |
| `recon` | 1 | - | Technology enumeration |
| `sca` | 1 | - | Dependency vulnerability scanning |
| `web` | 4 | - | Web application testing (ALPHA) |
| `diagram` | 8 | - | Mermaid visualization |
| `cvss` | 1 | - | CVSS score calculation |

### Core Module Breakdown

| Module | Key Files | Purpose |
|--------|-----------|---------|
| `config` | 1 | Configuration management |
| `logging` | 1 | Structured JSONL logging |
| `progress` | 1 | Progress tracking |
| `inventory` | 7 | Source inventory building |
| `json` | 1 | JSON utilities |
| `project` | 10 | Project management |
| `reporting` | 5 | Reporting utilities |
| `run` | 3 | Run lifecycle management |
| `sarif` | 2 | SARIF parsing |
| `startup` | 3 | Startup/banner initialization |

### Claude Code Integration

| Type | Count | Purpose |
|------|-------|---------|
| Commands | 21 | User-facing slash commands |
| Agents | 16 | Autonomous agent definitions |
| Skills | Multiple | Reusable capability modules |
| Personas | 9 | Expert persona files |

### Documentation

| Category | Count | Examples |
|----------|-------|----------|
| User Guides | 7+ | CLAUDE_CODE_USAGE.md, PYTHON_CLI.md, FUZZING_QUICKSTART.md |
| Architecture Docs | 4+ | ARCHITECTURE.md, EXTENDING_LAUNCHER.md, VISUAL_DESIGN.md |
| Package Docs | 4+ | Per-package README files |
| Tier Docs | 5+ | analysis-guidance.md, recovery.md, persona files |

---

## Strengths

### 1. **Innovative Approach to Security Testing**
RAPTOR combines traditional security tools with autonomous AI reasoning, providing a unique approach to vulnerability discovery and validation.

### 2. **Exploit Feasibility Analysis**
The `exploit_feasibility` package is a standout feature that prevents wasted effort on architecturally impossible exploits. It empirically verifies whether exploitation techniques will work.

### 3. **Multi-Stage Validation Pipeline**
The 7-stage validation pipeline (0→A→B→C→D→E→F) ensures that only real, reachable, exploitable vulnerabilities are reported.

### 4. **Modular Architecture**
Clean separation of concerns with no cross-package imports. Each package is independently executable with clear CLI interfaces.

### 5. **Cost Management**
Built-in budget enforcement, real-time cost tracking, and intelligent rate limit detection prevent runaway costs.

### 6. **Multi-Provider LLM Support**
Works with multiple LLM providers, avoiding vendor lock-in. Supports both cloud and local models.

### 7. **Comprehensive Tool Integration**
Integrates industry-standard tools (Semgrep, CodeQL, AFL++, rr) with autonomous AI analysis.

### 8. **Progressive Disclosure**
Loads expert personas only when needed, optimizing context usage and improving efficiency.

### 9. **Security-Conscious Design**
Protects against malicious repo settings, environment variable injection, and file path injection.

### 10. **Strong Documentation**
Extensive documentation with quickstarts, architecture guides, package READMEs, and inline code comments.

### 11. **OSS Forensics Capabilities**
Unique GitHub forensics capabilities with BigQuery integration, evidence collection, and hypothesis formation.

### 12. **Dev Container Support**
Pre-configured dev container with all dependencies eliminates setup friction.

---

## Areas for Improvement

### 1. **Web Application Testing (Alpha)**
The `/web` command is marked as STUB/ALPHA and should not be relied upon. This is a gap in coverage compared to other capabilities.

**Recommendation:** Enhance web scanning capabilities or clearly document limitations.

### 2. **Context Size Management**
The framework acknowledges it was "held together by vibe coding and duct tape" and is an "early release." Context management for large codebases could be challenging.

**Recommendation:** Implement better context window optimization strategies.

### 3. **Local Model Limitations**
Local models (Ollama) work for analysis but may produce non-compilable exploit code, limiting offline capabilities.

**Recommendation:** Document model quality thresholds for different tasks.

### 4. **Test Coverage**
While exploit_feasibility and exploitability_validation have good test coverage (275+ and 207+ tests respectively), other packages appear to have minimal test coverage.

**Recommendation:** Increase unit test coverage across all packages.

### 5. **Dev Container Size**
The dev container is massive (~6GB) which may be prohibitive for some users.

**Recommendation:** Consider slimmed-down variants for users who don't need all tools.

### 6. **CodeQL Licensing**
CodeQL does not allow commercial use, which limits RAPTOR's applicability in commercial settings.

**Recommendation:** Clearly document licensing restrictions and explore alternatives for commercial users.

### 7. **Platform Support**
The `rr` debugger is Linux only (x86_64), limiting crash analysis capabilities on macOS and other platforms.

**Recommendation:** Document platform limitations and provide alternatives.

### 8. **Dependency Management**
Auto-downloading of tools without explicit user consent could be unexpected behavior.

**Recommendation:** Add explicit confirmation before auto-installing tools.

---

## Security Considerations

### Positive Security Features

1. **Environment Sanitization**
   - `RaptorConfig.get_safe_env()` strips dangerous environment variables (TERMINAL, EDITOR, VISUAL, BROWSER, PAGER)
   - Prevents environment variable injection attacks

2. **Untrusted Repository Protection**
   - Detects malicious `.claude/settings.json` files in target repos
   - Blocks Claude Code sub-agent dispatch for repos with dangerous credential helpers
   - Uses `--add-dir` for sub-agents (file access only, no settings loading)

3. **File Path Injection Prevention**
   - Uses list-based subprocess arguments instead of string interpolation
   - Prevents command injection from untrusted file paths

4. **Explicit User Confirmation**
   - Dangerous operations (apply patches, delete, git push) require user confirmation
   - Safe operations (install, scan, read, generate) auto-execute

5. **CVE Awareness**
   - Documents CVE-2026-21852 (Phoenix Security CWE-78 disclosure)
   - Proactively checks for Claude Code credential helper injection

### Potential Security Concerns

1. **Auto-Installation Behavior**
   - RAPTOR will automatically install tools without asking (unless using devcontainer)
   - Could introduce unexpected binaries or dependencies

2. **API Key Management**
   - Requires API keys for LLM providers (Anthropic, OpenAI, Google, Mistral)
   - Keys stored in environment variables or config files

3. **Privileged Container Access**
   - Dev container runs with `--privileged` flag for rr debugger
   - Increases attack surface of the development environment

4. **External Tool Dependencies**
   - Relies on external tools (Semgrep, CodeQL, AFL++) with their own security postures
   - Users must review licenses and security implications of each tool

---

## Recommendations

### For Users

1. **Use the Dev Container**
   - Provides isolated environment with all dependencies
   - Eliminates setup friction and potential security issues from auto-installation

2. **Review Tool Licenses**
   - Carefully review licenses for Semgrep (LGPL 2.1), CodeQL (GitHub Terms), and GPL tools
   - CodeQL does not allow commercial use

3. **Set Budget Limits**
   - Configure `max_cost_per_scan` in LLMConfig to prevent unexpected costs
   - Monitor cost tracking for each analysis run

4. **Start with Test Repos**
   - Use provided test data in `/tests/data` to familiarize yourself with RAPTOR
   - Try `/analyze` command before running full `/scan` or `/agentic` workflows

5. **Use Exploit Feasibility Analysis**
   - Always run `analyze_binary()` before attempting exploit development
   - Review `exploitation_paths` section to understand what's actually possible

### For Contributors

1. **Increase Test Coverage**
   - Add unit tests for packages with minimal coverage
   - Target: 80%+ code coverage across all packages

2. **Enhance Web Scanning**
   - Complete the `/web` command implementation
   - Add comprehensive OWASP Top 10 testing

3. **Improve Documentation**
   - Add more examples to package READMEs
   - Document edge cases and known limitations

4. **Add More Semgrep Rules**
   - Contribute custom Semgrep rules for additional vulnerability categories
   - Rules in `engine/semgrep/rules/` are MIT licensed

5. **Optimize Context Management**
   - Implement better context window optimization
   - Add progressive loading strategies for large codebases

6. **Add CI/CD Integration**
   - Provide examples for integrating RAPTOR into CI/CD pipelines
   - Document usage with popular CI systems (GitHub Actions, GitLab CI, Jenkins)

7. **Improve Error Recovery**
   - Enhance recovery protocols in `tiers/recovery.md`
   - Add automatic retry logic for transient failures

### For Future Development

1. **Commercial Use Support**
   - Explore alternatives to CodeQL for commercial users
   - Document licensing workarounds

2. **Multi-Language Support**
   - Expand language support beyond current 12 languages
   - Add support for mobile app analysis (iOS, Android)

3. **Real-Time Monitoring**
   - Add continuous monitoring capabilities
   - Integrate with SIEM systems for enterprise use

4. **Collaborative Features**
   - Add support for team-based analysis
   - Enable sharing of findings and exploits across teams

5. **Performance Optimization**
   - Implement caching strategies for repeated scans
   - Optimize parallel execution for better throughput

---

## Conclusion

RAPTOR represents a significant advancement in autonomous security research. By combining traditional security tools (Semgrep, CodeQL, AFL++) with LLM-powered autonomous analysis, it provides a comprehensive platform for vulnerability discovery, validation, exploit generation, and patching.

**Key Differentiators:**
- Exploit feasibility analysis prevents wasted effort on impossible exploits
- Multi-stage validation pipeline ensures findings are real and exploitable
- Cost management prevents runaway LLM costs
- Progressive disclosure of expert personas optimizes context usage
- Strong security posture protects against malicious repos

**Target Audience:**
- Security researchers
- Penetration testers
- Code reviewers
- DevSecOps engineers
- Open-source maintainers

**Maturity Level:** Beta/Early Release
- Self-described as "held together by vibe coding and duct tape"
- Core functionality is solid and well-tested
- Some features (web scanning) are still alpha/stub
- Strong foundation for community contributions

**Bottom Line:** RAPTOR is a powerful, innovative framework that demonstrates how AI can augment security testing. While it has areas for improvement, its modular architecture and strong core capabilities make it a valuable tool for security research. The community is invited to contribute and help shape RAPTOR into a transformative security research platform.

---

## Appendix A: Quick Reference

### Installation

```bash
# Clone repository
git clone https://github.com/gadievron/raptor.git
cd raptor

# Install dependencies
pip install -r requirements.txt
pip install semgrep

# Set API keys
export ANTHROPIC_API_KEY=sk-ant-...
export OPENAI_API_KEY=sk-...

# Or use devcontainer
docker build -f .devcontainer/Dockerfile -t raptor-devcontainer:latest .
```

### Common Commands

```bash
# Full autonomous workflow
python3 raptor.py agentic --repo /path/to/code

# Static analysis only
python3 raptor.py scan --repo /path/to/code --policy_groups secrets,owasp

# Binary fuzzing
python3 raptor.py fuzz --binary /path/to/binary --duration 3600

# CodeQL analysis
python3 raptor.py codeql --repo /path/to/code --languages java

# LLM analysis of SARIF
python3 raptor.py analyze --repo /path/to/code --sarif findings.sarif

# Exploit feasibility check
python3 -c "from packages.exploit_feasibility import analyze_binary; print(analyze_binary('/path/to/binary'))"
```

### Claude Code Commands

```
/raptor    - Start RAPTOR assistant
/scan      - Static code analysis
/fuzz      - Binary fuzzing
/web       - Web application testing (STUB)
/agentic   - Full autonomous workflow
/codeql    - CodeQL-only deep analysis
/analyze   - LLM analysis only (50% faster & cheaper)
/validate  - Exploitability validation pipeline
/exploit   - Generate exploit PoCs (beta)
/patch     - Generate security patches (beta)
/understand - Adversarial code comprehension
/oss-forensics - GitHub forensic investigation
/crash-analysis - Autonomous crash analysis
/diagram   - Generate Mermaid visual maps
/project   - Project management
```

---

## Appendix B: File Structure Summary

```
raptor/
├── 📄 Core Entry Points (4 files)
│   ├── raptor.py              - Main unified launcher
│   ├── raptor_agentic.py      - Autonomous workflow (Semgrep + CodeQL)
│   ├── raptor_codeql.py       - CodeQL-only analysis
│   └── raptor_fuzzing.py      - Binary fuzzing workflow
├── 📦 Core Modules (14 files/dirs)
│   ├── config.py              - Configuration management
│   ├── logging.py             - Structured JSONL logging
│   ├── progress.py            - Progress tracking
│   ├── inventory/             - Source inventory (7 files)
│   ├── json/                  - JSON utilities
│   ├── project/               - Project management (10 files)
│   ├── reporting/             - Reporting utilities (5 files)
│   ├── run/                   - Run lifecycle (3 files)
│   ├── sarif/                 - SARIF parsing (2 files)
│   └── startup/               - Startup initialization (3 files)
├── 🛡️ Security Packages (15 packages)
│   ├── static-analysis/       - Semgrep scanning (2 files)
│   ├── codeql/                - CodeQL analysis (8 files)
│   ├── llm_analysis/          - LLM analysis (12 files)
│   ├── autonomous/            - Autonomous capabilities (6 files)
│   ├── fuzzing/               - AFL++ fuzzing (3 files)
│   ├── binary_analysis/       - GDB crash analysis (2 files)
│   ├── exploit_feasibility/   - Exploit feasibility (24 files, 275+ tests)
│   ├── exploitability_validation/ - Validation pipeline (5 files, 207+ tests)
│   ├── exploitation/          - Exploit development (2 files)
│   ├── recon/                 - Technology enumeration (1 file)
│   ├── sca/                   - Dependency scanning (1 file)
│   ├── web/                   - Web testing (4 files, ALPHA)
│   ├── diagram/               - Visualization (8 files)
│   └── cvss/                  - CVSS calculation (1 file)
├── 🔧 Analysis Engines (2 engines)
│   ├── codeql/suites/         - CodeQL query suites
│   └── semgrep/               - Semgrep rules (13+ custom rules)
├── 🎓 Expert System
│   ├── tiers/personas/        - 9 expert persona files
│   └── tiers/specialists/     - Specialist knowledge bases
├── 🤖 Claude Code Integration
│   ├── commands/              - 21 slash commands
│   ├── agents/                - 16 agent definitions
│   └── skills/                - Multiple reusable skills
├── 📚 Documentation (15+ files)
│   ├── README.md              - Main documentation
│   ├── CLAUDE.md              - Claude Code instructions
│   ├── DEPENDENCIES.md        - External tools and licenses
│   └── docs/                  - Detailed guides (7+ files)
├── 🧪 Testing
│   ├── test/                  - Shell-based tests (7 scripts)
│   └── tests/                 - Python unit tests
├── 🐳 Dev Container
│   ├── .devcontainer/         - VS Code dev container config
│   └── Dockerfile             - ~6GB Docker image
└── 📋 CI/CD
    └── .github/workflows/     - GitHub Actions (2 workflows)
```

---

**End of Report**

*This report provides a comprehensive analysis of the RAPTOR project as of April 11, 2026. For the most current information, refer to the project repository at https://github.com/gadievron/raptor*