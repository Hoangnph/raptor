# Appendices - Phụ Lục Tham Khảo

**Tổng Hợp Từ Source Code Thực Tế**

---

## Mục Lục

1. [API Reference](#api-reference)
2. [Data Models](#data-models)
3. [Glossary](#glossary)
4. [Resources](#resources)

---

## API Reference

### Core APIs

#### RaptorConfig (`core/config.py`)

```python
class RaptorConfig:
    @staticmethod
    def get_raptor_root() -> Path:
        """Get RAPTOR installation root"""

    @staticmethod
    def get_out_dir() -> Path:
        """Get output directory"""

    @staticmethod
    def get_logs_dir() -> Path:
        """Get logs directory"""

    @staticmethod
    def get_safe_env() -> dict:
        """Get sanitized environment for subprocesses"""

    # Constants
    OLLAMA_HOST: str = "http://localhost:11434"
    MAX_SEMGREP_WORKERS: int = 4
```

#### Logging (`core/logging.py`)

```python
def get_logger(name: str = "raptor") -> logging.Logger:
    """Get configured logger with JSONL audit trail"""

def log_security_event(event_type: str, details: dict) -> None:
    """Log security-relevant event"""
```

#### Run Lifecycle (`core/run/`)

```python
def get_output_dir(command: str, target_path: str = None,
                   explicit_out: Path = None) -> Path:
    """Resolve output directory"""

def start_run(out_dir: Path, command: str) -> None:
    """Mark run as started"""

def complete_run(out_dir: Path) -> None:
    """Mark run as completed"""

def fail_run(out_dir: Path, error: str) -> None:
    """Mark run as failed"""
```

#### SARIF Parser (`core/sarif/parser.py`)

```python
def load_sarif(path: Path, max_size: int = 100_000_000) -> dict:
    """Load SARIF file with size guard"""

def parse_sarif_findings(sarif: dict) -> list:
    """Extract findings from SARIF"""

def deduplicate_findings(findings: list) -> list:
    """Remove duplicate findings"""

def extract_cwe(rule: dict) -> str:
    """Extract CWE ID from rule"""

def extract_dataflow_path(result: dict) -> list:
    """Extract dataflow path from result"""
```

### Security Package APIs

#### Exploit Feasibility

```python
from packages.exploit_feasibility import (
    analyze_binary,
    check_exploit_viability,
    format_analysis_summary,
    save_exploit_context,
    load_exploit_context,
    map_findings_to_constraints,
)

result = analyze_binary('/path/to/binary')
print(format_analysis_summary(result, verbose=True))
```

#### Exploitability Validation

```python
from packages.exploitability_validation import (
    build_checklist,
    run_validation_phase,
)

checklist = build_checklist('/path/to/code', '/path/to/output')
report, findings = run_validation_phase(
    repo_path='/path/to/code',
    out_dir=Path('out/validation'),
    sarif_files=[Path('combined.sarif')],
)
```

#### LLM Client

```python
from packages.llm_analysis.llm.client import LLMClient
from packages.llm_analysis.llm.config import LLMConfig

config = LLMConfig(max_cost_per_scan=1.0)
client = LLMClient(config)

# Generate text
response = client.generate("Analyze this code...")

# Generate structured output
result, raw = client.generate_structured(
    "Analyze vulnerability...",
    schema={"is_exploitable": "boolean", "score": "number"}
)
```

---

## Data Models

### LLMAvailability

```python
@dataclass
class LLMAvailability:
    external_llm: bool   # SDK + API key reachable
    claude_code: bool    # Running inside CC or 'claude' on PATH
    llm_available: bool  # external_llm or claude_code
```

### ModelConfig

```python
@dataclass
class ModelConfig:
    provider: str              # "anthropic", "openai", "gemini", "mistral", "ollama"
    model_name: str
    api_key: Optional[str] = None
    api_base: Optional[str] = None
    max_tokens: int = 4096
    max_context: int = 32000
    temperature: float = 0.7
    timeout: int = 120
    cost_per_1k_tokens: float = 0.0
    enabled: bool = True
    role: Optional[str] = None  # "analysis", "code", "consensus", "fallback"
```

### LLMResponse

```python
@dataclass
class LLMResponse:
    content: str
    model: str
    provider: str
    tokens_used: int
    cost: float
    finish_reason: str
    input_tokens: int = 0
    output_tokens: int = 0
    thinking_tokens: int = 0
    duration: float = 0.0
```

### BinaryContext

```python
@dataclass
class BinaryContext:
    path: Path
    arch: str                    # "x86_64", "i386", "arm"
    bits: int                    # 32 or 64
    pie: bool
    nx: bool
    canary: bool
    relro: str                   # "None", "Partial", "Full"
    libc_version: str
    input_handler: str
    bad_bytes: List[int]
    total_gadgets: int
    usable_gadgets: int
```

### Finding

```python
@dataclass
class Finding:
    finding_id: str
    rule_id: str
    file: str
    line: int
    vulnerability_type: str
    status: str = "pending"

    llm_analysis: Optional[LLMAnalysis] = None
    sanity_check: Optional[SanityCheck] = None
    ruling: Optional[Ruling] = None
    feasibility: Optional[Feasibility] = None
    review: Optional[Review] = None

    proofs: List[Proof] = field(default_factory=list)
    pocs: List[PoC] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
```

---

## Glossary

### Thuật Ngữ Bảo Mật

| Thuật Ngữ | Giải Thích |
|-----------|-----------|
| **SARIF** | Static Analysis Results Interchange Format (JSON-based) |
| **CWE** | Common Weakness Enumeration |
| **CVSS** | Common Vulnerability Scoring System |
| **PIE** | Position Independent Executable |
| **NX** | No-eXecute (stack non-executable) |
| **RELRO** | Relocation Read-Only |
| **ROP** | Return-Oriented Programming |
| **GOT** | Global Offset Table |
| **ASAN** | AddressSanitizer |
| **IOC** | Indicator of Compromise |

### Thuật Ngữ RAPTOR

| Thuật Ngữ | Giải Thích |
|-----------|-----------|
| **Agentic** | Autonomous workflow with LLM reasoning |
| **Persona** | Expert knowledge file for specialized analysis |
| **Skill** | Reusable capability module for Claude Code |
| **Tier** | Progressive loading level for expert knowledge |
| **Stage** | Step in validation pipeline (0→F) |
| **PROXIMITY** | Score 0-10 for how close to successful exploitation |
| **Dispatch** | Parallel LLM task execution |
| **Fallback** | Automatic model switching on failure |

### Thuật Ngữ LLM

| Thuật Ngữ | Giải Thích |
|-----------|-----------|
| **Provider** | LLM service (Anthropic, OpenAI, etc.) |
| **Token** | Unit of text (~4 chars) |
| **Context Window** | Max tokens model can process |
| **Thinking Tokens** | Reasoning tokens (billed as output) |
| **Structured Output** | JSON output matching schema |
| **Instructor** | Library for reliable structured output |

---

## Resources

### Official Links

- **Repository:** https://github.com/gadievron/raptor
- **Issues:** https://github.com/gadievron/raptor/issues
- **Slack:** #raptor channel at Prompt||GTFO

### External Tools

| Tool | Link | License |
|------|------|---------|
| Semgrep | https://github.com/semgrep/semgrep | LGPL 2.1 |
| CodeQL | https://github.com/github/codeql-cli-binaries | GitHub Terms |
| AFL++ | https://github.com/AFLplusplus/AFLplusplus | Apache 2.0 |
| rr | https://github.com/rr-debugger/rr | MIT |
| Ollama | https://ollama.ai | MIT |

### LLM Providers

| Provider | Link | SDK |
|----------|------|-----|
| Anthropic | https://anthropic.com | `pip install anthropic` |
| OpenAI | https://openai.com | `pip install openai` |
| Google Gemini | https://ai.google.dev | `pip install google-genai` |
| Mistral | https://mistral.ai | Via OpenAI SDK |

### Documentation

| Doc | Location |
|-----|----------|
| Architecture | `docs/ARCHITECTURE.md` |
| Usage Guide | `docs/CLAUDE_CODE_USAGE.md` |
| Python CLI | `docs/PYTHON_CLI.md` |
| Dependencies | `DEPENDENCIES.md` |
| Exploit Feasibility | `packages/exploit_feasibility/README.md` |
| Validation Pipeline | `packages/exploitability_validation/README.md` |

---

**Kết thúc bộ tài liệu Harness Analytics**

*Toàn bộ nội dung được xác minh từ source code thực tế của dự án RAPTOR*
