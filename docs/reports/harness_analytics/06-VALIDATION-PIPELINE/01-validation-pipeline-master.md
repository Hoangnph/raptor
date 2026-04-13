# Validation Pipeline - Pipeline Xác Thực Khả Năng Exploit

**Multi-Stage Evidence-Based Validation**

---

## Mục Lục

1. [Tổng Quan Pipeline](#tổng-quan-pipeline)
2. [Tại Sao Cần Validation?](#tại-sao-cần-validation)
3. [Kiến Trúc Pipeline](#kiến-trúc-pipeline)
4. [Stage 0: Inventory](#stage-0-inventory)
5. [Stage A: Discovery](#stage-a-discovery)
6. [Stage B: Investigation](#stage-b-investigation)
7. [Stage C: Sanity](#stage-c-sanity)
8. [Stage D: Ruling](#stage-d-ruling)
9. [Stage E: Feasibility](#stage-e-feasibility)
10. [Stage F: Review](#stage-f-review)
11. [Data Models](#data-models)
12. [API Reference](#api-reference)
13. [Integration với RAPTOR](#integration-với-raptor)
14. [Best Practices](#best-practices)

---

## Tổng Quan Pipeline

Validation pipeline là **trái tim** của việc đảm bảo chất lượng trong RAPTOR. Nó biến những "lỗi tiềm năng" từ scanner thành **bằng chứng có thể khai thác** với độ tin cậy cao.

### Pipeline Overview

```
Stage 0 (Python)     build_checklist() → checklist.json
    │
Stage A (LLM)       Read code, identify vulns → findings.json (status: pending)
    │
Stage B (LLM)       Attack trees, hypotheses → 5 working documents
    │
Stage C (LLM)       Verify code at stated lines → findings.json (sanity_check added)
    │
Stage D (LLM)       Apply rulings → findings.json (ruling + final_status added)
    │
Stage E (Python)    analyze_binary() + map_findings_to_constraints() → findings.json (feasibility added)
    │
Stage F (LLM)       Self-review → updated outputs + validation-report.md
```

### ai trò các Stage

| Stage | Tên | Thực Hiện | Mục Đích |
|-------|-----|-----------|----------|
| **0** | Inventory | Python | Liệt kê TẤT CẢ functions để check coverage |
| **A** | Discovery | LLM | Xác định lỗ hổng tiềm năng |
| **B** | Investigation | LLM | Attack trees, hypotheses, evidence gathering |
| **C** | Sanity | LLM | Verify code tại lines - bắt hallucinations |
| **D** | Ruling | LLM | Xác định cuối cùng: exploitable/confirmed/ruled_out |
| **E** | Feasibility | Python | Binary constraint analysis (memory corruption only) |
| **F** | Review | LLM | Self-review - bắt nhầm lẫn, sửa schema errors |

---

## Tại Sao Cần Validation?

### Vấn Đề Scanner Truyền Thống

```
Semgrep reports: 50 findings
CodeQL reports:  30 findings
Total:           80 findings

After validation:
  Exploitable:   8 findings  (10%)
  Confirmed:     12 findings (15%)
  Ruled Out:     60 findings (75%) ← FALSE POSITIVES
```

**Không có validation:** Bạn phải điều tra 80 findings  
**Có validation:** Bạn chỉ tập trung vào 20 findings thực sự

### LLM Hallucination Problem

LLMs có thể "nhìn thấy" lỗ hổng không tồn tại:

```
LLM says: "Line 42 has SQL injection via string concatenation"
Reality:  Line 42 uses parameterized queries → NOT vulnerable

Sanity check (Stage C) catches this → Ruled Out
```

---

## Kiến Trúc Pipeline

### Package Structure

```
packages/exploitability_validation/
├── __init__.py            # Public API exports
├── orchestrator.py        # Pipeline execution engine
├── schemas.py             # JSON schemas for all outputs
├── checklist_builder.py   # Stage 0: Function extraction
├── agentic.py             # SARIF conversion, agentic integration
├── models.py              # Type-safe dataclasses
└── tests/
    └── test_validation.py # 207+ unit tests
```

### Output Files

Tất cả outputs vào `out/exploitability-validation-<timestamp>/`:

```
checklist.json          Stage 0 — all functions to check
findings.json           Stages A-F — findings with progressive enrichment
attack-surface.json     Stage B — sources, sinks, trust boundaries
attack-tree.json        Stage B — attack knowledge graph
hypotheses.json         Stage B — testable predictions
disproven.json          Stage B — failed approaches and why
attack-paths.json       Stage B — paths tried, PROXIMITY scores, blockers
exploit-context.json    Stage E — binary constraints (if binary provided)
validation-report.md    Summary — human-readable report
```

### Pipeline Execution Flow

```python
def run_validation_phase(
    repo_path: str,
    out_dir: Path,
    sarif_files: List[Path],
    total_findings: int,
    vuln_type: Optional[str] = None,
    binary_path: Optional[str] = None,
    skip_dedup: bool = False,
    skip_feasibility: bool = True,
    external_llm: bool = False,
) -> Tuple[Dict, List]:
    """
    Main entry point cho validation pipeline
    
    Returns: (validation_result, validated_findings)
    """
    
    orchestrator = ValidationOrchestrator(out_dir)
    
    # Stage 0: Build inventory
    checklist = build_checklist(repo_path, out_dir)
    
    # Convert SARIF to validation format
    findings = convert_sarif_to_findings(sarif_files)
    
    # Deduplicate findings
    if not skip_dedup:
        findings = deduplicate_findings(findings)
    
    # Filter by vulnerability type if specified
    if vuln_type:
        findings = filter_by_type(findings, vuln_type)
    
    # Stages A-D: LLM performs analysis
    findings = orchestrator.run_llm_stages(findings)
    
    # Stage E: Binary feasibility (if binary provided and memory corruption)
    if binary_path and not skip_feasibility:
        findings = run_stage_e_feasibility(findings, binary_path)
    
    # Stage F: Self-review
    findings = orchestrator.run_stage_f_review(findings)
    
    # Generate report
    report = generate_validation_report(findings)
    
    return report, findings
```

---

## Stage 0: Inventory

**Mục đích:** Xây dựng danh sách TẤT CẢ functions trong codebase

### Implementation

```python
def build_checklist(source_path: str, out_dir: Path) -> Dict:
    """
    Stage 0: Build function inventory
    
    Uses:
    - AST parsing for Python (tree-sitter)
    - Regex fallback for C, Java
    - Parallel processing
    """
    
    checklist = {
        "functions": [],
        "total_count": 0,
        "coverage": {
            "analyzed": 0,
            "pending": 0,
        }
    }
    
    # Enumerate source files
    files = enumerate_source_files(source_path)
    
    for file in files:
        if is_generated_file(file):
            continue  # Skip generated code
        
        # Extract functions
        functions = extract_functions(file)
        for func in functions:
            checklist["functions"].append({
                "file": str(file),
                "name": func.name,
                "line_start": func.line_start,
                "line_end": func.line_end,
                "language": func.language,
                "checked_by": [],  # Track which stages checked this
            })
    
    checklist["total_count"] = len(checklist["functions"])
    checklist["coverage"]["pending"] = checklist["total_count"]
    
    # Save
    save_json(out_dir / "checklist.json", checklist)
    
    return checklist
```

### Coverage Tracking

```python
def update_coverage(checklist: Dict, function_name: str, stage: str):
    """Mark function as checked by a stage"""
    for func in checklist["functions"]:
        if func["name"] == function_name:
            if stage not in func["checked_by"]:
                func["checked_by"].append(stage)
                checklist["coverage"]["analyzed"] += 1
                checklist["coverage"]["pending"] -= 1
```

---

## Stage A: Discovery

**Mục đích:** LLM đọc code và xác định lỗ hổng tiềm năng

### Process

```
Input: checklist.json + SARIF findings
Output: findings.json (status: pending)

LLM reads:
1. SARIF finding location (file, line)
2. Surrounding code context (±50 lines)
3. Dataflow path from source to sink
4. Function call chain

LLM determines:
1. Is vulnerability real or false positive?
2. What's the vulnerability type?
3. Can attacker control the input?
4. What's the impact?
```

### Example LLM Prompt

```markdown
You are analyzing a potential vulnerability at:
File: src/parser.c, Line 142
Rule: command-injection

Code context:
```c
140: void handle_request(char *user_input) {
141:     char cmd[256];
142:     sprintf(cmd, "process %s", user_input);
143:     system(cmd);
144: }
```

Questions:
1. Is this a REAL vulnerability? (yes/no)
2. Can attacker control `user_input`? (yes/no)
3. What's the exploitability? (high/medium/low)
4. What evidence supports this?
5. What evidence would rule it out?
```

### Output Schema

```json
{
  "finding_id": "FIND-0001",
  "rule_id": "command-injection",
  "file": "src/parser.c",
  "line": 142,
  "status": "pending",
  "vulnerability_type": "command_injection",
  "llm_analysis": {
    "is_real": true,
    "attacker_controlled": true,
    "exploitability": "high",
    "confidence": 0.85,
    "evidence": [
      "user_input comes from network request",
      "no sanitization before sprintf",
      "system() executes command"
    ]
  }
}
```

---

## Stage B: Investigation

**Mục đích:** Xây dựng attack knowledge graph

### Working Documents

Stage B tạo ra **5 JSON files** tạo thành knowledge graph:

**1. attack-surface.json**
```json
{
  "sources": [
    {"name": "user_input", "type": "network", "trust": "untrusted"}
  ],
  "sinks": [
    {"name": "system()", "type": "command_execution", "danger": "high"}
  ],
  "trust_boundaries": [
    {"from": "network", "to": "parser", "validation": "none"}
  ]
}
```

**2. attack-tree.json**
```json
{
  "root": "Achieve remote code execution",
  "children": [
    {
      "node": "Control user_input",
      "status": "confirmed",
      "evidence": "No input validation"
    },
    {
      "node": "Bypass input sanitization",
      "status": "confirmed", 
      "evidence": "No sanitization present"
    },
    {
      "node": "Execute arbitrary command",
      "status": "confirmed",
      "evidence": "system() with user-controlled string"
    }
  ]
}
```

**3. hypotheses.json**
```json
{
  "hypotheses": [
    {
      "id": "H1",
      "claim": "Attacker can inject shell commands via user_input",
      "evidence": ["No validation", "Direct string concatenation"],
      "status": "supported",
      "confidence": 0.9
    }
  ]
}
```

**4. disproven.json**
```json
{
  "disproven_approaches": [
    {
      "approach": "Escape command with semicolon",
      "why_failed": "Not applicable - direct injection works",
      "learned": "No escaping needed"
    }
  ]
}
```

**5. attack-paths.json**
```json
{
  "paths": [
    {
      "id": "P1",
      "steps": [
        "Send HTTP request with crafted input",
        "Input reaches system() without validation",
        "Command executes with server privileges"
      ],
      "proximity_score": 9.5,
      "blockers": [],
      "status": "viable"
    }
  ]
}
```

### PROXIMITY Scoring

Score 0-10 thể hiện khoảng cách đến successful exploitation:

| Score | Ý Nghĩa |
|-------|---------|
| 0-2 | Rất xa - cần nhiều bước chưa làm được |
| 3-4 | Đang tiến triển - có hướng đi |
| 5-6 | Gần - chỉ cần 1-2 bước nữa |
| 7-8 | Rất gần - gần như chắc chắn |
| 9-10 | Exploitable - có thể khai thác ngay |

---

## Stage C: Sanity

**Mục đích:** Verify code tại các lines được đề cập - bắt LLM hallucinations

### Process

```
LLM re-reads code at EXACT lines stated in findings
Checks:
1. Does the code actually exist at that line?
2. Is the vulnerability description accurate?
3. Are there sanitizers that were missed?
4. Is the dataflow path correct?
```

### Example

```
Stage A said: "Line 142 has SQL injection"
Stage C checks: Reads line 142
Reality: Line 142 uses parameterized query with ?
Result: SANITY CHECK FAILED → Finding ruled out
```

### Output

```json
{
  "finding_id": "FIND-0001",
  "sanity_check": {
    "passed": false,
    "reason": "Parameterized query used, not string concatenation",
    "corrected_description": "Uses prepared statement with bound parameters",
    "recommendation": "Rule out - false positive"
  }
}
```

---

## Stage D: Ruling

**Mục đích:** Final determination - mỗi finding receives ruling

### Possible Rulings

```python
RULING_VALUES = [
    "exploitable",      # Có thể khai thác được
    "confirmed",        # Lỗ hổng real nhưng impact thấp  
    "ruled_out",        # False positive
    "needs_more_info",  # Không thể xác định
]
```

### Decision Criteria

**Exploitable:**
- Vulnerability is real
- Attacker controls input
- No effective mitigations
- Impact is significant

**Confirmed:**
- Vulnerability is real
- But impact is limited (e.g., DoS only)
- Or requires specific conditions

**Ruled Out:**
- False positive from scanner
- Or effective mitigation present
- Or attacker cannot control input

**Needs More Info:**
- Cannot determine from available context
- Requires manual review

### Output

```json
{
  "finding_id": "FIND-0001",
  "ruling": {
    "final_status": "exploitable",
    "confidence": 0.92,
    "justification": "Command injection confirmed with no mitigations",
    "cvss_estimate": 9.8,
    "remediation_priority": "critical"
  }
}
```

---

## Stage E: Feasibility

**Mục đích:** Binary constraint analysis (chỉ áp dụng cho memory corruption)

### Applicability

```python
MEMORY_CORRUPTION_TYPES = {
    "buffer_overflow",
    "format_string_write",
    "format_string_read",
    "double_free",
    "use_after_free",
    "heap_overflow",
    "stack_overflow",
    "integer_overflow",
}

def should_run_stage_e(vuln_type: str) -> bool:
    return vuln_type in MEMORY_CORRUPTION_TYPES
```

**Web vulnerabilities (SQLi, XSS, SSRF) skip Stage E** → go directly to Stage F

### Process

```python
def run_stage_e_feasibility(findings: List[Dict], binary_path: str) -> List[Dict]:
    """Stage E: Binary feasibility analysis"""
    
    from packages.exploit_feasibility import (
        analyze_binary,
        map_findings_to_constraints,
        save_exploit_context
    )
    
    # 1. Analyze binary
    constraints = analyze_binary(binary_path)
    context_file = save_exploit_context(binary_path)
    
    # 2. Map each finding to constraints
    for finding in findings:
        if should_run_stage_e(finding['vulnerability_type']):
            feasibility = map_findings_to_constraints(
                [finding], constraints
            )
            finding['feasibility'] = feasibility[0]
    
    return findings
```

### Output

```json
{
  "finding_id": "FIND-0001",
  "feasibility": {
    "verdict": "exploitable",
    "impact": "code_execution",
    "exploitation_paths": [
      {
        "technique": "ROP chain",
        "target": "return address on stack",
        "viable": true
      }
    ],
    "blockers": [],
    "notes": "45 usable gadgets available, sufficient for ROP"
  }
}
```

---

## Stage F: Review

**Mục đích:** Self-review - catch misclassifications, schema errors

### What Stage F Checks

1. **Consistency:** Does final_status match the evidence?
2. **Schema Compliance:** Are all required fields present?
3. **Proximity Score Consistency:** Do scores make sense?
4. **Evidence Strength:** Is there enough evidence for the ruling?
5. **Misclassifications:** Were any findings wrongly ruled out?

### Review Process

```python
def run_stage_f_review(findings: List[Dict]) -> List[Dict]:
    """Stage F: Self-review"""
    
    review_prompt = """
    Review these vulnerability findings for:
    1. Consistency between evidence and ruling
    2. Missing required fields
    3. Incorrect classifications
    4. Weak evidence for exploitable claims
    
    For each finding, confirm or correct the status.
    """
    
    llm_response = llm.generate(review_prompt)
    
    # Apply corrections
    for correction in llm_response['corrections']:
        finding = find_by_id(correction['finding_id'])
        finding['final_status'] = correction['corrected_status']
        finding['review_notes'] = correction['reason']
    
    return findings
```

### Output

```json
{
  "finding_id": "FIND-0003",
  "review": {
    "original_status": "confirmed",
    "corrected_status": "exploitable",
    "reason": "Impact is actually full code execution, not limited DoS",
    "fields_added": ["cvss_estimate"],
    "fields_corrected": ["impact_description"]
  }
}
```

---

## Data Models

### Core Finding Model

```python
@dataclass
class Finding:
    """Core vulnerability record"""
    finding_id: str
    rule_id: str
    file: str
    line: int
    vulnerability_type: str
    status: str = "pending"
    
    # Progressive enrichment
    llm_analysis: Optional[LLMAnalysis] = None
    sanity_check: Optional[SanityCheck] = None
    ruling: Optional[Ruling] = None
    feasibility: Optional[Feasibility] = None
    review: Optional[Review] = None
    
    # Never None - defaults to empty
    proofs: List[Proof] = field(default_factory=list)
    pocs: List[PoC] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
```

### Status Normalization

LLMs output status trong nhiều formats:

```python
STATUS_MAPPING = {
    # ALL_CAPS (LLM hay dùng)
    "EXPLOITABLE": "exploitable",
    "CONFIRMED": "confirmed",
    "RULED_OUT": "ruled_out",
    "DISPROVEN": "ruled_out",
    
    # Title Case
    "Exploitable": "exploitable",
    "Confirmed": "confirmed",
    "Ruled Out": "ruled_out",
    
    # snake_case (correct)
    "exploitable": "exploitable",
    "confirmed": "confirmed",
    "ruled_out": "ruled_out",
}
```

Pipeline **tự động normalize** về snake_case.

---

## API Reference

### Public Functions

| Function | Description | Parameters | Return |
|----------|-------------|------------|--------|
| `build_checklist(source, out_dir)` | Stage 0 inventory | source path, output dir | Dict |
| `run_validation_phase(...)` | Full pipeline | See above | (report, findings) |
| `convert_sarif_to_findings(sarifs)` | SARIF → findings | List of SARIF paths | List[Finding] |
| `generate_validation_report(findings)` | Human-readable report | Validated findings | Dict |

### Usage

```python
from packages.exploitability_validation import run_validation_phase

report, findings = run_validation_phase(
    repo_path="/path/to/code",
    out_dir=Path("out/validation"),
    sarif_files=[Path("combined.sarif")],
    total_findings=80,
    binary_path="/path/to/binary",  # Optional
    skip_dedup=False,
    skip_feasibility=False,
)

print(f"Exploitable: {sum(1 for f in findings if f['status'] == 'exploitable')}")
print(f"Confirmed: {sum(1 for f in findings if f['status'] == 'confirmed')}")
print(f"Ruled Out: {sum(1 for f in findings if f['status'] == 'ruled_out')}")
```

---

## Best Practices

### 1. Always Run Validation After Scanning

```python
# ❌ Don't just trust scanner results
findings = parse_sarif("combined.sarif")
print(f"Found {len(findings)} vulnerabilities")

# ✅ Validate first
report, findings = run_validation_phase(...)
exploitable = [f for f in findings if f['status'] == 'exploitable']
print(f"Found {len(exploitable)} REAL exploitable vulnerabilities")
```

### 2. Provide Binary for Stage E

```python
# Without binary - Stage E skipped
run_validation_phase(repo_path="/code", binary_path=None)

# With binary - Full analysis including Stage E
run_validation_phase(repo_path="/code", binary_path="/binary")
```

### 3. Use Deduplication

```python
# Without dedup - May analyze same vuln multiple times
run_validation_phase(skip_dedup=True)

# With dedup - Clean findings
run_validation_phase(skip_dedup=False)  # DEFAULT
```

### 4. Review the Report

```bash
# Human-readable report
cat out/exploitability-validation-*/validation-report.md

# Detailed findings
cat out/exploitability-validation-*/findings.json

# Attack knowledge graph
cat out/exploitability-validation-*/attack-tree.json
```

---

**Tài liệu tiếp theo:** [08-PRACTICAL-GUIDES](../08-PRACTICAL-GUIDES/) - Hướng dẫn thực hành
