# Kế Hoạch Triển Khai Nâng Cấp RAPTOR

**Exploit-DB Integration + Web Scanning System Upgrade**

---

**Branch:** `feat/exploit-db-web-scanning-upgrade`  
**Ngày bắt đầu:** 12 tháng 4, 2026  
**Phương pháp:** TDD (Test-Driven Development)  
**Quy trình:** Zero Technical Debt  
**Tổng thời gian:** 11 weeks (~450 hours)  

---

## Mục Lục

1. [Tổng Quan](#tổng-quan)
2. [Kiến Trúc Tương Thích](#kiến-trúc-tương-thích)
3. [TDD Strategy](#tdd-strategy)
4. [Definition of Done (DoD)](#definition-of-done-dod)
5. [Zero Technical Debt Process](#zero-technical-debt-process)
6. [Subagent Communication Protocol](#subagent-communication-protocol)
7. [Task Breakdown](#task-breakdown)
8. [Dependency Graph](#dependency-graph)
9. [Testing Strategy](#testing-strategy)
10. [Quality Gates](#quality-gates)

---

## Tổng Quan

### Scope

| Feature | Description | Priority | Weeks |
|---------|-------------|----------|-------|
| Exploit-DB Integration | Hybrid (Local CSV + Remote API) | P0 | 2-3 |
| Recon Tools | subfinder + httpx + katana | P0 | 2 |
| Nuclei Integration | Vulnerability scanning (SARIF) | P0 | 2 |
| OWASP ZAP Integration | DAST (Python API) | P0 | 2 |
| Integration & Testing | Correlation, validation, docs | P0 | 3 |

### Design Principles

1. **Tương thích với kiến trúc hiện tại** — Tuân thủ RAPTOR modular design
2. **Không cross-package imports** — Packages chỉ import từ `core/`
3. **Standalone executability** — Mỗi package chạy độc lập
4. **CLI interface** — argparse cho mỗi module
5. **SARIF compatibility** — Tận dụng `core.sarif.parser`
6. **TDD first** — Viết test trước, code sau
7. **Zero debt** — Không merge nếu chưa pass tests + docs

---

## Kiến Trúc Tương Thích

### Existing RAPTOR Architecture

```
raptor/
├── core/                    # Shared utilities (KHÔNG SỬA)
│   ├── config.py
│   ├── logging.py
│   ├── sarif/parser.py     # ← REUSE cho Nuclei SARIF
│   └── json/utils.py       # ← REUSE cho JSON operations
├── packages/                # Security capabilities
│   ├── exploit_feasibility/ # ← INTEGRATE với Exploit-DB
│   ├── exploitability_validation/ # ← INTEGRATE với web findings
│   ├── llm_analysis/        # ← INTEGRATE với enriched findings
│   └── web/                 # ← ENHANCE (rewrite scanner.py)
└── engine/                  # Analysis engines (KHÔNG SỬA)
```

### New Packages Structure

```
packages/
├── exploit_db/                    # NEW — Tuân thủ RAPTOR patterns
│   ├── __init__.py
│   ├── database.py                # CSV parsing, indexing
│   ├── searcher.py                # Multi-strategy search
│   ├── correlator.py              # Finding-exploit correlation
│   ├── validator.py               # Exploit validation
│   ├── enricher.py                # Finding enrichment
│   ├── cli.py                     # CLI interface (argparse)
│   └── tests/                     # TDD: 100+ tests
│       ├── test_database.py
│       ├── test_searcher.py
│       ├── test_correlator.py
│       └── test_enricher.py
│
└── web/                           # ENHANCED — Rewrite scanner.py
    ├── __init__.py
    ├── scanner.py                 # REWRITE — Main orchestrator
    ├── client.py                  # KEEP — Good HTTP client
    ├── fuzzer.py                  # KEEP — LLM zero-day discovery
    ├── recon/                     # NEW — Sub-package
    │   ├── __init__.py
    │   ├── subfinder.py           # Subdomain enumeration
    │   ├── httpx.py               # Technology detection
    │   └── katana.py              # Deep crawling
    ├── nuclei/                    # NEW — Sub-package
    │   ├── __init__.py
    │   ├── runner.py              # Nuclei execution
    │   └── template_manager.py    # Template selection
    ├── zap/                       # NEW — Sub-package
    │   ├── __init__.py
    │   ├── scanner.py             # ZAP Python API
    │   └── automation.py          # ZAP Automation Framework
    └── tests/                     # TDD: 150+ tests
        ├── test_recon.py
        ├── test_nuclei.py
        ├── test_zap.py
        └── test_integration.py
```

### Integration Points

| New Component | Existing Component | Integration Method |
|--------------|-------------------|-------------------|
| `exploit_db/database.py` | `core/json/utils.py` | Use `load_json`, `save_json` |
| `exploit_db/correlator.py` | `packages/exploit_feasibility/` | Import `analyze_binary` |
| `web/nuclei/runner.py` | `core/sarif/parser.py` | Use `load_sarif`, `parse_sarif_findings` |
| `web/scanner.py` | `core/logging.py` | Use `get_logger` |
| `web/scanner.py` | `core/config.py` | Use `RaptorConfig.get_out_dir` |
| `web/zap/scanner.py` | `packages/llm_analysis/` | Use LLM for false positive elimination |

---

## TDD Strategy

### TDD Cycle

```
1. RED: Viết test fail
   ↓
2. GREEN: Viết code tối thiểu để pass
   ↓
3. REFACTOR: Cleanup code, giữ test pass
   ↓
4. COMMIT: Commit với test pass + docs
```

### Test Structure

**Mỗi module có:**
- Unit tests (80% coverage minimum)
- Integration tests (key workflows)
- Edge case tests (error handling)
- Performance tests (critical paths)

### Test File Naming

```
packages/<name>/tests/
├── test_<module>.py       # Unit tests
├── test_<module>_integration.py  # Integration tests
└── test_<module>_edge.py  # Edge cases
```

### Example TDD Flow

**Step 1: Write Test First**
```python
# packages/exploit_db/tests/test_database.py
def test_load_csv_valid():
    db = ExploitDatabase(Path('test_data/files.csv'))
    assert len(db.exploits) > 0
    assert db.exploits[0]['id'] == '50123'

def test_load_csv_invalid():
    with pytest.raises(FileNotFoundError):
        ExploitDatabase(Path('nonexistent.csv'))
```

**Step 2: Write Minimal Code**
```python
# packages/exploit_db/database.py
class ExploitDatabase:
    def __init__(self, csv_path: Path):
        if not csv_path.exists():
            raise FileNotFoundError(f"CSV not found: {csv_path}")
        self.exploits = self._load_csv(csv_path)

    def _load_csv(self, csv_path: Path) -> List[Dict]:
        with open(csv_path, newline='', encoding='utf-8') as f:
            return list(csv.DictReader(f))
```

**Step 3: Refactor**
```python
# Cleanup, add type hints, docstrings
# Keep tests passing
```

**Step 4: Commit**
```bash
git add packages/exploit_db/
git commit -m "feat(exploit-db): add CSV loader with tests

- Implement ExploitDatabase class with CSV parsing
- Add unit tests for valid/invalid cases
- Follow RAPTOR patterns (type hints, docstrings)

TDD: RED→GREEN→REFACTOR cycle complete
Tests: 2/2 passing
Coverage: 100%
"
```

### Test Requirements

| Package | Min Tests | Min Coverage |
|---------|-----------|--------------|
| `exploit_db/` | 100+ | 80% |
| `web/recon/` | 50+ | 80% |
| `web/nuclei/` | 40+ | 80% |
| `web/zap/` | 40+ | 80% |
| `web/` (integration) | 20+ | N/A |
| **Total** | **250+** | **80%+** |

---

## Definition of Done (DoD)

### Per-Module DoD

Mỗi module được coi là **DONE** khi:

- [ ] **Code**
  - [ ] Implement đầy đủ functionality
  - [ ] Type hints cho tất cả functions
  - [ ] Docstrings cho tất cả public APIs
  - [ ] Error handling comprehensive
  - [ ] Logging đúng chuẩn (`core.logging.get_logger`)

- [ ] **Tests**
  - [ ] Unit tests pass 100%
  - [ ] Integration tests pass
  - [ ] Coverage >= 80%
  - [ ] Edge cases covered
  - [ ] No flaky tests

- [ ] **CLI**
  - [ ] argparse interface hoàn chỉnh
  - [ ] `--help` output rõ ràng
  - [ ] Examples trong epilog
  - [ ] Exit codes đúng (0=success, 1=error, 130=interrupted)

- [ ] **Documentation**
  - [ ] README.md trong package
  - [ ] Usage examples
  - [ ] API reference
  - [ ] Troubleshooting section

- [ ] **Integration**
  - [ ] Compatible với RAPTOR core
  - [ ] Không phá existing tests
  - [ ] SARIF output (nếu applicable)
  - [ ] Output vào `out/` directory

- [ ] **Code Quality**
  - [ ] No linting errors
  - [ ] No type errors
  - [ ] No security issues
  - [ ] No TODOs trong production code

- [ ] **Review**
  - [ ] Self-review completed
  - [ ] All comments addressed
  - [ ] Performance acceptable
  - [ ] Memory leaks checked

### Per-Feature DoD

Mỗi feature được coi là **DONE** khi:

- [ ] Tất cả modules trong feature đạt DoD
- [ ] End-to-end tests pass
- [ ] Integration với existing RAPTOR workflow
- [ ] Documentation updated
- [ ] Dev container updated (nếu cần tools mới)
- [ ] CI/CD pipeline passes

### Per-Phase DoD

Mỗi phase được coi là **DONE** khi:

- [ ] Tất cả features trong phase đạt DoD
- [ ] Performance benchmarks acceptable
- [ ] Security review completed
- [ ] User acceptance testing pass
- [ ] Release notes drafted

---

## Zero Technical Debt Process

### Principles

1. **Không nợ code** — Không merge nếu chưa pass tests
2. **Không nợ docs** — Không merge nếu chưa có docs
3. **Không nợ tests** — Không merge nếu coverage < 80%
4. **Không nợ security** — Không merge nếu có security issues
5. **Không nợ performance** — Không merge nếu performance regression > 10%

### Process

```
Developer hoàn thành code
         ↓
    Chạy tests (local)
         ↓
    Pass? ──NO──> Fix → Retry
         ↓ YES
    Check coverage (>=80%)
         ↓
    >=80%? ──NO──> Add tests → Retry
         ↓ YES
    Check docs (README + docstrings)
         ↓
    Complete? ──NO──> Write docs → Retry
         ↓ YES
    Check security (no hardcoded secrets, etc.)
         ↓
    Clean? ──NO──> Fix security → Retry
         ↓ YES
    Check performance (benchmark)
         ↓
    OK? ──NO──> Optimize → Retry
         ↓ YES
    Commit với message chuẩn
         ↓
    Push → PR → Review → Merge
```

### Enforcement

| Check | Tool | When | Fail Action |
|-------|------|------|-------------|
| Tests | pytest | Pre-commit | Block commit |
| Coverage | coverage.py | Pre-commit | Block commit if < 80% |
| Linting | ruff/flake8 | Pre-commit | Block commit |
| Type checking | mypy | Pre-commit | Block commit |
| Security | bandit | Pre-commit | Block commit |
| Performance | pytest-benchmark | CI | Block merge if regression > 10% |
| Docs | Custom check | Code review | Block merge if incomplete |

### Technical Debt Tracking

Nếu PHẢI tạo debt (emergency):

```markdown
# Technical Debt Log

| ID | Date | Description | Reason | Payback Date | Status |
|----|------|-------------|--------|--------------|--------|
| TD-001 | 2026-04-12 | Missing edge cases | Emergency fix | 2026-04-19 | Open |
```

**Rule:** Maximum 1 open TD at any time. Must be paid back within 1 week.

---

## Subagent Communication Protocol

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Main Coordinator                          │
│              (docs/planning/PROGRESS.md)                     │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Subagent 1: Exploit-DB                                     │
│  Status: docs/planning/STATUS-exploit-db.md                 │
│  Protocol: docs/planning/PROTOCOL-exploit-db.md             │
│                                                              │
│  Subagent 2: Recon Tools                                    │
│  Status: docs/planning/STATUS-recon.md                      │
│  Protocol: docs/planning/PROTOCOL-recon.md                  │
│                                                              │
│  Subagent 3: Nuclei Integration                             │
│  Status: docs/planning/STATUS-nuclei.md                     │
│  Protocol: docs/planning/PROTOCOL-nuclei.md                 │
│                                                              │
│  Subagent 4: ZAP Integration                                │
│  Status: docs/planning/STATUS-zap.md                        │
│  Protocol: docs/planning/PROTOCOL-zap.md                    │
│                                                              │
│  Subagent 5: Integration & Testing                          │
│  Status: docs/planning/STATUS-integration.md                │
│  Protocol: docs/planning/PROTOCOL-integration.md            │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### File Structure

```
docs/planning/
├── IMPLEMENTATION-PLAN.md           # This file
├── PROGRESS.md                      # Global progress tracker
├── DECISIONS.md                     # Architectural decisions log
├── BLOCKERS.md                      # Current blockers
│
├── STATUS-exploit-db.md             # Subagent 1 status
├── PROTOCOL-exploit-db.md           # Communication protocol
├── STATUS-recon.md                  # Subagent 2 status
├── PROTOCOL-recon.md                # Communication protocol
├── STATUS-nuclei.md                 # Subagent 3 status
├── PROTOCOL-nuclei.md               # Communication protocol
├── STATUS-zap.md                    # Subagent 4 status
├── PROTOCOL-zap.md                  # Communication protocol
├── STATUS-integration.md            # Subagent 5 status
└── PROTOCOL-integration.md          # Communication protocol
```

### PROGRESS.md Format

```markdown
# Global Progress Tracker

## Phase 1: Foundation (Weeks 1-3)

### Exploit-DB
- [x] Week 1: Database core (CSV parser, indexer)
- [ ] Week 2: Advanced (correlation, enrichment)
- [ ] Week 3: Integration với validation pipeline

### Recon Tools
- [ ] Week 1-2: subfinder + httpx + katana
- [ ] Week 3: Integration tests

## Current Status: Week 1, Day 1
## Next Milestone: Week 1 completion (CSV parser + tests)
## Blockers: None
```

### Subagent Protocol Format

```markdown
# Protocol: <subagent-name>

## Role
<What this subagent does>

## Responsibilities
- <Task 1>
- <Task 2>

## Dependencies
- <What it depends on>

## Outputs
- <What it produces>

## Communication
- Status updates: Every 2 hours
- Blockers: Immediately
- Questions: Via PROTOCOL file

## Quality Standards
- TDD: RED→GREEN→REFACTOR
- Coverage: >= 80%
- Docs: Complete before merge
```

### Status File Format

```markdown
# Status: <subagent-name>

## Current Task
<What's being worked on>

## Progress
- [x] Task 1
- [ ] Task 2 (in progress)
- [ ] Task 3

## Tests
- Passing: X/Y
- Coverage: Z%

## Blockers
- <Any blockers>

## Next Steps
1. <Next step 1>
2. <Next step 2>

## Last Updated
<Timestamp>
```

### Communication Rules

1. **Status Updates:** Mỗi subagent update STATUS file mỗi 2 hours
2. **Blockers:** Update BLOCKERS.md ngay lập tức
3. **Decisions:** Log vào DECISIONS.md
4. **Questions:** Đặt câu hỏi trong PROTOCOL file
5. **Reviews:** Self-review trước khi request main coordinator review
6. **Merges:** Chỉ merge khi đạt DoD

---

## Task Breakdown

### Phase 1: Foundation (Weeks 1-3)

#### Week 1: Exploit-DB Core

| Task | Owner | Hours | Dependencies | DoD |
|------|-------|-------|--------------|-----|
| Create `packages/exploit_db/` structure | Subagent 1 | 2h | None | Structure exists |
| Implement CSV parser | Subagent 1 | 8h | Structure | Tests pass |
| Build inverted index | Subagent 1 | 8h | CSV parser | Tests pass |
| Multi-strategy search engine | Subagent 1 | 12h | Index | Tests pass, 50+ tests |
| CLI interface | Subagent 1 | 4h | Search engine | argparse complete |
| Documentation | Subagent 1 | 4h | All above | README complete |

**Week 1 Deliverables:**
- `packages/exploit_db/database.py`
- `packages/exploit_db/searcher.py`
- `packages/exploit_db/cli.py`
- `packages/exploit_db/tests/test_database.py`
- `packages/exploit_db/tests/test_searcher.py`
- `packages/exploit_db/README.md`

#### Week 2: Exploit-DB Advanced + Recon Start

| Task | Owner | Hours | Dependencies | DoD |
|------|-------|-------|--------------|-----|
| Correlation engine | Subagent 1 | 12h | Week 1 | Tests pass |
| Finding enrichment | Subagent 1 | 8h | Correlation | Tests pass |
| Remote API fallback | Subagent 1 | 8h | Search engine | Tests pass |
| Unit tests (100+) | Subagent 1 | 8h | All above | Coverage >= 80% |
| Create `packages/web/recon/` | Subagent 2 | 2h | None | Structure exists |
| subfinder integration | Subagent 2 | 8h | Structure | Tests pass |

#### Week 3: Recon Complete

| Task | Owner | Hours | Dependencies | DoD |
|------|-------|-------|--------------|-----|
| httpx integration | Subagent 2 | 8h | Week 2 | Tests pass |
| katana integration | Subagent 2 | 8h | Week 2 | Tests pass |
| Recon orchestrator | Subagent 2 | 8h | All above | Integration tests pass |
| Documentation | Subagent 2 | 4h | All above | README complete |

### Phase 2: Core Scanning (Weeks 4-6)

#### Week 4: Nuclei Integration

| Task | Owner | Hours | Dependencies | DoD |
|------|-------|-------|--------------|-----|
| Create `packages/web/nuclei/` | Subagent 3 | 2h | None | Structure exists |
| Nuclei execution wrapper | Subagent 3 | 8h | Structure | Tests pass |
| SARIF parsing | Subagent 3 | 4h | core.sarif.parser | Integration test pass |
| Template manager | Subagent 3 | 8h | Execution wrapper | Tests pass |
| CLI interface | Subagent 3 | 4h | All above | argparse complete |

#### Week 5: OWASP ZAP Integration

| Task | Owner | Hours | Dependencies | DoD |
|------|-------|-------|--------------|-----|
| Create `packages/web/zap/` | Subagent 4 | 2h | None | Structure exists |
| Python API client | Subagent 4 | 8h | Structure | Tests pass |
| Automation Framework | Subagent 4 | 8h | API client | Tests pass |
| Result conversion | Subagent 4 | 6h | API client | Integration test pass |

#### Week 6: Web Scanner Orchestration

| Task | Owner | Hours | Dependencies | DoD |
|------|-------|-------|--------------|-----|
| Rewrite scanner.py | Subagent 5 | 12h | All above | Integration tests pass |
| Orchestration logic | Subagent 5 | 8h | Rewrite | Tests pass |
| LLM fuzzer integration | Subagent 5 | 6h | Rewrite | Tests pass |

### Phase 3: Integration & Enhancement (Weeks 7-9)

| Task | Owner | Hours | Dependencies | DoD |
|------|-------|-------|--------------|-----|
| Exploit-DB + Web correlation | Subagent 1 + 5 | 12h | Phase 2 | Integration tests pass |
| CVE enrichment pipeline | Subagent 1 | 8h | Correlation | Tests pass |
| Validation pipeline integration | Subagent 5 | 8h | All above | End-to-end tests pass |
| Performance optimization | Subagent 5 | 8h | All above | Benchmarks acceptable |
| Documentation | All | 8h | All above | Complete |

### Phase 4: Testing & Release (Weeks 10-11)

| Task | Owner | Hours | Dependencies | DoD |
|------|-------|-------|--------------|-----|
| End-to-end tests | Subagent 5 | 16h | Phase 3 | All tests pass |
| Performance benchmarks | Subagent 5 | 8h | E2E tests | No regression > 10% |
| Security review | All | 8h | All above | No security issues |
| Documentation review | All | 8h | All above | Complete |
| Dev container update | Subagent 5 | 4h | All above | Tools bundled |
| Release notes | Main coordinator | 4h | All above | Complete |

---

## Dependency Graph

```
Week 1: Exploit-DB Core
  ↓
Week 2: Exploit-DB Advanced + Recon Start
  ↓
Week 3: Recon Complete
  ↓
Week 4: Nuclei Integration
  ↓
Week 5: ZAP Integration
  ↓
Week 6: Web Scanner Orchestration
  ↓
Week 7-8: Integration & Enhancement
  ↓
Week 9: Polish
  ↓
Week 10-11: Testing & Release
```

**Critical Path:**
```
Exploit-DB Core → Recon → Nuclei → ZAP → Orchestration → Integration → Release
```

**Parallel Opportunities:**
- Exploit-DB và Recon có thể làm song song (Week 2-3)
- Nuclei và ZAP có thể làm song song (Week 4-5)
- Documentation có thể làm song song với development

---

## Testing Strategy

### Test Pyramid

```
         ┌─────────────┐
         │  E2E Tests  │  ~20 tests
         ├─────────────┤
         │Integration  │  ~50 tests
         ├─────────────┤
         │  Unit Tests │  ~200 tests
         └─────────────┘
```

### Test Categories

| Category | Count | Coverage | Priority |
|----------|-------|----------|----------|
| Unit tests | 200+ | 80%+ per module | P0 |
| Integration tests | 50+ | Key workflows | P0 |
| E2E tests | 20+ | Full pipelines | P0 |
| Performance tests | 10+ | Critical paths | P1 |
| Security tests | 10+ | Attack vectors | P0 |

### Test Data

| Data Source | Purpose | Location |
|-------------|---------|----------|
| Exploit-DB sample CSV | Unit tests | `packages/exploit_db/tests/fixtures/` |
| Nuclei SARIF output | Integration tests | `packages/web/nuclei/tests/fixtures/` |
| ZAP JSON output | Integration tests | `packages/web/zap/tests/fixtures/` |
| Vulnerable web apps | E2E tests | Docker containers |

### Mocking Strategy

```python
# Mock external tools để test không cần install
@patch('subprocess.run')
def test_nuclei_scan(mock_run):
    mock_run.return_value = Mock(
        returncode=0,
        stdout='Scan complete',
        stderr=''
    )
    # Test logic mà không cần nuclei thực sự
```

---

## Quality Gates

### Pre-Commit Hooks

```bash
#!/bin/bash
# .husky/pre-commit

echo "Running pre-commit checks..."

# 1. Tests
pytest packages/exploit_db/tests -v || exit 1
pytest packages/web/tests -v || exit 1

# 2. Coverage
coverage run -m pytest packages/ -q
coverage report --fail-under=80 || exit 1

# 3. Linting
ruff check packages/ || exit 1

# 4. Type checking
mypy packages/ || exit 1

# 5. Security
bandit -r packages/ || exit 1

echo "All pre-commit checks passed!"
```

### CI/CD Pipeline

```yaml
# .github/workflows/upgrade-tests.yml
name: Upgrade Tests

on:
  pull_request:
    branches: [feat/exploit-db-web-scanning-upgrade]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.12'

      - name: Install dependencies
        run: pip install -r requirements-dev.txt

      - name: Install tools
        run: |
          go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
          go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
          go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
          go install -v github.com/projectdiscovery/katana/cmd/katana@latest

      - name: Run tests
        run: pytest packages/ -v --tb=short

      - name: Check coverage
        run: |
          coverage run -m pytest packages/ -q
          coverage report --fail-under=80

      - name: Run linting
        run: ruff check packages/

      - name: Run type checking
        run: mypy packages/

      - name: Run security checks
        run: bandit -r packages/
```

### Merge Requirements

- [ ] All tests pass
- [ ] Coverage >= 80%
- [ ] No linting errors
- [ ] No type errors
- [ ] No security issues
- [ ] Documentation complete
- [ ] Self-review completed
- [ ] At least 1 approval từ main coordinator

---

## Communication Schedule

| Event | Frequency | Participants | Format |
|-------|-----------|--------------|--------|
| Status update | Every 2 hours | Each subagent | Update STATUS file |
| Blocker report | Immediately | Subagent → Main | Update BLOCKERS.md |
| Decision log | As needed | Any | Update DECISIONS.md |
| Phase review | End of each phase | All | Meeting + report |
| Progress sync | Daily | Main coordinator | Update PROGRESS.md |

---

**End of Implementation Plan**

*Document này sẽ được update xuyên suốt quá trình development.*
