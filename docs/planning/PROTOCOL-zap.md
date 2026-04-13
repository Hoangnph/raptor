# Protocol: Subagent 4 — OWASP ZAP Integration

## Role

Implement OWASP ZAP DAST integration (`packages/web/zap/`) qua Python API client.

## Responsibilities

- [ ] Create `packages/web/zap/` structure
- [ ] Python API client integration
- [ ] ZAP Automation Framework (YAML)
- [ ] Result conversion → RAPTOR findings format
- [ ] CLI interface
- [ ] Write 40+ unit tests
- [ ] Write complete documentation

## Dependencies

- **Week 5:** OWASP ZAP installed (via Docker hoặc pip)
- `zapv2` Python package
- `core/logging.py` — For logging

## Outputs

- `packages/web/zap/scanner.py` — ZAP Python API integration
- `packages/web/zap/automation.py` — ZAP Automation Framework
- `packages/web/zap/tests/` — 40+ tests
- `packages/web/zap/README.md` — Documentation

## Communication

- **Status updates:** Every 2 hours — update `STATUS-zap.md`
- **Blockers:** Immediately — update `BLOCKERS.md`
- **Questions:** Add to this file

## Quality Standards

- **TDD:** RED→GREEN→REFACTOR
- **Coverage:** >= 80%
- **Mocking:** Mock ZAP API calls để test không cần ZAP thực

## Timeline

| Week | Tasks | Deliverables |
|------|-------|--------------|
| Week 5 | All ZAP integration | scanner.py, automation.py, tests |

## Questions

*No questions yet.*

---

*Created: 2026-04-12*
