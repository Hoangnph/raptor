# Protocol: Subagent 3 — Nuclei Integration

## Role

Implement Nuclei vulnerability scanning integration (`packages/web/nuclei/`) với SARIF output.

## Responsibilities

- [ ] Create `packages/web/nuclei/` structure
- [ ] Nuclei execution wrapper (CLI + HTTP API)
- [ ] SARIF output parsing (reuse `core.sarif.parser`)
- [ ] Template manager (selection, customization)
- [ ] CLI interface
- [ ] Write 40+ unit tests
- [ ] Write complete documentation

## Dependencies

- **Week 4:** Nuclei installed (via `go install`)
- `core/sarif/parser.py` — Reuse cho parsing
- `core/json/utils.py` — For JSON operations
- `core/logging.py` — For logging

## Outputs

- `packages/web/nuclei/runner.py` — Nuclei execution
- `packages/web/nuclei/template_manager.py` — Template management
- `packages/web/nuclei/tests/` — 40+ tests
- `packages/web/nuclei/README.md` — Documentation

## Communication

- **Status updates:** Every 2 hours — update `STATUS-nuclei.md`
- **Blockers:** Immediately — update `BLOCKERS.md`
- **Questions:** Add to this file

## Quality Standards

- **TDD:** RED→GREEN→REFACTOR
- **Coverage:** >= 80%
- **SARIF:** Compatible với `core.sarif.parser`
- **Mocking:** Mock subprocess để test không cần nuclei

## Timeline

| Week | Tasks | Deliverables |
|------|-------|--------------|
| Week 4 | All nuclei integration | runner.py, template_manager.py, tests |

## Questions

*No questions yet.*

---

*Created: 2026-04-12*
