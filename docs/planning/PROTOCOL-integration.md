# Protocol: Subagent 5 — Integration & Testing

## Role

Orchestrate web scanner, integrate all components, ensure end-to-end quality.

## Responsibilities

- [ ] Rewrite `packages/web/scanner.py` (orchestrator)
- [ ] Orchestrate recon → Nuclei → ZAP → correlation
- [ ] Integrate LLM fuzzer (complementary cho zero-day discovery)
- [ ] Exploit-DB + Web findings correlation
- [ ] Validation pipeline integration
- [ ] Performance optimization
- [ ] End-to-end tests (20+)
- [ ] Documentation hoàn chỉnh

## Dependencies

- **Week 6-9:** Depends trên tất cả subagents hoàn thành Phase 1-2
- `packages/exploit_db/` — Exploit-DB integration
- `packages/web/recon/` — Recon tools
- `packages/web/nuclei/` — Nuclei scanning
- `packages/web/zap/` — ZAP DAST
- `core/sarif/parser.py` — SARIF parsing
- `core/logging.py` — Logging

## Outputs

- `packages/web/scanner.py` — Rewritten orchestrator
- `packages/web/tests/test_integration.py` — E2E tests
- `docs/` — Updated documentation
- `README.md` — Web scanning guide

## Communication

- **Status updates:** Every 2 hours — update `STATUS-integration.md`
- **Blockers:** Immediately — update `BLOCKERS.md`
- **Questions:** Add to this file

## Quality Standards

- **TDD:** RED→GREEN→REFACTOR
- **Coverage:** >= 80% cho integration code
- **E2E Tests:** 20+ scenarios
- **Performance:** No regression > 10%

## Timeline

| Week | Tasks | Deliverables |
|------|-------|--------------|
| Week 6-7 | Scanner rewrite + orchestration | scanner.py, integration tests |
| Week 8 | Validation pipeline integration | E2E tests |
| Week 9 | Polish + performance | Benchmarks, docs |

## Questions

*No questions yet.*

---

*Created: 2026-04-12*
