# Protocol: Subagent 2 — Recon Tools Integration

## Role

Implement reconnaissance tools integration (`packages/web/recon/`) bao gồm subfinder, httpx, và katana.

## Responsibilities

- [ ] Create `packages/web/recon/` structure
- [ ] Integrate subfinder (subdomain enumeration)
- [ ] Integrate httpx (technology detection)
- [ ] Integrate katana (deep crawling với JS rendering)
- [ ] Build recon orchestrator
- [ ] Write 50+ unit tests
- [ ] Write complete documentation

## Dependencies

- **Week 1:** None (can start parallel với Exploit-DB)
- **Week 2:** External tools (subfinder, httpx, katana) — install via Go
- `core/json/utils.py` — For JSON operations
- `core/logging.py` — For logging
- `core/config.py` — For output directory

## Outputs

- `packages/web/recon/subfinder.py` — Subdomain enumeration
- `packages/web/recon/httpx.py` — Technology detection
- `packages/web/recon/katana.py` — Deep crawling
- `packages/web/recon/orchestrator.py` — Recon orchestration
- `packages/web/recon/tests/` — 50+ tests
- `packages/web/recon/README.md` — Documentation

## Communication

- **Status updates:** Every 2 hours — update `STATUS-recon.md`
- **Blockers:** Immediately — update `BLOCKERS.md`
- **Questions:** Add to this file
- **Decisions:** Log vào `DECISIONS.md`

## Quality Standards

- **TDD:** RED→GREEN→REFACTOR
- **Coverage:** >= 80%
- **Docs:** Complete trước merge
- **CLI:** argparse cho mỗi tool
- **Mocking:** Mock subprocess calls để test không cần tools thực

## Timeline

| Week | Tasks | Deliverables |
|------|-------|--------------|
| Week 2 | subfinder + httpx | subfinder.py, httpx.py, tests |
| Week 3 | katana + orchestrator | katana.py, orchestrator.py, integration tests |

## Questions

*No questions yet.*

---

*Created: 2026-04-12*
