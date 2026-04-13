# Architectural Decisions Log

**Branch:** `feat/exploit-db-web-scanning-upgrade`

---

## Decisions

### D-001: Use TDD Methodology

**Date:** 2026-04-12
**Decision:** Tất cả code phải được viết theo TDD cycle (RED→GREEN→REFACTOR)
**Reason:** Đảm bảo code quality ngay từ đầu, tránh technical debt
**Impact:** Tất cả commits phải có tests pass
**Status:** ✅ Active

### D-002: Zero Technical Debt Policy

**Date:** 2026-04-12
**Decision:** Không merge code nếu chưa đạt DoD
**Reason:** Maintainability lâu dài
**Impact:** Có thể chậm hơn nhưng chất lượng cao hơn
**Status:** ✅ Active

### D-003: Hybrid Exploit-DB Approach

**Date:** 2026-04-12
**Decision:** Sử dụng Local CSV primary + Remote API fallback
**Reason:** Best of both worlds — fast searches + always current
**Impact:** Cần ~2GB disk space cho local database
**Status:** ✅ Active

### D-004: Nuclei + ZAP Stack

**Date:** 2026-04-12
**Decision:** Sử dụng cả Nuclei VÀ ZAP (không phải chọn 1)
**Reason:** Complementary strengths — Nuclei cho known CVEs, ZAP cho active DAST
**Impact:** Phức tạp hơn nhưng coverage đầy đủ
**Status:** ✅ Active

### D-005: SARIF Compatibility

**Date:** 2026-04-12
**Decision:** Tận dụng `core.sarif.parser` cho Nuclei output
**Reason:** Zero new code cho SARIF parsing
**Impact:** Nuclei phải output SARIF (`-se` flag)
**Status:** ✅ Active

### D-006: No Cross-Package Imports

**Date:** 2026-04-12
**Decision:** Packages chỉ import từ `core/`, không import từ packages khác
**Reason:** Tuân thủ RAPTOR architectural principle
**Impact:** Integration phải qua orchestration layer
**Status:** ✅ Active

### D-007: Unified Finding Format

**Date:** 2026-04-13
**Decision:** Tất cả tools output unified finding format với các fields: id, type, severity, title, url, parameter, evidence, cve, cwe, confidence, source, remediation
**Reason:** Cần format thống nhất để aggregation và correlation
**Impact:** Scanner orchestrator normalize tất cả findings trước khi aggregate
**Status:** ✅ Active

### D-008: Graceful Degradation

**Date:** 2026-04-13
**Decision:** Scanner phải gracefully handle missing tools (tool không installed, import error, runtime error)
**Reason:** Production environments có thể không có tất cả tools
**Impact:** Mỗi phase catch exceptions và log warning, không abort toàn bộ scan
**Status:** ✅ Active

---

## Proposed Decisions (Pending)

| ID | Proposal | Proposed By | Status | Decision Date |
|----|----------|-------------|--------|---------------|
| None | - | - | - | - |

---

## Rejected Decisions

| ID | Proposal | Reason Rejected | Date |
|----|----------|-----------------|------|
| None | - | - | - |

---

*Last Updated: 2026-04-12*
