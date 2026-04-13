# Blockers Tracker

**Branch:** `feat/exploit-db-web-scanning-upgrade`

---

## Active Blockers

| ID | Date | Description | Reported By | Impact | Status | Resolution Plan |
|----|------|-------------|-------------|--------|--------|-----------------|
| None | - | - | - | - | - | - |

---

## Resolved Blockers

| ID | Date | Description | Resolution | Resolved Date |
|----|------|-------------|------------|---------------|
| None | - | - | - | - |

---

## Reporting a Blocker

Khi gặp blocker, subagent cần:

1. **Update file này** với thông tin blocker
2. **Mô tả rõ ràng:**
   - What: Blocker là gì?
   - Why: Tại sao nó block?
   - Impact: Ảnh hưởng đến tasks nào?
   - Help needed: Cần gì để resolve?
3. **Notify main coordinator** ngay lập tức
4. **Update STATUS file** của subagent

---

## Blocker Severity

| Level | Description | Response Time |
|-------|-------------|---------------|
| 🔴 Critical | Cannot proceed at all | Immediate |
| 🟡 High | Major functionality blocked | Within 2 hours |
| 🟢 Medium | Workaround exists but suboptimal | Within 4 hours |
| 🔵 Low | Minor inconvenience | Next sync |

---

## Escalation Path

```
Subagent detects blocker
    ↓
Update this file
    ↓
Update subagent STATUS file
    ↓
Notify main coordinator
    ↓
Main coordinator assigns resolution task
    ↓
Resolution implemented
    ↓
Update this file (Resolved)
```

---

*Last Updated: 2026-04-12*  
*Status: No blockers*
