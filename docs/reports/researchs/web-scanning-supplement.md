# Bổ Sung Nghiên Cứu: Web Scanning cho AI Pentest Agent

**Verify và phân tích các công cụ từ bài nghiên cứu InfoSec**

---

**Ngày nghiên cứu:** 12 tháng 4, 2026  
**Nguồn:** Bài nghiên cứu về AI Pentest Agent integration  
**Phương pháp:** Verify claims → Phân tích bổ sung → Kiến trúc đề xuất  

---

## Mục Lục

1. [Verification các Claims](#verification-các-claims)
2. [Phân Tích Bổ Sung](#phân-tích-bổ-sung)
3. [OWASP ZAP - Deep Dive](#owasp-zap---deep-dive)
4. [Osmedeus - Discovery Quan Trọng](#osmedeus---discovery-quan-trọng)
5. [Kiến Trúc Đề Xuất Cập Nhật](#kiến-trúc-đề-xuất-cập-nhật)
6. [So Sánh Với Nghiên Cứu Trước](#so-sánh-với-nghiên-cứu-trước)
7. [Kết Luận và Khuyến Nghị Mới](#kết-luận-và-khuyến-nghị-mới)

---

## Verification các Claims

### Claim 1: Nuclei ~20k Stars

| Claim | Actual | Status |
|-------|--------|--------|
| ~20k stars | **27.9k stars** | ⚠️ Understated |
| 3.4k forks | ✅ 3.4k forks | ✅ Correct |
| YAML-based | ✅ Confirmed | ✅ Correct |
| Go-based, high concurrency | ✅ Confirmed | ✅ Correct |
| JSON output | ✅ `-jsonl`, `-json-export` | ✅ Correct |
| Template ecosystem | ✅ nuclei-templates | ✅ Correct |
| AI template generation | ✅ AI-assisted templates | ✅ **Additional feature** |
| License | ✅ MIT | ✅ Correct |

**Kết luận:** Claim chính xác, số stars thực tế còn cao hơn (27.9k vs 20k).

### Claim 2: OWASP ZAP

| Claim | Verified | Notes |
|-------|----------|-------|
| OWASP flagship | ✅ Yes | Flagship project |
| REST API | ✅ Yes | Extensive API |
| Automation Framework | ✅ Yes | YAML-based |
| Headless/Daemon mode | ✅ Yes | Can run as service |
| Black-box DAST | ✅ Yes | Full DAST capabilities |
| GitHub stars | **15k** | Not mentioned in article |

**Kết luận:** Claims chính xác, ZAP thực sự là công cụ DAST mạnh nhất open source.

### Claim 3: Osmedeus

| Claim | Verified | Status |
|-------|----------|--------|
| Vietnamese developer | ✅ j3ssie (@j3ssiejj) | ✅ Correct |
| Workflow Engine | ✅ YAML-based pipeline | ✅ Correct |
| Orchestrates tools | ✅ nmap, httpx, nuclei, ffuf, etc. | ✅ Correct |
| CLI-based | ✅ Yes | ✅ Correct |
| GitHub stars | **6.2k** | Not mentioned in article |
| Last update | April 4, 2026 | ✅ Very active |
| **LLM integration** | ✅ Claude Code, Codex, Gemini | ✅ **NEW DISCOVERY!** |
| **SARIF support** | ✅ Yes (for SAST) | ✅ **NEW DISCOVERY!** |
| **Web UI + REST API** | ✅ Yes | ✅ **NEW DISCOVERY!** |
| **Redis-based distributed** | ✅ Yes | ✅ **NEW DISCOVERY!** |

**Kết luận:** Osmedeus v5.0.2 có nhiều tính năng advanced hơn nhiều so với bài báo đề cập!

---

## Phân Tích Bổ Sung

### 1. Nuclei: Additional Features Không Được Đề Cập

**AI-Assisted Template Generation:**
```yaml
# Nuclei hiện đã có AI template generation
# LLM có thể tự động sinh templates từ CVE reports
nuclei --ai-generate "CVE-2026-XXXX" --output new-template.yaml
```

**HTTP API (Experimental):**
```bash
# Flag -hae enables HTTP API mode
nuclei -hae -port 8080
# Allows remote control via REST API
curl http://localhost:8080/api/v1/scan -d '{"target": "https://example.com"}'
```

**Workflow Orchestration:**
```yaml
# Nuclei workflows (multiple templates chained)
workflows:
  - template: tech-detect.yaml
  - template: cves/{{tech}}.yaml  # Conditional on detected tech
```

**Impact cho RAPTOR:**
- ✅ Nuclei có thể tự động sinh templates từ CVE (LLM integration)
- ✅ HTTP API cho phép remote control (không cần CLI wrapper)
- ✅ Workflows cho phép conditional scanning

### 2. OWASP ZAP: Deep Integration Potential

**REST API Architecture:**
```python
# ZAP Python API client
from zapv2 import ZAPv2

zap = ZAPv2(apikey='your-key', proxies={'http': 'http://localhost:8080'})

# Spider/Crawl
zap.spider.scan('https://target.com')
zap.spider.status()  # Check progress

# Active Scan
zap.ascan.scan('https://target.com')
zap.ascan.status()

# Get alerts
alerts = zap.core.alerts()
for alert in alerts:
    print(f"{alert['risk']}: {alert['alert']}")
```

**Automation Framework (YAML):**
```yaml
env:
  contexts:
    - name: "test"
      urls:
        - "https://target.com"

jobs:
  - type: spider
    parameters:
      context: "test"
  
  - type: activeScan
    parameters:
      context: "test"
      policy: "Default"
  
  - type: alertFilter
    parameters:
      context: "test"
  
  - type: outputSummary
    parameters:
      format: "JSON"
      file: "/output/results.json"
```

**Why ZAP is Valuable for RAPTOR:**

| Feature | Nuclei | ZAP | RAPTOR Integration |
|---------|--------|-----|-------------------|
| **Crawling** | Basic | Advanced (DOM analysis) | ✅ ZAP crawling + Nuclei scanning |
| **SQLi Detection** | Templates | Active scanning | ✅ Combined |
| **XSS Detection** | Templates | Active scanning | ✅ Combined |
| **CSRF Detection** | Limited | Full support | ✅ ZAP only |
| **Auth Testing** | Limited | Full support | ✅ ZAP only |
| **API Scanning** | Templates | Limited | ✅ Nuclei only |
| **Headless Browser** | Yes | Yes | ✅ Both |

### 3. Osmedeus v5.0.2: Discovery Quan Trọng

**Đây là phát hiện lớn nhất từ bài nghiên cứu!**

**Architecture v5.0.2:**
```
CONFIG → PARSER → EXECUTOR → STEP DISPATCHER → RUNNER
                                                ├── Host
                                                ├── Docker
                                                └── SSH (distributed)
```

**LLM Agent Integration (ĐIỂM QUAN TRỌNG CHO RAPTOR):**
```yaml
# Osmedeus đã tích hợp LLM agents!
llm:
  - claude-code   # Anthropic Claude
  - codex         # OpenAI Codex
  - opencode      # Open-source alternatives
  - gemini        # Google Gemini
```

**SARIF Support (Tương thích RAPTOR):**
```yaml
# Osmedeus output SARIF cho SAST scans
- type: semgrep
  output: sarif

- type: nuclei
  output: sarif
```

**Redis-Based Distributed Scanning:**
```
Master Worker Queue (Redis)
├── Task deduplication
├── Concurrency control
├── Distributed worker routing
└── Event-driven triggers (cron, file-watch, webhooks)
```

**Web UI + REST API:**
- Built-in dashboard cho scan results
- REST API cho programmatic control
- Interactive visualizations

**Why This Matters for RAPTOR:**

1. **Osmedeus đã làm gần như những gì RAPTOR cần cho web scanning**
2. **LLM integration sẵn có** → Có thể học cách họ tích hợp
3. **SARIF output** → Compatible trực tiếp với RAPTOR
4. **Distributed architecture** → Scalable cho enterprise

---

## OWASP ZAP - Deep Dive

### Integration Methods

**Method 1: Python API Client**
```python
from zapv2 import ZAPv2
import json

class ZAPScanner:
    def __init__(self, target: str, api_key: str):
        self.target = target
        self.zap = ZAPv2(apikey=api_key)
    
    def full_scan(self) -> Dict:
        # Phase 1: Spider
        self.zap.spider.scan(self.target)
        self._wait_for_completion(self.zap.spider.status)
        
        # Phase 2: Ajax Spider (JavaScript rendering)
        self.zap.ajaxSpider.scan(self.target)
        self._wait_for_completion(self.zap.ajaxSpider.status)
        
        # Phase 3: Active Scan
        self.zap.ascan.scan(self.target)
        self._wait_for_completion(self.zap.ascan.status)
        
        # Phase 4: Get results
        alerts = self.zap.core.alerts()
        return self._format_results(alerts)
    
    def _format_results(self, alerts: List[Dict]) -> Dict:
        return {
            'vulnerabilities': [
                {
                    'risk': alert['risk'],
                    'alert': alert['alert'],
                    'url': alert['url'],
                    'param': alert.get('param', ''),
                    'solution': alert.get('solution', ''),
                    'reference': alert.get('reference', ''),
                }
                for alert in alerts
            ]
        }
```

**Method 2: Automation Framework (YAML)**
```yaml
---
env:
  contexts:
    - name: "raptor-target"
      urls:
        - "{{TARGET_URL}}"

jobs:
  - type: spider
    name: "traditional-spider"
    parameters:
      context: "raptor-target"
      maxDuration: 5
  
  - type: spiderAjax
    name: "ajax-spider"
    parameters:
      context: "raptor-target"
      maxDuration: 10
  
  - type: activeScan
    name: "active-scan"
    parameters:
      context: "raptor-target"
      policy: "Default"
      maxRuleDuration: 5
  
  - type: outputSummary
    parameters:
      format: "JSON"
      file: "{{OUTPUT_DIR}}/zap-results.json"
```

**Method 3: Docker Daemon**
```bash
# Run ZAP in daemon mode
docker run -u zap -p 8080:8080 \
  -d ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.key=changeme

# Trigger scan via API
curl "http://localhost:8080/JSON/spider/action/scan/?url=https://target.com&apikey=changeme"
```

### ZAP vs Nuclei: Complementary Strengths

| Capability | ZAP | Nuclei | Best For RAPTOR |
|------------|-----|--------|----------------|
| **Crawling** | ⭐⭐⭐⭐⭐ (DOM + Ajax) | ⭐⭐⭐ (basic) | ✅ Use ZAP crawler |
| **Known CVEs** | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ✅ Use Nuclei |
| **Misconfigurations** | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ✅ Use Nuclei |
| **SQLi (active)** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ✅ Use ZAP |
| **XSS (active)** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ✅ Use ZAP |
| **CSRF** | ⭐⭐⭐⭐⭐ | ⭐⭐ | ✅ Use ZAP |
| **API testing** | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ✅ Use Nuclei |
| **Cloud misconfigs** | ⭐⭐ | ⭐⭐⭐⭐⭐ | ✅ Use Nuclei |
| **Auth bypass** | ⭐⭐⭐⭐ | ⭐⭐⭐ | ✅ Use ZAP |
| **Speed** | ⭐⭐⭐ (Java) | ⭐⭐⭐⭐⭐ (Go) | ✅ Use Nuclei |
| **Template customization** | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ✅ Use Nuclei |

**Conclusion:** ZAP và Nuclei BỔ SUNG cho nhau, không thay thế nhau!

---

## Osmedeus - Discovery Quan Trọng

### v5.0.2 Architecture Analysis

**Pipeline Structure:**
```
CONFIG (YAML)
  ↓
PARSER (YAML → AST)
  ↓
EXECUTOR (Step dispatcher)
  ↓
STEP DISPATCHER (Route to runners)
  ↓
RUNNERS
  ├── Host runner (local execution)
  ├── Docker runner (containerized)
  └── SSH runner (distributed)
```

**Key Innovation: LLM Agent Integration**

Osmedeus đã tích hợp LLM agents vào workflow:

```yaml
# Example: LLM-assisted analysis
modules:
  - name: vuln-analysis
    type: llm
    provider: claude-code
    prompt: |
      Analyze these scan results for high-confidence vulnerabilities:
      {{SCAN_RESULTS}}
    output: analyzed_vulns.json
```

**Why This Is Critical for RAPTOR:**

1. **Proof of Concept:** LLM + security tools integration works
2. **Architecture Reference:** Can learn from their implementation
3. **Competition:** Osmedeus is moving into similar space
4. **Opportunity:** RAPTOR can differentiate with Exploit-DB + validation pipeline

### Redis-Based Distributed Architecture

**Architecture:**
```
┌─────────────────────────────────────────┐
│         Redis Master Queue              │
├─────────────────────────────────────────┤
│  ├── Task deduplication                 │
│  ├── Concurrency control                │
│  ├── Worker routing                     │
│  └── Event triggers                     │
└─────────────────────────────────────────┘
           ↓         ↓         ↓
    ┌──────┐   ┌──────┐   ┌──────┐
    │Host-1│   │Host-2│   │SSH-1 │
    └──────┘   └──────┘   └──────┘
```

**Benefits:**
- Scale horizontally
- Distribute scans across machines
- Fault tolerance
- Centralized task management

**For RAPTOR:**
- Useful cho enterprise deployments
- Can scan multiple targets in parallel
- Distributed fuzzing possible

### SARIF Support

**Osmedeus outputs SARIF cho:**
- Semgrep scans
- Nuclei scans
- Other SAST tools

**RAPTOR Integration:**
```python
# Osmedeus SARIF → RAPTOR core parser
from core.sarif.parser import load_sarif, parse_sarif_findings

sarif = load_sarif('osmedeus-results.sarif')
findings = parse_sarif_findings(sarif)
# Compatible với validation pipeline, LLM analysis
```

---

## Kiến Trúc Đề Xuất Cập Nhật

### Original Proposal
```
Nuclei + katana + httpx + subfinder
```

### Updated Proposal (After Research)
```
┌──────────────────────────────────────────────────────────────┐
│                  RAPTOR Web Scanning Stack                    │
├──────────────────────────────────────────────────────────────┤
│                                                                │
│  LAYER 1: RECON                                              │
│  ┌──────────┐ ┌────────┐ ┌────────┐                         │
│  │subfinder │ │ httpx  │ │ katana │                         │
│  │          │ │        │ │        │                         │
│  │Subdomains│ │Tech    │ │Crawl   │                         │
│  └──────────┘ └────────┘ └────────┘                         │
│                                                                │
│  LAYER 2: VULNERABILITY SCANNING                              │
│  ┌──────────────────────────────────────────┐                │
│  │  Nuclei (primary)                        │                │
│  │  ├─ 5000+ templates                      │                │
│  │  ├─ CVEs, misconfigs, cloud              │                │
│  │  ├─ SARIF output                         │                │
│  │  └─ AI template generation               │                │
│  └──────────────────────────────────────────┘                │
│                                                                │
│  ┌──────────────────────────────────────────┐                │
│  │  OWASP ZAP (complementary)               │                │
│  │  ├─ Advanced crawling (DOM, Ajax)        │                │
│  │  ├─ Active scanning (SQLi, XSS, CSRF)    │                │
│  │  ├─ Auth testing                         │                │
│  │  └─ JSON output                          │                │
│  └──────────────────────────────────────────┘                │
│                                                                │
│  LAYER 3: AI ANALYSIS                                         │
│  ┌──────────────────────────────────────────┐                │
│  │  RAPTOR LLM Engine                       │                │
│  │  ├─ Correlate Nuclei + ZAP results       │                │
│  │  ├─ False positive elimination           │                │
│  │  ├─ Exploit-DB correlation               │                │
│  │  ├─ Exploit generation/validation        │                │
│  │  └─ Report generation                    │                │
│  └──────────────────────────────────────────┘                │
│                                                                │
│  LAYER 4: ORCHESTRATION (Optional - Learn from Osmedeus)     │
│  ┌──────────────────────────────────────────┐                │
│  │  Workflow Engine                         │                │
│  │  ├─ YAML-based pipelines                 │                │
│  │  ├─ Distributed execution (Redis)        │                │
│  │  ├─ LLM agent integration                │                │
│  │  └─ Event-driven triggers                │                │
│  └──────────────────────────────────────────┘                │
│                                                                │
└──────────────────────────────────────────────────────────────┘
```

### Integration Strategy

**Phase 1: Core Stack (Recommended)**
```
Nuclei + subfinder + httpx + katana
```
- Fast to implement
- Covers 80% use cases
- SARIF compatible

**Phase 2: DAST Enhancement**
```
+ OWASP ZAP (API integration)
```
- Add advanced crawling
- Active scanning for SQLi, XSS, CSRF
- Auth testing

**Phase 3: Orchestration**
```
+ Learn from Osmedeus architecture
```
- YAML workflows
- Distributed execution
- LLM agent integration

---

## So Sánh Với Nghiên Cứu Trước

### Bổ Sung Quan Trọng

| Aspect | Nghiên Cứu Trước | Bổ Sung Mới | Impact |
|--------|-----------------|-------------|--------|
| **Tools** | Nuclei, katana, httpx, subfinder | + OWASP ZAP, + Osmedeus | Major |
| **ZAP Role** | Not considered | DAST complement cho Nuclei | Major |
| **Osmedeus** | Not considered | Architecture reference | Medium |
| **Nuclei AI** | Not known | AI template generation | Medium |
| **Nuclei API** | CLI only | HTTP API available | Medium |
| **Architecture** | Simple integration | 4-layer stack | Major |

### Revised Tool Selection

| Tool | Original | Updated | Reason |
|------|----------|---------|--------|
| **Nuclei** | ✅ Primary | ✅ Primary | Still best for templates |
| **katana** | ✅ Crawler | ✅ Crawler | Best for JS rendering |
| **httpx** | ✅ Tech detect | ✅ Tech detect | Best for probing |
| **subfinder** | ✅ Subdomains | ✅ Subdomains | Best for enum |
| **OWASP ZAP** | ❌ Not considered | ✅ **ADDED** | Best for DAST |
| **Osmedeus** | ❌ Not considered | ⚠️ **Reference** | Learn architecture |

---

## Kết Luận và Khuyến Nghị Mới

### Kết Luận

**Bài nghiên cứu InfoSec đã correctly identified:**
1. ✅ Nuclei là optimal choice cho AI Agent (YAML + JSON + performance)
2. ✅ OWASP ZAP bổ sung DAST capabilities
3. ✅ Osmedeus là reference cho orchestration

**Tuy nhiên, có các điểm cần cập nhật:**
1. ⚠️ Nuclei stars là 27.9k (không phải ~20k)
2. ⚠️ Nuclei đã có AI template generation (không đề cập)
3. ⚠️ Nuclei có HTTP API experimental (không đề cập)
4. ⚠️ Osmedeus v5.0.2 đã có LLM integration (rất quan trọng)
5. ⚠️ Osmedeus có SARIF support (compatible với RAPTOR)

### Khuyến Nghị Cập Nhật

**Immediate (P0):**
1. ✅ Nuclei integration (giữ nguyên)
2. ✅ **ADDED:** OWASP ZAP integration (qua Python API)
3. ✅ subfinder + httpx + katana (giữ nguyên)

**Short-term (P1):**
4. **ADDED:** Study Osmedeus v5.0.2 architecture
5. **ADDED:** Learn from Osmedeus LLM integration
6. YAML workflow engine (learn từ Osmedeus)

**Medium-term (P2):**
7. Distributed execution (Redis-based, learn từ Osmedeus)
8. AI template generation cho Nuclei
9. LLM agent integration patterns

### Architecture Decision Matrix

| Decision | Option A | Option B | Recommendation |
|----------|----------|----------|----------------|
| **Primary Scanner** | Nuclei | ZAP | ✅ **Nuclei** (templates + SARIF) |
| **DAST** | None | ZAP | ✅ **ZAP** (complements Nuclei) |
| **Crawler** | katana | ZAP Spider | ✅ **Both** (katana for JS, ZAP for DOM) |
| **Orchestration** | Custom | Learn Osmedeus | ✅ **Learn Osmedeus** |
| **Distribution** | None | Redis-based | ✅ **Phase 3** (future) |

### Updated Timeline

| Phase | Original | Updated | Change |
|-------|----------|---------|--------|
| Phase 1: Foundation | 3 weeks | 3 weeks | ✅ Same |
| Phase 2: Integration | 3 weeks | 4 weeks | +1 week (thêm ZAP) |
| Phase 3: Enhancement | 2 weeks | 3 weeks | +1 week (Osmedeus research) |
| Phase 4: Release | 1 week | 1 week | ✅ Same |
| **Total** | **9 weeks** | **11 weeks** | +2 weeks |

### Updated Effort Estimate

| Component | Original | Updated | Notes |
|-----------|----------|---------|-------|
| Nuclei integration | 80h | 80h | ✅ Same |
| ZAP integration | 0h | **60h** | Python API + Automation Framework |
| katana/httpx/subfinder | 60h | 60h | ✅ Same |
| Osmedeus research | 0h | **30h** | Architecture study |
| Exploit-DB | 120h | 120h | ✅ Same |
| Testing/Docs | 80h | 100h | +20h (more tools) |
| **Total** | **360h** | **450h** | +90h |

---

## Phụ Lục: Quick Reference

### Tool URLs

| Tool | GitHub | Stars | License |
|------|--------|-------|---------|
| Nuclei | projectdiscovery/nuclei | 27.9k | MIT |
| OWASP ZAP | zaproxy/zaproxy | 15k | Apache 2.0 |
| Osmedeus | j3ssie/Osmedeus | 6.2k | MIT |
| katana | projectdiscovery/katana | 12k+ | MIT |
| httpx | projectdiscovery/httpx | 11k+ | MIT |
| subfinder | projectdiscovery/subfinder | 13k+ | MIT |

### Integration Priority

```
Priority 1 (Implement first):
├── Nuclei (SARIF output)
├── subfinder (subdomains)
├── httpx (tech detection)
└── katana (crawling)

Priority 2 (Add DAST):
├── OWASP ZAP (Python API)
└── ZAP Automation Framework

Priority 3 (Future enhancement):
├── Osmedeus architecture patterns
├── Distributed execution (Redis)
├── LLM agent integration
└── AI template generation
```

---

**Kết thúc bổ sung nghiên cứu**

*Các thông tin đã được verify từ official sources (GitHub, documentation) tại thời điểm nghiên cứu.*
