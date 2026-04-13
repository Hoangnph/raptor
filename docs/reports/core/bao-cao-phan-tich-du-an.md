# Báo Cáo Phân Tích Dự Án RAPTOR

**Ngày Báo Cáo:** 11 tháng 4, 2026  
**Dự Án:** RAPTOR - Framework Nghiên Cứu Bảo Mật Tấn Công/Phòng Thủ Tự Động  
**Phiên Bản:** v1.0-beta (Kiến Trúc Module v2.0)  
**Repository:** https://github.com/gadievron/raptor  

---

## Mục Lục

1. [Tóm Tắt Điều Hành](#tóm-tắt-điều-hành)
2. [Tổng Quan Dự Án](#tổng-quan-dự-án)
3. [Kiến Trúc & Thiết Kế](#kiến-trúc--thiết-kế)
4. [Các Thành Phần Cốt Lõi](#các-thành-phần-cốt-lõi)
5. [Các Gói Bảo Mật](#các-gói-bảo-mật)
6. [Các Engine Phân Tích](#các-engine-phân-tích)
7. [Tích Hợp LLM](#tích-hợp-llm)
8. [Các Tính Năng Chính](#các-tính-năng-chính)
9. [Ngăn Xếp Kỹ Thuật](#ngăn-xếp-kỹ-thuật)
10. [Thống Kê Dự Án](#thống-kê-dự-án)
11. [Điểm Mạnh](#điểm-mạnh)
12. [Lĩnh Vực Cần Cải Thiện](#lĩnh-vực-cần-cải-thiện)
13. [Các Cân Nhắc Bảo Mật](#các-cân-nhắc-bảo-mật)
14. [Khuyến Nghị](#khuyến-nghị)
15. [Kết Luận](#kết-luận)

---

## Tóm Tắt Điều Hành

RAPTOR (Robot Kiểm Thâm Tự Động Đệ Quy - Recursive Autonomous Penetration Testing and Observation Robot) là một framework nghiên cứu bảo mật tự động tiên tiến được xây dựng trên nền tảng Claude Code và sử dụng suy luận LLM (Large Language Model). Framework kết hợp các công cụ kiểm thử bảo mật truyền thống (Semgrep, CodeQL, AFL++) với phân tích tự động dựa trên AI để cung cấp khả năng phát hiện lỗ hổng, xác thực, tạo exploit và vá lỗi một cách toàn diện.

**Các Điểm Nổi Bật Chính:**
- Kiểm thử bảo mật tự động đa lớp với cơ chế tiết lộ tiến trình
- Tích hợp với nhiều nhà cung cấp LLM (Anthropic, OpenAI, Google Gemini, Mistral, Ollama)
- Phân tích khả năng khai thác với xác minh thực nghiệm
- Pipeline xác thực khả năng khai thác đa giai đoạn
- Phân tích crash nâng cao với debug xác định (rr)
- Khả năng điều tra forensics OSS cho repository GitHub
- Kiến trúc module mở rộng với 15+ gói chuyên biệt
- Quản lý chi phí mạnh mẽ với thực thi ngân sách và theo dõi thời gian thực

**Tác Giả:** Gadi Evron, Daniel Cuthbert, Thomas Dullien (Halvar Flake), Michael Bargury, John Cartwright

**Giấy Phép:** MIT

---

## Tổng Quan Dự Án

### Mục Đích

RAPTOR được thiết kế để tự động:
1. **Hiểu code** thông qua phân tích code theo hướng tấn công, ánh xạ bề mặt tấn công và truy vết luồng dữ liệu
2. **Quét code** với Semgrep và CodeQL kèm xác thực luồng dữ liệu
3. **Fuzz binary** sử dụng American Fuzzy Lop (AFL++)
4. **Phân tích lỗ hổng** sử dụng suy luận LLM tiên tiến
5. **Tạo exploit** bằng cách tạo proof-of-concepts
6. **Tạo bản vá** để sửa các lỗ hổng bảo mật
7. **Điều tra forensics OSS** cho các cuộc điều tra repository GitHub có bằng chứng
8. **Quản lý chi phí** với thực thi ngân sách và theo dõi thời gian thực
9. **Báo cáo kết quả** ở các định dạng có cấu trúc

### Giá Trị Khác Biệt

- **Tự Động Hóa Agentic:** Kết hợp công cụ bảo mật truyền thống với suy luận AI tự động
- **Phân Tích Khả Năng Exploit:** Xác định xem lỗ hổng có thực sự có thể khai thác được không trước khi lãng phí công sức
- **Hỗ Trợ LLM Đa Nhà Cung Cấp:** Hoạt động với Anthropic Claude, OpenAI GPT, Google Gemini, Mistral, hoặc Ollama cục bộ
- **Nạp Chuyên Gia Tiến Trình:** Chỉ tải các persona và hướng dẫn chuyên biệt khi cần thiết
- **Thiết Kế Ý Thức Chi Phí:** Tích hợp sẵn thực thi ngân sách và theo dõi chi phí cho mỗi lần quét/phân tích

---

## Kiến Trúc & Thiết Kế

### Kiến Trúc Tổng Quan

```
┌─────────────────────────────────────────────────────────────┐
│                    Framework RAPTOR                          │
├─────────────────────────────────────────────────────────────┤
│  Điểm Truy Cập                                               │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐  │
│  │ raptor.py│ │raptor_   │ │raptor_   │ │raptor_       │  │
│  │(Launcher)│ │agentic.py│ │codeql.py │ │fuzzing.py    │  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────────┘  │
├─────────────────────────────────────────────────────────────┤
│  Lớp Cốt Lõi (Shared Utilities)                               │
│  ┌─────────┐ ┌────────┐ ┌──────────┐ ┌─────────────────┐  │
│  │ config  │ │logging │ │ progress │ │ sarif/parser    │  │
│  └─────────┘ └────────┘ └──────────┘ └─────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ inventory/  │ json/  │ project/ │ reporting/ │ run/   │   │
│  └──────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│  Lớp Gói (Các Khả Năng Bảo Mật)                               │
│  ┌─────────────┐ ┌──────────┐ ┌──────────────┐            │
│  │static-      │ │ codeql/  │ │ llm_         │            │
│  │analysis     │ │          │ │ analysis     │            │
│  └─────────────┘ └──────────┘ └──────────────┘            │
│  ┌─────────────┐ ┌──────────┐ ┌──────────────┐            │
│  │autonomous/  │ │ fuzzing/ │ │ binary_      │            │
│  │             │ │          │ │ analysis     │            │
│  └─────────────┘ └──────────┘ └──────────────┘            │
│  ┌─────────────┐ ┌──────────┐ ┌──────────────┐            │
│  │exploit_     │ │exploit-  │ │ diagram/     │            │
│  │feasibility  │ │ability_  │ │              │            │
│  │             │ │validation│ │              │            │
│  └─────────────┘ └──────────┘ └──────────────┘            │
│  ┌─────────────┐ ┌──────────┐ ┌──────────────┐            │
│  │exploita-    │ │ recon/   │ │ sca/         │            │
│  │tion         │ │          │ │              │            │
│  └─────────────┘ └──────────┘ └──────────────┘            │
│  ┌─────────────┐ ┌──────────┐                              │
│  │ web/        │ │ cvss/    │                              │
│  │             │ │          │                              │
│  └─────────────┘ └──────────┘                              │
├─────────────────────────────────────────────────────────────┤
│  Các Engine Phân Tích                                         │
│  ┌─────────────────────┐  ┌──────────────────────────┐     │
│  │ CodeQL Suites       │  │ Semgrep Rules            │     │
│  │ (custom queries)    │  │ (custom rules)           │     │
│  └─────────────────────┘  └──────────────────────────┘     │
├─────────────────────────────────────────────────────────────┤
│  Hệ Thống Chuyên Gia Phân Tầng                                 │
│  ┌──────────────────────────────────────────────────┐       │
│  │ 9 Expert Personas + Recovery Protocols            │       │
│  └──────────────────────────────────────────────────┘       │
├─────────────────────────────────────────────────────────────┤
│  Tích Hợp Claude Code                                         │
│  ┌─────────────┐ ┌──────────┐ ┌─────────────────────┐      │
│  │ Commands    │ │ Agents   │ │ Skills              │      │
│  │ (21 files)  │ │(16 files)│ │ (multiple skills)   │      │
│  └─────────────┘ └──────────┘ └─────────────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

### Nguyên Tắc Thiết Kế

1. **Một trách nhiệm cho mỗi gói** - Mỗi gói có một mục đích duy nhất, rõ ràng
2. **Không import chéo giữa các gói** - Các gói chỉ import từ core, không import lẫn nhau
3. **Khả năng thực thi độc lập** - Mỗi agent.py có thể chạy độc lập
4. **Giao diện CLI rõ ràng** - Mỗi gói có CLI dựa trên argparse
5. **Tiết lộ tiến trình** - Chỉ tải chuyên gia khi cần (360t → 925t → 2,500t+ token)
6. **Module và mở rộng** - Dễ dàng thêm các khả năng mới

### Cấu Trúc Thư Mục

```
raptor/
├── core/                    # Shared utilities (14 thư mục/module)
│   ├── config.py           # Quản lý cấu hình tập trung
│   ├── logging.py          # JSONL logging có cấu trúc
│   ├── progress.py         # Theo dõi tiến trình
│   ├── schema_constants.py # Các hằng số schema
│   ├── understand_bridge.py # Cầu nối hiểu code
│   ├── inventory/          # Xây dựng inventory nguồn
│   ├── json/               # JSON utilities
│   ├── project/            # Quản lý dự án
│   ├── reporting/          # Reporting utilities
│   ├── run/                # Quản lý vòng đời run
│   ├── sarif/              # SARIF parsing
│   ├── startup/            # Khởi tạo startup/banner
│   └── tests/              # Core unit tests
├── packages/               # Các khả năng bảo mật (15 gói)
├── engine/                 # Các engine phân tích
│   ├── codeql/suites/      # CodeQL query suites
│   └── semgrep/            # Semgrep rules và config
├── tiers/                  # Các persona và hướng dẫn chuyên gia
│   ├── personas/           # 9 file expert persona
│   └── specialists/        # Các cơ sở kiến thức chuyên gia
├── docs/                   # Tài liệu
├── test/                   # Shell-based test scripts
├── tests/                  # Python unit tests
├── .claude/                # Tích hợp Claude Code
│   ├── commands/           # 21 slash commands
│   ├── agents/             # 16 định nghĩa agent
│   └── skills/             # Nhiều skill module
├── .github/workflows/      # CI/CD pipelines
├── .devcontainer/          # VS Code dev container
├── raptor.py               # Launcher thống nhất chính
├── raptor_agentic.py       # Autonomous workflow (Semgrep + CodeQL)
├── raptor_codeql.py        # Phân tích chỉ CodeQL
└── raptor_fuzzing.py       # Binary fuzzing workflow
```

---

## Các Thành Phần Cốt Lõi

### 1. Quản Lý Cấu Hình (`core/config.py`)

**Mục Đích:** Quản lý cấu hình tập trung và đường dẫn

**Tính Năng:**
- Nguồn duy nhất cho tất cả đường dẫn
- Hỗ trợ biến môi trường (RAPTOR_ROOT)
- Xử lý biến môi trường an toàn (loại bỏ các biến nguy hiểm)
- Fallback linh hoạt sang auto-detection

**Phương Thức Chính:**
- `get_raptor_root()` - Lấy root cài đặt RAPTOR
- `get_out_dir()` - Lấy thư mục output
- `get_logs_dir()` - Lấy thư mục logs
- `get_safe_env()` - Môi trường đã làm sạch cho subprocesses

### 2. Structured Logging (`core/logging.py`)

**Mục Đích:** Logging thống nhất với audit trail

**Tính Năng:**
- Định dạng JSONL cho structured logs (máy đọc được)
- Output console cho con người đọc
- File logs có timestamp (raptor_<timestamp>.jsonl)
- Tự động tạo thư mục log

### 3. SARIF Parser (`core/sarif/parser.py`)

**Mục Đích:** Phân tích và trích xuất dữ liệu từ file SARIF 2.1.0

**Hàm Chính:**
- `parse_sarif(sarif_path)` - Tải và xác thực file SARIF
- `get_findings(sarif)` - Trích xuất danh sách finding
- `get_severity(result)` - Ánh xạ mức SARIF sang mức độ nghiêm trọng

### 4. Source Inventory (`core/inventory/`)

**Mục Đích:** Xây dựng và quản lý inventories code cho phân tích

**Thành Phần:**
- `builder.py` - build_inventory() với file enumeration + checksums
- `extractors.py` - Language-aware function extraction (12 ngôn ngữ)
- `languages.py` - LANGUAGE_MAP, detect_language
- `exclusions.py` - File exclusion logic + phát hiện file được sinh
- `diff.py` - compare_inventories() với SHA-256 diffing
- `coverage.py` - checked_by tracking + coverage stats

### 5. Quản Lý Dự Án (`core/project/`)

**Mục Đích:** Quản lý các workspace có tên cho các lần phân tích

**Tính Năng:**
- Named project workspaces
- Shared directory cho các lần phân tích
- Project status, diff, merge, report, export
- Theo dõi vòng đời run

### 6. Quản Lý Vòng Đời Run (`core/run/`)

**Mục Đích:** Theo dõi trạng thái và metadata của run phân tích

**Tính Năng:**
- Quản lý thư mục output
- Theo dõi trạng thái run (running, complete, failed)
- Persistence metadata (.raptor-run.json)

---

## Các Gói Bảo Mật

### 1. Phân Tích Tĩnh (`packages/static-analysis/`)

**Mục Đích:** Phân tích code tĩnh sử dụng Semgrep

**Điểm Truy Cập:** `scanner.py`

**Tính Năng:**
- Quét Semgrep với các policy group đã cấu hình
- Phân tích và chuẩn hóa output SARIF
- Tạo scan metrics (files scanned, findings, severities)
- Hỗ trợ nhiều policy group (secrets, owasp, crypto, v.v.)

**CLI:**
```bash
python3 packages/static-analysis/scanner.py --repo /path/to/code --policy_groups secrets,owasp
```

**Outputs:**
- `semgrep_<policy>.sarif` - SARIF 2.1.0 findings
- `scan_metrics.json` - Thống kê scan

### 2. Phân Tích CodeQL (`packages/codeql/`)

**Mục Đích:** Phân tích CodeQL chuyên sâu với xác thực luồng dữ liệu tự động

**Thành Phần:**
- `agent.py` - CodeQL workflow orchestrator chính
- `autonomous_analyzer.py` - Phân tích CodeQL sử dụng LLM
- `build_detector.py` - Tự động phát hiện hệ thống build
- `database_manager.py` - Tạo/quản lý database CodeQL
- `dataflow_validator.py` - Xác thực các đường dẫn dataflow
- `dataflow_visualizer.py` - Tạo sơ đồ dataflow trực quan
- `language_detector.py` - Phát hiện ngôn ngữ lập trình
- `query_runner.py` - Thực thi CodeQL queries

**Tính Năng:**
- Tự động phát hiện ngôn ngữ và hệ thống build
- Tạo database CodeQL
- Thực thi queries với custom suites
- Xác thực và trực quan hóa đường dẫn dataflow
- Đánh giá khả năng khai thác sử dụng LLM

**Ngôn Ngữ Hỗ Trợ:** Python, Java, C/C++, JavaScript, Go, và nhiều ngôn ngữ khác

**CLI:**
```bash
python3 packages/codeql/agent.py --repo /path/to/code --language python
```

**Outputs:**
- `codeql_*.sarif` - CodeQL findings
- `dataflow_*.json` - Validated dataflow paths
- `dataflow_*.svg` - Sơ đồ dataflow trực quan

### 3. Phân Tích LLM (`packages/llm_analysis/`)

**Mục Đích:** Phân tích lỗ hổng tự động sử dụng LLM

**Điểm Truy Cập:**
- `agent.py` - Phân tích độc lập (tương thích OpenAI/Anthropic)
- `orchestrator.py` - Điều phối đa agent (yêu cầu Claude Code)
- `crash_agent.py` - Phân tích crash binary

**Trừu Tượng Hóa LLM:**
```
llm/
├── client.py       # Giao diện client thống nhất
├── config.py       # API keys, chọn model, theo dõi chi phí
├── detection.py    # Phát hiện khả dụng LLM
├── model_data.py   # Chi phí model, giới hạn, endpoints
└── providers.py    # Các triển khai provider (Anthropic, OpenAI, v.v.)
```

**Tính Năng:**
- Không phụ thuộc provider (dễ dàng chuyển đổi OpenAI ↔ Anthropic ↔ Gemini)
- Cấu hình qua biến môi trường
- Rate limiting và xử lý lỗi
- Theo dõi chi phí với breakdown theo yêu cầu
- Structured output với xác thực Pydantic
- Thực thi ngân sách

**Các Provider Được Hỗ Trợ:**
- Anthropic Claude (native structured output)
- OpenAI GPT-4
- Google Gemini/Gemma
- Mistral
- Ollama (cục bộ)

**Ví Dụ Theo Dõi Chi Phí:**
```python
from packages.llm_analysis.llm.config import LLMConfig

config = LLMConfig(
    max_cost_per_scan=1.0  # Ngăn chặn vượt quá $1 mỗi lần quét
)
```

### 4. Khả Năng Tự Động (`packages/autonomous/`)

**Mục Đích:** Các khả năng agent tự động cấp cao hơn

**Thành Phần:**
- `corpus_generator.py` - Tạo corpus fuzzing thông minh
- `dialogue.py` - Quản lý dialogue của agent (MultiTurnAnalyser)
- `exploit_validator.py` - Tự động xác thực code exploit
- `goal_planner.py` - Lập kế hoạch định hướng mục tiêu
- `memory.py` - Quản lý bộ nhớ và ngữ cảnh của agent
- `planner.py` - Phân tách và lập kế hoạch tác vụ (FuzzingPlanner)

**Tính Năng:**
- Lập kế hoạch tác vụ tự động với suy luận LLM
- Biên dịch và kiểm thử exploit
- Tạo corpus nhận thức ngữ cảnh
- Bộ nhớ persistent qua các lần tương tác
- Đối thoại đa lượt cho phân tích sâu hơn
- Hoạt động định hướng mục tiêu

### 5. Phân Tích Binary (`packages/binary_analysis/`)

**Mục Đích:** Phân tích crash binary và debugging sử dụng GDB

**Thành Phần:**
- `crash_analyser.py` - Trích xuất và phân loại ngữ cảnh crash chính
- `debugger.py` - GDB automation wrapper

**Các Loại Crash Được Phát Hiện:**
- Tràn bộ nhớ stack (SIGSEGV với địa chỉ stack)
- Tham nhũng heap (SIGSEGV với địa chỉ heap, lỗi malloc)
- Use-after-free (SIGSEGV trên bộ nhớ đã giải phóng)
- Tràn số nguyên (SIGFPE, phát hiện wraparound)
- Lỗ hổng format string (SIGSEGV trong hàm printf)
- NULL pointer dereference (SIGSEGV tại địa chỉ thấp)

**Quy Trình Phân Tích:**
1. Chạy binary dưới GDB với input crash
2. Bắt signal và địa chỉ crash
3. Trích xuất stack trace và dump thanh ghi
4. Disassemble vị trí crash
5. Phân loại crash type dựa trên signal và ngữ cảnh

### 6. Fuzzing (`packages/fuzzing/`)

**Mục Địch:** Điều phối fuzzing binary sử dụng AFL++

**Thành Phần:**
- `afl_runner.py` - Quản lý và giám sát tiến trình AFL++
- `crash_collector.py` - Triage, deduplication và xếp hạng crash
- `corpus_manager.py` - Tạo và quản lý seed corpus

**Tính Năng:**
- Hỗ trợ fuzzing song song (nhiều instance AFL)
- Tự động deduplicate crash theo signal
- Dừng sớm khi đạt ngưỡng crash
- Hỗ trợ binary AFL-instrumented và chế độ QEMU
- Phân tích coverage với afl-showmap

**CLI:**
```bash
python3 raptor_fuzzing.py --binary /path/to/binary --duration 3600 --max-crashes 10
```

**Outputs:**
- `afl_output/` - Kết quả fuzzing AFL++
- Crash inputs được xếp hạng theo khả năng khai thác

### 7. Khả Năng Exploit (`packages/exploit_feasibility/`)

**Mục Đích:** Phân tích các giảm nhẹ hệ thống và binary để xác định xem việc khai thác có thực sự khả thi không

**Đổi Mới Chính:** Trả lời câu hỏi "Tôi có thực sự khai thác được không?" trước khi cố gắng phát triển exploit

**Tính Năng:**
- Xác minh thực nghiệm (thực sự kiểm tra xem kỹ thuật có hoạt động không)
- Phân tích nhận thức ràng buộc (null bytes, bad bytes, input handlers)
- Verdict trung thực (Có thể khai thác / Khó / Không thể)
- Persistence ngữ cảnh (tồn tại qua việc nén ngữ cảnh hội thoại)
- 275+ unit tests

**Các Câu Hỏi Chính Được Trả Lời:**
- Tôi có thực sự ghi được vào GOT entry đó không? (Full RELRO chặn cả GOT VÀ .fini_array)
- ROP chain của tôi có hoạt động với strcpy không? (Không - null bytes trong địa chỉ x86_64)
- %n có hoạt động trên hệ thống này không? (glibc 2.38+ có thể chặn)
- Có đủ gadgets khả dụng không? (Bad bytes có thể lọc ra hầu hết gadgets)

**API:**
```python
from packages.exploit_feasibility import analyze_binary, format_analysis_summary

result = analyze_binary('/path/to/binary')
print(format_analysis_summary(result, verbose=True))
```

**Ví Dụ Output:**
```
PHÂN TÍCH KHẢ NĂNG EXPLOIT
════════════════════════════════════════════════════════════════════════════════
Binary: /home/user/vuln
Verdict: Khó

CÁC BẢO VỆ
────────────────────────────────────────
  PIE:        Có (binary base được randomize)
  NX:         Có (không có shellcode trên stack)
  Canary:     Có (stack smashing protection)
  RELRO:      Full (GOT và .fini_array chỉ đọc)

CÁC GIẢM NHẸ GLIBC (phiên bản 2.38)
────────────────────────────────────────
  __malloc_hook:     Đã xóa (glibc 2.34+)
  __free_hook:       Đã xóa (glibc 2.34+)
  %n specifier:      BỊ CHẶN (đã kiểm tra thực nghiệm)

RÀNG BUỘC INPUT
────────────────────────────────────────
  Handler:    strcpy
  Bad bytes:  0x00
  Impact:     Không thể ghi địa chỉ x86_64 đầy đủ (null tại byte 6)

CHAIN BREAKS
────────────────────────────────────────
  ✗ GOT overwrite bị chặn bởi Full RELRO
  ✗ .fini_array bị chặn bởi Full RELRO
  ✗ Hook overwrite bị chặn (hooks đã xóa trong glibc 2.34+)
  ✗ Format string %n bị chặn bởi glibc
  ✗ Multi-gadget ROP bị chặn bởi null bytes trong địa chỉ
```

**Phụ Thuộc:**
- `pwntools` (phân tích binary)
- `ROPgadget` (liệt kê gadget)
- `one_gadget` (tùy chọn, phát hiện one-gadget)
- `checksec` (tùy chọn, phát hiện bảo vệ binary)

### 8. Xác Thực Khả Năng Exploit (`packages/exploitability_validation/`)

**Mục Đích:** Pipeline đa giai đoạn để xác thực rằng các finding lỗ hổng là thật, có thể tiếp cận và có thể khai thác

**Các Giai Đoạn Pipeline:**

| Giai Đoạn | Tên | Ai | Làm Gì |
|-----------|-----|-----|--------|
| **0** | Inventory | Python | `build_checklist()` — trích xuất tất cả hàm từ source |
| **A** | Discovery | LLM | Phân tích one-shot — xác định lỗ hổng tiềm năng |
| **B** | Investigation | LLM | Attack trees, hypotheses, thu thập bằng chứng hệ thống |
| **C** | Sanity | LLM | Xác minh findings với code thực tế (bắt hallucination) |
| **D** | Ruling | LLM | Xác định cuối cùng — exploitable, confirmed, hoặc ruled out |
| **E** | Feasibility | Python | Phân tích ràng buộc binary (chỉ memory corruption) |
| **F** | Review | LLM | Tự review — bắt nhầm lẫn, sửa lỗi schema |

**File Output:**
- `checklist.json` - Stage 0 inventory
- `findings.json` - Stages A-F với enrichment tiến trình
- `attack-surface.json` - Sources, sinks, trust boundaries
- `attack-tree.json` - Attack knowledge graph
- `hypotheses.json` - Predictions có thể kiểm tra
- `disproven.json` - Các phương pháp thất bại và lý do
- `attack-paths.json` - Các đường đã thử, điểm PROXIMITY, blockers
- `exploit-context.json` - Ràng buộc binary (nếu có binary)
- `validation-report.md` - Báo cáo tổng hợp dễ đọc

**Tích hợp với exploit_feasibility:**
- Stage E gọi `analyze_binary()` từ gói exploit_feasibility
- Stage E gọi `map_findings_to_constraints()` cho verdicts theo finding
- Lỗ hổng web (SQLi, XSS, SSRF) bỏ qua Stage E và tiến thẳng đến F

### 9. Exploitation (`packages/exploitation/`)

**Mục Đích:** Phát triển exploit và báo cáo

**Thành Phần:**
- `bootstrap.py` - Bootstrapping exploit
- `reporting.py` - Báo cáo exploit

### 10. Trinh Thám (`packages/recon/`)

**Mục Đích:** Trinh thám và liệt kê công nghệ

**Tính Năng:**
- Phát hiện ngôn ngữ lập trình
- Xác định frameworks và libraries
- Liệt kê dependencies
- Ánh xạ bề mặt tấn công
- Tạo báo cáo trinh thám

**Output:** `recon_report.json`

### 11. Phân Tích Thành Phần Phần Mềm (`packages/sca/`)

**Mục Đích:** Quét lỗ hổng dependency

**Tính Năng:**
- Phát hiện file dependency (requirements.txt, package.json, pom.xml, v.v.)
- Truy vấn cơ sở dữ liệu lỗ hổng (OSV, NVD, v.v.)
- Tạo báo cáo lỗ hổng dependency
- Đề xuất khắc phục (nâng cấp version)

**Output:** `sca_report.json`, `dependencies.json`

### 12. Kiểm Thử Ứng Dụng Web (`packages/web/`) ⚠️ ALPHA

**Mục Đích:** Kiểm thử bảo mật ứng dụng web

**Thành Phần:**
- `client.py` - HTTP client wrapper (quản lý session, headers)
- `crawler.py` - Web crawler (liệt kê endpoints)
- `fuzzer.py` - Input fuzzing (kiểm thử injection)
- `scanner.py` - Main orchestrator (kiểm tra OWASP Top 10)

**Lưu Ý:** Đây được đánh dấu là STUB/ALPHA và không nên dựa vào

### 13. Tạo Sơ Đồ (`packages/diagram/`)

**Mục Đích:** Tạo sơ đồ Mermaid trực quan từ kết quả phân tích

**Tính Năng:**
- Trực quan hóa context map (entry points → trust boundaries → sinks)
- Trực quan hóa flow trace (call chains, biến tainted, kiểm soát attacker)
- Trực quan hóa attack tree (knowledge graph với trạng thái)
- Trực quan hóa attack paths (step chains với điểm proximity)

**Tích Hợp:** Tự động sinh ở cuối lệnh `/validate` và `/understand`

**Sử Dụng Chương Trình:**
```python
from packages.diagram import render_and_write
from pathlib import Path

out_file = render_and_write(Path(".out/code-understanding-20240101/"), target="myapp")
```

### 14. Máy Tính CVSS (`packages/cvss/`)

**Mục Đích:** Tính toán điểm CVSS

**Thành Phần:** `calculator.py`

---

## Các Engine Phân Tích

### Engine CodeQL (`engine/codeql/`)

**Mục Đích:** CodeQL query suites và cấu hình

**Nội Dung:**
- Custom CodeQL query suites cho các ngôn ngữ khác nhau
- Cấu hình query cho taint tracking, security patterns, dataflow analysis

**Sử Dụng:** Được tiêu thụ bởi `packages/codeql/` cho quét CodeQL tự động

### Engine Semgrep (`engine/semgrep/`)

**Mục Đích:** Semgrep rules và cấu hình

**Custom Rules:**
- `auth/tls-skip-verify.yaml` - Phát hiện bỏ qua xác minh TLS
- `crypto/` - 8 rules liên quan đến crypto (weak-hash, weak-block-modes, weak-kdf-*, v.v.)
- `deserialisation/unsafe-java-deserialize.yaml` - Lỗ hổng deserialization Java
- `filesystem/path-traversal.yaml` - Phát hiện path traversal
- `flows/bad-mac-order.yaml` - Vấn đề thứ tự tính toán MAC
- `injection/command-taint.yaml`, `sql-concat.yaml` - Command injection, SQL injection
- `logging/logs-secrets.yaml` - Phát hiện secrets trong logs
- `secrets/hardcoded-api-key.yaml` - API keys được mã hóa cứng
- `sinks/ssrf.yaml` - Server-Side Request Forgery

**Cấu Hình:** `semgrep.yaml` - Cấu hình Semgrep chính

**Sử Dụng:** Được tiêu thụ bởi `packages/static-analysis/scanner.py` cho quét Semgrep

---

## Tích Hợp LLM

### Các Provider Được Hỗ Trợ

| Provider | Hỗ Trợ Model | Chi Phí | Structured Output |
|----------|--------------|---------|-------------------|
| **Anthropic Claude** | claude-opus-4-6, v.v. | ~$0.03/lỗ hổng | ✅ Native |
| **OpenAI GPT-4** | GPT-4, v.v. | ~$0.03/lỗ hổng | ✅ Qua Instructor |
| **Google Gemini** | Gemini 2.5, Gemma 4 | ~$0.03/lỗ hổng | ✅ Native SDK |
| **Mistral** | Various | Thay đổi | ✅ Qua OpenAI SDK |
| **Ollama (local)** | llama3:70b, v.v. | MIỄN PHÍ | ⚠️ Giới hạn |

**Lưu Ý:** Tạo exploit yêu cầu các model tiên tiến (Claude, GPT, hoặc Gemini). Các model cục bộ hoạt động cho phân tích nhưng có thể sinh code exploit không biên dịch được.

### Quản Lý Chi Phí

**Tính Năng:**
- Thực thi ngân sách (ngăn chặn vượt quá giới hạn chi phí)
- Theo dõi chi phí thời gian thực với thông báo lỗi chi tiết
- Phát hiện rate limit thông minh với hướng dẫn theo provider
- Định giá split input/output với breakdown theo yêu cầu
- Chọn model thông minh từ cấu hình hoặc môi trường

**Cấu Hình:**
```json
// ~/.config/raptor/models.json
{
  "models": [
    {"provider": "anthropic", "model": "claude-opus-4-6", "api_key": "sk-ant-..."},
    {"provider": "ollama", "model": "llama3:70b"}
  ]
}
```

**Biến Môi Trường:**
- `ANTHROPIC_API_KEY` - Anthropic Claude API key
- `OPENAI_API_KEY` - OpenAI API key
- `GEMINI_API_KEY` - Google Gemini API key
- `MISTRAL_API_KEY` - Mistral API key
- `OLLAMA_HOST` - Ollama server URL (mặc định: `http://localhost:11434`)
- `RAPTOR_CONFIG` - Đường dẫn đến file cấu hình models JSON của RAPTOR

### Structured Output

**Triển Khai:** Instructor + Pydantic fallback cho phản hồi JSON đáng tin cậy

**Lợi Ích:**
- Định dạng output nhất quán qua các provider
- Xác thực schema cho dữ liệu quan trọng
- Giảm graceful khi model không hỗ trợ native structured output

---

## Các Tính Năng Chính

### 1. Hiểu Code Theo Hướng Tấn Công

**Lệnh:** `/understand <target> [--map] [--trace <entry>] [--hunt <pattern>] [--teach <subject>]`

**Chế Độ:**
- `--map` — Xây dựng ngữ cảnh: entry points, trust boundaries, sinks → `context-map.json`
- `--trace <entry>` — Theo dõi một luồng dữ liệu source → sink với full call chain → `flow-trace-<id>.json`
- `--hunt <pattern>` — Tìm tất cả biến thể của pattern trên codebase → `variants.json`
- `--teach <subject>` — Giải thích framework, library, hoặc pattern chuyên sâu (inline)

**Skills:**
- `map.md` — Liệt kê entry point, ánh xạ trust boundary, catalog sink
- `trace.md` — Truy vết data flow từng bước với branch coverage
- `hunt.md` — Phân tích biến thể structural, semantic, và root-cause
- `teach.md` — Giải thích framework/pattern với kết luận bảo mật

### 2. Điều Tra Forensics OSS

**Lệnh:** `/oss-forensics <prompt> [--max-followups 3] [--max-retries 3]`

**Khả Năng:**
- Thu Thập Bằng Chứng: Thu thập bằng chứng đa nguồn (GH Archive, GitHub API, Wayback Machine, local git)
- Tích Hợp BigQuery: Truy vấn dữ liệu sự kiện GitHub bất biến qua GH Archive
- Khôi Phục Nội Dung Đã Xóa: Khôi phục commits, issues, và nội dung repository đã xóa
- Trích Xuất IOC: Tự động trích xuất indicators of compromise từ báo cáo vendor
- Xác Minh Bằng Chứng: Xác minh bằng chứng nghiêm ngặt với nguồn gốc
- Hình Thành Giả Thuyết: Hình thành giả thuyết dựa trên bằng chứng với tinh chỉnh lặp
- Báo Cáo Forensic: Báo cáo chi tiết với timeline, attribution, và IOCs

**Agents:**
- `oss-forensics-agent` - Main orchestrator
- `oss-investigator-gh-archive-agent` - Truy vấn GH Archive qua BigQuery
- `oss-investigator-gh-api-agent` - Truy vấn GitHub API trực tiếp
- `oss-investigator-gh-recovery-agent` - Khôi phục nội dung đã xóa
- `oss-investigator-local-git-agent` - Phân tích repos đã clone cho dangling commits
- `oss-investigator-ioc-extractor-agent` - Trích xuất IOCs từ báo cáo vendor
- `oss-hypothesis-former-agent` - Hình thành giả thuyết dựa trên bằng chứng
- `oss-evidence-verifier-agent` - Xác minh bằng chứng
- `oss-hypothesis-checker-agent` - Xác thực claims
- `oss-report-generator-agent` - Tạo báo cáo forensic cuối cùng

**Yêu Cầu:** `GOOGLE_APPLICATION_CREDENTIALS` cho BigQuery

### 3. Phân Tích Crash

**Lệnh:** `/crash-analysis <bug-tracker-url> <git-repo-url>`

**Khả Năng:**
- Phân tích root-cause tự động cho crash C/C++
- Debug record-replay xác định với rr
- Function execution traces
- Phân tích code coverage với gcov
- Truy vấn thực thi dòng nhanh

**Yêu Cầu:** rr, gcc/clang (với ASAN), gdb, gcov

### 4. Các Persona Chuyên Gia (9 Tổng Cộng)

Tải theo yêu cầu qua "Use [persona name]":

1. **Mark Dowd** - Chuyên gia binary exploitation
2. **Charlie Miller/Halvar Flake** - Security researcher
3. **Security Researcher** - Nghiên cứu bảo mật tổng quát
4. **Patch Engineer** - Phát triển bản vá bảo mật
5. **Penetration Tester** - Phương pháp penetration testing
6. **Fuzzing Strategist** - Phát triển chiến lược fuzzing
7. **Binary Exploitation Specialist** - Chuyên gia binary exploitation
8. **CodeQL Dataflow Analyst** - Phát triển CodeQL query
9. **CodeQL Finding Analyst** - Phân tích CodeQL finding

### 5. Tích Hợp Claude Code

**Commands (21 tổng cộng):**
- `/raptor` - RAPTOR security testing assistant (bắt đầu từ đây)
- `/scan` - Phân tích code tĩnh (Semgrep + CodeQL + LLM)
- `/fuzz` - Binary fuzzing (AFL++ + crash analysis)
- `/web` - Kiểm thử ứng dụng web (STUB - xem như alpha)
- `/agentic` - Full autonomous workflow (phân tích + tạo exploit/patch)
- `/codeql` - CodeQL-only deep analysis với dataflow
- `/analyze` - LLM analysis only (không tạo exploit/patch - nhanh & rẻ hơn 50%)
- `/validate` - Exploitability validation pipeline
- `/exploit` - Tạo exploit proof-of-concepts (beta)
- `/patch` - Tạo security patches cho lỗ hổng (beta)
- `/understand` - Adversarial code comprehension
- `/oss-forensics` - Điều tra forensic có bằng chứng
- `/crash-analysis` - Autonomous crash root-cause analysis
- `/diagram` - Tạo sơ đồ trực quan Mermaid
- `/project` - Quản lý dự án
- `/create-skill` - Lưu các phương pháp tùy chỉnh (thử nghiệm)
- `/test-workflows` - Chạy bộ test toàn diện (stub)
- `/commands` - Hiển thị tất cả commands có sẵn

**Agents (16 tổng cộng):**
- `crash-analysis-agent` - Main crash analysis orchestrator
- `crash-analyzer-agent` - Phân tích root-cause chuyên sâu sử dụng rr traces
- `crash-analyzer-checker-agent` - Xác minh phân tích nghiêm ngặt
- `function-trace-generator-agent` - Tạo function execution traces
- `coverage-analysis-generator-agent` - Tạo dữ liệu coverage gcov
- `exploitability-validator-agent` - Xác minh khả năng exploit
- `offsec-specialist` - Offensive security specialist với SecOpsAgentKit
- Nhiều agent điều tra OSS khác

### 6. Quản Lý Dự Án

**Commands:**
```
/project create myapp --target /path/to/code -d "Description"
/project use myapp
/scan                          # output goes to project dir
/project status                # shows all runs and findings
/project report                # merged view across all runs
/project clean --keep 3        # delete old runs
```

**Tính Năng:**
- Named workspaces tùy chọn
- Shared directory cho các lần phân tích
- Project status, diff, merge, report, export

### 7. Bảo Mật: Repos Không Tin Cậy

**Bảo Vệ Chống Lại:**
- File `.claude/settings.json` độc hại trong repos
- Injection biến môi trường (TERMINAL, EDITOR, VISUAL, BROWSER, PAGER)
- Injection đường dẫn file từ repos được quét

**Biện Pháp Bảo Vệ:**
- Chặn Claude Code sub-agent dispatch nếu tìm thấy settings độc hại
- `RaptorConfig.get_safe_env()` loại bỏ các biến môi trường nguy hiểm
- Sử dụng list-based subprocess arguments (không nội suy chuỗi)
- Sử dụng `--add-dir` cho sub-agents (chỉ truy cập file, không tải settings)

### 8. Quản Lý Vòng Đời Run

**Trước khi bắt đầu:**
```bash
OUTPUT_DIR=$(python3 -m core.run start <command> --target <resolved_target>)
```

**Sau khi hoàn thành thành công:**
```bash
python3 -m core.run complete "$OUTPUT_DIR"
```

**Khi thất bại:**
```bash
python3 -m core.run fail "$OUTPUT_DIR" "error description"
```

### 9. Đồng Thuận Đa Model

Khi được cấu hình, RAPTOR có thể sử dụng nhiều model LLM cho phân tích đồng thuận, cải thiện độ tin cậy của findings và giảm false positives.

### 10. Phân Tích Cross-Finding

Nhóm cấu trúc các findings để xác định root causes chung và các vấn đề hệ thống.

---

## Ngăn Xếp Kỹ Thuật

### Ngôn Ngữ Lập Trình

- **Python 3.9+** - Ngôn ngữ chính cho tất cả orchestration và phân tích
- **C/C++** - Test fixtures và công cụ phân tích crash
- **JavaScript** - Test fixtures cho quét web
- **Shell (Bash)** - Test scripts

### Phụ Thuộc Cốt Lõi

**Bắt Buộc:**
- `requests>=2.31.0` - HTTP requests
- `pydantic>=2.9.2` - Xác thực dữ liệu và structured output
- `instructor>=1.0.0` - Structured output cho LLMs

**Tùy Chọn:**
- `openai` - Hỗ trợ OpenAI, Gemini (qua shim), Mistral, Ollama
- `anthropic` - Hỗ trợ Anthropic Claude (native structured output)
- `google-genai` - Google Gemini native SDK (chi phí thinking token chính xác)
- `tabulate>=0.9.0` - Trực quan hóa dataflow nâng cao
- `tree-sitter` + language grammars - Enhanced inventory metadata
- `beautifulsoup4>=4.12.0` - Quét web
- `playwright>=1.40.0` - Web automation

### Công Cụ Bên Ngoài

**Bắt Buộc:**
- **Semgrep** (LGPL 2.1) - Static analysis scanner
  - Cài đặt: `pip install semgrep`

**Tùy Chọn:**
- **AFL++** (Apache 2.0) - Binary fuzzer
  - Cài đặt: `brew install afl++` hoặc `apt install afl++`
- **CodeQL** (GitHub Terms) - Semantic code analysis
  - Cài đặt: Tải từ GitHub
  - Lưu ý: Miễn phí cho nghiên cứu bảo mật, hạn chế sử dụng thương mại
- **Ollama** (MIT) - Local hoặc remote model server
  - Cài đặt: Tải từ https://ollama.ai
- **rr** (MIT) - Record-replay debugger (chỉ Linux, x86_64)
  - Cài đặt: `apt install rr` hoặc build từ source
- **gcov** (GPL) - Code coverage (đi kèm với gcc)
- **AddressSanitizer** (Apache 2.0) - Memory error detector (tích hợp trong gcc >= 4.8, clang >= 3.1)
- **Google Cloud BigQuery** - Cho OSS forensics
  - Cấu hình: Yêu cầu `GOOGLE_APPLICATION_CREDENTIALS`

**Công Cụ Hệ Thống (đã cài sẵn trên hầu hết hệ thống):**
- **LLDB** (Apache 2.0) - macOS debugger (Xcode Command Line Tools)
- **GDB** (GPL v3) - Linux debugger
- **GNU Binutils** (GPL v3) - nm, addr2line, objdump, file, strings

### Công Cụ Phát Triển

**CI/CD:**
- GitHub Actions workflows cho Python tests
- GitHub Actions workflows cho Bash tests
- GitHub CodeQL scanning

**Dev Container:**
- VS Code Dev Container với tất cả phụ thuộc đã cài sẵn
- Docker image ~6GB dựa trên Microsoft Python 3.12 devcontainer
- Bao gồm: Semgrep, CodeQL v2.15.5, AFL++, rr, gcc, g++, clang, make, cmake, autotools, gdb, binutils
- Kiểm thử web: Playwright browser automation (Chromium, Firefox, Webkit)
- Lưu ý: Yêu cầu flag `--privileged` cho rr debugger

**Kiểm Thử:**
- Python unit tests với pytest
- Shell-based integration tests
- 275+ tests trong gói exploit_feasibility
- 207+ tests trong gói exploitability_validation

---

## Thống Kê Dự Án

### Số Liệu Code

| Số Liệu | Số Lượng |
|---------|----------|
| File Python (.py) | 258 |
| File Markdown (.md) | 105 |
| Shell scripts (.sh) | 7 |
| File cấu hình YAML | 13 |
| Tổng thư mục | ~80+ |

### Phân Tích Gói

| Gói | File Chính | Tests | Mục Đích |
|-----|------------|-------|----------|
| `static-analysis` | 2 | - | Quét Semgrep |
| `codeql` | 8 | - | Phân tích chuyên sâu CodeQL |
| `llm_analysis` | 12 | - | Phân tích lỗ hổng LLM |
| `autonomous` | 6 | - | Lập kế hoạch & bộ nhớ tự động |
| `fuzzing` | 3 | - | Điều phối fuzzing AFL++ |
| `binary_analysis` | 2 | - | Phân tích crash GDB |
| `exploit_feasibility` | 24 | 275+ | Khả năng exploit binary |
| `exploitability_validation` | 5 | 207+ | Pipeline xác thực đa giai đoạn |
| `exploitation` | 2 | - | Phát triển exploit & báo cáo |
| `recon` | 1 | - | Liệt kê công nghệ |
| `sca` | 1 | - | Quét lỗ hổng dependency |
| `web` | 4 | - | Kiểm thử ứng dụng web (ALPHA) |
| `diagram` | 8 | - | Trực quan hóa Mermaid |
| `cvss` | 1 | - | Tính toán điểm CVSS |

### Phân Tích Module Cốt Lõi

| Module | File Chính | Mục Đích |
|--------|------------|----------|
| `config` | 1 | Quản lý cấu hình |
| `logging` | 1 | JSONL logging có cấu trúc |
| `progress` | 1 | Theo dõi tiến trình |
| `inventory` | 7 | Xây dựng inventory nguồn |
| `json` | 1 | JSON utilities |
| `project` | 10 | Quản lý dự án |
| `reporting` | 5 | Reporting utilities |
| `run` | 3 | Quản lý vòng đời run |
| `sarif` | 2 | SARIF parsing |
| `startup` | 3 | Khởi tạo startup/banner |

### Tích Hợp Claude Code

| Loại | Số Lượng | Mục Đích |
|------|----------|----------|
| Commands | 21 | Slash commands cho người dùng |
| Agents | 16 | Định nghĩa agent tự động |
| Skills | Nhiều | Module khả năng tái sử dụng |
| Personas | 9 | File expert persona |

### Tài Liệu

| Danh Mục | Số Lượng | Ví Dụ |
|----------|----------|-------|
| Hướng Dẫn Người Dùng | 7+ | CLAUDE_CODE_USAGE.md, PYTHON_CLI.md, FUZZING_QUICKSTART.md |
| Tài Liệu Kiến Trúc | 4+ | ARCHITECTURE.md, EXTENDING_LAUNCHER.md, VISUAL_DESIGN.md |
| Tài Liệu Gói | 4+ | File README cho từng gói |
| Tài Liệu Tiers | 5+ | analysis-guidance.md, recovery.md, file persona |

---

## Điểm Mạnh

### 1. **Phương Pháp Kiểm Thử Bảo Mật Đổi Mới**
RAPTOR kết hợp công cụ bảo mật truyền thống với suy luận AI tự động, cung cấp phương pháp độc đáo cho phát hiện và xác thực lỗ hổng.

### 2. **Phân Tích Khả Năng Exploit**
Gói `exploit_feasibility` là tính năng nổi bật ngăn chặn lãng phí công sức vào các exploit không thể thực hiện về mặt kiến trúc. Nó xác minh thực nghiệm liệu kỹ thuật exploit có hoạt động không.

### 3. **Pipeline Xác Thực Đa Giai Đoạn**
Pipeline xác thực 7 giai đoạn (0→A→B→C→D→E→F) đảm bảo chỉ các lỗ hổng thực sự, có thể tiếp cận và có thể khai thác mới được báo cáo.

### 4. **Kiến Trúc Module**
Phân tách trách nhiệm rõ ràng với không có import chéo giữa các gói. Mỗi gói có thể thực thi độc lập với giao diện CLI rõ ràng.

### 5. **Quản Lý Chi Phí**
Thực thi ngân sách tích hợp sẵn, theo dõi chi phí thời gian thực, và phát hiện rate limit thông minh ngăn chặn chi phí vượt tầm kiểm soát.

### 6. **Hỗ Trợ LLM Đa Provider**
Hoạt động với nhiều nhà cung cấp LLM, tránh vendor lock-in. Hỗ trợ cả model đám mây và cục bộ.

### 7. **Tích Hợp Công Cụ Toàn Diện**
Tích hợp các công cụ tiêu chuẩn ngành (Semgrep, CodeQL, AFL++, rr) với phân tích AI tự động.

### 8. **Tiết Lộ Tiến Trình**
Chỉ tải các persona chuyên gia khi cần thiết, tối ưu hóa sử dụng ngữ cảnh và cải thiện hiệu quả.

### 9. **Thiết Kế Ý Thức Bảo Mật**
Bảo vệ chống lại settings repo độc hại, injection biến môi trường, và injection đường dẫn file.

### 10. **Tài Liệu Phong Phú**
Tài liệu mở rộng với quickstarts, hướng dẫn kiến trúc, README gói, và comment trong code.

### 11. **Khả Năng Forensics OSS**
Khả năng forensics GitHub độc đáo với tích hợp BigQuery, thu thập bằng chứng, và hình thành giả thuyết.

### 12. **Hỗ Trợ Dev Container**
Dev container được cấu hình sẵn với tất cả phụ thuộc loại bỏ ma sát thiết lập.

---

## Lĩnh Vực Cần Cải Thiện

### 1. **Kiểm Thử Ứng Dụng Web (Alpha)**
Lệnh `/web` được đánh dấu là STUB/ALPHA và không nên dựa vào. Đây là khoảng trống trong coverage so với các khả năng khác.

**Khuyến Nghị:** Nâng cao khả năng quét web hoặc tài liệu hóa rõ ràng các hạn chế.

### 2. **Quản Lý Kích Thước Ngữ Cảnh**
Framework thừa nhận nó được "ghép lại với nhau bằng vibe coding và băng keo" và là "bản phát hành sớm." Quản lý ngữ cảnh cho codebase lớn có thể là thách thức.

**Khuyến Nghị:** Triển khai các chiến lược tối ưu hóa context window tốt hơn.

### 3. **Hạn Chế Của Model Cục Bộ**
Các model cục bộ (Ollama) hoạt động cho phân tích nhưng có thể sinh code exploit không biên dịch được, hạn chế khả năng offline.

**Khuyến Nghị:** Tài liệu hóa ngưỡng chất lượng model cho các tác vụ khác nhau.

### 4. **Độ Phủ Test Coverage**
Mặc dù exploit_feasibility và exploitability_validation có độ phủ test tốt (275+ và 207+ tests), các gói khác dường như có độ phủ test tối thiểu.

**Khuyến Nghị:** Tăng độ phủ unit test trên tất cả các gói.

### 5. **Kích Thước Dev Container**
Dev container rất lớn (~6GB) có thể gây khó khăn cho một số người dùng.

**Khuyến Nghị:** Cân nhắc các biến thể nhẹ hơn cho người dùng không cần tất cả công cụ.

### 6. **Giấy Phép CodeQL**
CodeQL không cho phép sử dụng thương mại, hạn chế khả năng áp dụng của RAPTOR trong môi trường thương mại.

**Khuyến Nghị:** Tài liệu hóa rõ ràng các hạn chế giấy phép và tìm kiếm giải pháp thay thế cho người dùng thương mại.

### 7. **Hỗ Trợ Nền Tảng**
Debugger `rr` chỉ hỗ trợ Linux (x86_64), hạn chế khả năng phân tích crash trên macOS và các nền tảng khác.

**Khuyến Nghị:** Tài liệu hóa các hạn chế nền tảng và cung cấp các phương án thay thế.

### 8. **Quản Lý Phụ Thuộc**
Tự động tải công cụ mà không có sự đồng ý rõ ràng của người dùng có thể là hành vi không mong đợi.

**Khuyến Nghị:** Thêm xác nhận rõ ràng trước khi tự động cài đặt công cụ.

---

## Các Cân Nhắc Bảo Mật

### Các Tính Năng Bảo Mật Tích Cực

1. **Làm Sạch Môi Trường**
   - `RaptorConfig.get_safe_env()` loại bỏ các biến môi trường nguy hiểm (TERMINAL, EDITOR, VISUAL, BROWSER, PAGER)
   - Ngăn chặn tấn công injection biến môi trường

2. **Bảo Vệ Repository Không Tin Cậy**
   - Phát hiện file `.claude/settings.json` độc hại trong repos mục tiêu
   - Chặn Claude Code sub-agent dispatch cho repos với credential helpers nguy hiểm
   - Sử dụng `--add-dir` cho sub-agents (chỉ truy cập file, không tải settings)

3. **Ngăn Chặn Injection Đường Dẫn File**
   - Sử dụng list-based subprocess arguments thay vì nội suy chuỗi
   - Ngăn chặn command injection từ đường dẫn file không tin cậy

4. **Xác Nhận Người Dùng Rõ Ràng**
   - Các hoạt động nguy hiểm (áp dụng patches, xóa, git push) yêu cầu xác nhận người dùng
   - Các hoạt động an toàn (cài đặt, quét, đọc, sinh) tự động thực thi

5. **Nhận Thức CVE**
   - Tài liệu hóa CVE-2026-21852 (Phoenix Security CWE-78 disclosure)
   - Chủ động kiểm tra injection Claude Code credential helper

### Các Mối Quan Tâm Bảo Mật Tiềm Ẩn

1. **Hành Vi Tự Động Cài Đặt**
   - RAPTOR sẽ tự động cài đặt công cụ mà không hỏi (trừ khi sử dụng devcontainer)
   - Có thể đưa vào các binary hoặc phụ thuộc không mong đợi

2. **Quản Lý API Key**
   - Yêu cầu API keys cho các nhà cung cấp LLM (Anthropic, OpenAI, Google, Mistral)
   - Keys được lưu trong biến môi trường hoặc file cấu hình

3. **Truy Cập Container Đặc Quyền**
   - Dev container chạy với flag `--privileged` cho rr debugger
   - Tăng bề mặt tấn công của môi trường phát triển

4. **Phụ Thuộc Công Cụ Bên Ngoài**
   - Dựa vào các công cụ bên ngoài (Semgrep, CodeQL, AFL++) với tư thế bảo mật riêng
   - Người dùng phải xem xét giấy phép và tác động bảo mật của từng công cụ

---

## Khuyến Nghị

### Cho Người Dùng

1. **Sử Dụng Dev Container**
   - Cung cấp môi trường cô lập với tất cả phụ thuộc
   - Loại bỏ ma sát thiết lập và các vấn đề bảo mật tiềm ẩn từ tự động cài đặt

2. **Xem Xét Giấy Phép Công Cụ**
   - Cân nhắc kỹ giấy phép cho Semgrep (LGPL 2.1), CodeQL (GitHub Terms), và các công cụ GPL
   - CodeQL không cho phép sử dụng thương mại

3. **Đặt Giới Hạn Ngân Sách**
   - Cấu hình `max_cost_per_scan` trong LLMConfig để ngăn chặn chi phí không mong đợi
   - Theo dõi theo dõi chi phí cho mỗi lần phân tích

4. **Bắt Đầu Với Repos Test**
   - Sử dụng dữ liệu test có sẵn trong `/tests/data` để làm quen với RAPTOR
   - Thử lệnh `/analyze` trước khi chạy full `/scan` hoặc `/agentic` workflows

5. **Sử Dụng Phân Tích Khả Năng Exploit**
   - Luôn chạy `analyze_binary()` trước khi cố gắng phát triển exploit
   - Xem xét phần `exploitation_paths` để hiểu những gì thực sự có thể

### Cho Người Đóng Góp

1. **Tăng Độ Phủ Test**
   - Thêm unit tests cho các gói có độ phủ tối thiểu
   - Mục tiêu: 80%+ code coverage trên tất cả các gói

2. **Nâng Cao Quét Web**
   - Hoàn thành triển khai lệnh `/web`
   - Thêm kiểm thử OWASP Top 10 toàn diện

3. **Cải Thiện Tài Liệu**
   - Thêm nhiều ví dụ vào README của gói
   - Tài liệu hóa các edge case và hạn chế đã biết

4. **Thêm Nhiều Semgrep Rules**
   - Đóng góp custom Semgrep rules cho các danh mục lỗ hổng bổ sung
   - Các rules trong `engine/semgrep/rules/` được cấp phép MIT

5. **Tối Ưu Hóa Quản Lý Ngữ Cảnh**
   - Triển khai chiến lược tối ưu hóa context window tốt hơn
   - Thêm chiến lược tải tiến trình cho codebase lớn

6. **Thêm Tích Hợp CI/CD**
   - Cung cấp ví dụ tích hợp RAPTOR vào pipelines CI/CD
   - Tài liệu hóa sử dụng với các hệ thống CI phổ biến (GitHub Actions, GitLab CI, Jenkins)

7. **Cải Thiện Recovery Lỗi**
   - Nâng cao recovery protocols trong `tiers/recovery.md`
   - Thêm logic retry tự động cho các lỗi tạm thời

### Cho Phát Triển Tương Lai

1. **Hỗ Trợ Sử Dụng Thương Mại**
   - Tìm kiếm giải pháp thay thế cho CodeQL cho người dùng thương mại
   - Tài liệu hóa các giải pháp giấy phép

2. **Hỗ Trợ Đa Ngôn Ngữ**
   - Mở rộng hỗ trợ ngôn ngữ vượt quá 12 ngôn ngữ hiện tại
   - Thêm hỗ trợ phân tích ứng dụng di động (iOS, Android)

3. **Giám Sát Thời Gian Thực**
   - Thêm khả năng giám sát liên tục
   - Tích hợp với các hệ thống SIEM cho sử dụng doanh nghiệp

4. **Tính Năng Cộng Tác**
   - Thêm hỗ trợ cho phân tích nhóm
   - Cho phép chia sẻ findings và exploits qua các nhóm

5. **Tối Ưu Hiệu Suất**
   - Triển khai chiến lược caching cho các lần quét lặp lại
   - Tối ưu hóa thực thi song song cho throughput tốt hơn

---

## Kết Luận

RAPTOR đại diện cho một bước tiến đáng kể trong nghiên cứu bảo mật tự động. Bằng cách kết hợp các công cụ bảo mật truyền thống (Semgrep, CodeQL, AFL++) với phân tích tự động sử dụng LLM, nó cung cấp một nền tảng toàn diện cho phát hiện lỗ hổng, xác thực, tạo exploit và vá lỗi.

**Các Điểm Khác Biệt Chính:**
- Phân tích khả năng exploit ngăn chặn lãng phí công sức vào các khai thác không thể
- Pipeline xác thực đa giai đoạn đảm bảo findings là thật và có thể khai thác
- Quản lý chi phí ngăn chặn chi phí LLM vượt tầm kiểm soát
- Tiết lộ tiến trình các persona chuyên gia tối ưu hóa sử dụng ngữ cảnh
- Tư thế bảo mật mạnh mẽ bảo vệ chống lại các repo độc hại

**Đối Tượng Mục Tiêu:**
- Nhà nghiên cứu bảo mật
- Penetration testers
- Người review code
- Kỹ sư DevSecOps
- Open-source maintainers

**Mức Độ Trưởng Thành:** Beta/Phát Hành Sớm
- Tự mô tả là "ghép lại với nhau bằng vibe coding và băng keo"
- Chức năng cốt lõi vững chắc và được kiểm thử tốt
- Một số tính năng (quét web) vẫn ở alpha/stub
- Nền tảng vững chắc cho đóng góp cộng đồng

**Kết Luận Chung:** RAPTOR là một framework mạnh mẽ, đổi mới thể hiện cách AI có thể tăng cường kiểm thử bảo mật. Mặc dù có các lĩnh vực cần cải thiện, kiến trúc module và các khả năng cốt lõi mạnh mẽ làm cho nó trở thành công cụ có giá trị cho nghiên cứu bảo mật. Cộng đồng được mời đóng góp và giúp định hình RAPTOR thành một nền tảng nghiên cứu bảo mật chuyển đổi.

---

## Phụ Lục A: Tham Khảo Nhanh

### Cài Đặt

```bash
# Clone repository
git clone https://github.com/gadievron/raptor.git
cd raptor

# Cài đặt phụ thuộc
pip install -r requirements.txt
pip install semgrep

# Đặt API keys
export ANTHROPIC_API_KEY=sk-ant-...
export OPENAI_API_KEY=sk-...

# Hoặc sử dụng devcontainer
docker build -f .devcontainer/Dockerfile -t raptor-devcontainer:latest .
```

### Các Lệnh Thường Dùng

```bash
# Full autonomous workflow
python3 raptor.py agentic --repo /path/to/code

# Chỉ phân tích tĩnh
python3 raptor.py scan --repo /path/to/code --policy_groups secrets,owasp

# Binary fuzzing
python3 raptor.py fuzz --binary /path/to/binary --duration 3600

# Phân tích CodeQL
python3 raptor.py codeql --repo /path/to/code --languages java

# Phân tích LLM của SARIF
python3 raptor.py analyze --repo /path/to/code --sarif findings.sarif

# Kiểm tra khả năng exploit
python3 -c "from packages.exploit_feasibility import analyze_binary; print(analyze_binary('/path/to/binary'))"
```

### Các Lệnh Claude Code

```
/raptor    - Khởi động RAPTOR assistant
/scan      - Phân tích code tĩnh
/fuzz      - Binary fuzzing
/web       - Kiểm thử ứng dụng web (STUB)
/agentic   - Full autonomous workflow
/codeql    - CodeQL-only deep analysis
/analyze   - LLM analysis only (nhanh & rẻ hơn 50%)
/validate  - Exploitability validation pipeline
/exploit   - Tạo exploit PoCs (beta)
/patch     - Tạo security patches (beta)
/understand - Adversarial code comprehension
/oss-forensics - Điều tra forensic GitHub
/crash-analysis - Autonomous crash analysis
/diagram   - Tạo sơ đồ trực quan Mermaid
/project   - Quản lý dự án
```

---

## Phụ Lục B: Tóm Tắt Cấu Trúc File

```
raptor/
├── 📄 Core Entry Points (4 files)
│   ├── raptor.py              - Main unified launcher
│   ├── raptor_agentic.py      - Autonomous workflow (Semgrep + CodeQL)
│   ├── raptor_codeql.py       - CodeQL-only analysis
│   └── raptor_fuzzing.py      - Binary fuzzing workflow
├── 📦 Core Modules (14 files/dirs)
│   ├── config.py              - Quản lý cấu hình
│   ├── logging.py             - JSONL logging có cấu trúc
│   ├── progress.py            - Theo dõi tiến trình
│   ├── inventory/             - Source inventory (7 files)
│   ├── json/                  - JSON utilities
│   ├── project/               - Quản lý dự án (10 files)
│   ├── reporting/             - Reporting utilities (5 files)
│   ├── run/                   - Quản lý vòng đời run (3 files)
│   ├── sarif/                 - SARIF parsing (2 files)
│   └── startup/               - Khởi tạo startup (3 files)
├── 🛡️ Security Packages (15 packages)
│   ├── static-analysis/       - Quét Semgrep (2 files)
│   ├── codeql/                - Phân tích CodeQL (8 files)
│   ├── llm_analysis/          - Phân tích LLM (12 files)
│   ├── autonomous/            - Khả năng tự động (6 files)
│   ├── fuzzing/               - Fuzzing AFL++ (3 files)
│   ├── binary_analysis/       - Phân tích crash GDB (2 files)
│   ├── exploit_feasibility/   - Khả năng exploit (24 files, 275+ tests)
│   ├── exploitability_validation/ - Pipeline xác thực (5 files, 207+ tests)
│   ├── exploitation/          - Phát triển exploit (2 files)
│   ├── recon/                 - Liệt kê công nghệ (1 file)
│   ├── sca/                   - Quét dependency (1 file)
│   ├── web/                   - Kiểm thử web (4 files, ALPHA)
│   ├── diagram/               - Trực quan hóa (8 files)
│   └── cvss/                  - Tính toán CVSS (1 file)
├── 🔧 Analysis Engines (2 engines)
│   ├── codeql/suites/         - CodeQL query suites
│   └── semgrep/               - Semgrep rules (13+ custom rules)
├── 🎓 Expert System
│   ├── tiers/personas/        - 9 file expert persona
│   └── tiers/specialists/     - Cơ sở kiến thức chuyên gia
├── 🤖 Tích Hợp Claude Code
│   ├── commands/              - 21 slash commands
│   ├── agents/                - 16 định nghĩa agent
│   └── skills/                - Nhiều skill tái sử dụng
├── 📚 Tài Liệu (15+ files)
│   ├── README.md              - Tài liệu chính
│   ├── CLAUDE.md              - Hướng dẫn Claude Code
│   ├── DEPENDENCIES.md        - Công cụ bên ngoài và giấy phép
│   └── docs/                  - Hướng dẫn chi tiết (7+ files)
├── 🧪 Kiểm Thử
│   ├── test/                  - Shell-based tests (7 scripts)
│   └── tests/                 - Python unit tests
├── 🐳 Dev Container
│   ├── .devcontainer/         - VS Code dev container config
│   └── Dockerfile             - Docker image ~6GB
└── 📋 CI/CD
    └── .github/workflows/     - GitHub Actions (2 workflows)
```

---

**Hết Báo Cáo**

*Báo cáo này cung cấp phân tích toàn diện về dự án RAPTOR tính đến ngày 11 tháng 4, 2026. Để biết thông tin cập nhật nhất, tham khảo repository dự án tại https://github.com/gadievron/raptor*