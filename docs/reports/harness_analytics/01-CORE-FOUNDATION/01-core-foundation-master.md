# RAPTOR Core Foundation -- Tai Lieu Toan Tap

**Phien ban:** 3.0.0
**Ngay cap nhat:** 2026-04-12
**Pham vi:** Toan bo cac module trong thu muc `core/`

---

## Muc Luc

1. [He thong Cau hinh (core/config.py)](#1-he-thong-cau-hinh-coreconfigpy)
2. [He thong Logging (core/logging.py)](#2-he-thong-logging-coreloggingpy)
3. [Theo doi Tien trinh (core/progress.py)](#3-theo-doi-tien-trinh-coreprogresspy)
4. [Source Inventory (core/inventory/*)](#4-source-inventory-coreinventory)
5. [Quan ly Du an (core/project/*)](#5-quan-ly-du-an-coreproject)
6. [Vong doi Run (core/run/*)](#6-vong-doi-run-corerun)
7. [SARIF Parsing (core/sarif/*)](#7-sarif-parsing-coresarif)
8. [Bao cao (core/reporting/*)](#8-bao-cao-corereporting)
9. [JSON Utilities (core/json/*)](#9-json-utilities-corejson)
10. [He thong Khoi dong (core/startup/*)](#10-he-thong-khoi-dong-corestartup)
11. [Schema Constants (core/schema_constants.py)](#11-schema-constants-coreschema_constantspy)
12. [Understand Bridge (core/understand_bridge.py)](#12-understand-bridge-coreunderstand_bridgepy)

---

## 1. He thong Cau hinh (`core/config.py`)

### Ly thuyet

Module `RaptorConfig` la trung tam quan ly cau hinh cho toan bo framework RAPTOR. No cung cap:

- **Duong dan (Paths):** Xac dinh vi tri cua cac thu muc quan trong nhu `engine/`, `out/`, `codeql_dbs/`, v.v.
- **Timeouts:** Gioi han thoi gian cho tung loai thao tac (Semgrep, CodeQL, LLM, Git...).
- **Gioi han Tai nguyen:** Kich thuoc file toi da, so luong worker, RAM cho CodeQL.
- **Phu thuoc Tool:** Khai bao cac tool ben ngoai can thiet (`afl++`, `codeql`, `gdb`, `semgrep`, `rr`) voi muc do nghiem trong (`required` hoac `degrades`).
- **Bao mat Moi truong:** Danh sach cac bien moi truong nguy hiem can loai bo de tranh tan cong Command Injection (CWE-78).

### Thiet ke

**Pattern su dung:** Singleton class voi cac static method. Tat ca cac gia tri duoc khai bao la class-level attributes de de dang truy cap.

**Cau truc phu thuoc tool:**
```
TOOL_DEPS = {
    "tool_name": {"binary": "ten_binary", "severity": "required|degrades", "affects": "/path"},
}
```
- `severity: "required"` -- tinh nang khong hoat dong neu thieu tool.
- `severity: "degrades"` -- tinh nang van hoat dong nhung bi gioi han.
- `group:` -- nhom tool, chi can it nhat 1 tool trong nhom la hien dien.

### API Reference

#### Lop `RaptorConfig`

| Thuoc tinh / Phuong thuc | Kieu | Mo ta |
|---|---|---|
| `VERSION` | `str` | Phien ban hien tai: `"3.0.0"` |
| `TOOL_DEPS` | `Dict` | Phu thuoc tool ben ngoai |
| `TOOL_GROUPS` | `Dict` | Nhom tool (vd: scanner) |
| `REPO_ROOT` | `Path` | Thu muc goc cua repository |
| `ENGINE_DIR` | `Path` | Thu muc engine |
| `BASE_OUT_DIR` | `Path` | Thu muc output mac dinh (`out/`) |
| `DEFAULT_TIMEOUT` | `int` | 1800 giay (30 phut) |
| `SEMGREP_TIMEOUT` | `int` | 900 giay (15 phut) |
| `CODEQL_TIMEOUT` | `int` | 1800 giay |
| `LLM_TIMEOUT` | `int` | 120 giay |
| `RESOURCE_READ_LIMIT` | `int` | 5 MiB |
| `MAX_SEMGREP_WORKERS` | `int` | 4 workers |
| `MAX_CODEQL_WORKERS` | `int` | 2 workers |
| `CODEQL_RAM_MB` | `int` | 8192 MB |
| `CODEQL_THREADS` | `int` | 0 = dung tat ca CPU |
| `CODEQL_DB_CACHE_DAYS` | `int` | 7 ngay |
| `BASELINE_SEMGREP_PACKS` | `List[Tuple]` | 3 goi semgrep mac dinh |
| `POLICY_GROUP_TO_SEMGREP_PACK` | `Dict` | Anh xa nhom policy voi semgrep pack |
| `PROXY_ENV_VARS` | `List[str]` | Cac bien proxy can xoa |
| `DANGEROUS_ENV_VARS` | `List[str]` | Cac bien nguy hiem (TERM, EDITOR, PAGER...) |
| `GIT_ENV_VARS` | `Dict` | Bien moi truong cho Git an toan |
| `MCP_VERSION` | `str` | `"0.6.0"` |
| `LOG_FORMAT_CONSOLE` | `str` | Dinh dang log console |
| `LOG_FORMAT_FILE` | `str` | Dinh dang log file (JSON) |
| `get_out_dir()` | `static` | Tra ve duong dan output directory (ho tro env `RAPTOR_OUT_DIR`) |
| `get_job_out_dir(job_id)` | `static` | Tra ve output directory cho mot job cu the |
| `get_safe_env()` | `static` | Tao ban copy cua os.environ da loai bien bao mat |
| `get_git_env()` | `static` | Tao moi truong an toan cho git |
| `ensure_directories()` | `static` | Tao tat ca thu muc can thiet neu chua ton tai |

### Thuc hanh

```python
from core.config import RaptorConfig

# Lay output directory
out_dir = RaptorConfig.get_out_dir()

# Lay duong dan cho mot job cu the
job_dir = RaptorConfig.get_job_out_dir("job-123")

# Lay moi truong an toan de chay subprocess
safe_env = RaptorConfig.get_safe_env()

# Dam bao tat ca thu muc da duoc tao
RaptorConfig.ensure_directories()

# Truy cap timeout
timeout = RaptorConfig.CODEQL_TIMEOUT  # 2400
```

### Best Practices

1. **Luon su dung `RaptorConfig.get_out_dir()`** thay vi hardcode duong dan `out/`. Dieu nay ho tro bien moi truong `RAPTOR_OUT_DIR`.
2. **Su dung `get_safe_env()`** khi chay bat ky subprocess nao de tranh tancong command injection qua bien moi truong.
3. **Goi `ensure_directories()`** o dau chuong trinh de dam bao tat ca thu muc ton tai.
4. **Khong sua doi truc tiep** cac gia tri trong `RaptorConfig` -- chung la hang so class-level.

### Troubleshooting

| Van de | Nguyen nhan | Giai phap |
|---|---|---|
| `FileNotFoundError` khi chay scan | Thu muc output chua ton tai | Goi `RaptorConfig.ensure_directories()` |
| Tool bi bao "unavailable" | Thieu binary trong PATH | Cai dat tool (`apt install codeql`, `pip install semgrep`) |
| Subprocess bi treo | Timeout qua ngan | Tang gia tri timeout trong `RaptorConfig` |
| Loi command injection | Bien moi truong nguy hiem khong duoc loc | Luon dung `get_safe_env()` |

---

## 2. He thong Logging (`core/logging.py`)

### Ly thuyet

He thong logging cua RAPTOR duoc thiet ke voi **hai kenh output dong thoi**:

1. **Console (stderr):** Dang van ban de doc, muc INFO tro len, dung cho nguoi dung theo doi truc tiep.
2. **File (JSONL):** Dinh dang JSON co cau truc, muc DEBUG tro len, dung cho audit trail va phan tich sau.

Module su dung **Singleton pattern** de dam bao chi co mot logger instance trong toan bo ứng dung.

### Thiet ke

**Cac thanh phan chinh:**

- **`JSONFormatter`:** Ke thua `logging.Formatter`, chuyen doi `LogRecord` thanh JSON string. Bao gom timestamp, level, logger name, module, function, line number, message, va cac truong extra (job_id, tool, duration).
- **`RaptorLogger`:** Singleton wrapper quanh `logging.Logger`. Quan ly ca console handler va file handler.
- **`get_logger()`:** Factory function de lay global logger instance.

**Cau truc JSON log:**
```json
{
  "timestamp": "2026-04-12T10:30:00",
  "level": "INFO",
  "logger": "raptor",
  "module": "builder",
  "function": "build_inventory",
  "line": 42,
  "message": "Built inventory: 150 files",
  "job_id": "job-123",
  "tool": "semgrep",
  "duration": 45.2
}
```

### API Reference

#### Lop `JSONFormatter`

| Phuong thuc | Mo ta |
|---|---|
| `format(record)` | Chuyen doi LogRecord thanh JSON string |

#### Lop `RaptorLogger`

| Phuong thuc | Mo ta |
|---|---|
| `debug(message, **kwargs)` | Ghi log muc DEBUG |
| `info(message, **kwargs)` | Ghi log muc INFO |
| `warning(message, **kwargs)` | Ghi log muc WARNING |
| `error(message, **kwargs)` | Ghi log muc ERROR |
| `critical(message, **kwargs)` | Ghi log muc CRITICAL |
| `log_job_start(job_id, tool, arguments)` | Ghi su kien bat dau job |
| `log_job_complete(job_id, tool, status, duration)` | Ghi su kien ket thuc job |
| `log_security_event(event_type, message, **kwargs)` | Ghi su kien bao mat |

#### Functions

| Function | Mo ta |
|---|---|
| `get_logger()` | Tra ve global `RaptorLogger` instance |

### Thuc hanh

```python
from core.logging import get_logger

logger = get_logger()

# Log co ban
logger.info("Starting scan", tool="semgrep")
logger.debug(f"Processing file: {filepath}")
logger.warning("Low disk space", free_gb=2.5)
logger.error("Scan failed", exc_info=True)

# Log voi extra fields
logger.info("File processed", job_id="job-123", tool="semgrep", duration=5.2)

# Log su kien job
logger.log_job_start("job-123", "semgrep", {"target": "/path/to/code"})
logger.log_job_complete("job-123", "semgrep", "completed", 45.2)

# Log su kien bao mat
logger.log_security_event("unauthorized_access", "Attempted to access /etc/passwd")

# Log exception
try:
    risky_operation()
except Exception:
    logger.error("Operation failed", exc_info=True, stack_info=True)
```

### Best Practices

1. **Su dung `get_logger()`** o dau moi file de lay logger instance.
2. **Truyen extra fields** qua `**kwargs` de them context (job_id, tool, duration) vao JSON log.
3. **Dung `exc_info=True`** khi log exception de co stack trace trong file audit.
4. **Su dung `log_security_event()`** cho bat ky su kien bao mat nao de de dang loc va canh bao.
5. **Console output huong den stderr** de khong lam on stdout (stdout danh cho data output).

### Troubleshooting

| Van de | Nguyen nhan | Giai phap |
|---|---|---|
| Log file khong xuat hien | Thu muc log chua duoc tao | Goi `RaptorConfig.ensure_directories()` truoc khi khoi tao logger |
| JSON log thieu truong | Truong extra khong duoc truyen dung | Dung `**kwargs` thay vi hardcode trong message |
| Log bi trung lap | Nhieu instance logger | Singleton da xu ly -- kiem tra import |
| Console qua nhieu log | Muc DEBUG hien thi ra console | Console handler mac dinh chi hien thi INFO+ |

---

## 3. Theo doi Tien trinh (`core/progress.py`)

### Ly thuyet

`HackerProgress` cung cap hien thi tien trinh kieu "Matrix/Hacker" tren terminal cho cac thao tac keo dai (>15 giay). No ho tro:

- **Spinner xoay:** Hieu hieu animation voi cac ky tu Unicode block.
- **Thanh tien trinh:** Hien thi `current/total` voi ETA (thoi gian uoc tinh con lai).
- **Context manager:** Tu dong hien thi "SEQUENCE ACTIVE" khi bat dau va "Complete" khi ket thuc.

### Thiet ke

**Pattern:** Context manager (`__enter__`/`__exit__`) ket hop voi update rate-limiting (chi update moi 1 giay de tranh lam cham terminal).

**Spinner characters:** `['▌', '▀', '▐', '▄']` -- 4 ky tu block quay vong.

### API Reference

#### Lop `HackerProgress`

| Thuoc tinh / Phuong thuc | Kieu | Mo ta |
|---|---|---|
| `__init__(total, operation, disabled)` | | Khoi tao voi tong so buoc, ten thao tac, co the vo hieu hoa |
| `update(current=None, message="")` | | Cap nhat tien trinh hien thi |
| `finish(message="Complete")` | | Ket thuc hien thi tien trinh |
| `__enter__()` | | Context manager entry |
| `__exit__(exc_type, exc_val, exc_tb)` | | Context manager exit -- tu dong xu ly success/error |
| `SPINNERS` | `list` | Danh sach ky tu spinner |

### Thuc hanh

```python
from core.progress import HackerProgress

# Cach 1: Dung voi context manager (khuyen nghi)
with HackerProgress(total=100, operation="Analyzing vulnerabilities") as progress:
    for i in range(1, 101):
        process_file(i)
        progress.update(current=i, message=f"Processing file_{i}")

# Cach 2: Dung thu cong
progress = HackerProgress(total=50, operation="Scanning")
for i in range(50):
    progress.update()
progress.finish("Scan complete")

# Cach 3: Khong biet truoc tong so
with HackerProgress(operation="Searching") as progress:
    for item in search():
        progress.update(message=f"Found: {item}")

# Cach 4: Vo hieu hoa (cho testing hoac CI)
progress = HackerProgress(total=10, operation="Test", disabled=True)
```

### Best Practices

1. **Luon dung context manager** (`with` statement) de dam bao cleanup dung cach.
2. **Rate limiting da duoc tich hop** (1 giay/update) -- khong can lo ve performance.
3. **Dung `disabled=True`** trong CI/CD hoac testing de tranh lam on log output.
4. **Output ra stderr** de khong anh huong stdout data.

### Troubleshooting

| Van de | Nguyen nhan | Giai phap |
|---|---|---|
| Tien trinh khong hien thi | `disabled=True` hoac output khong phai terminal | Kiem tra co dang chay trong pipeline CI khong |
| Terminal bi loang | Chuong trinh bi git giua chung | Context manager `__exit__` se xu ly -- kiem tra exception handling |
| ETA khong chinh xac | Toc do khong deu | Binh thuong -- ETA duoc tinh trung binh dong |

---

## 4. Source Inventory (`core/inventory/*`)

### Ly thuyet

Module Source Inventory co nhiem vu **kiem ke ma nguon** cua project can phan tich. No thuc hien:

- **Phat hien file nguon:** Quet toan bo thu muc, loc theo extension, loai tru file binary, file sinh ra tu dong, va thu muc khong can thiet.
- **Trich xuat code items:** Dung AST (Python), tree-sitter (khi co san), hoac regex fallback de lay thong tin functions, globals, macros, classes.
- **Tinh toan metrics:** SHA-256 checksum, SLOC (source lines of code), so luong functions.
- **Theo doi coverage:** Danh dau code items da duoc kiem tra boi cong cu nao (`checked_by`).
- **So sanh inventory:** So sanh hai phien ban inventory qua SHA-256 de phat hien thay doi.

### Thiet ke

**Kien truc phan tang:**

```
builder.py          -> Entry point, dieu phoi toan bo qua trinh
languages.py        -> Phat hien ngon ngu qua file extension
exclusions.py       -> Logic loai tru file (patterns, binary, generated)
extractors.py       -> Trich xuat code items (AST, tree-sitter, regex)
lookup.py           -> Tim function tu checklist theo file:line
diff.py             -> So sanh hai inventory qua SHA-256
coverage.py         -> Quan ly checked_by va thong ke coverage
```

**Thu tu uu tien trich xuat:**
1. **Tree-sitter** (neu co san) -- rich metadata cho tat ca ngon ngu
2. **Python AST** (luon co san) -- metadata day du cho Python
3. **Regex fallback** -- co ban, ho tro tat ca ngon ngu

**Cac loai code item:**
- `KIND_FUNCTION` ("function") -- Ham/phuong thuc
- `KIND_GLOBAL` ("global") -- Bien toan cuc/hang so
- `KIND_MACRO` ("macro") -- C/C++ #define macros
- `KIND_CLASS` ("class") -- Lop/interface

### API Reference

#### Module `builder`

| Function | Mo ta |
|---|---|
| `build_inventory(target_path, output_dir, exclude_patterns, extensions, skip_generated, parallel)` | Xay dung toan bo source inventory |

#### Module `languages`

| Function / Hang so | Mo ta |
|---|---|
| `LANGUAGE_MAP` | Dict anh xa file extension -> ten ngon ngu (24 ngon ngu) |
| `detect_language(filepath)` | Phat hien ngon ngu tu file extension |

#### Module `exclusions`

| Function / Hang so | Mo ta |
|---|---|
| `DEFAULT_EXCLUDES` | Danh sach ~60 pattern loai tru mac dinh |
| `GENERATED_MARKERS` | Danh sach marker phat hien file auto-generated |
| `is_binary_file(filepath)` | Kiem tra file binary qua null bytes |
| `is_generated_file(content)` | Kiem tra file generated qua header markers |
| `should_exclude(filepath, patterns)` | Kiem tra file co nen bi loai tru khong |
| `match_exclusion_reason(filepath, patterns)` | Nhu `should_exclude` nhung tra ve ly do cu the |

#### Module `extractors`

| Class / Function | Mo ta |
|---|---|
| `CodeItem` | Dataclass co so cho code construct |
| `FunctionInfo` | Dataclass cho function (ke thua CodeItem) |
| `FunctionMetadata` | Metadata bao mat (visibility, attributes, return_type, parameters) |
| `PythonExtractor` | Trich xuat Python qua AST |
| `JavaScriptExtractor` | Trich xuat JS/TS qua regex |
| `CExtractor` | Trich xuat C/C++ qua regex (ANSI + K&R style) |
| `JavaExtractor` | Trich xuat Java qua regex |
| `GoExtractor` | Trich xuat Go qua regex |
| `GenericExtractor` | Fallback cho cac ngon ngu khac |
| `TreeSitterExtractor` | Trich xuat qua tree-sitter (rich metadata) |
| `extract_functions(filepath, language, content)` | Entry point trich xuat functions |
| `extract_items(filepath, language, content)` | Entry point trich xuat TAT CA items (functions + globals + macros) |
| `count_sloc(content, language)` | Dem source lines of code |
| `_get_ts_languages()` | Tra ve danh sach ngon ngu co tree-sitter |

#### Module `lookup`

| Function | Mo ta |
|---|---|
| `normalise_path(path, repo_root)` | Chuan hoa duong dan (xu ly file://, absolute, relative) |
| `lookup_function(checklist, file_path, line, repo_root)` | Tim function chua mot line cu the trong checklist |

#### Module `diff`

| Function | Mo ta |
|---|---|
| `compare_inventories(old, new)` | So sanh hai inventory qua SHA-256, tra ve added/removed/modified |

#### Module `coverage`

| Function | Mo ta |
|---|---|
| `update_coverage(inventory, checked_functions, source_label)` | Danh dau functions da duoc kiem tra |
| `get_coverage_stats(inventory)` | Tinh toan thong ke coverage |
| `format_coverage_summary(inventory)` | Dinh dang ban tom tat coverage de doc |

### Thuc hanh

```python
from core.inventory import (
    build_inventory, get_coverage_stats, get_items,
    lookup_function, compare_inventories
)

# Xay dung inventory
inventory = build_inventory(
    target_path="/path/to/repo",
    output_dir="/path/to/output",
    skip_generated=True,
    parallel=True,
)

print(f"Found {inventory['total_files']} files, {inventory['total_items']} items")

# Lay thong ke coverage
stats = get_coverage_stats(inventory)
print(f"Coverage: {stats['coverage_percent']:.1f}%")
print(f"By kind: {stats['by_kind']}")

# Lookup function tu file:line
func = lookup_function(inventory, "src/auth.py", 42, repo_root="/path/to/repo")
if func:
    print(f"Found function: {func['name']}")

# So sanh voi inventory cu
old_inventory = load_json("old_checklist.json")
diff = compare_inventories(old_inventory, inventory)
if diff:
    print(f"Added: {len(diff['added'])}")
    print(f"Modified: {len(diff['modified'])}")
```

### Best Practices

1. **Bat parallel processing** cho codebase lon (>10 files) de tang toc do.
2. **Cai dat tree-sitter** de co metadata phong phu (visibility, parameters, return types) cho tat ca ngon ngu.
3. **Giữ lai `checklist.json`** git qua cac lan chay -- he thong se tu dong carry forward `checked_by` cho cac file khong thay doi.
4. **Dung `extract_items()`** thay vi `extract_functions()` de lay ca globals va macros.
5. **Su dung `match_exclusion_reason()`** de ghi nhan ly do loai tru file trong inventory.

### Troubleshooting

| Van de | Nguyen nhan | Giai phap |
|---|---|---|
| Inventory trong (0 files) | Extension khong nam trong `LANGUAGE_MAP` | Kiem tra file extensions cua project |
| Thieu functions | Tree-sitter khong cai dat cho ngon ngu do | Cai `tree-sitter-python`, `tree-sitter-javascript`, etc. hoac chap nhan regex fallback |
| Qua nhieu file bi exclude | Pattern qua rong trong `DEFAULT_EXCLUDES` | Truyen `exclude_patterns` tuy chinh |
| SLOC khong chinh xac | Regex fallback khong phat hien duoc comment | Cai tree-sitter de dem chinh xac |
| Coverage khong duoc carry forward | SHA-256 khop nhung inventory format khac | Kiem tra `limitations` trong inventory |

---

## 5. Quan ly Du an (`core/project/*`)

### Ly thuyet

He thong quan ly du an (Project) cho phep **nhom cac lan phan tich** lien quan vao mot workspace duy nhat. Mot project bao gom:

- **Project metadata:** Ten, target codebase, output directory, mo ta, ghi chu.
- **Run directories:** Thu muc con timestamped cho moi lan chay (scan, validate, agentic...).
- **Lifecycle operations:** Create, use (active), list, delete, rename, clean, merge, export, import.

### Thiet ke

**Kien truc:**

```
project.py      -> Model Project va ProjectManager
cli.py          -> CLI entry point cho `raptor project <subcommand>`
clean.py        -> Xoa cac run cu, giu lai N run moi nhat
diff.py         -> So sanh findings git hai run
export.py       -> Xuat/nhap project qua zip (voi xac thuc bao mat)
findings_utils.py-> Tien ich doc findings
merge.py        -> Gop nhieu run thanh mot
report.py       -> Tao bao cao tong hop
schema.py       -> Validation schema cho project.json va run metadata
```

**Luu tru:** Project JSON files luu tai `~/.raptor/projects/<name>.json`. Output directories mac dinh tai `out/projects/<name>/`.

**Active project:** Duoc quan ly qua symlink `~/.raptor/projects/.active` -> `<name>.json`.

### API Reference

#### Lop `Project`

| Thuoc tinh / Phuong thuc | Kieu | Mo ta |
|---|---|---|
| `name` | `str` | Ten project |
| `target` | `str` | Duong dan toi codebase muc tieu |
| `output_dir` | `str` | Thu muc output |
| `created` | `str` | Ngay tao (ISO format) |
| `description` | `str` | Mo ta ngan |
| `notes` | `str` | Ghi chu chi tiet |
| `version` | `int` | Phien ban schema (hien tai: 1) |
| `output_path` | `property` | Tra ve Path object cua output_dir |
| `get_run_dirs()` | `method` | Danh sach run directories (moi nhat truoc) |
| `get_run_dirs_by_type()` | `method` | Nhom run directories theo loai command |

#### Lop `ProjectManager`

| Phuong thuc | Mo ta |
|---|---|
| `__init__(projects_dir)` | Khoi tao voi duong dan projects dir |
| `create(name, target, description, output_dir, resolve_target, created)` | Tao project moi |
| `load(name)` | Tai project theo ten (tra ve None neu khong tim thay) |
| `list_projects()` | Liet ke tat ca projects |
| `delete(name, purge)` | Xoa project (purge=True se xoa ca output directory) |
| `rename(old_name, new_name)` | Doi ten project |
| `update_notes(name, notes)` | Cap nhat ghi chu |
| `update_description(name, description)` | Cap nhat mo ta |
| `add_directory(name, directory, target, output_dir)` | Them run directory vao project |
| `remove_run(name, run_name, to_path)` | Di chuyen run ra khoi project |
| `set_active(name)` | Thiet lap active project symlink |
| `get_active()` | Lay ten active project hien tai |
| `find_project_for_target(target)` | Tu dong tim project co target khop |

#### Cac functions khac

| Function | Module | Mo ta |
|---|---|---|
| `clean_project(project, keep, dry_run)` | `clean.py` | Xoa run cu, giu N run moi nhat |
| `plan_clean(project, keep)` | `clean.py` | Lap ke hoach xoa (khong thay doi filesystem) |
| `execute_clean(plan)` | `clean.py` | Thuc thi ke hoach xoa |
| `diff_runs(run_dir_a, run_dir_b)` | `diff.py` | So sanh findings git hai run |
| `merge_runs(run_dirs, output_dir)` | `merge.py` | Gop nhieu run thanh mot |
| `merge_findings(run_dirs)` | `merge.py` | Gop findings, deduplicate by ID |
| `export_project(output_dir, dest_path, project_json_path, force)` | `export.py` | Xuat project thanh zip |
| `import_project(zip_path, projects_dir, force, output_base)` | `export.py` | Nhap project tu zip |
| `validate_zip_contents(zip_path)` | `export.py` | Kiem tra zip co an toan khong |
| `generate_project_report(project)` | `report.py` | Tao bao cao tong hop |
| `validate_project(data)` | `schema.py` | Validation project.json |
| `validate_run_metadata(data)` | `schema.py` | Validation .raptor-run.json |
| `get_finding_id(finding)` | `findings_utils.py` | Trich xuat finding ID |
| `load_findings_from_dir(run_dir)` | `findings_utils.py` | Doc findings tu run directory |

### Thuc hanh

```python
from core.project import Project, ProjectManager

mgr = ProjectManager()

# Tao project moi
project = mgr.create(
    name="my-webapp",
    target="/path/to/webapp",
    description="Main web application",
)

# Set active project
mgr.set_active("my-webapp")

# Lay active project
active = mgr.get_active()  # "my-webapp"

# Liet ke projects
for p in mgr.list_projects():
    print(f"{p.name}: {p.target}")

# Lay cac run directories
runs = project.get_run_dirs()
for run in runs:
    print(f"  {run.name}")

# Them run directory co san vao project
mgr.add_directory("my-webapp", "/path/to/existing/run")

# Xoa run cu, giu 3 run moi nhat
from core.project import clean_project
stats = clean_project(project, keep=3, dry_run=True)  # Dry run de xem truoc

# Xuat project
from core.project import export_project
result = export_project(project.output_path, "backup.zip", force=True)
print(f"Exported: {result['path']}, SHA-256: {result['sha256']}")

# Nhap project
from core.project import export_project as ep
result = ep.import_project("backup.zip", mgr.projects_dir, force=True)
print(f"Imported: {result['name']}")
```

### Best Practices

1. **Luon dat ten project co y nghia** (chu thuong, gach noi) -- ten phai hop le theo regex `^[a-zA-Z0-9][a-zA-Z0-9._-]*$`.
2. **Su dung `set_active()`** de chuyen doi git nhanh git cac project.
3. **Export dinh ky** de sao luu -- zip bao gom ca `.project.json` metadata.
4. **Dung `plan_clean()` truoc `execute_clean()`** de xem truoc nhung gi se bi xoa.
5. **Import validation** tu dong kiem tra path traversal, absolute paths, va symlinks trong zip.
6. **Project notes** ho tro Markdown -- dung de ghi chu phan tich, quyet dinh, va ket luan.

### Troubleshooting

| Van de | Nguyen nhan | Giai phap |
|---|---|---|
| "Project name contains invalid characters" | Ten co ky tu dac biet | Chi dung chu cai, so, gach noi, dau cham, underscore |
| "Refusing to delete suspicious path" | Output directory qua gan goc he thong | He thong bao ve -- khong cho phep xoa `/`, `~`, hoac duong dan ngan |
| "Unsafe zip file rejected: Path traversal" | Zip file co path `../` | Chi import zip duoc tao boi `raptor project export` |
| Project khong hien thi trong `list` | File JSON bi hu hoac sai thu muc | Kiem tra `~/.raptor/projects/` co file `<name>.json` khong |
| Run directory khong duoc phat hien | Thieu `.raptor-run.json` | Goi `generate_run_metadata()` de tao JIT |

---

## 6. Vong doi Run (`core/run/*`)

### Ly thuyet

Module Run quan ly **vong doi cua mot lan phan tich** (scan, validate, agentic, v.v.). Moi run co:

- **Output directory:** Thu muc chua tat ca ket qua, duoc dat ten theo mau `<command>-YYYYMMDD-HHMMSS`.
- **Metadata file:** `.raptor-run.json` ghi nhan trang thai (running/completed/failed/cancelled).
- **Lifecycle transitions:** start -> complete/fail/cancel.

### Thiet ke

**Trang thai (Status):**
- `running` -- Dang thuc thi
- `completed` -- Hoan thanh thanh cong
- `failed` -- That bai co loi
- `cancelled` -- Huy bo nguoi dung (Ctrl-C)

**Resolution thu tu output directory:**
1. Explicit `--out` argument (dung nguyen)
2. Active project (.active symlink -> env var)
3. Mac dinh: `out/<command>_timestamp/`

### API Reference

#### Module `metadata`

| Function / Hang so | Mo ta |
|---|---|
| `RUN_METADATA_FILE` | `".raptor-run.json"` |
| `STATUS_RUNNING` | `"running"` |
| `STATUS_COMPLETED` | `"completed"` |
| `STATUS_FAILED` | `"failed"` |
| `STATUS_CANCELLED` | `"cancelled"` |
| `start_run(output_dir, command, extra)` | Viet metadata ban dau, status=running |
| `complete_run(output_dir, extra)` | Cap nhat status=completed |
| `fail_run(output_dir, error, extra)` | Cap nhat status=failed |
| `cancel_run(output_dir, extra)` | Cap nhat status=cancelled |
| `tracked_run(output_dir, command, extra)` | Context manager -- tu dong quan ly toan bo lifecycle |
| `load_run_metadata(run_dir)` | Doc metadata tu run directory |
| `is_run_directory(path)` | Kiem tra directory co phai run directory khong |
| `infer_command_type(run_dir)` | Suy ra loai command tu metadata hoac ten directory |
| `generate_run_metadata(run_dir)` | Tao metadata cho directory co san (JIT adoption) |
| `parse_timestamp_from_name(name)` | Trich xuat timestamp tu ten directory |

#### Module `output`

| Function / Class | Mo ta |
|---|---|
| `get_output_dir(command, target_name, explicit_out, target_path)` | Xac dinh output directory theo thu tu uu tien |
| `TargetMismatchError` | Exception khi target khong khop voi active project |

### Thuc hanh

```python
from core.run import tracked_run, start_run, complete_run, fail_run, get_output_dir

# Cach 1: Dung context manager (khuyen nghi)
out_dir = get_output_dir("scan", target_name="myapp")
with tracked_run(out_dir, "scan") as run_dir:
    # Thuc hien quet...
    run_scan(run_dir)
    # .raptor-run.json se tu dong cap nhat:
    # - completed neu thanh cong
    # - failed neu co exception
    # - cancelled neu Ctrl-C

# Cach 2: Thu cong
out_dir = get_output_dir("validate")
start_run(out_dir, "validate")
try:
    run_validation(out_dir)
    complete_run(out_dir)
except Exception as e:
    fail_run(out_dir, error=str(e))

# Kiem tra run directory
from core.run import is_run_directory, infer_command_type, load_run_metadata
from pathlib import Path

run_dir = Path("out/scan-20260412-103000")
if is_run_directory(run_dir):
    cmd_type = infer_command_type(run_dir)  # "scan"
    meta = load_run_metadata(run_dir)
    print(f"Status: {meta['status']}")
```

### Best Practices

1. **Luon dung `tracked_run` context manager** -- tu dong xu ly ca success, exception, va Ctrl-C.
2. **Goi `get_output_dir()`** de dam bao output directory dung vi tri (project hay standalone).
3. **Kiem tra `TargetMismatchError`** khi lam viec voi nhieu project -- tranh nham lan target.
4. **Generate metadata cho existing directories** khi import vao project.

### Troubleshooting

| Van de | Nguyen nhan | Giai phap |
|---|---|---|
| "Target is outside project" | Target path khac voi project target | Dung `raptor project create` voi target moi hoac `raptor project use none` |
| "No .raptor-run.json" | Quen goi `start_run()` hoac directory khong phai run | Goi `generate_run_metadata()` de tao |
| Run bi mac kẹt "running" | Chuong trinh bi crash giua chung | Cap nhat thu cong: `fail_run(run_dir, error="stale")` |
| Ten directory khong co timestamp | Dung custom path qua `--out` | He thong van hoat dong -- chi khong co thoi gian trong ten |

---

## 7. SARIF Parsing (`core/sarif/*`)

### Ly thuyet

SARIF (Static Analysis Results Interchange Format) la chuan JSON de trao doi ket qua phan tich tinh. Module nay:

- **Doc va validate** file SARIF voi size guard (100 MiB) va JSON schema validation.
- **Trich xuat findings** tu SARIF results, chuan hoa cau truc.
- **Deduplicate** findings dua tren fingerprint (file + line + rule).
- **Merge** nhieu file SARIF thanh mot.
- **Sinh metrics** tong hop (findings by severity, by rule, tools used).

### Thiet ke

**Quy trinh parse SARIF:**
```
load_sarif() -> validate size & JSON
  -> get_tool_name() & get_rules() -> build rules lookup
    -> parse_sarif_findings() -> extract each result
      -> extract_dataflow_path() (neu co codeFlows)
        -> deduplicate_findings()
```

**CWE extraction:** Trich xuat CWE ID tu nhieu nguon trong SARIF rule:
- `properties.cwe`
- `properties.tags` (vd: `"external/cwe/cwe-89"`)
- Description text

### API Reference

| Function | Mo ta |
|---|---|
| `load_sarif(sarif_path)` | Doc file SARIF voi safety guards, tra ve dict hoac None |
| `parse_sarif_findings(sarif_path)` | Parse findings tu SARIF, tra ve list of finding dicts |
| `validate_sarif(sarif_path, schema_path)` | Validate SARIF file (basic + optional jsonschema) |
| `deduplicate_findings(findings)` | Loai bo trung lap qua fingerprint |
| `merge_sarif(sarif_paths)` | Gop nhieu file SARIF thanh mot |
| `generate_scan_metrics(sarif_paths)` | Sinh metrics tong hop |
| `sanitize_finding_for_display(finding)` | Cat ngan snippet va message de hien thi |
| `extract_dataflow_path(code_flows)` | Trich xuat dataflow path tu SARIF codeFlows |
| `get_tool_name(run)` | Lay ten tool tu SARIF run |
| `get_rules(run)` | Lay rules dictionary tu SARIF run |
| `_extract_cwe_from_rule(rule)` | Trich xuat CWE ID tu rule |

### Thuc hanh

```python
from core.sarif.parser import (
    load_sarif, parse_sarif_findings, validate_sarif,
    merge_sarif, generate_scan_metrics, deduplicate_findings
)
from pathlib import Path

# Doc va parse SARIF
sarif_path = Path("results/semgrep.sarif")
if validate_sarif(sarif_path):
    findings = parse_sarif_findings(sarif_path)
    print(f"Parsed {len(findings)} findings")

    # Deduplicate
    unique = deduplicate_findings(findings)
    print(f"Unique: {len(unique)} findings")

# Merge nhieu file SARIF
merged = merge_sarif(["semgrep.sarif", "codeql.sarif"])
print(f"Merged {len(merged['runs'])} runs")

# Sinh metrics
metrics = generate_scan_metrics(["semgrep.sarif", "codeql.sarif"])
print(f"Total findings: {metrics['total_findings']}")
print(f"By severity: {metrics['findings_by_severity']}")
print(f"Tools: {metrics['tools_used']}")

# Trich xuat dataflow path
from core.sarif.parser import extract_dataflow_path
for finding in findings:
    if finding.get("has_dataflow"):
        path = finding["dataflow_path"]
        print(f"Source: {path['source']['file']}:{path['source']['line']}")
        print(f"Sink: {path['sink']['file']}:{path['sink']['line']}")
```

### Best Practices

1. **Luon dung `load_sarif()`** thay vi `json.loads()` -- co size guard va error handling.
2. **Validate SARIF** truoc khi parse de dam bao dinh dang dung.
3. **Deduplicate findings** khi merge ket qua tu nhieu tool.
4. **Sanitize findings** truoc khi hien thi len console hoac bao cao.

### Troubleshooting

| Van de | Nguyen nhan | Giai phap |
|---|---|---|
| "File too large" | SARIF > 100 MiB | Tang `max_size` trong `load_sarif()` hoac tach nho file |
| "Invalid JSON" | File SARIF bi hu hoac khong phai JSON | Kiem tra file co dung SARIF output khong |
| "Root must be an object" | JSON root la array thay vi object | SARIF phai bat dau bang `{` |
| Thieu CWE ID | Tool khong cung cap CWE trong SARIF rule | He thong de trong `cwe_id` -- khong phai loi |
| Dataflow path null | Ket qua khong co codeFlows | Binh thuong -- chi CodeQL moi co dataflow paths |

---

## 8. Bao cao (`core/reporting/*`)

### Ly thuyet

He thong bao cao duoc thiet ke theo **kien truc 2 lop**:

**Layer 1 (Domain-agnostic):**
- `ReportSpec`, `ReportSection` -- cau truc bao cao
- `render_report()` -- renderer markdown
- `render_console_table()` -- renderer terminal box-drawing
- Formatting utilities

**Layer 2 (Findings-aware):**
- `build_findings_spec()` -- xay dung ReportSpec tu findings
- `findings_summary()` -- bang "Results at a Glance"
- `get_display_status()` -- chuyen doi trang thai qua cac dinh dang khac nhau

### Thiet ke

**Pattern:** Tach biet **specification** (cau tru du lieu) khoi **rendering** (hien thi). `ReportSpec` mo ta "cai gi" can render, renderer quyet dinh "nhu the nao".

**Cot bang findings:** `["#", "Type", "CWE", "File", "Status", "Severity", "CVSS"]`

**Trang thai hien thi (`get_display_status`):**
- Validate pipeline: `ruling.status`, `final_status` -> Exploitable/Confirmed/Ruled Out/False Positive
- Agentic pipeline: `is_true_positive`, `is_exploitable` booleans -> Exploitable/Confirmed/False Positive
- Error: `error` field -> Error(<type>)

### API Reference

#### Module `spec`

| Class | Mo ta |
|---|---|
| `ReportSection(title, content)` | Mot section bao cao voi ten va content da render |
| `ReportSpec` | Specification cua toan bo bao cao (title, metadata, summary, table, details, sections, output_files) |

#### Module `renderer`

| Function | Mo ta |
|---|---|
| `render_report(spec, separator)` | Render ReportSpec thanh markdown string |
| `_render_table(columns, rows)` | Render markdown table |

#### Module `console`

| Function | Mo ta |
|---|---|
| `render_console_table(columns, rows, title, footer, max_widths)` | Render box-drawing table tren terminal |

#### Module `formatting`

| Function | Mo ta |
|---|---|
| `get_display_status(finding)` | Chuyen doi finding dict thanh status string de hien thi |
| `title_case_type(vuln_type)` | Chuyen `sql_injection` -> "SQL Injection" |
| `truncate_path(path, max_len)` | Cat ngan duong dan dai |
| `format_elapsed(seconds)` | Dinh dang thoi gian (45s, 2m 30s, 1h 15m) |

#### Module `findings`

| Function / Hang so | Mo ta |
|---|---|
| `FINDINGS_COLUMNS` | Danh sach cot mac dinh |
| `build_findings_rows(findings, filename_only)` | Xay dung data rows tu findings |
| `build_findings_summary(findings)` | Dem findings theo status |
| `findings_summary_line(counts)` | Tao dong tom tat ("3 Exploitable, 2 False Positive out of 10 findings") |
| `build_finding_detail(finding, index)` | Xay dung detail section cho mot finding |
| `build_findings_spec(findings, title, metadata, extra_summary, warnings, extra_sections, output_files, include_details)` | Entry point chinh -- xay dung ReportSpec tu findings |
| `findings_summary(findings)` | Tao "Results at a Glance" text (bang + dong trang thai) |

### Thuc hanh

```python
from core.reporting import (
    ReportSpec, ReportSection, render_report,
    render_console_table, build_findings_spec,
    findings_summary, get_display_status,
    FINDINGS_COLUMNS
)

# Cach 1: Dung build_findings_spec (khuyen nghi cho findings)
spec = build_findings_spec(
    findings=findings_list,
    title="Security Report",
    metadata={
        "Target": "/path/to/webapp",
        "Date": "2026-04-12",
        "Tool": "RAPTOR v3.0.0",
    },
    extra_summary={"Files scanned": 150, "SLOC": 25000},
    warnings=["1 finding(s) have no final verdict"],
    include_details=True,
)

# Render markdown
markdown_output = render_report(spec)

# Cach 2: Render console table
table_str = render_console_table(
    columns=FINDINGS_COLUMNS,
    rows=build_findings_rows(findings_list, filename_only=True),
    title="Results at a Glance",
    footer=findings_summary_line(build_findings_summary(findings_list)),
    max_widths={3: 40},  # Gioi han cot File 40 ky tu
)
print(table_str)

# Cach 3: Tao ReportSpec thu cong
spec = ReportSpec(
    title="Custom Report",
    metadata={"Author": "Analyst"},
    summary={"Total": 100, "Checked": 85},
    table_columns=["Name", "Status"],
    table_rows=[("Item 1", "OK"), ("Item 2", "FAIL")],
    detail_title="Details",
    detail_sections=[
        ReportSection("Detail 1", "Content here"),
        ReportSection("Detail 2", "More content"),
    ],
)
print(render_report(spec))
```

### Best Practices

1. **Dung `build_findings_spec()`** cho bao cao vulnerability -- da co san dinh dang, cot, va logic.
2. **Truyen `include_details=False`** khi chi can bang tong hop (bao cao executive).
3. **Dung `filename_only=True`** khi render console table, `False` cho markdown.
4. **Custom sections** qua `extra_sections` de them thong tin rieng (environment, recommendations).
5. **Warnings** nen duoc them khi co van de trong pipeline -- giup phat hien bugs som.

### Troubleshooting

| Van de | Nguyen nhan | Giai phap |
|---|---|---|
| Trang thai "Unknown" | Finding khong co field verdict nao | Kiem tra pipeline -- co the bi thieu `ruling`, `is_true_positive`, `is_exploitable` |
| Bang bi lech tren terminal | Ten file qua dai | Dung `max_widths` trong `render_console_table()` |
| Thieu finding trong bao cao | Finding khong co ID hop le | Kiem tra `get_finding_id()` tra ve gia tri |
| Markdown khong render dung | Content co ky tu dac biet | Escape ky tu `|` trong markdown tables |

---

## 9. JSON Utilities (`core/json/*`)

### Ly thuyet

Module JSON utilities cung cap **cac ham doc/ghi JSON dung chung** cho toan bo framework, xu ly:

- Doc JSON voi error handling nhat quan (return None khi fail).
- Ghi JSON voi atomic write (write to temp -> rename) de tranh corruption.
- Tu dong chuyen doi `Path` va `datetime` objects.
- Ho tro JSON co comment (`//` lines).

### Thiet ke

**Pattern:** Centralize 60+ file su dung JSON patterns vao mot module duy nhat.

**Atomic write:** Ghi vao file tam `.~<name>.tmp` roi rename -- tren POSIX, `rename()` la atomic operation. Neu process bi kill giua chung, file tam van ton tai (de nhan dien) va file chinh khong bi hu.

### API Reference

| Function / Class | Mo ta |
|---|---|
| `load_json(path, strict=False)` | Doc JSON file. Tra ve None neu khong doc duoc (strict=False) hoac raise exception (strict=True) |
| `load_json_with_comments(path)` | Doc JSON co the chua `//` comments (dung cho config files) |
| `save_json(path, data)` | Ghi JSON voi pretty-print, atomic write, Path/datetime serialization |
| `_RaptorEncoder` | Custom JSONEncoder xu ly Path va datetime objects |

### Thuc hanh

```python
from core.json import load_json, save_json, load_json_with_comments
from pathlib import Path
from datetime import datetime

# Doc JSON (safe -- tra ve None neu loi)
data = load_json("config.json")
if data is None:
    print("File not found or invalid JSON")

# Doc JSON bat buoc phai thanh cong (strict mode)
config = load_json("required_config.json", strict=True)

# Doc JSON co comments
models = load_json_with_comments("~/.config/raptor/models.json")

# Ghi JSON (atomic, tu dong tao thu muc cha)
save_json("output/results.json", {
    "timestamp": datetime.now(),
    "path": Path("/some/path"),
    "data": [1, 2, 3],
})

# Path va datetime duoc tu dong chuyen doi:
# {
#   "timestamp": "2026-04-12T10:30:00+00:00",
#   "path": "/some/path",
#   "data": [1, 2, 3]
# }
```

### Best Practices

1. **Luon dung `load_json()`/`save_json()`** thay vi `json.loads()`/`json.dump()` -- co error handling va atomic write.
2. **Dung `strict=True`** cho cac file bat buoc phai ton tai (config, schema).
3. **Mac dinh `strict=False`** cho cac file optional (metadata, cache).
4. **Atomic write** giup tranh corruption khi process bi kill -- khong can try/extra khi goi `save_json()`.

### Troubleshooting

| Van de | Nguyen nhan | Giai phap |
|---|---|---|
| `load_json()` tra ve None | File khong ton tai hoac JSON bi hu | Kiem tra file ton tai, dung `strict=True` de xem exception |
| File JSON bi trong | Qua trinh ghi bi ngat | Atomic write da phong ngua -- kiem tra file `.~*.tmp` con sot |
| `TypeError: not JSON serializable` | Object khong phai Path/datetime/standard type | Chuyen doi object thanh string/dict truoc khi goi `save_json()` |

---

## 10. He thong Khoi dong (`core/startup/*`)

### Ly thuyet

Module startup thuc hien **kiem tra moi truong va hien thi banner** khi RAPTOR khoi dong:

- **Tool availability:** Kiem tra cac binary can thiet (`afl++`, `codeql`, `gdb`, `semgrep`, `rr`).
- **LLM configuration:** Phat hien LLM provider (Ollama, OpenAI, Anthropic, Gemini, Mistral).
- **Environment check:** Output directory, disk space, bien cau hinh, tree-sitter.
- **Active project:** Hien thi thong tin project dang active.
- **Banner:** ASCII logo + quote + system status.

### Thiet ke

**Kien truc:**

```
__init__.py     -> Bien dung chung (REPO_ROOT, PROJECTS_DIR), helpers
banner.py       -> Dinh dang va hien thi banner
init.py         -> Main startup entry point, thuc hien tat ca checks
launcher.py     -> Launcher cho Claude Code, quan ly project resolution
```

**Banner format:**
```
[ASCII Logo]

 tools: semgrep ✓  codeql ✓  gdb ✓  afl++ ✗
   env: out/ ✓  disk 120 GB free  tree-sitter ✓ (python, javascript)
   llm: ollama/llama3 (primary, local)
        claude code ✓

 warn: /fuzz limited -- afl++ not found

 Project: my-webapp (/path/to/webapp)

 For defensive security research, education, and authorized penetration testing.

raptor:~$ "Hack the planet!"
```

### API Reference

#### Module `__init__`

| Function / Bien | Mo ta |
|---|---|
| `REPO_ROOT` | Duong dan goc repository |
| `PROJECTS_DIR` | `~/.raptor/projects/` |
| `ACTIVE_LINK` | `~/.raptor/projects/.active` |
| `get_active_name()` | Doc ten active project tu symlink |
| `sync_project_env_file()` | Cap nhat CLAUDE_ENV_FILE voi bien project |

#### Module `banner`

| Function | Mo ta |
|---|---|
| `read_logo()` | Doc ASCII logo tu file `raptor-offset` |
| `read_random_quote()` | Lay quote ngau nhien tu file `hackers-8ball` |
| `format_banner(logo, quote, tool_results, tool_warnings, llm_lines, llm_warnings, env_parts, env_warnings, project_line)` | Tong hop banner cuoi cung |

#### Module `init`

| Function | Mo ta |
|---|---|
| `check_tools()` | Kiem tra tool ben ngoai, tra ve (results, warnings, unavailable_features) |
| `check_llm()` | Kiem tra LLM availability, tra ve (lines, warnings) |
| `check_env(unavailable_features)` | Kiem tra moi truong, tra ve (parts, warnings) |
| `check_active_project()` | Tra ve dong trang thai active project |
| `setup_env_file()` | Them `bin/` vao PATH trong CLAUDE_ENV_FILE |
| `main()` | Entry point chinh -- thuc hien tat ca checks va in banner |

#### Module `launcher`

| Function | Mo ta |
|---|---|
| `_activate(name)` | Kich hoat project (symlink + env vars) |
| `_deactivate()` | Huy active project |
| `_find_project_for(directory, exclude)` | Tim project co target khop voi directory |
| `_check_mismatch(caller_dir)` | Kiem tra va hoi neu cwd khong khop active project |
| `main()` | Entry point launcher -- parse args, resolve project, exec Claude Code |

### Thuc hanh

```bash
# Khoi dong banner (tu dong chay khi dung raptor)
python3 -m core.startup.init

# Launcher -- khoi dong Claude Code voi RAPTOR
raptor                    # Khoi dong binh thuong
raptor /path/to/code      # Scan target cu the
raptor -p my-webapp       # Khoi dong voi project cu the
raptor -c                 # Resume phien lam viec truoc
raptor -m sonnet          # Chon model
raptor project status     # Xem trang thai project

# Launcher routing -- `raptor project` duoc chuyen den Python CLI
raptor project create myapp --target /path/to/code
raptor project use myapp
raptor project list
```

### Best Practices

1. **Banner chay tu dong** khi khoi dong RAPTOR -- khong can goi thu cong.
2. **Launcher xu ly argument parsing** -- cac flag `-p`, `-m`, `-c` duoc chuyen tiep.
3. **Mismatch prompt** giup tranh nham lan git cac project -- luon tra loi khi co canh bao.
4. **CLAUDE_ENV_FILE** duoc cap nhat tu dong -- giup Claude Code co access den bien moi truong RAPTOR.

### Troubleshooting

| Van de | Nguyen nhan | Giai phap |
|---|---|---|
| Banner hien thi "unavailable" cho tool | Tool chua cai dat | Cai dat tool tuong ung (`apt install gdb`, tai CodeQL) |
| "LLM detection error" | Khong the import LLM modules | Kiem tra `packages/llm_analysis/` va dependencies |
| "out/ directory not writable" | Quyen ghi bi han che | `chmod 755 out/` hoac dat `RAPTOR_OUT_DIR` |
| "Low disk space" | < 5 GB trong | Xoa run cu (`raptor project clean`) hoac tang dung luong |
| Claude Code khong khoi dong | Khong co `claude` trong PATH | Cai dat Claude Code: `npm install -g @anthropic-ai/claude-code` |

---

## 11. Schema Constants (`core/schema_constants.py`)

### Ly thuyet

Module nay chua **cac hang so enum va mapping dung chung** cho ca hai pipeline `/validate` va `/agentic`. Day la "single source of truth" cho:

- Cac loai ton thuong (VULN_TYPES)
- Cap do nghiem trong (SEVERITY_LEVELS)
- Cac gia tri ruling cho tung pipeline
- Mapping CWE <-> vuln_type hai chieu
- Cac muc do tin cay (CONFIDENCE_LEVELS)
- Ly do false positive (FP_REASONS)

### Thiet ke

**Bieu do canh truong git hai pipeline:**

| Concept | /validate | /agentic | Shared? |
|---|---|---|---|
| ID | `id` | `finding_id` | Khong |
| Vuln type | `vuln_type` | `vuln_type` | Co |
| CWE | `cwe_id` | `cwe_id` | Co |
| True positive | `is_true_positive` | `is_true_positive` | Co |
| Exploitable | `is_exploitable` | `is_exploitable` | Co |
| Severity | `severity_assessment` | `severity_assessment` | Co |
| CVSS | `cvss_score_estimate` | `cvss_score_estimate` | Co |
| Ruling | `ruling.status` | `ruling` | Khac enum |
| Confidence | `confidence` | `confidence` | Co |

**Ly do khong chia se mot so truong:**
- **ID:** Nguon goc khac nhau (validate tao moi, agentic chuyen tu SARIF)
- **Proximity:** Chi co y nghia trong multi-stage pipeline
- **Ruling enums:** Validate = pipeline outcome, Agentic = categorised verdict

### API Reference

| Hang so | Kieu | Mo ta |
|---|---|---|
| `VULN_TYPES` | `List[str]` | 25+ loai ton thuong (command_injection, sql_injection, xss, ...) |
| `SEVERITY_LEVELS` | `List[str]` | 5 muc: critical, high, medium, low, informational |
| `AGENTIC_RULING_VALUES` | `List[str]` | validated, false_positive, unreachable, test_code, dead_code, mitigated |
| `VALIDATE_RULING_VALUES` | `List[str]` | confirmed, ruled_out, exploitable |
| `CONFIDENCE_LEVELS` | `List[str]` | high, medium, low |
| `FP_REASONS` | `List[str]` | sanitized_input, dead_code, test_only, unreachable_path, safe_api_usage, compiler_optimized, defense_in_depth, other |
| `CWE_TO_VULN_TYPE` | `Dict[str, str]` | Mapping CWE -> vuln_type (24 entries) |
| `VULN_TYPE_TO_CWE` | `Dict[str, str]` | Mapping vuln_type -> CWE (19 entries) |

### Thuc hanh

```python
from core.schema_constants import (
    VULN_TYPES, SEVERITY_LEVELS, VALIDATE_RULING_VALUES,
    AGENTIC_RULING_VALUES, CWE_TO_VULN_TYPE, VULN_TYPE_TO_CWE
)

# Kiem tra vuln_type co hop le khong
def is_valid_vuln_type(vtype):
    return vtype in VULN_TYPES

# Chuyen doi giua CWE va vuln_type
cwe = "CWE-78"
vtype = CWE_TO_VULN_TYPE.get(cwe, "other")  # "command_injection"

cwe_back = VULN_TYPE_TO_CWE.get(vtype)  # "CWE-78"

# Validation ruling
def is_valid_ruling(value, pipeline):
    if pipeline == "validate":
        return value in VALIDATE_RULING_VALUES
    return value in AGENTIC_RULING_VALUES
```

### Best Practices

1. **Luon import tu `schema_constants`** thay vi hardcode enum values trong code.
2. **Dung `VULN_TYPE_TO_CWE`** khi can infer CWE tu vuln_type (agentic pipeline).
3. **Dung `CWE_TO_VULN_TYPE`** khi classify SARIF findings (orchestrator).
4. **Khi them vuln_type moi**, cap nhat ca hai mapping dictionaries.

---

## 12. Understand Bridge (`core/understand_bridge.py`)

### Ly thuyet

Understand Bridge la **cau noi git /understand va /validate** pipelines, cho phep analyst:

1. Chay `/understand` de map attack surface (sources, sinks, trust boundaries).
2. Tu dong chuyen ket qua thanh starting state cho `/validate`.
3. `/validate` bat dau tu diem da co context, khong bat dau tu con so 0.

### Thiet ke

**Ba chuc nang chinh:**

1. **Populate attack-surface.json:** Copy sources/sinks/trust_boundaries tu context-map.json.
2. **Import flow traces:** Chuyen flow-trace-*.json thanh attack-paths.json entries.
3. **Enrich checklist:** Danh dau entry points va sinks la "high-priority" trong checklist.

**Auto-detection:** Bridge tu dong tim understand run gan nhat trong project output directory qua `infer_command_type()`.

### API Reference

| Function | Mo ta |
|---|---|
| `find_understand_dir(project_output_dir)` | Tim understand run gan nhat trong project |
| `load_understand_context(understand_dir, validate_dir)` | Import /understand outputs lam /validate starting state |
| `enrich_checklist(checklist, context_map)` | Danh dau entry points/sinks la high-priority |
| `TRACE_SOURCE_LABEL` | `"understand:trace"` -- label cho paths import tu understand |

### Thuc hanh

```python
from core.understand_bridge import (
    find_understand_dir, load_understand_context, enrich_checklist
)
from pathlib import Path

# Auto-detect understand dir trong project
understand_dir = find_understand_dir(project.output_path)
if understand_dir:
    print(f"Found understand run: {understand_dir}")

# Load context va import vao validate
bridge = load_understand_context(
    understand_dir=understand_dir,
    validate_dir=validate_output_dir,
)

if bridge["context_map_loaded"]:
    print(f"Sources: {bridge['attack_surface']['sources']}")
    print(f"Sinks: {bridge['attack_surface']['sinks']}")
    print(f"Traces imported: {bridge['flow_traces']['imported_as_paths']}")

    # Enrich checklist voi priority markers
    from core.json import load_json
    checklist = load_json(validate_output_dir / "checklist.json")
    enriched = enrich_checklist(checklist, bridge["context_map"])
    # Functions trong entry points/sinks se co priority="high"
```

### Best Practices

1. **Chay `/understand` truoc `/validate`** khi lam viec voi codebase lon -- tiet kiem thoi gian.
2. **Bridge tu dong phat hien** understand run trong project -- khong can chi dinh thu cong.
3. **Priority markers** giup Stage B (/validate) tap trung vao code quan trong nhat truoc.
4. **Flow traces** duoc import nhu starting attack paths -- Stage B co the tiep tuc tu do.

### Troubleshooting

| Van de | Nguyen nhan | Giai phap |
|---|---|---|
| "no context-map.json found" | Chua chay `/understand` hoac run da bi xoa | Chay `/understand` truoc |
| Khong co flow traces import | Khong co flow-trace-*.json files | Binh thuong -- chi co khi understand chay dataflow analysis |
| Checklist khong duoc enrich | Context map khong co entry_points hoac sink_details | Kiem tra quality cua understand run |
| Duplicate entries trong attack-surface | Merge da co san file | He thong merge de-dup theo key -- an toan |

---

## Phu Luc

### A. So do phu thuoc (Dependency Graph)

```
core/config.py          <- Tat ca modules khac deu phu thuoc
core/json/utils.py      <- Inventory, Project, Run, SARIF, Reporting
core/logging.py         <- Inventory, Project, Run, SARIF, Startup
core/progress.py        <- Doc lap (standalone utility)

core/inventory/*        <- Project (checklist), Understand Bridge
core/run/*              <- Project (get_run_dirs), Launcher
core/sarif/*            <- Agentic pipeline, Reporting
core/reporting/*        <- Validate pipeline, Agentic pipeline
core/project/*          <- Launcher, CLI
core/startup/*          <- Launcher, bin/raptor
core/schema_constants.py<- Validate, Agentic pipelines
core/understand_bridge.py<- Validate pipeline Stage 0
```

### B. Huong dan Import nhanh

```python
# Import tat ca tu core package
from core import (
    RaptorConfig, get_logger,
    deduplicate_findings, parse_sarif_findings, validate_sarif,
    generate_scan_metrics, sanitize_finding_for_display,
)

# Inventory
from core.inventory import (
    build_inventory, get_coverage_stats, get_items,
    lookup_function, compare_inventories,
    LANGUAGE_MAP, detect_language,
    DEFAULT_EXCLUDES, is_binary_file, is_generated_file,
    CodeItem, FunctionInfo, FunctionMetadata,
    extract_functions, extract_items, count_sloc,
)

# Project
from core.project import (
    Project, ProjectManager,
    clean_project, plan_clean, execute_clean,
    generate_project_report,
)

# Run
from core.run import (
    tracked_run, start_run, complete_run, fail_run, cancel_run,
    load_run_metadata, is_run_directory, infer_command_type,
    get_output_dir, TargetMismatchError,
)

# Reporting
from core.reporting import (
    ReportSpec, ReportSection, render_report,
    render_console_table, build_findings_spec,
    findings_summary, get_display_status,
    FINDINGS_COLUMNS,
)

# JSON
from core.json import load_json, save_json, load_json_with_comments

# Schema
from core.schema_constants import (
    VULN_TYPES, SEVERITY_LEVELS, VALIDATE_RULING_VALUES,
    AGENTIC_RULING_VALUES, CWE_TO_VULN_TYPE, VULN_TYPE_TO_CWE,
    CONFIDENCE_LEVELS, FP_REASONS,
)

# Understand Bridge
from core.understand_bridge import (
    find_understand_dir, load_understand_context, enrich_checklist,
)
```

### C. Cau truc thu muc

```
core/
├── __init__.py              # Re-exports chinh
├── config.py                # Cau hinh trung tam
├── logging.py               # He thong logging
├── progress.py              # Theo doi tien trinh
├── schema_constants.py      # Hang so enum va mapping
├── understand_bridge.py     # Cau noi understand -> validate
├── inventory/
│   ├── __init__.py          # Re-exports
│   ├── builder.py           # Xay dung inventory
│   ├── languages.py         # Phat hien ngon ngu
│   ├── exclusions.py        # Logic loai tru file
│   ├── extractors.py        # Trich xuat code items (AST, tree-sitter, regex)
│   ├── lookup.py            # Lookup function tu checklist
│   ├── diff.py              # So sanh inventory
│   ├── coverage.py          # Coverage tracking
│   └── tests/               # Tests
├── project/
│   ├── __init__.py          # Re-exports
│   ├── project.py           # Model Project & ProjectManager
│   ├── cli.py               # CLI entry point
│   ├── clean.py             # Xoa run cu
│   ├── diff.py              # So sanh findings
│   ├── export.py            # Xuat/nhap zip
│   ├── findings_utils.py    # Tien ich findings
│   ├── merge.py             # Gop nhieu run
│   ├── report.py            # Bao cao tong hop
│   ├── schema.py            # Validation schemas
│   └── tests/
├── run/
│   ├── __init__.py          # Re-exports
│   ├── __main__.py          # CLI entry point
│   ├── metadata.py          # Run lifecycle
│   ├── output.py            # Output directory resolution
│   └── tests/
├── sarif/
│   ├── __init__.py          # (trong)
│   ├── parser.py            # SARIF parsing utilities
│   └── tests/
├── reporting/
│   ├── __init__.py          # Re-exports
│   ├── spec.py              # Report specification
│   ├── renderer.py          # Markdown renderer
│   ├── console.py           # Console table renderer
│   ├── formatting.py        # Formatting utilities
│   ├── findings.py          # Findings-specific report building
│   └── tests/
├── json/
│   ├── __init__.py          # Re-exports
│   ├── utils.py             # JSON load/save utilities
│   └── tests/
└── startup/
    ├── __init__.py          # Bien dung chung
    ├── banner.py            # Banner formatting
    ├── init.py              # Startup checks
    ├── launcher.py          # Claude Code launcher
    └── tests/
```

---

**Ket luan:** RAPTOR Core Foundation la he sinh thai 10 module lien ket, cung cap nen tang cho toan bo framework phan tich bao mat. Tu cau hinh trung tam, logging co cau truc, inventory thong minh, quan ly du an, den bao cao chuyen nghiep -- moi module duoc thiet ke voi nguyen tac: **reusable, testable, va maintainable**.
