# Security Analysis - Phân Tích Bảo Mật

**Verifies từ Source Code Thực Tế**

---

## Mục Lục

1. [Security Controls](#security-controls)
2. [Threat Model](#threat-model)
3. [Vulnerability Mitigations](#vulnerability-mitigations)
4. [OSS Forensics](#oss-forensics)

---

## Security Controls

### 1. Environment Sanitization

**Source:** `core/config.py`

```python
DANGEROUS_ENV_VARS = {
    "TERMINAL", "EDITOR", "VISUAL", "BROWSER", "PAGER",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"
}
```

**Why:** Tools may shell-evaluate these variables, allowing command injection.

**Implementation:**
```python
def get_safe_env() -> dict:
    env = os.environ.copy()
    for var in DANGEROUS_ENV_VARS:
        env.pop(var, None)
    return env
```

**Usage:** All subprocess calls should use `get_safe_env()`.

### 2. Repo Settings Check

**Source:** `raptor_agentic.py`

**Threat:** Malicious `.claude/settings.json` with credential helpers that execute shell commands.

**CVE:** CVE-2026-21852 (Phoenix Security CWE-78 disclosure)

**Implementation:**
```python
def _check_repo_claude_settings(repo_path: str) -> bool:
    """Returns True if dangerous helpers found (block CC dispatch)"""
    dangerous_keys = [
        "apiKeyHelper", "awsAuthHelper", "awsAuthRefresh", "gcpAuthRefresh",
    ]

    claude_dir = Path(repo_path) / ".claude"
    settings_files = [claude_dir / name
                      for name in ("settings.json", "settings.local.json")
                      if (claude_dir / name).exists()]

    for settings_path in settings_files:
        if settings_path.stat().st_size > 1_000_000:
            continue  # Skip large files
        data = json.loads(settings_path.read_text())
        for key in dangerous_keys:
            if key in data and isinstance(data[key], str):
                return True  # Block dispatch
    return False
```

**Behavior when found:**
- Prints warning to user
- Blocks Claude Code sub-agent dispatch
- Scanning and external LLM analysis proceed normally

### 3. Subprocess Safety

**Rule:** List-based arguments only, no string interpolation.

```python
# ✅ SAFE
subprocess.run(["semgrep", "--config", config_path, target])

# ❌ UNSAFE
subprocess.run(f"semgrep --config {config_path} {target}", shell=True)
```

### 4. API Key Redaction in Logs

**Source:** `packages/llm_analysis/llm/client.py`

```python
def _sanitize_log_message(msg: str) -> str:
    msg = re.sub(r'sk-ant-[a-zA-Z0-9-_]{20,}', '[REDACTED-API-KEY]', msg)
    msg = re.sub(r'sk-[a-zA-Z0-9-_]{20,}', '[REDACTED-API-KEY]', msg)
    msg = re.sub(r'pk-[a-zA-Z0-9-_]{20,}', '[REDACTED-API-KEY]', msg)
    msg = re.sub(r'AIza[a-zA-Z0-9-_]{30,}', '[REDACTED-API-KEY]', msg)
    msg = re.sub(r'Bearer [a-zA-Z0-9-_]{20,}', 'Bearer [REDACTED]', msg)
    return msg
```

### 5. LiteLLM Protection

**Source:** `packages/llm_analysis/llm/detection.py`

```python
if installed in ("1.82.7", "1.82.8"):
    # Block execution - litellm contains malicious code
    raise SystemExit("RAPTOR cannot run with litellm {version} installed")
```

**Threat:** litellm 1.82.7/1.82.8 exfiltrates API keys, SSH keys, cloud credentials.

---

## Threat Model

### Threats Mitigated

| Threat | Mitigation | Source |
|--------|-----------|--------|
| Malicious repo settings | Settings check + CC dispatch block | `raptor_agentic.py` |
| Env var injection | `get_safe_env()` | `core/config.py` |
| Command injection | List-based subprocess args | All Python files |
| API key leakage | Log sanitization | `client.py` |
| Malicious dependencies | LiteLLM version check | `detection.py` |
| Sub-agent settings loading | `--add-dir` flag | Claude Code docs |

### Threats NOT Mitigated

| Threat | Reason |
|--------|--------|
| Malicious code in scanned repo | Outside RAPTOR scope |
| LLM provider compromise | Trust boundary at provider |
| Supply chain attack on deps | Python packaging issue |
| Physical access attacks | Not applicable threat model |

---

## Vulnerability Mitigations

### Binary Mitigations (exploit_feasibility)

**Source:** `packages/exploit_feasibility/mitigations.py`

```python
GLIBC_MITIGATIONS = {
    "2.34+": {
        "__malloc_hook": "REMOVED",
        "__free_hook": "REMOVED",
    },
    "2.35+": {
        "tcache": "Enhanced checking",
    },
    "2.38+": {
        "%n_specifier": "BLOCKED (empirically tested)",
    }
}
```

**Binary Protections:**
- PIE: Position Independent Executable
- NX: No-eXecute (stack non-executable)
- Canary: Stack canary
- RELRO: None/Partial/Full
- Fortify: FORTIFY_SOURCE

### Web Vulnerabilities

**Source:** `engine/semgrep/rules/`

Custom rules detect:
- Command injection (CWE-78)
- SQL injection (CWE-89)
- Path traversal (CWE-22)
- TLS skip verify (CWE-295)
- Weak crypto (CWE-327)
- Hardcoded secrets (CWE-798)
- SSRF (CWE-918)
- Unsafe deserialization (CWE-502)
- Logs secrets (CWE-532)

---

## OSS Forensics

### Architecture

**Source:** `.claude/skills/oss-forensics/`

**7-Phase Workflow:**
1. Evidence collection (parallel)
2. Hypothesis formation
3. Hypothesis testing
4. Evidence verification
5. Report generation

### Data Sources

| Source | Method | Reliability |
|--------|--------|-------------|
| GH Archive | BigQuery queries | **Immutable** |
| GitHub API | Live API calls | Current |
| Wayback Machine | Archived content | Historical |
| Local git | Dangling commits | Physical evidence |
| Vendor reports | IOC extraction | Third-party |

### Evidence Verification

```python
# All evidence is verified against original sources
store.verify_all()  # Returns verified/unverified/failed
```

---

**Tài liệu tiếp theo:** [09-APPENDICES](../09-APPENDICES/)
