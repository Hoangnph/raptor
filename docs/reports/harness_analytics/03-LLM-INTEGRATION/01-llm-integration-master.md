# LLM Integration - Tích Hợp LLM Toàn Diện

**Phân Tích Từ Source Code Thực Tế**

---

## Mục Lục

1. [Kiến Trúc LLM System](#kiến-trúc-llm-system)
2. [Detection System](#detection-system)
3. [Configuration](#configuration)
4. [Client với Automatic Fallback](#client-với-automatic-fallback)
5. [Provider Implementations](#provider-implementations)
6. [Cost Management](#cost-management)
7. [Structured Output](#structured-output)
8. [Error Handling](#error-handling)
9. [API Reference](#api-reference)
10. [Best Practices](#best-practices)

---

## Kiến Trúc LLM System

LLM system trong RAPTOR gồm **4 modules chính**:

```
packages/llm_analysis/llm/
├── detection.py      # Single source of truth cho availability
├── config.py         # ModelConfig, LLMConfig, model selection
├── model_data.py     # Static data: costs, limits, endpoints
└── providers.py      # Provider implementations + Instructor
```

### Luồng Dữ Liệu

```
detect_llm_availability()
  │
  ├─ 1. Check litellm (block malicious versions 1.82.7/1.82.8)
  ├─ 2. Check cloud API keys (gated on SDK availability)
  ├─ 3. Check config file (~/.config/raptor/models.json)
  ├─ 4. Check Ollama reachability (HTTP call to /api/tags)
  ├─ 5. Check Claude Code (CLAUDECODE env var or 'claude' on PATH)
  └─ 6. Cache result (per-process)
       │
       v
LLMClient.generate(prompt)
  │
  ├─ 1. Check budget
  ├─ 2. Select model for task
  ├─ 3. Check cache
  ├─ 4. Try models in order (same tier only)
  │    ├─ OpenAICompatibleProvider (OpenAI, Ollama, Mistral, Gemini shim)
  │    ├─ AnthropicProvider (Claude native SDK)
  │    └─ GeminiProvider (Google native SDK)
  ├─ 5. Track cost (thread-safe)
  └─ 6. Save to cache
```

---

## Detection System

**File:** `detection.py`

**Mục Đích:** Single source of truth cho "LLM nào khả dụng?"

### LLMAvailability Dataclass

```python
@dataclass
class LLMAvailability:
    external_llm: bool   # SDK + API key reachable
    claude_code: bool    # Running inside CC or 'claude' on PATH
    llm_available: bool  # external_llm or claude_code
```

### Detection Logic (từ source code thực tế)

```python
def detect_llm_availability() -> LLMAvailability:
    # 1. Check litellm - BLOCK malicious versions
    litellm_found = _check_litellm_installed()
    if litellm_found and version in ("1.82.7", "1.82.8"):
        # Dừng ngay lập tức - litellm chứa malicious code
        raise SystemExit("RAPTOR cannot run with litellm {version} installed")

    # 2. Check cloud API keys (gated on SDK)
    has_anthropic = bool(os.getenv("ANTHROPIC_API_KEY")) and (
        ANTHROPIC_SDK_AVAILABLE or OPENAI_SDK_AVAILABLE
    )
    has_openai = bool(os.getenv("OPENAI_API_KEY")) and OPENAI_SDK_AVAILABLE
    has_gemini = bool(os.getenv("GEMINI_API_KEY")) and (
        GENAI_SDK_AVAILABLE or OPENAI_SDK_AVAILABLE
    )
    has_mistral = bool(os.getenv("MISTRAL_API_KEY")) and OPENAI_SDK_AVAILABLE

    # 3. Check config file for models with valid keys
    has_config_file = _config_has_keyed_models()

    # 4. Check Ollama (requires OpenAI SDK)
    has_ollama = OPENAI_SDK_AVAILABLE and bool(_get_available_ollama_models())

    # 5. Check Claude Code
    in_claude_code = bool(os.getenv("CLAUDECODE"))
    claude_on_path = shutil.which("claude") is not None
    claude_code = in_claude_code or claude_on_path

    external_llm = has_cloud_keys or has_config_file or has_ollama

    return LLMAvailability(
        external_llm=external_llm,
        claude_code=claude_code,
        llm_available=external_llm or claude_code,
    )
```

### LiteLLM Security Check

```python
# Source: detection.py
if installed in ("1.82.7", "1.82.8"):
    msg = (
        f"  ⚠️  WARNING: litellm=={installed} is installed and contains malicious code.\n"
        f"  It exfiltrates API keys, SSH keys, and cloud credentials.\n"
        f"  RAPTOR no longer uses litellm, but the package can still harm your system.\n"
    )
    if installed == "1.82.8":
        msg += (
            f"  Version 1.82.8 runs on ANY Python startup via a .pth file.\n"
            f"  Do NOT use pip to remove it — pip invokes Python, triggering the payload.\n"
            f"\n"
            f"  Safe removal (no Python invoked):\n"
            f"    find / -path '*/litellm*' -name '*.pth' -delete 2>/dev/null\n"
            f"    find / -path '*/site-packages/litellm*' -exec rm -rf {{}} + 2>/dev/null\n"
        )
    raise SystemExit(...)
```

### SDK Availability

Từ source code thực tế:

```python
# detection.py - canonical source
try:
    import openai
    OPENAI_SDK_AVAILABLE = True
except ImportError:
    OPENAI_SDK_AVAILABLE = False

try:
    import anthropic
    ANTHROPIC_SDK_AVAILABLE = True
except ImportError:
    ANTHROPIC_SDK_AVAILABLE = False

try:
    from google import genai
    GENAI_SDK_AVAILABLE = True
except ImportError:
    GENAI_SDK_AVAILABLE = False
```

### Ollama Model Detection

```python
def _get_available_ollama_models() -> List[str]:
    """Cached per-process to avoid repeated HTTP checks"""
    global _cached_ollama_models, _ollama_checked
    if _ollama_checked:
        return _cached_ollama_models or []

    _ollama_checked = True
    try:
        ollama_url = _validate_ollama_url(RaptorConfig.OLLAMA_HOST)
        response = requests.get(f"{ollama_url}/api/tags", timeout=2)
        if response.status_code == 200:
            data = response.json()
            _cached_ollama_models = [model['name'] for model in data.get('models', [])]
            return _cached_ollama_models
    except Exception:
        pass
    _cached_ollama_models = []
    return []
```

---

## Configuration

**File:** `config.py`

### ModelConfig Dataclass

```python
@dataclass
class ModelConfig:
    provider: str              # "anthropic", "openai", "mistral", "ollama", "gemini"
    model_name: str            # "claude-opus-4-6", "gpt-5.4", etc.
    api_key: Optional[str] = None
    api_base: Optional[str] = None    # For non-Anthropic providers
    max_tokens: int = 4096
    max_context: int = 32000
    temperature: float = 0.7
    timeout: int = 120
    cost_per_1k_tokens: float = 0.0  # Fallback rate
    enabled: bool = True
    role: Optional[str] = None       # "analysis", "code", "consensus", "fallback"
```

### LLMConfig

```python
@dataclass
class LLMConfig:
    primary_model: Optional[ModelConfig]    # Auto-selected từ config file
    fallback_models: List[ModelConfig]      # Auto-populated
    specialized_models: Dict[str, ModelConfig]  # Task-specific
    enable_fallback: bool = True
    max_retries: int = 3
    retry_delay: float = 2.0
    retry_delay_remote: float = 5.0
    enable_caching: bool = True
    cache_dir: Path = Path("out/llm_cache")
    enable_cost_tracking: bool = True
    max_cost_per_scan: float = 10.0  # USD
```

### Config File Format

**Path:** `~/.config/raptor/models.json`

```json
{
  "models": [
    {
      "provider": "anthropic",
      "model": "claude-opus-4-6",
      "api_key": "sk-ant-...",
      "role": "analysis"
    },
    {
      "provider": "openai",
      "model": "gpt-5.4",
      "api_key": "sk-...",
      "role": "code"
    },
    {
      "provider": "ollama",
      "model": "llama3:70b",
      "role": "fallback"
    }
  ]
}
```

**Hỗ trợ comments** (dùng `//`):
```json
{
  "models": [
    // Primary analysis model
    {"provider": "anthropic", "model": "claude-opus-4-6"}
  ]
}
```

### Model Selection Logic

Từ source code thực tế (`_get_best_thinking_model()`):

```python
# Priority ranking for thinking models
thinking_model_patterns = [
    # Tier 1: Most capable
    ("anthropic", "claude-opus-4-6", 110),
    ("openai", "gpt-5.4-pro", 100),
    ("openai", "o3", 90),

    # Tier 2: Strong
    ("openai", "gpt-5.2", 80),
    ("openai", "o4-mini", 78),
    ("mistral", "mistral-large-latest", 75),

    # Tier 3: Fallback
    ("anthropic", "claude-sonnet-4-6", 70),
    ("gemini", "gemini-2.5-pro", 65),
]
```

---

## Client với Automatic Fallback

**File:** `client.py`

### LLMClient Class

```python
class LLMClient:
    def __init__(self, config: Optional[LLMConfig] = None):
        self.config = config or LLMConfig()
        self.providers: Dict[str, LLMProvider] = {}
        self.total_cost = 0.0
        self.request_count = 0
        self.task_type_costs: Dict[str, float] = {}
        self._stats_lock = threading.RLock()
```

### Generate với Fallback

Từ source code thực tế:

```python
def generate(self, prompt: str, system_prompt: Optional[str] = None,
             task_type: Optional[str] = None, **kwargs) -> LLMResponse:
    # 1. Check budget
    if not self._check_budget():
        raise RuntimeError(f"LLM budget exceeded: ${self.total_cost:.4f} spent")

    # 2. Get model for task
    model_config = kwargs.pop('model_config', None)
    if not model_config:
        if task_type:
            model_config = self.config.get_model_for_task(task_type)
        else:
            model_config = self.config.primary_model

    # 3. Check cache
    cache_key = self._get_cache_key(prompt, system_prompt, model_config.model_name)
    cached_content = self._get_cached_response(cache_key)
    if cached_content:
        return LLMResponse(content=cached_content, cost=0.0, tokens_used=0, ...)

    # 4. Try models (SAME TIER ONLY: local→local, cloud→cloud)
    models_to_try = [model_config]
    if self.config.enable_fallback:
        is_local_primary = model_config.provider.lower() == "ollama"
        for fallback in self.config.fallback_models:
            is_local_fallback = fallback.provider.lower() == "ollama"
            if is_local_primary == is_local_fallback:
                models_to_try.append(fallback)

    # 5. Retry với exponential backoff
    for model in models_to_try:
        for attempt in range(self.config.max_retries):
            try:
                provider = self._get_provider(model)
                response = provider.generate(prompt, system_prompt, **kwargs)

                # Track cost (thread-safe)
                with self._stats_lock:
                    self.total_cost += response.cost
                    self.request_count += 1

                # Cache response
                self._save_to_cache(cache_key, response)

                return response

            except Exception as e:
                if not _is_retryable_error(e):
                    break  # Skip retries for non-retryable errors

                delay = min(self.config.retry_delay * (2 ** attempt), 30)
                time.sleep(delay)
```

### Tier Restriction

Quan trọng: **Không mix local và cloud** trong fallback:

```python
# Source: client.py
# Skip if different tier (don't mix local and cloud)
is_local_primary = model_config.provider.lower() == "ollama"
is_local_fallback = fallback.provider.lower() == "ollama"
if is_local_primary == is_local_fallback:
    models_to_try.append(fallback)
```

---

## Provider Implementations

**File:** `providers.py`

### 1. OpenAICompatibleProvider

Dùng cho: **OpenAI, Ollama, Mistral, Gemini (shim)**

```python
class OpenAICompatibleProvider(LLMProvider):
    def __init__(self, config: ModelConfig):
        self.client = OpenAI(
            api_key=config.api_key or "unused",
            base_url=config.api_base,
            timeout=config.timeout,
        )

        # Instructor for structured output
        if INSTRUCTOR_AVAILABLE:
            self.instructor_client = instructor.from_openai(self.client)
        else:
            # JSON-in-prompt fallback
            self.instructor_client = None
```

**Generate Implementation:**
```python
def generate(self, prompt, system_prompt=None, **kwargs):
    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})

    response = self.client.chat.completions.create(
        model=self.config.model_name,
        messages=messages,
        temperature=kwargs.get("temperature", self.config.temperature),
        max_tokens=kwargs.get("max_tokens", self.config.max_tokens),
    )

    # Extract thinking tokens (o3, o4-mini, qwen3, etc.)
    details = getattr(response.usage, 'completion_tokens_details', None)
    if details:
        thinking_tokens = getattr(details, 'reasoning_tokens', 0)
    else:
        thinking_tokens = 0

    # Cost: thinking tokens billed as output
    cost = self._calculate_cost_split(input_tokens, output_tokens, thinking_tokens)

    return LLMResponse(
        content=message.content,
        tokens_used=input_tokens + output_tokens + thinking_tokens,
        cost=cost,
        thinking_tokens=thinking_tokens,
        ...
    )
```

### 2. AnthropicProvider

Dùng cho: **Claude models (native SDK)**

```python
class AnthropicProvider(LLMProvider):
    def __init__(self, config: ModelConfig):
        self.client = anthropic.Anthropic(
            api_key=config.api_key,
            timeout=config.timeout,
        )

        if INSTRUCTOR_AVAILABLE:
            self.instructor_client = instructor.from_anthropic(self.client)
```

**Generate Implementation:**
```python
def generate(self, prompt, system_prompt=None, **kwargs):
    messages = [{"role": "user", "content": prompt}]

    create_kwargs = {
        "model": self.config.model_name,
        "messages": messages,
        "temperature": kwargs.get("temperature", self.config.temperature),
        "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
    }
    if system_prompt:
        create_kwargs["system"] = system_prompt  # Anthropic uses 'system' parameter

    response = self.client.messages.create(**create_kwargs)

    # Extract usage
    input_tokens = response.usage.input_tokens
    output_tokens = response.usage.output_tokens
    thinking_tokens = getattr(response.usage, 'cache_creation_input_tokens', 0)

    cost = self._calculate_cost_split(input_tokens, output_tokens, thinking_tokens)

    return LLMResponse(
        content=response.content[0].text,
        tokens_used=input_tokens + output_tokens,
        cost=cost,
        ...
    )
```

### 3. GeminiProvider

Dùng cho: **Google Gemini/Gemma (native genai SDK)**

```python
class GeminiProvider(LLMProvider):
    def __init__(self, config: ModelConfig):
        self.client = genai.Client(
            api_key=config.api_key,
        )
```

**Structured Output:**
```python
def generate_structured(self, prompt, schema, system_prompt=None):
    # Convert JSON Schema to Gemini format
    gemini_schema = _schema_to_gemini(schema)

    # Gemini doesn't support union types ["string", "null"]
    # Uses single type + nullable flag
    response = self.client.models.generate_content(
        model=self.config.model_name,
        contents=prompt,
        config={
            "response_mime_type": "application/json",
            "response_schema": gemini_schema,
        }
    )
```

---

## Cost Management

### Cost Calculation

Từ source code thực tế:

```python
def _calculate_cost_split(self, input_tokens, output_tokens, thinking_tokens=0):
    """Thinking tokens billed as output on ALL providers"""
    rates = MODEL_COSTS.get(self.config.model_name)
    if not rates:
        rate = self.config.cost_per_1k_tokens
        return ((input_tokens + output_tokens + thinking_tokens) / 1000) * rate

    return (
        (input_tokens / 1000) * rates["input"]
        + ((output_tokens + thinking_tokens) / 1000) * rates["output"]
    )
```

### Model Costs (từ model_data.py)

| Model | Input ($/1K) | Output ($/1K) | Max Context |
|-------|-------------|---------------|-------------|
| claude-opus-4-6 | 0.005 | 0.025 | 1M |
| claude-sonnet-4-6 | 0.003 | 0.015 | 1M |
| gpt-5.4 | 0.0025 | 0.015 | 1M |
| gpt-5.4-pro | 0.030 | 0.180 | 1M |
| gpt-5.2 | 0.00175 | 0.014 | 400K |
| o3 | 0.002 | 0.008 | 200K |
| o4-mini | 0.0011 | 0.0044 | 200K |
| gemini-2.5-pro | 0.00125 | 0.010 | 1M |
| gemma-4-31b-it | **0** | **0** | 256K |
| mistral-large-latest | 0.0005 | 0.0015 | 256K |

### Budget Check

```python
def _check_budget(self, estimated_cost=0.1):
    if not self.config.enable_cost_tracking:
        return True

    with self._stats_lock:
        if self.total_cost + estimated_cost > self.config.max_cost_per_scan:
            logger.error(
                f"Budget exceeded: ${self.total_cost:.2f} + "
                f"${estimated_cost:.2f} > ${self.config.max_cost_per_scan:.2f}"
            )
            return False
    return True
```

---

## Structured Output

### Instructor Integration

```python
def generate_structured(self, prompt, schema, system_prompt=None):
    pydantic_model = _dict_schema_to_pydantic(schema)

    # Try Instructor first
    if self.instructor_client is not None:
        try:
            result, completion = self.instructor_client.chat.completions.create_with_completion(
                model=self.config.model_name,
                response_model=pydantic_model,
                messages=messages,
            )
            return result.model_dump(), json.dumps(result)
        except Exception:
            # Disable Instructor, use JSON fallback
            self.instructor_client = None

    # Fallback: JSON-in-prompt
    return self._structured_fallback(prompt, schema, pydantic_model, system_prompt)
```

### Schema Coercion

```python
def _coerce_to_schema(data, schema):
    """Fix common LLM type mismatches before Pydantic validation"""
    properties = schema.get("properties", {})
    coerced = dict(data)

    for field_name, field_spec in properties.items():
        value = coerced[field_name]
        field_type = field_spec.get("type", "string")

        # "true" → True, "0.85" → 0.85, null → ""
        if field_type == "boolean" and not isinstance(value, bool):
            coerced[field_name] = value.lower() in ("true", "yes", "1")
        elif field_type == "number" and not isinstance(value, (int, float)):
            coerced[field_name] = float(value)
        elif field_type == "string" and value is None:
            coerced[field_name] = ""

    return coerced
```

---

## Error Handling

### Error Classification

Từ source code thực tế:

```python
def _is_auth_error(error):
    """Detect authentication errors"""
    if _OPENAI_AVAILABLE:
        if isinstance(error, openai.AuthenticationError):
            return True
    if _ANTHROPIC_AVAILABLE:
        if isinstance(error, anthropic.AuthenticationError):
            return True

    # String fallback
    error_str = str(error).lower()
    return any(indicator in error_str for indicator in [
        "401", "403", "authentication", "unauthorized",
        "invalid api key", "incorrect api key"
    ])

def _is_quota_error(error):
    """Detect rate limit/quota errors"""
    if _OPENAI_AVAILABLE:
        if isinstance(error, openai.RateLimitError):
            return True
    if _ANTHROPIC_AVAILABLE:
        if isinstance(error, anthropic.RateLimitError):
            return True

    error_str = str(error).lower()
    return any([
        "429" in error_str,
        "quota exceeded" in error_str,
        "rate limit" in error_str,
        "generate_content_free_tier" in error_str,  # Gemini
    ])

def _is_retryable_error(error):
    """Check if error is transient"""
    if _is_quota_error(error):
        return True  # Rate limits are retryable (with backoff)

    error_type = type(error).__name__
    retryable_types = ("Timeout", "ConnectionError", "APIConnectionError",
                       "InternalServerError", "ServiceUnavailableError")
    if any(t in error_type for t in retryable_types):
        return True

    # Non-retryable: schema validation, auth errors, bad request
    return False
```

### Quota Guidance

```python
def _get_quota_guidance(model_name, provider):
    if provider in ("gemini", "google"):
        return "\n→ Google Gemini quota/rate limit exceeded"
    elif provider == "openai":
        return "\n→ OpenAI rate limit exceeded"
    elif provider == "anthropic":
        return "\n→ Anthropic rate limit exceeded"
    elif provider == "ollama":
        return "\n→ Ollama server limit exceeded"
```

---

## API Reference

### Public Functions

| Function | File | Description |
|----------|------|-------------|
| `detect_llm_availability()` | detection.py | Single source of truth |
| `generate(prompt, ...)` | client.py | Generate với fallback |
| `generate_structured(prompt, schema, ...)` | client.py | Structured JSON output |
| `_get_best_thinking_model()` | config.py | Auto-select best model |

### Dataclasses

| Class | File | Purpose |
|-------|------|---------|
| `LLMAvailability` | detection.py | Availability flags |
| `ModelConfig` | config.py | Per-model config |
| `LLMConfig` | config.py | Global LLM config |
| `LLMResponse` | providers.py | Standard response |
| `StructuredResponse` | providers.py | Structured output |

---

## Best Practices

### 1. Luôn Dùng detect_llm_availability()

```python
# ✅ ĐÚNG
from packages.llm_analysis import detect_llm_availability
env = detect_llm_availability()
if not env.llm_available:
    print("No LLM available")

# ❌ SAI
if os.getenv("ANTHROPIC_API_KEY"):  # Ad-hoc check
```

### 2. Configure qua Config File

```bash
# Tạo config
mkdir -p ~/.config/raptor
cat > ~/.config/raptor/models.json << 'EOF'
{
  "models": [
    {"provider": "anthropic", "model": "claude-sonnet-4-6"},
    {"provider": "openai", "model": "gpt-5.2", "role": "fallback"}
  ]
}
EOF
chmod 600 ~/.config/raptor/models.json
```

### 3. Budget Enforcement

```python
from packages.llm_analysis.llm.config import LLMConfig

config = LLMConfig(max_cost_per_scan=1.0)  # $1 limit
client = LLMClient(config)
```

### 4. Task-Specific Models

```python
config = LLMConfig(
    specialized_models={
        "analysis": ModelConfig(provider="anthropic", model_name="claude-opus-4-6"),
        "code": ModelConfig(provider="openai", model_name="gpt-5.4"),
    }
)
```

---

**Tài liệu tiếp theo:** [04-CLAUDE-CODE-INTEGRATION](../04-CLAUDE-CODE-INTEGRATION/) - Commands, Agents, Skills
