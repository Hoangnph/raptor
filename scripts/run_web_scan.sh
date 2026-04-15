#!/usr/bin/env bash
# run_web_scan.sh - Run RAPTOR web scanner with LLM enabled
#
# Usage: bash scripts/run_web_scan.sh <target_url>
# Example: bash scripts/run_web_scan.sh http://localhost:3000
#
# This script:
# 1. Loads Qwen API key from .env
# 2. Sets OpenAI-compatible environment variables
# 3. Runs the full RAPTOR web scan with all phases

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

# Check arguments
if [ $# -lt 1 ]; then
    echo "Usage: bash scripts/run_web_scan.sh <target_url>"
    echo "Example: bash scripts/run_web_scan.sh http://localhost:3000"
    exit 1
fi

TARGET_URL="$1"

# Load .env file
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ENV_FILE="$PROJECT_DIR/.env"

if [ -f "$ENV_FILE" ]; then
    info "Loading environment from .env..."
    export $(grep -v '^#' "$ENV_FILE" | xargs)
else
    warn ".env file not found at $ENV_FILE"
fi

# Extract Qwen API key
QWEN_KEY="${qwen_api_token:-}"
if [ -z "$QWEN_KEY" ]; then
    warn "qwen_api_token not found in .env - LLM fuzzing will be disabled"
else
    info "Qwen API key loaded"
    export OPENAI_API_KEY="$QWEN_KEY"
    export OPENAI_API_BASE="https://dashscope.aliyuncs.com/compatible-mode/v1"
fi

# Add Go bin to PATH
if command -v go &>/dev/null; then
    export PATH="$(go env GOPATH)/bin:$PATH"
fi

# Run scanner
info "Starting RAPTOR web scanner..."
info "Target: $TARGET_URL"
info "LLM: ${OPENAI_API_KEY:+Enabled (Qwen via OpenAI-compatible API)}"
info "LLM: ${OPENAI_API_KEY:-Disabled}"

cd "$PROJECT_DIR/packages/web"
python3 scanner.py --url "$TARGET_URL" --max-depth 3 --max-pages 100

info "Scan complete. Check output directory for results."
