#!/usr/bin/env bash
# install-tools.sh — Install all external security tools for RAPTOR
# Idempotent: safe to run multiple times; skips already-installed tools.
#
# Tools installed:
#   - subfinder (Go)
#   - httpx     (Go)
#   - katana    (Go)
#   - nuclei    (Go)
#   - OWASP ZAP (via pip: zap-cli or system package)
#
# Usage: bash scripts/install-tools.sh

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

# ---------------------------------------------------------------------------
# Helper: check if a command exists
# ---------------------------------------------------------------------------
command_exists() {
    command -v "$1" &>/dev/null
}

# ---------------------------------------------------------------------------
# Go (required for subfinder, httpx, katana, nuclei)
# ---------------------------------------------------------------------------
install_go() {
    if command_exists go; then
        info "Go already installed: $(go version)"
        return 0
    fi

    info "Installing Go..."
    local GO_VERSION="1.23.4"
    local OS_ARCH="linux-amd64"

    if [[ "$(uname -s)" == "Darwin" ]]; then
        OS_ARCH="darwin-amd64"
        if [[ "$(uname -m)" == "arm64" ]]; then
            OS_ARCH="darwin-arm64"
        fi
    fi

    local GO_URL="https://go.dev/dl/go${GO_VERSION}.${OS_ARCH}.tar.gz"
    local TMPDIR_GO
    TMPDIR_GO=$(mktemp -d)

    if curl -fsSL "$GO_URL" -o "${TMPDIR_GO}/go.tar.gz"; then
        sudo tar -C /usr/local -xzf "${TMPDIR_GO}/go.tar.gz"
        rm -rf "$TMPDIR_GO"
        export PATH="/usr/local/go/bin:$PATH"
        info "Go installed: $(go version)"
    else
        error "Failed to download Go. Install manually from https://go.dev/dl/"
        rm -rf "$TMPDIR_GO"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Go-based tools: subfinder, httpx, katana, nuclei
# ---------------------------------------------------------------------------
install_go_tool() {
    local tool_name="$1"
    local go_path="$2"

    if command_exists "$tool_name"; then
        info "$tool_name already installed: $($tool_name -version 2>/dev/null || echo 'version unknown')"
        return 0
    fi

    info "Installing $tool_name from $go_path..."
    if go install -v "$go_path"@latest; then
        if command_exists "$tool_name"; then
            info "$tool_name installed successfully"
        else
            warn "$tool_name installed but not in PATH. Add \$(go env GOPATH)/bin to your PATH."
        fi
    else
        error "Failed to install $tool_name"
        return 1
    fi
}

install_go_tools() {
    # Ensure Go bin is in PATH
    local GOBIN
    GOBIN="$(go env GOPATH)/bin"
    if [[ ":$PATH:" != *":$GOBIN:"* ]]; then
        export PATH="$GOBIN:$PATH"
    fi

    install_go_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
    install_go_tool "httpx"      "github.com/projectdiscovery/httpx/cmd/httpx"
    install_go_tool "katana"     "github.com/projectdiscovery/katana/cmd/katana"
    install_go_tool "nuclei"     "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"

    # Update nuclei templates if nuclei is available
    if command_exists nuclei; then
        info "Updating nuclei templates..."
        nuclei -update-templates 2>/dev/null || warn "Could not update nuclei templates"
    fi
}

# ---------------------------------------------------------------------------
# OWASP ZAP
# ---------------------------------------------------------------------------
install_zap() {
    # Check for ZAP in multiple ways
    if command_exists zap.sh || command_exists zaproxy || command_exists zap; then
        info "OWASP ZAP already installed"
        return 0
    fi

    info "Installing OWASP ZAP..."

    local OS_NAME
    OS_NAME="$(uname -s)"

    if [[ "$OS_NAME" == "Linux" ]]; then
        # Try apt first (Debian/Ubuntu)
        if command_exists apt-get; then
            if sudo apt-get install -y zaproxy 2>/dev/null; then
                info "OWASP ZAP installed via apt"
                return 0
            fi
        fi

        # Fallback: download from GitHub releases
        local ZAP_VERSION="2.15.0"
        local ZAP_URL="https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz"
        local ZAP_DIR="/opt/zap"

        warn "Installing ZAP from GitHub releases..."
        if sudo mkdir -p "$ZAP_DIR" && curl -fsSL "$ZAP_URL" -o /tmp/zap.tar.gz; then
            sudo tar -xzf /tmp/zap.tar.gz -C "$ZAP_DIR" --strip-components=1
            rm -f /tmp/zap.tar.gz
            if command_exists zap.sh || [[ -f "$ZAP_DIR/zap.sh" ]]; then
                info "OWASP ZAP installed to $ZAP_DIR"
                info "Add $ZAP_DIR to your PATH to use zap.sh"
            else
                error "ZAP installation may have failed. Check $ZAP_DIR"
            fi
        else
            error "Failed to download ZAP. Install manually from https://www.zaproxy.org/download/"
        fi

    elif [[ "$OS_NAME" == "Darwin" ]]; then
        # macOS: use Homebrew if available
        if command_exists brew; then
            info "Installing ZAP via Homebrew..."
            brew install --cask zaproxy 2>/dev/null || warn "Failed to install ZAP via Homebrew"
        else
            warn "Homebrew not found. Install ZAP manually from https://www.zaproxy.org/download/"
        fi
    else
        warn "Unsupported OS: $OS_NAME. Install ZAP manually from https://www.zaproxy.org/download/"
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    info "========================================="
    info "RAPTOR Security Tools Installer"
    info "========================================="
    echo ""

    info "Step 1/3: Checking/installing Go..."
    install_go
    echo ""

    info "Step 2/3: Checking/installing Go-based tools..."
    install_go_tools
    echo ""

    info "Step 3/3: Checking/installing OWASP ZAP..."
    install_zap
    echo ""

    info "========================================="
    info "Installation complete!"
    info "========================================="
    echo ""

    # Verify all tools
    info "Verifying installations:"
    local all_ok=true
    for tool in go subfinder httpx katana nuclei; do
        if command_exists "$tool"; then
            info "  [OK] $tool"
        else
            warn "  [MISSING] $tool"
            all_ok=false
        fi
    done

    if command_exists zap.sh || command_exists zaproxy || command_exists zap; then
        info "  [OK] OWASP ZAP"
    else
        warn "  [MISSING] OWASP ZAP"
        all_ok=false
    fi

    echo ""
    if $all_ok; then
        info "All tools installed successfully!"
    else
        warn "Some tools are missing. Check the output above for details."
        warn "Ensure $(go env GOPATH)/bin is in your PATH."
    fi
}

main "$@"
