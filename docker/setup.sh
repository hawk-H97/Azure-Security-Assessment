#!/bin/bash
# ╔══════════════════════════════════════════════════════════════╗
# ║         🛡  AZURE AUDIT PRO  v1  —  Setup Script             ║
# ║         Developer: 🦅 Singaram                               ║
# ╚══════════════════════════════════════════════════════════════╝
#
# Works whether setup.sh is run from:
#   • project root:   ./setup.sh
#   • docker/ folder: ./docker/setup.sh
#   • moved anywhere: bash /path/to/setup.sh

set -e

CYAN='\033[96m'
GREEN='\033[92m'
YELLOW='\033[93m'
RED='\033[91m'
BOLD='\033[1m'
RESET='\033[0m'

echo ""
echo -e "${CYAN}${BOLD}  🛡  AZURE AUDIT PRO v1 — Setup${RESET}"
echo -e "${CYAN}  ═══════════════════════════════════${RESET}"
echo ""

# ── Resolve TOOL_DIR (always the project root) ────────────────────────────
# setup.sh may live at: <root>/setup.sh  OR  <root>/docker/setup.sh
# In both cases we walk up until we find main.py
_THIS_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "$_THIS_SCRIPT/main.py" ]; then
    # setup.sh is in the project root
    TOOL_DIR="$_THIS_SCRIPT"
elif [ -f "$(dirname "$_THIS_SCRIPT")/main.py" ]; then
    # setup.sh is one level deep (e.g. docker/)
    TOOL_DIR="$(dirname "$_THIS_SCRIPT")"
else
    # Fallback: use current working directory
    TOOL_DIR="$(pwd)"
fi

VENV_DIR="$TOOL_DIR/.venv"

echo -e "${CYAN}  Project root : ${YELLOW}$TOOL_DIR${RESET}"
echo -e "${CYAN}  Virtualenv   : ${YELLOW}$VENV_DIR${RESET}"
echo ""

# ── Check Python ──────────────────────────────────────────────────────────
echo -e "${CYAN}  [1/5]  Checking Python version...${RESET}"
PYTHON_CMD=""
for cmd in python3.12 python3.11 python3.10 python3.9 python3 python; do
    if command -v "$cmd" &>/dev/null; then
        VER=$("$cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        MAJOR=$(echo "$VER" | cut -d. -f1)
        MINOR=$(echo "$VER" | cut -d. -f2)
        if [ "$MAJOR" -ge 3 ] && [ "$MINOR" -ge 9 ]; then
            PYTHON_CMD="$cmd"
            echo -e "${GREEN}  ✓  Found Python $VER at $(which $cmd)${RESET}"
            break
        fi
    fi
done

if [ -z "$PYTHON_CMD" ]; then
    echo -e "${RED}  ✖  Python 3.9+ required but not found.${RESET}"
    echo -e "${YELLOW}  Install from: https://www.python.org/downloads/${RESET}"
    exit 1
fi

# ── Check pip ─────────────────────────────────────────────────────────────
echo -e "${CYAN}  [2/5]  Checking pip...${RESET}"
if ! $PYTHON_CMD -m pip --version &>/dev/null; then
    echo -e "${YELLOW}  pip not found — installing...${RESET}"
    curl -sS https://bootstrap.pypa.io/get-pip.py | $PYTHON_CMD
fi
echo -e "${GREEN}  ✓  pip ready${RESET}"

# ── Create virtual environment ────────────────────────────────────────────
echo -e "${CYAN}  [3/5]  Creating virtual environment at $VENV_DIR ...${RESET}"

if [ -d "$VENV_DIR" ]; then
    echo -e "${YELLOW}  ⚠  Virtual environment already exists — skipping creation${RESET}"
else
    $PYTHON_CMD -m venv "$VENV_DIR"
    echo -e "${GREEN}  ✓  Virtual environment created${RESET}"
fi

# Activate
source "$VENV_DIR/bin/activate"

# ── Install packages ──────────────────────────────────────────────────────
echo -e "${CYAN}  [4/5]  Installing Azure SDK packages...${RESET}"
pip install --upgrade pip --quiet

REQ_FILE="$TOOL_DIR/requirements.txt"
if [ ! -f "$REQ_FILE" ]; then
    echo -e "${RED}  ✖  requirements.txt not found at: $REQ_FILE${RESET}"
    echo -e "${YELLOW}  Make sure you are running setup.sh from inside the project folder.${RESET}"
    exit 1
fi

pip install -r "$REQ_FILE" --quiet
echo -e "${GREEN}  ✓  All packages installed${RESET}"

# ── Verify key imports ────────────────────────────────────────────────────
echo -e "${CYAN}  [5/5]  Verifying installation...${RESET}"
VERIFY_FAIL=0
verify_import() {
    local label="$1"
    local module="$2"
    if $PYTHON_CMD -c "import $module" 2>/dev/null; then
        echo -e "${GREEN}    ✓  $label${RESET}"
    else
        echo -e "${RED}    ✖  $label — import failed${RESET}"
        VERIFY_FAIL=1
    fi
}

verify_import "azure-identity"              "azure.identity"
verify_import "azure-mgmt-resource"         "azure.mgmt.resource"
verify_import "azure-mgmt-compute"          "azure.mgmt.compute"
verify_import "azure-mgmt-network"          "azure.mgmt.network"
verify_import "azure-mgmt-storage"          "azure.mgmt.storage"
verify_import "azure-mgmt-sql + six"        "azure.mgmt.sql"
verify_import "azure-mgmt-keyvault"         "azure.mgmt.keyvault"
verify_import "azure-mgmt-monitor"          "azure.mgmt.monitor"
verify_import "azure-mgmt-security"         "azure.mgmt.security"
verify_import "azure-mgmt-authorization"    "azure.mgmt.authorization"
verify_import "openpyxl"                    "openpyxl"

if [ "$VERIFY_FAIL" -eq 1 ]; then
    echo -e "${RED}  ✖  One or more packages failed — try running: pip install -r requirements.txt${RESET}"
    exit 1
fi
echo -e "${GREEN}  ✓  All packages verified${RESET}"

# ── Create output directory ───────────────────────────────────────────────
mkdir -p "$TOOL_DIR/output"
mkdir -p "$TOOL_DIR/compliance/azure"

# ── Write a convenience run.sh at the project root ───────────────────────
cat > "$TOOL_DIR/run.sh" << RUNEOF
#!/bin/bash
# 🛡  Azure Audit Pro v1 — Quick Launcher  (auto-generated by setup.sh)
TOOL_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
VENV="\$TOOL_DIR/.venv"
if [ ! -d "\$VENV" ]; then
    echo "Virtual environment not found. Run: bash setup.sh"
    exit 1
fi
source "\$VENV/bin/activate"
cd "\$TOOL_DIR"
python main.py "\$@"
RUNEOF
chmod +x "$TOOL_DIR/run.sh"

echo ""
echo -e "${GREEN}${BOLD}  ═══════════════════════════════════════════════════${RESET}"
echo -e "${GREEN}${BOLD}  🛡  Azure Audit Pro v1 — Setup Complete!${RESET}"
echo -e "${GREEN}${BOLD}  ═══════════════════════════════════════════════════${RESET}"
echo ""
echo -e "${CYAN}  To run the audit:${RESET}"
echo ""
echo -e "${YELLOW}    cd $TOOL_DIR${RESET}"
echo -e "${YELLOW}    bash run.sh${RESET}"
echo ""
echo -e "${CYAN}  Or directly:${RESET}"
echo -e "${YELLOW}    source $VENV_DIR/bin/activate${RESET}"
echo -e "${YELLOW}    python $TOOL_DIR/main.py${RESET}"
echo ""
echo -e "${CYAN}  Required Azure permissions (per subscription):${RESET}"
echo -e "    • Security Reader role${RESET}"
echo -e "    • Reader role${RESET}"
echo -e "    Or use: az login  (DefaultAzureCredential)${RESET}"
echo ""
echo -e "  ${BOLD}🦅  Developed by Singaram — Azure Audit Pro${RESET}"
echo ""
