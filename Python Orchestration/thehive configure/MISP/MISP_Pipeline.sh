#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASH_SCRIPT="${SCRIPT_DIR}/thehive_to_misp.sh"
PYTHON_SCRIPT="${SCRIPT_DIR}/event_publish.py"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
log_info()    { echo -e "${CYAN}[*]${NC} $*"; }
log_ok()      { echo -e "${GREEN}[+]${NC} $*"; }
log_error()   { echo -e "${RED}[-]${NC} $*"; }
log_section() {
    echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${CYAN}  $*${NC}"
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${NC}"
}
log_section "Pre-flight checks"
[[ ! -f "$BASH_SCRIPT" ]]   && log_error "Not found: thehive_to_misp.sh"  && exit 1
[[ ! -f "$PYTHON_SCRIPT" ]] && log_error "Not found: event_publish.py"    && exit 1
command -v python3 &>/dev/null || { log_error "python3 not in PATH"; exit 1; }
command -v jq      &>/dev/null || { log_error "jq not in PATH";      exit 1; }
log_ok "thehive_to_misp.sh found"
log_ok "event_publish.py found"
log_ok "python3: $(python3 --version)"
log_ok "jq: $(jq --version)"
log_section "Step 1 — Export all TheHive cases to MISP"
bash "$BASH_SCRIPT"
if [[ $? -ne 0 ]]; then
    log_error "thehive_to_misp.sh failed — aborting."
    exit 1
fi
log_ok "Step 1 complete."
log_info "Waiting 10s for MISP to index new events..."
sleep 10
log_section "Step 2 — List events (last 4h, default)"
python3 "$PYTHON_SCRIPT"
log_ok "Step 2 complete."
log_section "Step 3 — Enrich + publish all events"
echo "y" | python3 "$PYTHON_SCRIPT" --publish
if [[ $? -ne 0 ]]; then
    log_error "event_publish.py --publish failed."
    exit 1
fi
log_ok "Step 3 complete."
log_section "Pipeline finished"
log_ok "All TheHive cases synced, enriched, and published to MISP."