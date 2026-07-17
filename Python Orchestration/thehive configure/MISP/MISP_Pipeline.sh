#!/bin/bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASH_SCRIPT="${SCRIPT_DIR}/thehive_to_misp.sh"
PYTHON_SCRIPT="${SCRIPT_DIR}/event_publish.py"
LOG_DIR="${SCRIPT_DIR}/logs"
LOG_FILE="${LOG_DIR}/misp_pipeline_$(date +%Y%m%d_%H%M%S).log"
LOCK_FILE="${SCRIPT_DIR}/.pipeline.lock"

mkdir -p "$LOG_DIR"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log_ok()    { echo -e "${GREEN}[+]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
log_error() { echo -e "${RED}[-]${NC} $*"; }
exec 200>"$LOCK_FILE"
if ! flock -n 200; then
    log_error "Another pipeline run is already in progress (lock: $LOCK_FILE). Exiting."
    exit 1
fi
[[ ! -f "$BASH_SCRIPT" ]]   && log_error "Not found: thehive_to_misp.sh" && exit 1
[[ ! -f "$PYTHON_SCRIPT" ]] && log_error "Not found: event_publish.py"   && exit 1
command -v python3 &>/dev/null || { log_error "python3 not in PATH"; exit 1; }
command -v jq      &>/dev/null || { log_error "jq not in PATH";      exit 1; }
{
    echo "=== MISP Pipeline run: $(date -u '+%Y-%m-%d %H:%M:%S UTC') ==="
    echo ""
    STEP1_STATUS=0
    echo "--- Step 1: Export TheHive cases to MISP ---"
    bash "$BASH_SCRIPT"
    STEP1_STATUS=$?
    if [[ $STEP1_STATUS -ne 0 ]]; then
        echo "[!] Step 1 exited non-zero ($STEP1_STATUS) — continuing to Steps 2/3 anyway."
    fi
    echo ""
    STEP2_STATUS=0
    echo "--- Step 2: List events (last 4h) ---"
    python3 "$PYTHON_SCRIPT"
    STEP2_STATUS=$?
    echo ""
    STEP3_STATUS=0
    echo "--- Step 3: Enrich + publish all events ---"
    echo "y" | python3 "$PYTHON_SCRIPT" --publish
    STEP3_STATUS=$?
    echo ""
    echo "=== Pipeline finished: $(date -u '+%Y-%m-%d %H:%M:%S UTC') ==="
    echo "=== Step exit codes — step1=$STEP1_STATUS step2=$STEP2_STATUS step3=$STEP3_STATUS ==="
} > "$LOG_FILE" 2>&1
STEP1_STATUS=$(grep -oP 'step1=\K[0-9]+' "$LOG_FILE" | tail -1 || echo "1")
STEP2_STATUS=$(grep -oP 'step2=\K[0-9]+' "$LOG_FILE" | tail -1 || echo "1")
STEP3_STATUS=$(grep -oP 'step3=\K[0-9]+' "$LOG_FILE" | tail -1 || echo "1")
CASES_FOUND=$(grep -oP 'Found \K[0-9]+(?= cases to sync)' "$LOG_FILE" | tail -1 || echo "0")
NEW_EVENTS=$(grep -c '\[+\] Success! MISP Event Created' "$LOG_FILE" || echo "0")
PUBLISHED=$(grep -oP 'Result: \K[0-9]+(?= published)' "$LOG_FILE" | tail -1 || echo "0")
FAILED=$(grep -oP 'published ✓\s+\K[0-9]+(?= failed)' "$LOG_FILE" | tail -1 || echo "0")
if [[ "$STEP2_STATUS" -eq 0 && "$STEP3_STATUS" -eq 0 ]]; then
    if [[ "$STEP1_STATUS" -ne 0 ]]; then
        log_warn "Step 1 had an issue (see log) but pipeline continued."
    fi
    log_ok "Export done — ${CASES_FOUND} case(s) checked, ${NEW_EVENTS} new event(s) created, ${PUBLISHED} published, ${FAILED} failed."
    echo -e "${CYAN}    Full log: ${LOG_FILE}${NC}"
    exit 0
else
    log_error "Pipeline failed — step1=$STEP1_STATUS step2=$STEP2_STATUS step3=$STEP3_STATUS — see ${LOG_FILE} for details."
    exit 1
fi
