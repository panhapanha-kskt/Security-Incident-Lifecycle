#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# attack_simulator_minimal.sh — Wazuh SOC Attack Simulation Suite (Minimal)
# Target: Kali Agent (Agent-Kali / ID 006)
# Enhanced: Shows real-time AR feedback from agent iptables + AR log
# ═══════════════════════════════════════════════════════════════════════════════
set -uo pipefail  # REMOVED -e to prevent silent exits

# ── Colour palette ────────────────────────────────────────────────────────────
RED="\033[38;5;196m"; ORANGE="\033[38;5;208m"; YELLOW="\033[38;5;226m"
GREEN="\033[38;5;47m"; CYAN="\033[38;5;51m"; GRAY="\033[38;5;244m"
TEAL="\033[38;5;86m"; BOLD="\033[1m"; RESET="\033[0m"

# ── Config ────────────────────────────────────────────────────────────────────
DELAY=5
LOG_FILE="/tmp/wazuh_sim_$(date +%Y%m%d_%H%M%S).log"
FAKE_SSHD_LOG="/var/log/auth.log"
AR_LOG="/var/ossec/logs/active-responses.log"
ATTACKER_IP="10.10.10.99"

# ── Helpers ───────────────────────────────────────────────────────────────────
ts()   { date '+%Y-%m-%d %H:%M:%S'; }
log()  { echo "$(ts) $*" | tee -a "$LOG_FILE"; }
ok()   { echo -e "  ${GREEN}[✔]${RESET} $*"; log "OK: $*"; }
info() { echo -e "  ${CYAN}[→]${RESET} $*"; log "INFO: $*"; }
warn() { echo -e "  ${YELLOW}[!]${RESET} $*"; log "WARN: $*"; }
err()  { echo -e "  ${RED}[✘]${RESET} $*"; log "ERR: $*"; }

banner() {
    local sev="$1" msg="$2"
    local color="$CYAN"
    [[ "$sev" == "CRITICAL" ]] && color="$RED"
    [[ "$sev" == "HIGH"     ]] && color="$ORANGE"
    [[ "$sev" == "MEDIUM"   ]] && color="$YELLOW"
    echo ""
    echo -e "${color}${BOLD}┌─────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${color}${BOLD}│  [$sev]  $msg${RESET}"
    echo -e "${color}${BOLD}└─────────────────────────────────────────────────────────────┘${RESET}"
}

inject_syslog() {
    local line="$1"
    [[ ! -f "$FAKE_SSHD_LOG" ]] && touch "$FAKE_SSHD_LOG"
    echo "$(date '+%b %d %H:%M:%S') $(hostname) $line" >> "$FAKE_SSHD_LOG"
}

require_root() {
    [[ $EUID -ne 0 ]] && { echo -e "${RED}[FATAL]${RESET} Run as root."; exit 1; }
}

# ── Active Response watcher ───────────────────────────────────────────────────
# Polls iptables + AR log for up to $timeout seconds, prints what it finds
watch_ar() {
    local label="$1"
    local target_ip="${2:-}"
    local timeout="${3:-30}"
    local found_iptables=0
    local found_ar_log=0
    local ar_log_mark
    ar_log_mark=$(wc -l < "$AR_LOG" 2>/dev/null || echo 0)

    echo ""
    echo -e "  ${TEAL}${BOLD}── Watching for Active Response (up to ${timeout}s) ──${RESET}"

    for i in $(seq 1 "$timeout"); do
        sleep 1
        printf "\r  ${GRAY}[%2ds]${RESET} Waiting for AR…" "$i"

        # Check iptables for IP block
        if [[ -n "$target_ip" && $found_iptables -eq 0 ]]; then
            if iptables -L INPUT -n 2>/dev/null | grep -q "$target_ip"; then
                echo ""
                echo -e "  ${GREEN}${BOLD}[AR CONFIRMED]${RESET} iptables DROP rule appeared:"
                iptables -L INPUT -n | grep "$target_ip" | while read -r line; do
                    echo -e "    ${GREEN}$line${RESET}"
                done
                found_iptables=1
                log "AR-CONFIRMED: iptables DROP $target_ip appeared at ${i}s"
            fi
        fi

        # Check AR log for new entries
        if [[ $found_ar_log -eq 0 ]]; then
            local current_lines
            current_lines=$(wc -l < "$AR_LOG" 2>/dev/null || echo 0)
            if [[ "$current_lines" -gt "$ar_log_mark" ]]; then
                echo ""
                echo -e "  ${TEAL}${BOLD}[AR LOG]${RESET} New active-response entries:"
                tail -n +"$((ar_log_mark + 1))" "$AR_LOG" 2>/dev/null | while read -r line; do
                    echo -e "    ${TEAL}$line${RESET}"
                done
                found_ar_log=1
                log "AR-LOG: new entries at ${i}s"
            fi
        fi

        [[ $found_iptables -eq 1 && $found_ar_log -eq 1 ]] && break
    done

    echo ""
    if [[ $found_iptables -eq 0 && -n "$target_ip" ]]; then
        warn "No iptables DROP for $target_ip after ${timeout}s — check interceptor on manager"
    fi
    if [[ $found_ar_log -eq 0 ]]; then
        warn "No AR log entries after ${timeout}s — AR may not have fired yet"
    fi
}

# ── FIM watcher ───────────────────────────────────────────────────────────────
watch_fim_ar() {
    local file_path="$1"
    local timeout="${2:-45}"
    local found=0

    echo ""
    echo -e "  ${TEAL}${BOLD}── Watching for FIM Active Response on $file_path (up to ${timeout}s) ──${RESET}"

    for i in $(seq 1 "$timeout"); do
        sleep 1
        printf "\r  ${GRAY}[%2ds]${RESET} Waiting for chattr lock…" "$i"

        if lsattr "$file_path" 2>/dev/null | grep -q '\-i\-'; then
            echo ""
            echo -e "  ${GREEN}${BOLD}[FIM AR CONFIRMED]${RESET} $file_path is now IMMUTABLE:"
            lsattr "$file_path" | while read -r line; do
                echo -e "    ${GREEN}$line${RESET}"
            done
            found=1
            log "FIM-AR-CONFIRMED: $file_path locked immutable at ${i}s"

            # Also show AR log
            echo ""
            echo -e "  ${TEAL}[AR LOG]${RESET} fim-respond entries:"
            grep "fim-respond" "$AR_LOG" 2>/dev/null | tail -5 | while read -r line; do
                echo -e "    ${TEAL}$line${RESET}"
            done
            break
        fi
    done

    echo ""
    if [[ $found -eq 0 ]]; then
        warn "File $file_path not locked after ${timeout}s"
        # Show recent AR log anyway
        echo -e "  ${GRAY}Recent AR log:${RESET}"
        tail -5 "$AR_LOG" 2>/dev/null | while read -r line; do
            echo -e "    ${GRAY}$line${RESET}"
        done
    fi
}

# ── Cleanup ───────────────────────────────────────────────────────────────────
cleanup() {
    echo -e "\n${CYAN}${BOLD}[CLEANUP]${RESET} Removing simulation artefacts…"
    rm -f /tmp/msfconsole

    if grep -q "wazuh_sim_mod_marker" /etc/passwd 2>/dev/null; then
        sed -i '/wazuh_sim_mod_marker/d' /etc/passwd
        ok "Removed marker from /etc/passwd"
    fi

    # Unlock files locked by FIM AR
    for f in /etc/sudoers /etc/passwd; do
        if lsattr "$f" 2>/dev/null | grep -q '\-i\-'; then
            chattr -i "$f"
            ok "Removed immutable flag from $f"
        fi
    done

    # Flush attacker IP from iptables
    if iptables -L INPUT -n 2>/dev/null | grep -q "$ATTACKER_IP"; then
        iptables -D INPUT -s "$ATTACKER_IP" -j DROP 2>/dev/null || true
        ok "Removed iptables DROP for $ATTACKER_IP"
    fi

    ok "Cleanup complete. Log: $LOG_FILE"
}

# ══════════════════════════════════════════════════════════════════════════════
# SCENARIO 1 — REVERSE SHELL TOOL (Rule 100101)
# ══════════════════════════════════════════════════════════════════════════════
scenario_01_reverse_shell_tool() {
    banner "CRITICAL" "Scenario 01 — Reverse Shell Tool Detected (Rule 100101)"
    info "Target: Rule 100101 — msfconsole/meterpreter detected in /tmp"
    info "Expected AR: Wazuh_1_0 → firewall-drop blocks agent IP (local execution)"
    echo ""

    # Create fake msfconsole in /tmp — FIM realtime detects new file
    cat > /tmp/msfconsole << 'FAKESCRIPT'
#!/bin/bash
echo "wazuh_sim: fake msfconsole process running"
sleep 60
FAKESCRIPT
    chmod +x /tmp/msfconsole

    info "Dropping fake msfconsole into /tmp (FIM realtime will detect)…"
    ok "Created /tmp/msfconsole — Wazuh FIM should fire rule 100101"

    info "Launching process so syscollector sees it…"
    /tmp/msfconsole &
    SIM_PID=$!
    ok "PID $SIM_PID running"

    echo ""
    echo -e "  ${YELLOW}Expected flow:${RESET}"
    echo -e "    FIM detects /tmp/msfconsole → rule 100101 (HIGH/CRITICAL)"
    echo -e "    interceptor creates TheHive case"
    echo -e "    Wazuh_1_0 responder → firewall-drop on agent IP 192.168.200.128"
    echo -e "    (no srcip for local tool → agent_ip fallback)"
    echo ""

    # Watch for AR — agent_ip blocked since no external srcip
    watch_ar "rule:100101" "192.168.200.128" 40

    kill "$SIM_PID" 2>/dev/null || true
    sleep 2
    rm -f /tmp/msfconsole
    ok "Cleaned up /tmp/msfconsole"
    sleep "$DELAY"
}

# ══════════════════════════════════════════════════════════════════════════════
# SCENARIO 2 — CRITICAL FILE MODIFIED (Rules 100117 / 100123)
# ══════════════════════════════════════════════════════════════════════════════
scenario_02_critical_file_modified() {
    banner "CRITICAL" "Scenario 02 — Critical File Modified (Rules 100117 / 100123)"
    info "Target: Rule 100117 (single mod) → 100123 (3+ mods in 300s)"
    info "Expected AR: WazuhFIM_1_0 → fim-respond.sh → chattr +i locks file"
    echo ""

    # Unlock first in case previous run left it locked
    chattr -i /etc/sudoers 2>/dev/null || true
    chattr -i /etc/passwd  2>/dev/null || true

    info "Round 1/4 — touching /etc/sudoers (triggers rule 100117)…"
    touch /etc/sudoers
    ok "touch /etc/sudoers (1)"

    echo ""
    echo -e "  ${YELLOW}Expected flow after first touch:${RESET}"
    echo -e "    FIM detects /etc/sudoers modified → rule 100117 (HIGH)"
    echo -e "    interceptor creates TheHive case"
    echo -e "    WazuhFIM_1_0 → fim-respond.sh → chattr +i /etc/sudoers"
    echo ""

    # Watch for FIM AR after first touch
    watch_fim_ar "/etc/sudoers" 30

    # Unlock for subsequent rounds (AR may have locked it)
    chattr -i /etc/sudoers 2>/dev/null || true
    chattr -i /etc/passwd  2>/dev/null || true

    echo ""
    info "Rounds 2-4 — triggering repeated mods for rule 100123…"

    for i in 2 3 4; do
        chattr -i /etc/sudoers 2>/dev/null || true
        touch /etc/sudoers
        ok "touch /etc/sudoers ($i)"
        sleep 2

        chattr -i /etc/passwd 2>/dev/null || true
        if grep -q "wazuh_sim_mod_marker" /etc/passwd 2>/dev/null; then
            sed -i '/wazuh_sim_mod_marker/d' /etc/passwd
        else
            echo "# wazuh_sim_mod_marker iter=$i ts=$(date +%s)" >> /etc/passwd
        fi
        ok "/etc/passwd modified ($i)"
        sleep 2
    done

    ok "4 rounds complete — rule 100123 REPEATED CRITICAL FILE MODS should fire"
    echo ""
    echo -e "  ${YELLOW}Expected:${RESET} rule 100123 CRITICAL case in TheHive + WazuhFIM AR"
    watch_fim_ar "/etc/sudoers" 30

    # Final cleanup of immutable flags
    chattr -i /etc/sudoers 2>/dev/null || true
    chattr -i /etc/passwd  2>/dev/null || true
    sed -i '/wazuh_sim_mod_marker/d' /etc/passwd 2>/dev/null || true

    sleep "$DELAY"
}

# ══════════════════════════════════════════════════════════════════════════════
# SCENARIO 3 — SSH BRUTE FORCE (Rules 5710 / 5712)
# ══════════════════════════════════════════════════════════════════════════════
scenario_03_invalid_user_login() {
    banner "MEDIUM" "Scenario 03 — SSH Brute Force (Rules 5710 / 5712)"
    info "Target: Rule 5710 (invalid user) + 5712 (brute force escalation)"
    info "Expected AR: Wazuh_1_0 → firewall-drop blocks $ATTACKER_IP"
    echo ""

    # Flush any existing block so we can see it appear fresh
    iptables -D INPUT -s "$ATTACKER_IP" -j DROP 2>/dev/null || true
    ok "Cleared any existing iptables block for $ATTACKER_IP"

    echo ""
    info "Injecting SSH auth failures from $ATTACKER_IP…"

    for user in admin Administrator ghost fakeuser backdoor; do
        inject_syslog "sshd[9999]: Invalid user $user from $ATTACKER_IP port 54321"
        inject_syslog "sshd[9999]: Connection closed by invalid user $user $ATTACKER_IP port 54321 [preauth]"
        info "  Injected: Invalid user '$user' from $ATTACKER_IP"
        sleep 0.5
    done

    for user in backup deploy testuser; do
        inject_syslog "sshd[9999]: Failed password for invalid user $user from $ATTACKER_IP port 54321 ssh2"
        info "  Injected: Failed password for '$user' from $ATTACKER_IP"
        sleep 0.5
    done

    ok "All lines injected (8 failures from $ATTACKER_IP)"
    echo ""
    echo -e "  ${YELLOW}Expected flow:${RESET}"
    echo -e "    Wazuh detects rule 5710/5712 from $ATTACKER_IP"
    echo -e "    Brute-force escalation → MEDIUM/HIGH"
    echo -e "    interceptor creates TheHive case"
    echo -e "    Wazuh_1_0 → firewall-drop $ATTACKER_IP"
    echo -e "    iptables DROP rule appears on this agent"
    echo ""

    watch_ar "rule:5710/5712" "$ATTACKER_IP" 30

    # Show final iptables state
    echo ""
    echo -e "  ${TEAL}${BOLD}── Final iptables INPUT state ──${RESET}"
    iptables -L INPUT -n --line-numbers | head -20 | while read -r line; do
        if echo "$line" | grep -q "$ATTACKER_IP"; then
            echo -e "    ${GREEN}${BOLD}$line${RESET}"
        else
            echo -e "    ${GRAY}$line${RESET}"
        fi
    done

    sleep "$DELAY"
}

# ══════════════════════════════════════════════════════════════════════════════
# MENU
# ══════════════════════════════════════════════════════════════════════════════
list_scenarios() {
    echo ""
    echo -e "${CYAN}${BOLD}  Available Simulations${RESET}"
    echo -e "${GRAY}  ──────────────────────────────────────────────────────────${RESET}"
    echo -e "  ${RED}[CRITICAL]${RESET}"
    echo -e "   1  Reverse Shell Tool     → Rule 100101  → firewall-drop agent IP"
    echo -e "   2  Critical File Modified → Rules 100117/100123 → chattr +i lock"
    echo -e "  ${YELLOW}[MEDIUM]${RESET}"
    echo -e "   3  SSH Brute Force        → Rules 5710/5712 → firewall-drop attacker IP"
    echo ""
}

print_header() {
    echo ""
    echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}${BOLD}║      WAZUH SOC ATTACK SIMULATION SUITE (MINIMAL)            ║${RESET}"
    echo -e "${CYAN}${BOLD}║      Kali Agent — Group 7 Blue Team  — CBSA                 ║${RESET}"
    echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════════╝${RESET}"
    echo -e "  ${GRAY}Log    : $LOG_FILE${RESET}"
    echo -e "  ${GRAY}AR log : $AR_LOG${RESET}"
    echo -e "  ${GRAY}Delay  : ${DELAY}s between scenarios${RESET}"
    echo ""
    echo -e "  ${YELLOW}⚠  Ensure wazuh-agent is running and thehive-intercept.py is active.${RESET}"
    echo ""
}

require_root
MODE="all"; SCENARIO=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --all)      MODE="all" ;;
        --scenario) MODE="single"; SCENARIO="$2"; shift ;;
        --list)     list_scenarios; exit 0 ;;
        --cleanup)  cleanup; exit 0 ;;
        --delay)    DELAY="$2"; shift ;;
        -h|--help)
            echo "Usage: sudo $0 [--all|--scenario N|--list|--cleanup|--delay N]"
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
    shift
done

print_header

case "$MODE" in
    single)
        [[ -z "$SCENARIO" ]] && { echo "Specify --scenario N (1-3)"; exit 1; }
        case "$SCENARIO" in
            1) scenario_01_reverse_shell_tool ;;
            2) scenario_02_critical_file_modified ;;
            3) scenario_03_invalid_user_login ;;
            *) echo "Invalid scenario (1-3)"; exit 1 ;;
        esac
        ;;
    all)
        scenario_01_reverse_shell_tool
        scenario_02_critical_file_modified
        scenario_03_invalid_user_login
        ;;
esac

echo ""
echo -e "${GREEN}${BOLD}[DONE]${RESET} All simulations completed."
echo -e "  ${GRAY}Full log : $LOG_FILE${RESET}"
echo -e "  ${CYAN}Cleanup  : sudo $0 --cleanup${RESET}"
echo ""
