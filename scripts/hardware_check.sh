#!/usr/bin/env bash
# =============================================================================
# Zovark Hardware Sizing Check
# =============================================================================
# Validates host hardware against Zovark deployment requirements and
# recommends a deployment tier based on available resources.
#
# Usage:
#   ./scripts/hardware_check.sh                  # basic check
#   ./scripts/hardware_check.sh 5000             # with daily alert volume estimate
#   ./scripts/hardware_check.sh --help
#
# Exit codes:
#   0  All critical requirements met
#   1  One or more critical requirements NOT met
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Color helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

pass()  { printf "  ${GREEN}[PASS]${NC}  %s\n" "$*"; }
warn()  { printf "  ${YELLOW}[WARN]${NC}  %s\n" "$*"; }
fail()  { printf "  ${RED}[FAIL]${NC}  %s\n" "$*"; }
info()  { printf "  ${CYAN}[INFO]${NC}  %s\n" "$*"; }
header(){ printf "\n${BOLD}── %s${NC}\n" "$*"; }

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    cat <<'USAGE'
Zovark Hardware Sizing Check

Usage:
  ./scripts/hardware_check.sh [daily_alert_volume]

Arguments:
  daily_alert_volume   Optional. Estimated alerts per day (e.g. 5000).
                       Used to project processing time per tier.

Examples:
  ./scripts/hardware_check.sh            # basic hardware check
  ./scripts/hardware_check.sh 10000      # check + processing time estimate

Requirements (critical minimums):
  RAM        16 GB       (recommend 32 GB+)
  CPU cores   4          (recommend 8+)
  Disk free  50 GB       (recommend 100 GB+)
  Docker     installed
  Docker Compose installed

GPU is optional but strongly recommended for LLM inference.
USAGE
    exit 0
fi

DAILY_VOLUME="${1:-}"

# ---------------------------------------------------------------------------
# Counters
# ---------------------------------------------------------------------------
CRITICAL_FAILURES=0
WARNINGS=0

# Collected metrics (set defaults; overwritten when detection succeeds)
RAM_GB=0
CPU_CORES=0
DISK_FREE_GB=0
GPU_DETECTED=false
GPU_VRAM_MB=0
GPU_NAME=""
DOCKER_OK=false
COMPOSE_OK=false

# ---------------------------------------------------------------------------
# Helper: detect OS
# ---------------------------------------------------------------------------
detect_os() {
    case "$(uname -s)" in
        Linux*)   echo "linux";;
        Darwin*)  echo "macos";;
        MINGW*|MSYS*|CYGWIN*) echo "windows";;
        *)        echo "unknown";;
    esac
}

OS="$(detect_os)"

printf "\n${BOLD}============================================================${NC}\n"
printf "${BOLD}  Zovark Hardware Sizing Check${NC}\n"
printf "${BOLD}============================================================${NC}\n"
info "Detected OS: ${OS}"
info "Date: $(date '+%Y-%m-%d %H:%M:%S')"

# ===================================================================
# 1. RAM
# ===================================================================
header "1. Memory (RAM)"

MIN_RAM_GB=16
REC_RAM_GB=32

get_ram() {
    if [[ "$OS" == "linux" ]]; then
        if [[ -f /proc/meminfo ]]; then
            local kb
            kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
            RAM_GB=$(( kb / 1024 / 1024 ))
            return 0
        fi
    elif [[ "$OS" == "macos" ]]; then
        local bytes
        bytes=$(sysctl -n hw.memsize 2>/dev/null || echo 0)
        RAM_GB=$(( bytes / 1024 / 1024 / 1024 ))
        return 0
    elif [[ "$OS" == "windows" ]]; then
        # Try wmic (available in Git Bash / MSYS2)
        if command -v wmic &>/dev/null; then
            local bytes
            bytes=$(wmic ComputerSystem get TotalPhysicalMemory 2>/dev/null \
                    | awk 'NR==2 {gsub(/[^0-9]/,""); print}')
            if [[ -n "$bytes" && "$bytes" -gt 0 ]] 2>/dev/null; then
                RAM_GB=$(( bytes / 1024 / 1024 / 1024 ))
                return 0
            fi
        fi
        # Try powershell as fallback
        if command -v powershell.exe &>/dev/null; then
            local bytes
            bytes=$(powershell.exe -NoProfile -Command \
                "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory" 2>/dev/null \
                | tr -d '\r\n ')
            if [[ -n "$bytes" && "$bytes" -gt 0 ]] 2>/dev/null; then
                RAM_GB=$(( bytes / 1024 / 1024 / 1024 ))
                return 0
            fi
        fi
    fi
    # Fallback: free command
    if command -v free &>/dev/null; then
        local kb
        kb=$(free -k 2>/dev/null | awk '/^Mem:/ {print $2}')
        if [[ -n "$kb" && "$kb" -gt 0 ]] 2>/dev/null; then
            RAM_GB=$(( kb / 1024 / 1024 ))
            return 0
        fi
    fi
    return 1
}

if get_ram; then
    info "Total RAM: ${RAM_GB} GB"
    if (( RAM_GB < MIN_RAM_GB )); then
        fail "RAM ${RAM_GB} GB is below minimum ${MIN_RAM_GB} GB"
        (( CRITICAL_FAILURES++ )) || true
    elif (( RAM_GB < REC_RAM_GB )); then
        warn "RAM ${RAM_GB} GB meets minimum but ${REC_RAM_GB} GB+ recommended"
        (( WARNINGS++ )) || true
    else
        pass "RAM ${RAM_GB} GB meets recommended ${REC_RAM_GB} GB+"
    fi
else
    warn "Could not detect RAM on this platform"
    (( WARNINGS++ )) || true
fi

# ===================================================================
# 2. CPU Cores
# ===================================================================
header "2. CPU Cores"

MIN_CORES=4
REC_CORES=8

get_cores() {
    if [[ "$OS" == "linux" ]]; then
        CPU_CORES=$(nproc 2>/dev/null || grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo 0)
    elif [[ "$OS" == "macos" ]]; then
        CPU_CORES=$(sysctl -n hw.ncpu 2>/dev/null || echo 0)
    elif [[ "$OS" == "windows" ]]; then
        CPU_CORES="${NUMBER_OF_PROCESSORS:-0}"
        if [[ "$CPU_CORES" -eq 0 ]] 2>/dev/null; then
            if command -v wmic &>/dev/null; then
                CPU_CORES=$(wmic cpu get NumberOfLogicalProcessors 2>/dev/null \
                            | awk 'NR==2 {gsub(/[^0-9]/,""); print}')
            fi
        fi
    else
        CPU_CORES=$(nproc 2>/dev/null || echo 0)
    fi
    [[ "$CPU_CORES" -gt 0 ]] 2>/dev/null
}

if get_cores; then
    info "CPU cores (logical): ${CPU_CORES}"
    if (( CPU_CORES < MIN_CORES )); then
        fail "CPU cores ${CPU_CORES} is below minimum ${MIN_CORES}"
        (( CRITICAL_FAILURES++ )) || true
    elif (( CPU_CORES < REC_CORES )); then
        warn "CPU cores ${CPU_CORES} meets minimum but ${REC_CORES}+ recommended"
        (( WARNINGS++ )) || true
    else
        pass "CPU cores ${CPU_CORES} meets recommended ${REC_CORES}+"
    fi
else
    warn "Could not detect CPU cores on this platform"
    (( WARNINGS++ )) || true
fi

# ===================================================================
# 3. Disk Space
# ===================================================================
header "3. Disk Space"

MIN_DISK_GB=50
REC_DISK_GB=100

get_disk() {
    # Try to get free space on the root (/) or current drive
    if command -v df &>/dev/null; then
        # df -BG gives output in GB on Linux; on macOS we parse 512-byte blocks
        if [[ "$OS" == "linux" ]]; then
            DISK_FREE_GB=$(df -BG / 2>/dev/null | awk 'NR==2 {gsub(/G/,"",$4); print int($4)}')
        elif [[ "$OS" == "macos" ]]; then
            local blocks
            blocks=$(df / 2>/dev/null | awk 'NR==2 {print $4}')
            DISK_FREE_GB=$(( blocks * 512 / 1024 / 1024 / 1024 ))
        else
            # Windows Git Bash: df often works on the current mount
            DISK_FREE_GB=$(df -BG . 2>/dev/null | awk 'NR==2 {gsub(/G/,"",$4); print int($4)}')
            if [[ -z "$DISK_FREE_GB" || "$DISK_FREE_GB" -eq 0 ]] 2>/dev/null; then
                # Fallback: parse df without -BG
                local kb
                kb=$(df -k . 2>/dev/null | awk 'NR==2 {print $4}')
                if [[ -n "$kb" && "$kb" -gt 0 ]] 2>/dev/null; then
                    DISK_FREE_GB=$(( kb / 1024 / 1024 ))
                fi
            fi
        fi
        [[ "$DISK_FREE_GB" -gt 0 ]] 2>/dev/null && return 0
    fi
    return 1
}

if get_disk; then
    info "Free disk space: ${DISK_FREE_GB} GB"
    if (( DISK_FREE_GB < MIN_DISK_GB )); then
        fail "Free disk ${DISK_FREE_GB} GB is below minimum ${MIN_DISK_GB} GB"
        (( CRITICAL_FAILURES++ )) || true
    elif (( DISK_FREE_GB < REC_DISK_GB )); then
        warn "Free disk ${DISK_FREE_GB} GB meets minimum but ${REC_DISK_GB} GB+ recommended"
        (( WARNINGS++ )) || true
    else
        pass "Free disk ${DISK_FREE_GB} GB meets recommended ${REC_DISK_GB} GB+"
    fi
else
    warn "Could not detect free disk space on this platform"
    (( WARNINGS++ )) || true
fi

# ===================================================================
# 4. GPU (nvidia-smi)
# ===================================================================
header "4. GPU (NVIDIA)"

check_gpu() {
    if ! command -v nvidia-smi &>/dev/null; then
        warn "nvidia-smi not found — no NVIDIA GPU detected or driver not installed"
        info "GPU is optional but strongly recommended for LLM inference"
        (( WARNINGS++ )) || true
        return
    fi

    # Query GPU name and memory
    local gpu_info
    gpu_info=$(nvidia-smi --query-gpu=name,memory.total --format=csv,noheader,nounits 2>/dev/null || true)

    if [[ -z "$gpu_info" ]]; then
        warn "nvidia-smi present but returned no GPU data"
        (( WARNINGS++ )) || true
        return
    fi

    GPU_DETECTED=true

    # Parse first GPU (multi-GPU: we report each but size by the first)
    local gpu_count=0
    while IFS=',' read -r name vram; do
        name=$(echo "$name" | xargs)  # trim whitespace
        vram=$(echo "$vram" | xargs)
        (( gpu_count++ )) || true

        if [[ $gpu_count -eq 1 ]]; then
            GPU_NAME="$name"
            GPU_VRAM_MB="$vram"
        fi

        info "GPU #${gpu_count}: ${name} — ${vram} MB VRAM"
    done <<< "$gpu_info"

    # Recommend tier based on VRAM
    if (( GPU_VRAM_MB >= 80000 )); then
        pass "VRAM ${GPU_VRAM_MB} MB — Enterprise tier (A100/H100 class)"
        info "Supports: 70B+ models, concurrent inference, batch processing"
    elif (( GPU_VRAM_MB >= 24000 )); then
        pass "VRAM ${GPU_VRAM_MB} MB — Professional tier (RTX 4090 / A5000 class)"
        info "Supports: 14B-34B models with good throughput"
    elif (( GPU_VRAM_MB >= 12000 )); then
        warn "VRAM ${GPU_VRAM_MB} MB — Development tier (RTX 3060/4060 class)"
        info "Supports: 7B-14B quantized models (Qwen2.5-14B Q4_K_M fits)"
        (( WARNINGS++ )) || true
    elif (( GPU_VRAM_MB >= 4000 )); then
        warn "VRAM ${GPU_VRAM_MB} MB — Essentials tier (entry-level GPU)"
        info "Supports: 7B quantized models only. Path C will be slow."
        (( WARNINGS++ )) || true
    else
        fail "VRAM ${GPU_VRAM_MB} MB — below recommended minimum for LLM inference"
        info "Consider CPU-only inference (very slow) or cloud GPU."
        (( WARNINGS++ )) || true
    fi
}

check_gpu

# ===================================================================
# 5. Docker & Docker Compose
# ===================================================================
header "5. Docker & Docker Compose"

# Docker
if command -v docker &>/dev/null; then
    DOCKER_VERSION=$(docker --version 2>/dev/null | head -1)
    # Verify the daemon is reachable
    if docker info &>/dev/null; then
        pass "Docker installed and daemon running — ${DOCKER_VERSION}"
        DOCKER_OK=true
    else
        warn "Docker installed but daemon not running or not accessible"
        info "${DOCKER_VERSION}"
        info "Try: sudo systemctl start docker  (or start Docker Desktop)"
        (( WARNINGS++ )) || true
    fi
else
    fail "Docker is NOT installed"
    info "Install: https://docs.docker.com/engine/install/"
    (( CRITICAL_FAILURES++ )) || true
fi

# Docker Compose (v2 plugin or standalone)
if docker compose version &>/dev/null 2>&1; then
    COMPOSE_VERSION=$(docker compose version 2>/dev/null | head -1)
    pass "Docker Compose (plugin) — ${COMPOSE_VERSION}"
    COMPOSE_OK=true
elif command -v docker-compose &>/dev/null; then
    COMPOSE_VERSION=$(docker-compose --version 2>/dev/null | head -1)
    pass "Docker Compose (standalone) — ${COMPOSE_VERSION}"
    COMPOSE_OK=true
else
    fail "Docker Compose is NOT installed"
    info "Install: https://docs.docker.com/compose/install/"
    (( CRITICAL_FAILURES++ )) || true
fi

# ===================================================================
# 6. Deployment Tier Recommendation
# ===================================================================
header "6. Deployment Tier Recommendation"

# Tier logic:
#   Enterprise:    >= 64 GB RAM, >= 16 cores, GPU >= 80 GB VRAM
#   Professional:  >= 32 GB RAM, >= 8 cores,  GPU >= 24 GB VRAM
#   Development:   >= 16 GB RAM, >= 4 cores,  GPU >= 4 GB VRAM (or any GPU)
#   Essentials:    Meets minimums, no/small GPU

TIER="Essentials"

if (( RAM_GB >= 64 && CPU_CORES >= 16 )) && [[ "$GPU_DETECTED" == true ]] && (( GPU_VRAM_MB >= 80000 )); then
    TIER="Enterprise"
elif (( RAM_GB >= 32 && CPU_CORES >= 8 )) && [[ "$GPU_DETECTED" == true ]] && (( GPU_VRAM_MB >= 24000 )); then
    TIER="Professional"
elif (( RAM_GB >= 16 && CPU_CORES >= 4 )) && [[ "$GPU_DETECTED" == true ]] && (( GPU_VRAM_MB >= 4000 )); then
    TIER="Development"
fi

case "$TIER" in
    Enterprise)
        printf "  ${GREEN}${BOLD}>>> Recommended Tier: ENTERPRISE${NC}\n"
        info "Full production deployment with 70B+ models"
        info "Concurrent pipeline execution, < 5s per alert (Path A)"
        info "Handles 50,000+ alerts/day"
        ;;
    Professional)
        printf "  ${GREEN}${BOLD}>>> Recommended Tier: PROFESSIONAL${NC}\n"
        info "Production deployment with 14B-34B models"
        info "Good throughput for Path A/B, acceptable Path C"
        info "Handles 10,000-50,000 alerts/day"
        ;;
    Development)
        printf "  ${YELLOW}${BOLD}>>> Recommended Tier: DEVELOPMENT${NC}\n"
        info "Development / small production with 7B-14B quantized models"
        info "Path A fast (~350ms), Path C slower (120-280s on single GPU)"
        info "Handles 1,000-10,000 alerts/day"
        ;;
    Essentials)
        printf "  ${YELLOW}${BOLD}>>> Recommended Tier: ESSENTIALS${NC}\n"
        info "Minimum viable deployment — template-only (Path A) recommended"
        info "CPU-only LLM inference will be very slow for Path B/C"
        info "Handles up to 1,000 alerts/day (Path A only)"
        ;;
esac

# ===================================================================
# 7. Processing Time Estimate (if daily_alert_volume provided)
# ===================================================================
if [[ -n "$DAILY_VOLUME" ]]; then
    header "7. Processing Time Estimate"

    if ! [[ "$DAILY_VOLUME" =~ ^[0-9]+$ ]]; then
        warn "Invalid daily_alert_volume: '${DAILY_VOLUME}' — must be a positive integer"
    else
        info "Daily alert volume: ${DAILY_VOLUME}"
        info ""

        # Assumptions per tier (seconds per alert, weighted average across paths)
        # Path distribution: ~60% Path A (template), ~25% Path B, ~15% Path C
        # Plus benign: assume 40% of all alerts are benign (Path A speed)
        case "$TIER" in
            Enterprise)
                # Path A: 0.35s, B: 10s, C: 30s, benign: 0.35s
                AVG_SEC_PER_ALERT=5    # blended average
                CONCURRENCY=8
                ;;
            Professional)
                # Path A: 0.35s, B: 30s, C: 60s, benign: 0.35s
                AVG_SEC_PER_ALERT=12
                CONCURRENCY=4
                ;;
            Development)
                # Path A: 0.35s, B: 60s, C: 200s, benign: 0.35s
                AVG_SEC_PER_ALERT=35
                CONCURRENCY=2
                ;;
            Essentials)
                # Path A: 0.35s, B: 120s, C: 600s (CPU), benign: 0.35s
                AVG_SEC_PER_ALERT=85
                CONCURRENCY=1
                ;;
        esac

        TOTAL_SEC=$(( DAILY_VOLUME * AVG_SEC_PER_ALERT / CONCURRENCY ))
        TOTAL_HOURS=$(( TOTAL_SEC / 3600 ))
        TOTAL_MIN=$(( (TOTAL_SEC % 3600) / 60 ))

        info "Tier: ${TIER}"
        info "Avg time per alert (blended): ~${AVG_SEC_PER_ALERT}s"
        info "Estimated concurrency: ${CONCURRENCY} workers"
        info ""

        if (( TOTAL_HOURS > 24 )); then
            fail "Estimated wall time: ${TOTAL_HOURS}h ${TOTAL_MIN}m — EXCEEDS 24 hours"
            info "This volume requires a higher tier or more hardware."
            (( WARNINGS++ )) || true
        elif (( TOTAL_HOURS > 12 )); then
            warn "Estimated wall time: ${TOTAL_HOURS}h ${TOTAL_MIN}m — tight for daily processing"
        else
            pass "Estimated wall time: ${TOTAL_HOURS}h ${TOTAL_MIN}m — within daily budget"
        fi

        info ""
        info "Note: Estimates assume 60% attack (Path A/B/C mix) + 40% benign."
        info "Actual times depend on alert types, LLM speed, and template coverage."
    fi
fi

# ===================================================================
# Summary
# ===================================================================
header "Summary"

printf "\n"
printf "  %-20s %s\n" "RAM:" "${RAM_GB} GB"
printf "  %-20s %s\n" "CPU Cores:" "${CPU_CORES}"
printf "  %-20s %s\n" "Disk Free:" "${DISK_FREE_GB} GB"
if [[ "$GPU_DETECTED" == true ]]; then
    printf "  %-20s %s (%s MB VRAM)\n" "GPU:" "${GPU_NAME}" "${GPU_VRAM_MB}"
else
    printf "  %-20s %s\n" "GPU:" "Not detected"
fi
printf "  %-20s %s\n" "Docker:" "$( [[ "$DOCKER_OK" == true ]] && echo 'OK' || echo 'MISSING/STOPPED' )"
printf "  %-20s %s\n" "Docker Compose:" "$( [[ "$COMPOSE_OK" == true ]] && echo 'OK' || echo 'MISSING' )"
printf "  %-20s %s\n" "Recommended Tier:" "${TIER}"
printf "\n"

if (( CRITICAL_FAILURES > 0 )); then
    printf "  ${RED}${BOLD}RESULT: ${CRITICAL_FAILURES} critical failure(s), ${WARNINGS} warning(s)${NC}\n"
    printf "  ${RED}Fix critical issues before deploying Zovark.${NC}\n\n"
    exit 1
else
    if (( WARNINGS > 0 )); then
        printf "  ${YELLOW}${BOLD}RESULT: All critical checks passed, ${WARNINGS} warning(s)${NC}\n"
        printf "  ${YELLOW}Zovark can run but review warnings for optimal performance.${NC}\n\n"
    else
        printf "  ${GREEN}${BOLD}RESULT: All checks passed — hardware meets recommended specs${NC}\n\n"
    fi
    exit 0
fi
