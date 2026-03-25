#!/usr/bin/env bash
# =============================================================================
# 03_run_pipeline.sh — subsystem-by-subsystem Joern pipeline runner
#
# For each subsystem in subsystems.txt:
#   1. joern-parse  → subsystem.cpg  (Code Property Graph binary)
#   2. 01_extract_nodes.sc           → nodes_<sub>.json
#   3. 02_extract_edges.sc           → edges_<sub>.json
#   4. fix_ids.py                    → rewrite node IDs to be globally unique
#
# After all subsystems are processed, fix_ids.py does a final global pass
# to ensure no ID collisions exist across subsystem boundaries.
#
# Usage (called by nervo.sh build, or standalone):
#   ./03_run_pipeline.sh <linux_src> <out_dir> <subsystems_file> <gcc_merged.json>
#
# Environment:
#   JOERN            path to joern CLI binary     (default: ./joern-cli/joern)
#   JOERN_PARSE      path to joern-parse binary   (default: ./joern-cli/joern-parse)
#   JAVA_OPTS        JVM heap for Joern           (default: -Xmx16g)
#   NERVO_DIR        directory of nervo scripts   (default: script's own dir)
#   PARALLEL_JOBS    max concurrent Joern parses  (default: 1)
#                    WARNING: each Joern parse can use up to 16 GB — be careful
# =============================================================================

set -euo pipefail

# ── args ──────────────────────────────────────────────────────────────────────
LINUX_SRC="${1:-}"
OUT_DIR="${2:-}"
SUBSYSTEMS_FILE="${3:-}"
GCC_MERGED="${4:-}"

[[ -n "$LINUX_SRC" ]]       || { echo "[pipeline] ERROR: linux_src required";       exit 1; }
[[ -n "$OUT_DIR" ]]         || { echo "[pipeline] ERROR: out_dir required";          exit 1; }
[[ -n "$SUBSYSTEMS_FILE" ]] || { echo "[pipeline] ERROR: subsystems_file required";  exit 1; }
[[ -n "$GCC_MERGED" ]]      || { echo "[pipeline] ERROR: gcc_merged.json required";  exit 1; }

[[ -d "$LINUX_SRC" ]]           || { echo "[pipeline] ERROR: linux_src not found: $LINUX_SRC"; exit 1; }
[[ -f "$SUBSYSTEMS_FILE" ]]     || { echo "[pipeline] ERROR: subsystems file not found: $SUBSYSTEMS_FILE"; exit 1; }
[[ -f "$GCC_MERGED" ]]          || { echo "[pipeline] ERROR: gcc_merged.json not found: $GCC_MERGED"; exit 1; }

# ── env ───────────────────────────────────────────────────────────────────────
NERVO_DIR="${NERVO_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
JOERN="${JOERN:-/usr/local/bin/joern}"
JOERN_PARSE="${JOERN_PARSE:-/usr/local/bin/joern-parse}"
JAVA_OPTS="${JAVA_OPTS:--Xmx16g}"
PARALLEL_JOBS="${PARALLEL_JOBS:-1}"

CPG_DIR="$OUT_DIR/cpg"
JSON_DIR="$OUT_DIR/json"

mkdir -p "$CPG_DIR" "$JSON_DIR"

# ── colours ───────────────────────────────────────────────────────────────────
DIM='\033[2m'; GRN='\033[0;32m'; YLW='\033[0;33m'; RED='\033[0;31m'; RST='\033[0m'
log()     { echo -e "${DIM}[pipeline]${RST} $*"; }
success() { echo -e "${GRN}[pipeline]${RST} $*"; }
warn()    { echo -e "${YLW}[pipeline]${RST} $*"; }
error()   { echo -e "${RED}[pipeline]${RST} $*" >&2; }

# ── read subsystem list ───────────────────────────────────────────────────────
mapfile -t SUBSYSTEMS < "$SUBSYSTEMS_FILE"
TOTAL=${#SUBSYSTEMS[@]}
log "Subsystems to process: $TOTAL"
log "Parallel jobs: $PARALLEL_JOBS"
log "Output dir: $OUT_DIR"


# =============================================================================
# mangle a path into a safe filename component
#   /opt/linux/net/ipv4  →  net_ipv4
# =============================================================================
mangle() {
    local path="$1"
    local rel
    # strip linux_src prefix
    rel="${path#$LINUX_SRC/}"
    # replace / with _
    echo "${rel//\//_}"
}


# =============================================================================
# validate_cpg: check the CPG binary is readable before proceeding
# A malformed binary (from oversized input) produces no error but breaks
# all downstream extraction silently.
# =============================================================================
validate_cpg() {
    local cpg_file="$1"
    local sub_label="$2"

    if [[ ! -f "$cpg_file" ]]; then
        error "CPG file missing after parse: $cpg_file"
        return 1
    fi

    local size
    size=$(stat -c%s "$cpg_file" 2>/dev/null || stat -f%z "$cpg_file")
    if [[ "$size" -lt 1024 ]]; then
        error "CPG file suspiciously small ($size bytes) for $sub_label — parse may have failed silently"
        return 1
    fi

    # try to open the CPG in Joern with a trivial query
    local test_out
    test_out=$(JAVA_TOOL_OPTIONS="$JAVA_OPTS" \
        "$JOERN" --script /dev/stdin \
                 2>/dev/null <<'EOF'
importCpg(params.get("cpgFile").l.head)
val n = cpg.method.size
println(s"OK:$n")
EOF
    ) || true

    if echo "$test_out" | grep -q "^OK:"; then
        local count
        count=$(echo "$test_out" | grep "^OK:" | sed 's/OK://')
        log "  CPG validated: $count methods in $sub_label"
        return 0
    else
        error "CPG validation failed for $sub_label — binary may be corrupt"
        return 1
    fi
}


# =============================================================================
# process_subsystem: parse one subsystem directory through the full pipeline
# =============================================================================
process_subsystem() {
    local sub_path="$1"
    local idx="$2"
    local label
    label=$(mangle "$sub_path")

    local cpg_file="$CPG_DIR/${label}.cpg"
    local nodes_file="$JSON_DIR/nodes_${label}.json"
    local edges_file="$JSON_DIR/edges_${label}.json"

    log "[$idx/$TOTAL] $label"

    # ── skip if already done (incremental re-runs) ────────────────────────
    if [[ -f "$nodes_file" && -f "$edges_file" ]]; then
        local nsize esize
        nsize=$(stat -c%s "$nodes_file" 2>/dev/null || stat -f%z "$nodes_file")
        esize=$(stat -c%s "$edges_file" 2>/dev/null || stat -f%z "$edges_file")
        if [[ "$nsize" -gt 10 && "$esize" -gt 10 ]]; then
            log "  [$label] already done — skipping"
            return 0
        fi
    fi

    # ── step A: joern-parse → CPG binary ─────────────────────────────────
    log "  [$label] joern-parse..."
    JAVA_TOOL_OPTIONS="$JAVA_OPTS" \
        "$JOERN_PARSE" "$sub_path" \
            --language C \
            --output "$cpg_file" \
            2>"$OUT_DIR/logs/${label}_parse.log" \
    || {
        error "joern-parse failed for $label — see $OUT_DIR/logs/${label}_parse.log"
        return 1
    }

    # ── step B: validate CPG before proceeding ────────────────────────────
    validate_cpg "$cpg_file" "$label" || return 1

    # ── step C: extract nodes ─────────────────────────────────────────────
    log "  [$label] extracting nodes..."
    NERVO_CPG_FILE="$cpg_file" NERVO_OUT_FILE="$nodes_file" \
    JAVA_TOOL_OPTIONS="$JAVA_OPTS" \
        "$JOERN" --script "$NERVO_DIR/01_extract_nodes.sc" \
                 2>"$OUT_DIR/logs/${label}_nodes.log" \
    || {
        error "01_extract_nodes.sc failed for $label"
        return 1
    }

    # ── step D: extract edges ─────────────────────────────────────────────
    log "  [$label] extracting edges..."
    NERVO_CPG_FILE="$cpg_file" NERVO_OUT_FILE="$edges_file" \
    JAVA_TOOL_OPTIONS="$JAVA_OPTS" \
        "$JOERN" --script "$NERVO_DIR/02_extract_edges.sc" \
                 2>"$OUT_DIR/logs/${label}_edges.log" \
    || {
        error "02_extract_edges.sc failed for $label"
        return 1
    }

    success "  [$label] done"
    return 0
}


# =============================================================================
# main loop — process all subsystems
# =============================================================================
mkdir -p "$OUT_DIR/logs"

FAILED=()

if [[ "$PARALLEL_JOBS" -gt 1 ]]; then
    # ── parallel mode: use a job pool ────────────────────────────────────
    warn "Parallel mode: $PARALLEL_JOBS jobs — ensure $((PARALLEL_JOBS * 16)) GB RAM available"

    job_count=0
    idx=0
    for sub in "${SUBSYSTEMS[@]}"; do
        idx=$((idx + 1))
        (
            process_subsystem "$sub" "$idx" || echo "FAILED:$sub" >> "$OUT_DIR/failed.txt"
        ) &
        job_count=$((job_count + 1))
        if [[ "$job_count" -ge "$PARALLEL_JOBS" ]]; then
            wait
            job_count=0
        fi
    done
    wait

    if [[ -f "$OUT_DIR/failed.txt" ]]; then
        while IFS= read -r line; do
            FAILED+=("${line#FAILED:}")
        done < "$OUT_DIR/failed.txt"
    fi
else
    # ── serial mode (default — safer for large subsystems) ───────────────
    idx=0
    for sub in "${SUBSYSTEMS[@]}"; do
        idx=$((idx + 1))
        if ! process_subsystem "$sub" "$idx"; then
            FAILED+=("$sub")
        fi
    done
fi


# =============================================================================
# fix_ids.py — rewrite node IDs to be globally unique across all subsystems
#
# Without this, two subsystems might both emit a Function node with id=42.
# fix_ids.py reads all nodes_*.json files, assigns unique IDs globally, and
# rewrites all edges to reference the new IDs.
# =============================================================================
log "Running fix_ids.py for global ID uniqueness..."
python3 "$NERVO_DIR/fix_ids.py" \
    --json-dir "$JSON_DIR" \
    --gcc-merged "$GCC_MERGED" \
    2>"$OUT_DIR/logs/fix_ids.log" \
|| {
    error "fix_ids.py failed — see $OUT_DIR/logs/fix_ids.log"
    exit 1
}
success "fix_ids.py done"


# =============================================================================
# summary
# =============================================================================
echo ""
success "═══════════════════════════════════════════════════"
success " Pipeline complete"
success " Subsystems:  $TOTAL"
success " Failed:      ${#FAILED[@]}"
success " Nodes dir:   $JSON_DIR"
success "═══════════════════════════════════════════════════"

if [[ ${#FAILED[@]} -gt 0 ]]; then
    warn "Failed subsystems:"
    for f in "${FAILED[@]}"; do
        warn "  $f"
    done
    exit 1
fi