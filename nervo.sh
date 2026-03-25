
#!/usr/bin/env bash
# =============================================================================
# nervo.sh — master CLI orchestrator for Nervo (Linux Kernel GPS)
#
# Commands:
#   nervo.sh build   <linux_src>        — full build pipeline
#   nervo.sh predict <syscall_expr>     — trace a syscall path
#   nervo.sh query   <cypher>           — raw Cypher query against Neo4j
#   nervo.sh status                     — show graph health
#   nervo.sh capture start <syscall>    — arm a bpftrace probe manually
#   nervo.sh checkup                    — re-verify all stale dynamic edges
# =============================================================================

set -euo pipefail

# ── paths (override via env) ──────────────────────────────────────────────────
NERVO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JOERN="${JOERN:-$NERVO_DIR/joern-cli/joern}"
JOERN_PARSE="${JOERN_PARSE:-$NERVO_DIR/joern-cli/joern-parse}"
JAVA_OPTS="${JAVA_OPTS:--Xmx16g}"
LINUX_SRC="${LINUX_SRC:-}"
OUT_DIR="${OUT_DIR:-$NERVO_DIR/out}"
PLUGIN_SO="$NERVO_DIR/nervo_gcc_plugin.so"
COMPILED_FILES="$OUT_DIR/nervo_compiled_files.txt"
SUBSYSTEMS_FILE="$OUT_DIR/subsystems.txt"
NEO4J_URI="${NEO4J_URI:-bolt://localhost:7687}"
NEO4J_USER="${NEO4J_USER:-neo4j}"
NEO4J_PASS="${NEO4J_PASS:-neo4j}"
KERNEL_VERSION_FILE="$NERVO_DIR/.kernel_version"

# ── colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[0;33m'
BLU='\033[0;34m'
CYN='\033[0;36m'
DIM='\033[2m'
RST='\033[0m'

log()     { echo -e "${DIM}[nervo]${RST} $*"; }
success() { echo -e "${GRN}[nervo]${RST} $*"; }
warn()    { echo -e "${YLW}[nervo]${RST} $*"; }
error()   { echo -e "${RED}[nervo]${RST} $*" >&2; }
step()    { echo -e "\n${BLU}══${RST} $* ${BLU}══${RST}"; }
die()     { error "$*"; exit 1; }

# ── helpers ───────────────────────────────────────────────────────────────────
require_neo4j() {
    python3 - <<EOF
from neo4j import GraphDatabase
try:
    d = GraphDatabase.driver("$NEO4J_URI", auth=("$NEO4J_USER", "$NEO4J_PASS"))
    d.verify_connectivity()
    d.close()
except Exception as e:
    print(f"Cannot reach Neo4j at $NEO4J_URI: {e}")
    exit(1)
EOF
}

require_root() {
    [[ $EUID -eq 0 ]] || die "bpftrace probes require root (CAP_BPF). Re-run with sudo."
}

check_kernel_version() {
    local current
    current="$(uname -r)"
    if [[ -f "$KERNEL_VERSION_FILE" ]]; then
        local stored
        stored="$(cat "$KERNEL_VERSION_FILE")"
        if [[ "$current" != "$stored" ]]; then
            warn "Kernel version changed: $stored → $current"
            warn "Marking all dynamic edges stale..."
            python3 "$NERVO_DIR/dynamic_capture.py" --mark-all-stale \
                --neo4j-uri "$NEO4J_URI" \
                --neo4j-user "$NEO4J_USER" \
                --neo4j-pass "$NEO4J_PASS"
            echo "$current" > "$KERNEL_VERSION_FILE"
            warn "All dynamic edges marked stale. Run: nervo.sh checkup"
        fi
    else
        echo "$current" > "$KERNEL_VERSION_FILE"
    fi
}

# =============================================================================
# COMMAND: build <linux_src>
# =============================================================================
cmd_build() {
    local linux_src="${1:-$LINUX_SRC}"
    [[ -n "$linux_src" ]]    || die "Usage: nervo.sh build <linux_src>"
    [[ -d "$linux_src" ]]    || die "Linux source not found: $linux_src"
    [[ -f "$linux_src/.config" ]] || die "No .config found in $linux_src — run make defconfig first"

    mkdir -p "$OUT_DIR"

    # ── step 1: compile the GCC plugin ───────────────────────────────────────
    step "Step 1/7 — Compile GCC plugin"
    if [[ -f "$PLUGIN_SO" ]]; then
        success "Plugin already built — skipping (delete $PLUGIN_SO to rebuild)"
    else
        make -f "$NERVO_DIR/nervo_plugin.mk"             || die "GCC plugin build failed"
        [[ -f "$PLUGIN_SO" ]] || die "Plugin .so not found after build: $PLUGIN_SO"
        success "Plugin built: $PLUGIN_SO"
    fi

    # ── step 2: build kernel with plugin (produces compiled_files + TU JSON) ─
    step "Step 2/7 — Build kernel with GCC plugin"
    if [[ -f "$COMPILED_FILES" ]]; then
        local nfiles
        nfiles="$(wc -l < "$COMPILED_FILES")"
        success "Kernel already built — $nfiles files in manifest (delete $COMPILED_FILES to rebuild)"
    else
        log "This runs make over the full kernel tree — may take a while"
        make -C "$linux_src" \
            CC="gcc -fplugin=$PLUGIN_SO -fplugin-arg-nervo_gcc_plugin-out=$OUT_DIR" \
            -j"$(nproc)" \
            || die "Kernel build with plugin failed"
        [[ -f "$COMPILED_FILES" ]] || die "Plugin did not produce $COMPILED_FILES"
        local nbuilt
        nbuilt="$(wc -l < "$COMPILED_FILES")"
        success "Kernel build done. $nbuilt files compiled. Manifest: $COMPILED_FILES"
    fi

    # ── step 3: derive subsystem list from manifest ───────────────────────────
    step "Step 3/7 — Derive subsystem list"
    if [[ -f "$SUBSYSTEMS_FILE" ]]; then
        local nsub
        nsub="$(wc -l < "$SUBSYSTEMS_FILE")"
        success "Subsystems already derived — $nsub subsystems (delete $SUBSYSTEMS_FILE to redo)"
    else
        python3 "$NERVO_DIR/derive_subsystems.py" \
            "$linux_src" "$COMPILED_FILES" --stats \
            > "$SUBSYSTEMS_FILE" \
            || die "derive_subsystems.py failed"
        local nsub
        nsub="$(wc -l < "$SUBSYSTEMS_FILE")"
        success "Found $nsub subsystems → $SUBSYSTEMS_FILE"
    fi

    # ── step 4: extract constants from kernel headers ─────────────────────────
    step "Step 4/7 — Extract kernel constants"
    if [[ -f "$OUT_DIR/constants.json" ]]; then
        success "Constants already extracted (delete $OUT_DIR/constants.json to redo)"
    else
        python3 "$NERVO_DIR/07_extract_constants.py" "$linux_src" \
            --out "$OUT_DIR/constants.json" --stats \
            || die "07_extract_constants.py failed"
        success "Constants extracted"
    fi

    # ── step 5: merge & process GCC plugin TU output ─────────────────────────
    step "Step 5/7 — Process GCC plugin output"
    if [[ -f "$OUT_DIR/gcc_merged.json" ]]; then
        success "GCC output already merged (delete $OUT_DIR/gcc_merged.json to redo)"
    else
        python3 "$NERVO_DIR/06_merge_plugin_output.py" \
            --linux-src "$linux_src" \
            --plugin-out "$OUT_DIR" \
            --merged-out "$OUT_DIR/gcc_merged.json" --stats \
            || die "06_merge_plugin_output.py failed"
        success "GCC output merged"
    fi

    # ── step 6: Joern parse + node/edge extraction (uses subsystem list) ──────
    step "Step 6/7 — Joern parse → extract → fix IDs"
    bash "$NERVO_DIR/03_run_pipeline.sh" \
        "$linux_src" \
        "$OUT_DIR" \
        "$SUBSYSTEMS_FILE" \
        "$OUT_DIR/gcc_merged.json" \
        || die "03_run_pipeline.sh failed"
    success "Joern extraction complete"

    # ── step 7: bulk load into Neo4j + stitch cross-subsystem edges ───────────
    step "Step 7/7 — Load into Neo4j + stitch"
    require_neo4j
    python3 "$NERVO_DIR/04_load_neo4j.py" \
        --nodes-dir "$OUT_DIR/json" \
        --edges-dir "$OUT_DIR/json" \
        --constants "$OUT_DIR/constants.json" \
        --uri "$NEO4J_URI" \
        --user "$NEO4J_USER" \
        --password "$NEO4J_PASS" \
        || die "04_load_neo4j.py failed"

    python3 "$NERVO_DIR/05_stitch_cross_subsystem.py" \
        --uri "$NEO4J_URI" \
        --user "$NEO4J_USER" \
        --password "$NEO4J_PASS" \
        || die "05_stitch_cross_subsystem.py failed"

    # store kernel version for staleness tracking
    uname -r > "$KERNEL_VERSION_FILE"

    echo ""
    success "═══════════════════════════════════════"
    success " Graph is ready. Run: nervo.sh status"
    success "═══════════════════════════════════════"
}

# =============================================================================
# COMMAND: predict <syscall_expr>
# =============================================================================
cmd_predict() {
    local syscall="${1:-}"
    [[ -n "$syscall" ]] || die "Usage: nervo.sh predict 'socket(AF_INET, SOCK_STREAM, 0)'"
    require_neo4j
    check_kernel_version

    log "Predicting path for: $syscall"
    python3 "$NERVO_DIR/predict.py" \
        --syscall "$syscall" \
        --uri "$NEO4J_URI" \
        --user "$NEO4J_USER" \
        --password "$NEO4J_PASS" \
        --dynamic-capture "$NERVO_DIR/dynamic_capture.py"
}

# =============================================================================
# COMMAND: query <cypher>
# =============================================================================
cmd_query() {
    local cypher="${1:-}"
    [[ -n "$cypher" ]] || die "Usage: nervo.sh query 'MATCH (f:Function {name:\"sys_socket\"}) RETURN f'"
    require_neo4j

    python3 - <<EOF
from neo4j import GraphDatabase
import json

driver = GraphDatabase.driver("$NEO4J_URI", auth=("$NEO4J_USER", "$NEO4J_PASS"))
with driver.session() as s:
    result = s.run("""$cypher""")
    records = [dict(r) for r in result]
    print(json.dumps(records, indent=2, default=str))
driver.close()
EOF
}

# =============================================================================
# COMMAND: status
# =============================================================================
cmd_status() {
    require_neo4j
    check_kernel_version

    echo -e "\n${CYN}══ Nervo Graph Status ══${RST}"

    python3 - <<'EOF'
from neo4j import GraphDatabase
import os

uri   = os.environ.get("NEO4J_URI",  "bolt://localhost:7687")
user  = os.environ.get("NEO4J_USER", "neo4j")
pwd   = os.environ.get("NEO4J_PASS", "neo4j")

driver = GraphDatabase.driver(uri, auth=(user, pwd))
with driver.session() as s:
    def q(cypher):
        return s.run(cypher).single()

    fn_count       = q("MATCH (f:Function)           RETURN count(f)  AS n")["n"]
    edge_count     = q("MATCH ()-[r:CALLS]->()        RETURN count(r)  AS n")["n"]
    indirect_count = q("MATCH ()-[r:INDIRECT_CALL]->() RETURN count(r) AS n")["n"]
    branch_count   = q("MATCH (b:BranchPoint)         RETURN count(b)  AS n")["n"]
    const_count    = q("MATCH (c:Constant)             RETURN count(c)  AS n")["n"]
    dyn_total      = q("MATCH ()-[r:RESOLVES_TO {resolvedBy:'dynamic'}]->() RETURN count(r) AS n")["n"]
    dyn_stale      = q("MATCH ()-[r:RESOLVES_TO {resolvedBy:'dynamic', state:'stale'}]->() RETURN count(r) AS n")["n"]
    dyn_verified   = q("MATCH ()-[r:RESOLVES_TO {resolvedBy:'dynamic', state:'verified'}]->() RETURN count(r) AS n")["n"]

    print(f"  Functions          : {fn_count:>8,}")
    print(f"  Direct call edges  : {edge_count:>8,}")
    print(f"  Indirect calls     : {indirect_count:>8,}")
    print(f"  Branch points      : {branch_count:>8,}")
    print(f"  Constants          : {const_count:>8,}")
    print(f"  Dynamic edges      : {dyn_total:>8,}  (verified: {dyn_verified}  stale: {dyn_stale})")

driver.close()
EOF

    echo ""
    if [[ -f "$KERNEL_VERSION_FILE" ]]; then
        log "Kernel version in graph : $(cat "$KERNEL_VERSION_FILE")"
    fi
    log "Live kernel             : $(uname -r)"
}

# =============================================================================
# COMMAND: capture start <syscall_expr>
# =============================================================================
cmd_capture() {
    local subcommand="${1:-}"
    local syscall="${2:-}"
    [[ "$subcommand" == "start" ]] || die "Usage: nervo.sh capture start '<syscall>'"
    [[ -n "$syscall" ]]            || die "Usage: nervo.sh capture start 'socket(AF_INET, SOCK_STREAM, 0)'"
    require_root
    require_neo4j

    log "Arming bpftrace probe for: $syscall"
    python3 "$NERVO_DIR/dynamic_capture.py" \
        --arm \
        --syscall "$syscall" \
        --uri "$NEO4J_URI" \
        --user "$NEO4J_USER" \
        --password "$NEO4J_PASS"
}

# =============================================================================
# COMMAND: checkup
# =============================================================================
cmd_checkup() {
    require_neo4j
    check_kernel_version

    log "Re-verifying all stale dynamic edges..."
    python3 "$NERVO_DIR/dynamic_capture.py" \
        --checkup \
        --uri "$NEO4J_URI" \
        --user "$NEO4J_USER" \
        --password "$NEO4J_PASS"

    success "Checkup complete"
    cmd_status
}

# =============================================================================
# ENTRYPOINT
# =============================================================================
usage() {
    cat <<EOF

${CYN}nervo.sh${RST} — Linux Kernel GPS

  ${GRN}nervo.sh build${RST}   <linux_src>               Build the full kernel graph
  ${GRN}nervo.sh predict${RST} '<syscall(args)>'          Trace a syscall execution path
  ${GRN}nervo.sh query${RST}   '<Cypher>'                 Run a raw Cypher query
  ${GRN}nervo.sh status${RST}                             Show graph health + node counts
  ${GRN}nervo.sh capture${RST} start '<syscall(args)>'   Arm a bpftrace probe manually
  ${GRN}nervo.sh checkup${RST}                            Re-verify stale dynamic edges

${DIM}Environment variables:${RST}
  JOERN          path to joern binary           (default: ./joern-cli/joern)
  JOERN_PARSE    path to joern-parse binary     (default: ./joern-cli/joern-parse)
  JAVA_OPTS      JVM options for Joern          (default: -Xmx16g)
  LINUX_SRC      path to kernel source tree
  OUT_DIR        output directory               (default: ./out)
  NEO4J_URI      Neo4j bolt URI                 (default: bolt://localhost:7687)
  NEO4J_USER     Neo4j username                 (default: neo4j)
  NEO4J_PASS     Neo4j password                 (default: neo4j)

EOF
    exit 1
}

export NEO4J_URI NEO4J_USER NEO4J_PASS

case "${1:-}" in
    build)   shift; cmd_build   "$@" ;;
    predict) shift; cmd_predict "$@" ;;
    query)   shift; cmd_query   "$@" ;;
    status)         cmd_status       ;;
    capture) shift; cmd_capture "$@" ;;
    checkup)        cmd_checkup      ;;
    *)              usage            ;;
esac