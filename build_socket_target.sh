#!/usr/bin/env bash
# =============================================================================
# build_socket_target.sh — targeted Nervo build for socket() path analysis
#
# Instead of compiling the whole kernel, this script compiles exactly the
# .c files that sit on the socket(AF_INET, SOCK_STREAM, 0) execution path:
#
#   ① arch/x86/entry/syscalls  →  __x64_sys_socket entry glue
#   ② net/socket.c             →  __sys_socket, sock_create, __sock_create
#   ③ net/ipv4/af_inet.c       →  inet_create, inet_family_ops
#   ④ net/ipv4/tcp_ipv4.c      →  tcp_v4_init_sock, tcp_v4_connect
#   ⑤ net/ipv4/tcp.c           →  tcp_sendmsg, tcp_recvmsg
#   ⑥ net/ipv4/tcp_output.c    →  tcp_write_xmit, tcp_transmit_skb
#   ⑦ net/ipv4/udp.c           →  udp_sendmsg, udp_init_sock
#   ⑧ net/ipv4/ip_output.c     →  ip_local_out, ip_output, ip_finish_output2
#   ⑨ net/ipv4/route.c         →  ip_route_output_flow
#   ⑩ net/core/sock.c          →  sk_alloc, sock_init_data
#   ⑪ net/core/skbuff.c        →  alloc_skb, skb_clone
#   ⑫ net/core/dev.c           →  dev_queue_xmit, __dev_xmit_skb
#   ⑬ net/core/neighbour.c     →  neigh_resolve_output, neigh_hh_output
#
# What this script does
# ---------------------
# 1. Compile each .c file with `make <file>.o` + GCC plugin → TU JSON files
# 2. Run 06_merge_plugin_output.py to deduplicate call edges / fn-ptr assigns
# 3. Symlink all .c files into a staging dir → one joern-parse invocation
# 4. Run 01_extract_nodes.sc + 02_extract_edges.sc
# 5. Run fix_ids.py for globally unique node IDs
# 6. Run 07_extract_constants.py for symbol→value resolution
# 7. Load into Neo4j with 04_load_neo4j.py
# 8. Stitch cross-subsystem edges with 05_stitch_cross_subsystem.py
#
# Usage
# -----
#   ./build_socket_target.sh <linux_src>
#
#   # Override output directory:
#   OUT_DIR=/tmp/nervo_socket ./build_socket_target.sh /opt/linux
#
# Environment
# -----------
#   NERVO_DIR      directory of nervo scripts          (default: script dir)
#   OUT_DIR        output directory                    (default: ./out_socket)
#   JOERN          path to joern binary                (default: joern-cli/joern)
#   JOERN_PARSE    path to joern-parse binary          (default: joern-cli/joern-parse)
#   JAVA_OPTS      JVM heap for Joern                  (default: -Xmx8g)
#   NEO4J_URI      Neo4j bolt URI                      (default: bolt://localhost:7687)
#   NEO4J_USER     Neo4j username                      (default: neo4j)
#   NEO4J_PASS     Neo4j password                      (default: neo4j)
#   SKIP_PLUGIN    set to 1 to skip GCC compilation    (use if plugin already ran)
#   SKIP_JOERN     set to 1 to skip Joern parse        (use if CPG already built)
# =============================================================================

set -euo pipefail

# ── arg ───────────────────────────────────────────────────────────────────────
LINUX_SRC="${1:-}"
[[ -n "$LINUX_SRC" ]] || { echo "Usage: $0 <linux_src>"; exit 1; }
[[ -d "$LINUX_SRC" ]] || { echo "ERROR: linux_src not found: $LINUX_SRC"; exit 1; }
[[ -f "$LINUX_SRC/.config" ]] || {
    echo "ERROR: no .config in $LINUX_SRC — run: make defconfig"
    exit 1
}
LINUX_SRC="$(cd "$LINUX_SRC" && pwd)"   # absolute

# ── env ───────────────────────────────────────────────────────────────────────
NERVO_DIR="${NERVO_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
OUT_DIR="${OUT_DIR:-$NERVO_DIR/out_socket}"
JOERN="${JOERN:-$NERVO_DIR/joern-cli/joern}"
JOERN_PARSE="${JOERN_PARSE:-$NERVO_DIR/joern-cli/joern-parse}"
JAVA_OPTS="${JAVA_OPTS:--Xmx8g}"      # socket path is small — 8 GB is enough
NEO4J_URI="${NEO4J_URI:-bolt://localhost:7687}"
NEO4J_USER="${NEO4J_USER:-neo4j}"
NEO4J_PASS="password"
PLUGIN_SO="$NERVO_DIR/nervo_gcc_plugin.so"

SKIP_PLUGIN="${SKIP_PLUGIN:-0}"
SKIP_JOERN="${SKIP_JOERN:-0}"

# ── output layout ─────────────────────────────────────────────────────────────
PLUGIN_OUT="$OUT_DIR/plugin"   # per-TU JSON files from GCC plugin
STAGE_DIR="$OUT_DIR/src"       # symlinked .c files for joern-parse
CPG_FILE="$OUT_DIR/cpg/socket_path.cpg"
JSON_DIR="$OUT_DIR/json"
GCC_MERGED="$OUT_DIR/gcc_merged.json"
CONSTANTS="$OUT_DIR/constants.json"

mkdir -p "$PLUGIN_OUT" "$STAGE_DIR" "$(dirname "$CPG_FILE")" "$JSON_DIR" "$OUT_DIR/logs"

# ── colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[0;33m'
BLU='\033[0;34m'; DIM='\033[2m'; RST='\033[0m'
log()     { echo -e "${DIM}[socket-build]${RST} $*"; }
success() { echo -e "${GRN}[socket-build]${RST} $*"; }
warn()    { echo -e "${YLW}[socket-build]${RST} $*"; }
error()   { echo -e "${RED}[socket-build]${RST} $*" >&2; }
step()    { echo -e "\n${BLU}══${RST} $* ${BLU}══${RST}"; }
die()     { error "$*"; exit 1; }

# =============================================================================
# THE TARGET FILE LIST
# Each entry is relative to LINUX_SRC.
# Edit this list to add/remove files from the analysis scope.
# =============================================================================
TARGET_FILES=(
    # ① Syscall entry — the macro-generated sys_socket wrapper
    "net/socket.c"

    # ② Protocol family registration + inet_create
    "net/ipv4/af_inet.c"

    # ③ TCP transport layer
    "net/ipv4/tcp_ipv4.c"
    "net/ipv4/tcp.c"
    "net/ipv4/tcp_output.c"
    "net/ipv4/tcp_input.c"

    # ④ UDP transport layer
    "net/ipv4/udp.c"

    # ⑤ IP / network layer — output path
    "net/ipv4/ip_output.c"
    "net/ipv4/ip_forward.c"

    # ⑥ Routing
    "net/ipv4/route.c"

    # ⑦ Socket / sk_buff core
    "net/core/sock.c"
    "net/core/skbuff.c"

    # ⑧ Device queue + qdisc hand-off
    "net/core/dev.c"

    # ⑨ ARP / neighbour cache
    "net/core/neighbour.c"

    # ① VFS and File Descriptor hooks (Sockets are files)
    "fs/file_table.c"
    "fs/read_write.c"
    "fs/fcntl.c"

    # ② Security / LSM hooks (Intercepts socket, bind, etc.)
    "security/security.c"
    "security/selinux/hooks.c"
    "security/apparmor/lsm.c"
    "security/bpf/hooks.c"

    # ③ Extended IPv4 / Core Routing
    "net/ipv4/raw.c"
    "net/ipv4/icmp.c"
    "net/ipv4/fib_frontend.c"
    "net/ipv4/fib_semantics.c"
    "net/ipv4/fib_trie.c"

    # ④ Netlink (Essential for routing and socket config)
    "net/netlink/af_netlink.c"
    "net/netlink/genetlink.c"

    # ⑤ UNIX Sockets (Local IPC, often implicitly invoked)
    "net/unix/af_unix.c"
    "net/unix/garbage.c"

    # ⑥ Core Datagram, Filters (eBPF), and Generic Streams
    "net/core/datagram.c"
    "net/core/filter.c"
    "net/core/request_sock.c"
    "net/core/stream.c"
)

# Verify files exist before we start
MISSING=0
for rel in "${TARGET_FILES[@]}"; do
    if [[ ! -f "$LINUX_SRC/$rel" ]]; then
        warn "  File not found (will skip): $LINUX_SRC/$rel"
        MISSING=$((MISSING + 1))
    fi
done
[[ $MISSING -gt 0 ]] && warn "$MISSING file(s) not found — they will be skipped"

# =============================================================================
# STEP 1 — Compile each file with the GCC plugin
#
# We use `make <file>.o` which re-uses the kernel's own Makefile flags:
#   - all -I include paths
#   - all -D CONFIG_* defines from .config
#   - the same compiler version the kernel expects
#
# The plugin intercepts every call/fn-ptr-assign and writes a TU JSON file
# into PLUGIN_OUT.
# =============================================================================
step "Step 1 — Compile target files with GCC plugin"

if [[ "$SKIP_PLUGIN" == "1" ]]; then
    warn "SKIP_PLUGIN=1 — skipping compilation"
elif [[ ! -f "$PLUGIN_SO" ]]; then
    die "GCC plugin not found: $PLUGIN_SO — run: make -f nervo_plugin.mk"
else
    GCC_FLAGS="-fplugin=$PLUGIN_SO -fplugin-arg-nervo_gcc_plugin-out=$PLUGIN_OUT"

    COMPILED=0
    FAILED_COMPILE=()

    for rel in "${TARGET_FILES[@]}"; do
        abs="$LINUX_SRC/$rel"
        [[ -f "$abs" ]] || continue

        # Kernel make target: strip .c → .o
        obj_target="${rel%.c}.o"

        log "  Compiling $rel..."

        # The kernel Makefile expects to be run from LINUX_SRC.
        # KCFLAGS injects our plugin flags into every cc invocation.
        if make -C "$LINUX_SRC" \
                "$obj_target" \
                KCFLAGS="$GCC_FLAGS" \
                -j1 \
                > "$OUT_DIR/logs/compile_${rel//\//_}.log" 2>&1; then
            COMPILED=$((COMPILED + 1))
        else
            warn "  make failed for $rel — partial output may still be useful"
            FAILED_COMPILE+=("$rel")
        fi
    done

    success "Compiled $COMPILED/${#TARGET_FILES[@]} files"
    if [[ ${#FAILED_COMPILE[@]} -gt 0 ]]; then
        warn "Failed: ${FAILED_COMPILE[*]}"
        warn "Check logs in $OUT_DIR/logs/"
    fi

    # Emit the compiled-files manifest (03_run_pipeline.sh expects it, and
    # derive_subsystems.py can use it if you want to extend the analysis later)
    printf '%s\n' "${TARGET_FILES[@]/#/$LINUX_SRC/}" \
        > "$OUT_DIR/nervo_compiled_files.txt"
    success "Manifest written: $OUT_DIR/nervo_compiled_files.txt"
fi


# =============================================================================
# STEP 2 — Merge GCC plugin TU output
#
# 06_merge_plugin_output.py deduplicates call edges and fn-ptr assignments
# across all the TU JSON files written by the plugin in step 1.
# =============================================================================
step "Step 2 — Merge GCC plugin output"

if [[ -f "$GCC_MERGED" ]]; then
    success "Already merged: $GCC_MERGED (delete to redo)"
elif [[ "$SKIP_PLUGIN" == "1" ]]; then
    # Create an empty merged file so downstream steps don't fail
    echo "[]" > "$GCC_MERGED"
    warn "SKIP_PLUGIN=1 — wrote empty gcc_merged.json"
else
    # Count TU files before deciding
    TU_COUNT=$(find "$PLUGIN_OUT" -maxdepth 1 -name "*.json" | wc -l)
    if [[ "$TU_COUNT" -eq 0 ]]; then
        warn "No TU JSON files in $PLUGIN_OUT"
        warn "This means the plugin either wasn't triggered or wrote to a different dir"
        warn "Creating empty gcc_merged.json — fn-ptr resolutions will be unavailable"
        echo "[]" > "$GCC_MERGED"
    else
        log "Found $TU_COUNT TU JSON files in $PLUGIN_OUT"
        /usr/bin/python3 "$NERVO_DIR/06_merge_plugin_output.py" \
            --linux-src  "$LINUX_SRC" \
            --plugin-out "$PLUGIN_OUT" \
            --merged-out "$GCC_MERGED" \
            --stats \
            2>"$OUT_DIR/logs/merge_plugin.log" \
            || die "06_merge_plugin_output.py failed — see $OUT_DIR/logs/merge_plugin.log"
        success "Merged: $GCC_MERGED"
    fi
fi


# =============================================================================
# STEP 3 — Build Joern staging directory
#
# Create a flat staging directory with symlinks to all target .c files.
# Joern will parse this single directory as one CPG named "socket_path".
#
# Why symlinks rather than copies:
#   - No wasted disk space
#   - CPG paths in nodes will still show the real kernel path
#   - Re-runs pick up edits to the source automatically
#
# Note: Joern's C parser works syntactically — it does NOT need resolved
# includes.  It will warn about unknown types but will still build a correct
# call graph and control flow graph from the function bodies.
# =============================================================================
step "Step 3 — Build Joern staging directory"

for rel in "${TARGET_FILES[@]}"; do
    abs="$LINUX_SRC/$rel"
    [[ -f "$abs" ]] || continue

    # Use a flat name to avoid collisions: net_socket.c, net_ipv4_tcp.c …
    flat="${rel//\//_}"
    link="$STAGE_DIR/$flat"

    if [[ ! -L "$link" ]]; then
        ln -s "$abs" "$link"
        log "  Linked: $flat"
    fi
done

LINKED=$(find "$STAGE_DIR" -maxdepth 1 -name "*.c" | wc -l)
success "Staging dir ready: $LINKED files in $STAGE_DIR"


# =============================================================================
# STEP 4 — joern-parse staging directory → socket_path.cpg
# =============================================================================
step "Step 4 — Joern parse → socket_path.cpg"

if [[ "$SKIP_JOERN" == "1" ]]; then
    warn "SKIP_JOERN=1 — skipping joern-parse"
elif [[ -f "$CPG_FILE" ]]; then
    SIZE=$(stat -c%s "$CPG_FILE" 2>/dev/null || stat -f%z "$CPG_FILE")
    success "CPG already exists: $CPG_FILE ($((SIZE / 1024)) KB) — skipping (delete to rebuild)"
else
    log "Running joern-parse on $STAGE_DIR ..."
    log "(This takes 2–5 minutes for ~15 files)"

    JAVA_TOOL_OPTIONS="$JAVA_OPTS" \
        "$JOERN_PARSE" "$STAGE_DIR" \
            --language C \
            --output "$CPG_FILE" \
            2>"$OUT_DIR/logs/joern_parse.log" \
        || die "joern-parse failed — see $OUT_DIR/logs/joern_parse.log"

    SIZE=$(stat -c%s "$CPG_FILE" 2>/dev/null || stat -f%z "$CPG_FILE")
    success "CPG built: $CPG_FILE ($((SIZE / 1024)) KB)"
fi


# =============================================================================
# STEP 5 — Extract nodes and edges from the CPG
# =============================================================================
step "Step 5 — Extract nodes"

NODES_FILE="$JSON_DIR/nodes_socket_path.json"
EDGES_FILE="$JSON_DIR/edges_socket_path.json"

if [[ -f "$NODES_FILE" ]]; then
    success "Nodes already extracted: $NODES_FILE — skipping"
else
    log "Running 01_extract_nodes.sc..."
    NERVO_CPG_FILE="$CPG_FILE" NERVO_OUT_FILE="$NODES_FILE" \
    JAVA_TOOL_OPTIONS="$JAVA_OPTS" \
        "$JOERN" --script "$NERVO_DIR/01_extract_nodes.sc" \
                 2>"$OUT_DIR/logs/extract_nodes.log" \
        || die "01_extract_nodes.sc failed — see $OUT_DIR/logs/extract_nodes.log"
    success "Nodes written: $NODES_FILE"
fi

step "Step 5b — Extract edges"

if [[ -f "$EDGES_FILE" ]]; then
    success "Edges already extracted: $EDGES_FILE — skipping"
else
    log "Running 02_extract_edges.sc..."
    NERVO_CPG_FILE="$CPG_FILE" NERVO_OUT_FILE="$EDGES_FILE" \
    JAVA_TOOL_OPTIONS="$JAVA_OPTS" \
        "$JOERN" --script "$NERVO_DIR/02_extract_edges.sc" \
                 2>"$OUT_DIR/logs/extract_edges.log" \
        || die "02_extract_edges.sc failed — see $OUT_DIR/logs/extract_edges.log"
    success "Edges written: $EDGES_FILE"
fi


# =============================================================================
# STEP 6 — fix_ids.py
#
# Rewrites Joern node IDs to globally unique integers and merges GCC plugin
# call edges into the edge files.  Output: nodes_all.json + edges_all.json.
# =============================================================================
step "Step 6 — Fix node IDs + merge GCC edges"

if [[ -f "$JSON_DIR/nodes_all.json" ]]; then
    success "nodes_all.json already exists — skipping fix_ids (delete to redo)"
else
    /usr/bin/python3 "$NERVO_DIR/fix_ids.py" \
        --json-dir  "$JSON_DIR" \
        --gcc-merged "$GCC_MERGED" \
        2>"$OUT_DIR/logs/fix_ids.log" \
        || die "fix_ids.py failed — see $OUT_DIR/logs/fix_ids.log"
    success "fix_ids done — nodes_all.json + edges_all.json written"
fi


# =============================================================================
# STEP 7 — Extract kernel constants
#
# Parses include/uapi/ headers for #define / enum values so that
# predict.py can resolve AF_INET→2, SOCK_STREAM→1, etc.
# =============================================================================
step "Step 7 — Extract kernel constants"

if [[ -f "$CONSTANTS" ]]; then
    success "Constants already extracted: $CONSTANTS — skipping"
else
    /usr/bin/python3 "$NERVO_DIR/07_extract_constants.py" "$LINUX_SRC" \
        --out   "$CONSTANTS" \
        --stats \
        2>"$OUT_DIR/logs/constants.log" \
        || die "07_extract_constants.py failed — see $OUT_DIR/logs/constants.log"
    success "Constants extracted: $CONSTANTS"
fi


# =============================================================================
# STEP 8 — Load into Neo4j
# =============================================================================
step "Step 8 — Load into Neo4j"

log "Verifying Neo4j connection at $NEO4J_URI..."
/usr/bin/python3 - <<EOF || die "Cannot reach Neo4j at $NEO4J_URI"
from neo4j import GraphDatabase
d = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "password"))
d.verify_connectivity(); d.close()
print("[socket-build] Neo4j OK")
EOF

# --wipe clears only the socket_path data if you re-run.
# Remove --wipe if you are adding to an existing graph (e.g. layering in more files).
/usr/bin/python3 "$NERVO_DIR/04_load_neo4j.py" \
    --nodes-dir  "$JSON_DIR" \
    --edges-dir  "$JSON_DIR" \
    --constants  "$CONSTANTS" \
    --uri        "$NEO4J_URI" \
    --user       "$NEO4J_USER" \
    --password   "$NEO4J_PASS" \
    --wipe \
    2>"$OUT_DIR/logs/load_neo4j.log" \
    || die "04_load_neo4j.py failed — see $OUT_DIR/logs/load_neo4j.log"
success "Neo4j loaded"


# =============================================================================
# STEP 9 — Stitch cross-subsystem edges
#
# Resolves fn-ptr call sites by matching IndirectCall expressions against
# FnPtrAssignment records (e.g. sock->ops->bind → inet_bind).
# =============================================================================
step "Step 9 — Stitch cross-subsystem edges"

/usr/bin/python3 "$NERVO_DIR/05_stitch_cross_subsystem.py" \
    --max-unresolved 60 \
    --max-unresolved 60 \
    --uri      "$NEO4J_URI" \
    --user     "$NEO4J_USER" \
    --password "$NEO4J_PASS" \
    2>"$OUT_DIR/logs/stitch.log" \
    || die "05_stitch_cross_subsystem.py failed — see $OUT_DIR/logs/stitch.log"
success "Stitching complete"


# =============================================================================
# DONE — print quick-start predict commands
# =============================================================================
echo ""
success "═══════════════════════════════════════════════════════════════"
success " Socket path graph is ready"
success "═══════════════════════════════════════════════════════════════"
echo ""
echo -e "  ${GRN}TCP socket:${RST}"
echo "    ./nervo.sh predict 'socket(AF_INET, SOCK_STREAM, 0)' \\"
echo "        --uri $NEO4J_URI"
echo ""
echo -e "  ${GRN}UDP socket:${RST}"
echo "    ./nervo.sh predict 'socket(AF_INET, SOCK_DGRAM, 0)' \\"
echo "        --uri $NEO4J_URI"
echo ""
echo -e "  ${GRN}Raw query (show all functions loaded):${RST}"
echo "    ./nervo.sh query 'MATCH (f:Function) RETURN f.name, f.file ORDER BY f.name LIMIT 50'"
echo ""
echo -e "  ${GRN}Re-run without recompiling:${RST}"
echo "    SKIP_PLUGIN=1 SKIP_JOERN=1 $0 $LINUX_SRC"
echo ""
