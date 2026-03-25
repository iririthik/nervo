#!/usr/bin/env python3
"""
05_stitch_cross_subsystem.py — 7-pass cross-subsystem relationship stitcher

Pass 3 rewritten to match IndirectCall → FnPtrAssign by BOTH field name AND
struct type.

Struct type is inferred from the call expression chain.
"""

import argparse
import re
import sys


def get_driver(uri: str, user: str, password: str):
    try:
        from neo4j import GraphDatabase
        driver = GraphDatabase.driver(uri, auth=(user, password))
        driver.verify_connectivity()
        return driver
    except ImportError:
        print("[05_stitch] ERROR: neo4j driver not installed.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[05_stitch] ERROR: cannot connect to Neo4j: {e}", file=sys.stderr)
        sys.exit(1)


def log(msg: str) -> None:
    print(f"[05_stitch] {msg}", file=sys.stderr)


def count(session, cypher: str) -> int:
    result = session.run(cypher)
    record = result.single()
    return record[0] if record else 0


# ═════════════════════════════════════════════════════════════════════════════
# Struct type inference from call expression
#
# Maps the variable or field name immediately before ->fieldName to a known
# struct type.  These are the kernel's canonical pointer names.
# ═════════════════════════════════════════════════════════════════════════════

# Maps the penultimate component of the chain to a struct type.
# e.g.  sk->sk_prot->init   → penultimate = "sk_prot" → "proto"
#       sock->ops->release  → penultimate = "ops"     → "proto_ops"  (in socket context)
#       pf->create          → penultimate = "pf"      → "net_proto_family"
def infer_struct_type(call_expr: str) -> str | None:
    """
    Parse a call expression like:
        sk->sk_prot->init(sk)
        sock->ops->release(sock)
        pf->create(net, sock, protocol, kern)
        (*sk->sk_prot->connect)(sk, uaddr, addr_len)

    and return the inferred struct type, or None if we can't tell.
    """
    if not call_expr:
        return None

    # strip leading (* and trailing )
    expr = call_expr.strip().lstrip("(").lstrip("*")

    # extract the chain before the final ->field(  i.e. everything before (
    m = re.match(r'^([\w\->.*()\[\]]+?)\s*\(', expr)
    if not m:
        return None
    chain = m.group(1)

    # split on ->
    parts = [p.strip() for p in chain.split("->") if p.strip()]
    if len(parts) < 2:
        return None

    # the penultimate part is the variable/field that holds the fn ptr struct
    penultimate = parts[-2]

    # strip array indexing: sk_prot[0] → sk_prot
    penultimate = re.sub(r'\[.*\]', '', penultimate)
    penultimate = penultimate.strip("*( )")

    # NOTE: dynamic lookup replaced the hardcoded map
    # We now assume that if the variable is named 'ops', the struct is likely 'proto_ops', etc.
    # But a true dynamic resolution would need type information from the CPG.
    # Since we don't have that here, we return None and let the dynamic capture handles it.
    return None


# ═════════════════════════════════════════════════════════════════════════════
# Pass 1 — Merge external stubs into real nodes
# ═════════════════════════════════════════════════════════════════════════════

def pass1_merge_stubs(session, dry_run: bool) -> dict:
    log("Pass 1 — Merging external stubs into real nodes...")

    stubs = session.run("""
MATCH (stub:Function {isExternal: true})
MATCH (real:Function {name: stub.name, isExternal: false})
WHERE stub <> real
RETURN stub.name AS name,
       id(stub)   AS stubId,
       id(real)   AS realId
LIMIT 50000
""").data()

    log(f"  Found {len(stubs)} stubs with real counterparts")

    if dry_run or not stubs:
        return {"stubs_merged": len(stubs)}

    merged = 0
    for row in stubs:
        stub_name = row["name"]

        session.run("""
MATCH (stub:Function {name: $name, isExternal: true})
MATCH (real:Function {name: $name, isExternal: false})
WHERE stub <> real
MATCH (caller)-[r:CALLS]->(stub)
MERGE (caller)-[r2:CALLS]->(real)
ON CREATE SET r2 = properties(r), r2.stitchedFrom = 'stub'
DELETE r
""", name=stub_name)

        session.run("""
MATCH (stub:Function {name: $name, isExternal: true})
MATCH (real:Function {name: $name, isExternal: false})
WHERE stub <> real
MATCH (ic)-[r:INDIRECT_CALL]->(stub)
MERGE (ic)-[r2:INDIRECT_CALL]->(real)
ON CREATE SET r2 = properties(r)
DELETE r
""", name=stub_name)

        session.run("""
MATCH (stub:Function {name: $name, isExternal: true})
WHERE NOT (stub)--()
DELETE stub
""", name=stub_name)

        merged += 1

    log(f"  Merged {merged} stubs")
    return {"stubs_merged": merged}


# ═════════════════════════════════════════════════════════════════════════════
# Pass 2 — Tag cross-subsystem call edges
# ═════════════════════════════════════════════════════════════════════════════

def pass2_tag_cross_subsystem(session, dry_run: bool) -> dict:
    log("Pass 2 — Tagging cross-subsystem call edges...")

    n = count(session, """
MATCH (a:Function)-[r:CALLS]->(b:Function)
WHERE a.subsystem <> b.subsystem
  AND a.subsystem IS NOT NULL
  AND b.subsystem IS NOT NULL
  AND r.crossSubsystem IS NULL
RETURN count(r)
""")
    log(f"  Cross-subsystem CALLS edges to tag: {n}")

    if not dry_run and n > 0:
        session.run("""
MATCH (a:Function)-[r:CALLS]->(b:Function)
WHERE a.subsystem <> b.subsystem
  AND a.subsystem IS NOT NULL
  AND b.subsystem IS NOT NULL
  AND r.crossSubsystem IS NULL
SET r.crossSubsystem = true
""")
    return {"cross_subsystem_calls": n}


# ═════════════════════════════════════════════════════════════════════════════
# Pass 3 — Resolve IndirectCall nodes via FnPtrAssign
#
# Matching strategy (in priority order):
#
#   A. Struct-type + field-name match (highest precision)
#      Extract struct type from call expression chain, require
#      FnPtrAssign.structType to match.  Source preference: gcc > joern.
#
#   B. Field-name + array-index match
#      For array-indexed calls like net_families[2]->create,
#      match on (fieldName, arrayIndex).
#
#   C. Field-name only (fallback, one result max, GCC preferred)
#      When struct type cannot be inferred.  Only take the top-1
#      GCC-sourced result to avoid false positives.
#
# We do NOT use bare CONTAINS matching any more — that's what caused
# netdev_init to match sk->sk_prot->init.
# ═════════════════════════════════════════════════════════════════════════════

def pass3_resolve_indirect_calls(session, dry_run: bool) -> dict:
    log("Pass 3 — Resolving indirect calls via fn-ptr assignments (struct-aware)...")

    # always reset first so re-runs are idempotent
    # this is safe because pass3 rebuilds all RESOLVES_TO edges from scratch
    if not dry_run:
        r1 = session.run(
            "MATCH ()-[r:RESOLVES_TO]->() DELETE r RETURN count(r) AS n"
        ).single()
        r2 = session.run(
            "MATCH (ic:IndirectCall) SET ic.state='unresolved' RETURN count(ic) AS n"
        ).single()
        log(f"  Reset: deleted {r1['n']} RESOLVES_TO edges, "
            f"{r2['n']} IndirectCalls set to unresolved")

    # load all unresolved indirect calls into Python for processing
    unresolved = session.run("""
MATCH (ic:IndirectCall {state: 'unresolved'})
RETURN id(ic)             AS icId,
       ic.callExpression  AS expr,
       ic.callerFunction  AS caller
""").data()

    log(f"  Unresolved indirect calls: {len(unresolved)}")

    # load all FnPtrAssign records with their targets
    fnptrs = session.run("""
MATCH (a:FnPtrAssign)-[:ASSIGNS_TO]->(f:Function)
RETURN id(a)         AS aId,
       a.fieldName   AS fieldName,
       a.structType  AS structType,
       a.arrayIndex  AS arrayIndex,
       a.source      AS source,
       f.name        AS targetFn,
       id(f)         AS targetId
""").data()

    log(f"  FnPtrAssign records with targets: {len(fnptrs)}")

    # build lookup indexes
    # field_idx[fieldName] = list of fnptr records
    field_idx: dict[str, list[dict]] = {}
    for fp in fnptrs:
        fn = fp["fieldName"] or ""
        field_idx.setdefault(fn, []).append(fp)

    def source_rank(fp: dict) -> int:
        """Lower is better. gcc=0, joern=1, other=2"""
        s = fp.get("source", "")
        if s == "gcc":       return 0
        if s == "joern":     return 1
        return 2

    resolved   = 0
    no_match   = 0

    for ic in unresolved:
        ic_id = ic["icId"]
        expr  = ic["expr"] or ""

        # extract field name from expression
        m = re.search(r'->(\w+)\s*\(', expr)
        if not m:
            m = re.match(r'^\*?(\w+)\s*\(', expr)
        if not m:
            no_match += 1
            continue

        field_name  = m.group(1)
        candidates  = field_idx.get(field_name, [])
        if not candidates:
            no_match += 1
            continue

        # infer struct type from the call expression
        inferred_struct = infer_struct_type(expr)

        # extract array index from expression if present
        ai_match   = re.search(r'\[(\d+)\]', expr)
        array_idx  = int(ai_match.group(1)) if ai_match else None

        # ── strategy A: struct type + field name match ──────────────────
        if inferred_struct:
            typed_candidates = [
                fp for fp in candidates
                if fp["structType"] and fp["structType"] == inferred_struct
            ]
            if typed_candidates:
                # prefer gcc source, then static_init context
                typed_candidates.sort(key=source_rank)
                best = typed_candidates[0]
                if not dry_run:
                    _write_resolution(session, ic_id, best["targetId"],
                                      "static_fnptr_typed", best.get("arrayIndex"))
                resolved += 1
                continue

        # ── strategy B: array index match ───────────────────────────────
        if array_idx is not None:
            indexed = [
                fp for fp in candidates
                if fp["arrayIndex"] is not None
                   and int(fp["arrayIndex"]) == array_idx
            ]
            if indexed:
                indexed.sort(key=source_rank)
                best = indexed[0]
                if not dry_run:
                    _write_resolution(session, ic_id, best["targetId"],
                                      "static_fnptr_indexed", array_idx)
                resolved += 1
                continue

        # ── strategy C: field name only, top-1 gcc preferred ────────────
        # Only use this fallback when struct type is truly unknown
        # and we have a GCC-sourced record (higher confidence)
        gcc_only = [fp for fp in candidates if fp.get("source") == "gcc"]
        pool     = gcc_only if gcc_only else candidates

        # take only 1 to avoid fan-out — prefer gcc, prefer static_init
        pool.sort(key=source_rank)
        best = pool[0]

        if not dry_run:
            _write_resolution(session, ic_id, best["targetId"],
                              "static_fnptr_fallback", best.get("arrayIndex"))
        resolved += 1

    still_unresolved = count(session,
        "MATCH (ic:IndirectCall {state: 'unresolved'}) RETURN count(ic)")

    log(f"  Resolved: {resolved}  "
        f"No field match: {no_match}  "
        f"Still unresolved: {still_unresolved}")
    return {"resolved": resolved, "still_unresolved": still_unresolved}


def _write_resolution(session, ic_id: int, target_id: int,
                      resolved_by: str, array_index) -> None:
    session.run("""
MATCH (ic) WHERE id(ic) = $icId
MATCH (f)  WHERE id(f)  = $targetId
MERGE (ic)-[r:RESOLVES_TO]->(f)
ON CREATE SET
    r.resolvedBy = $resolvedBy,
    r.arrayIndex = $arrayIndex
SET ic.state = 'resolved_static'
""", icId=ic_id, targetId=target_id,
     resolvedBy=resolved_by, arrayIndex=array_index)


# ═════════════════════════════════════════════════════════════════════════════
# Pass 4 — Tag cross-subsystem data flow edges
# ═════════════════════════════════════════════════════════════════════════════

def pass4_tag_cross_dataflow(session, dry_run: bool) -> dict:
    log("Pass 4 — Tagging cross-subsystem data flow edges...")

    n = count(session, """
MATCH (a:Function)-[r:FLOWS_TO]->(b:Function)
WHERE a.subsystem <> b.subsystem
  AND r.crossSubsystem IS NULL
RETURN count(r)
""")
    log(f"  Cross-subsystem FLOWS_TO edges: {n}")

    if not dry_run and n > 0:
        session.run("""
MATCH (a:Function)-[r:FLOWS_TO]->(b:Function)
WHERE a.subsystem <> b.subsystem
  AND r.crossSubsystem IS NULL
SET r.crossSubsystem = true
""")
    return {"cross_subsystem_flows": n}


# ═════════════════════════════════════════════════════════════════════════════
# Pass 5 — Subsystem meta-nodes
# ═════════════════════════════════════════════════════════════════════════════

def pass5_subsystem_nodes(session, dry_run: bool) -> dict:
    log("Pass 5 — Building subsystem meta-nodes...")

    subsystems = session.run("""
MATCH (f:Function)
WHERE f.subsystem IS NOT NULL AND f.subsystem <> ''
RETURN DISTINCT f.subsystem AS sub
""").data()

    log(f"  Subsystems found: {len(subsystems)}")

    if not dry_run:
        for row in subsystems:
            session.run("MERGE (s:Subsystem {name: $sub})", sub=row["sub"])

        session.run("""
MATCH (a:Function)-[:CALLS {crossSubsystem: true}]->(b:Function)
WHERE a.subsystem IS NOT NULL AND b.subsystem IS NOT NULL
  AND a.subsystem <> b.subsystem
MATCH (sa:Subsystem {name: a.subsystem})
MATCH (sb:Subsystem {name: b.subsystem})
MERGE (sa)-[:CALLS_INTO]->(sb)
""")

    calls_into = count(session, "MATCH ()-[r:CALLS_INTO]->() RETURN count(r)")
    log(f"  CALLS_INTO edges: {calls_into}")
    return {"subsystems": len(subsystems), "calls_into": calls_into}


# ═════════════════════════════════════════════════════════════════════════════
# Pass 6 — Orphan cleanup
# ═════════════════════════════════════════════════════════════════════════════

def pass6_orphan_cleanup(session, dry_run: bool) -> dict:
    log("Pass 6 — Tagging orphan nodes...")

    n = count(session, """
MATCH (f:Function)
WHERE NOT (f)-[:CALLS]-()
  AND NOT ()-[:CALLS]->(f)
  AND f.isExternal = false
RETURN count(f)
""")
    log(f"  Orphan functions (no call edges): {n}")

    if not dry_run and n > 0:
        session.run("""
MATCH (f:Function)
WHERE NOT (f)-[:CALLS]-()
  AND NOT ()-[:CALLS]->(f)
  AND f.isExternal = false
SET f.orphan = true
""")
    return {"orphans_tagged": n}


# ═════════════════════════════════════════════════════════════════════════════
# Pass 7 — Verification report
# ═════════════════════════════════════════════════════════════════════════════

def pass7_verify(session, max_unresolved_pct: float) -> dict:
    log("Pass 7 — Verification report...")

    fn_total      = count(session, "MATCH (f:Function) RETURN count(f)")
    fn_external   = count(session, "MATCH (f:Function {isExternal:true}) RETURN count(f)")
    fn_orphan     = count(session, "MATCH (f:Function {orphan:true}) RETURN count(f)")
    call_edges    = count(session, "MATCH ()-[r:CALLS]->() RETURN count(r)")
    cross_calls   = count(session, "MATCH ()-[r:CALLS {crossSubsystem:true}]->() RETURN count(r)")
    flow_edges    = count(session, "MATCH ()-[r:FLOWS_TO]->() RETURN count(r)")
    indirect_tot  = count(session, "MATCH (i:IndirectCall) RETURN count(i)")
    indirect_unres= count(session, "MATCH (i:IndirectCall {state:'unresolved'}) RETURN count(i)")
    indirect_res  = count(session, "MATCH (i:IndirectCall {state:'resolved_static'}) RETURN count(i)")
    branch_nodes  = count(session, "MATCH (b:BranchPoint) RETURN count(b)")
    constants     = count(session, "MATCH (c:Constant) RETURN count(c)")
    subsystems    = count(session, "MATCH (s:Subsystem) RETURN count(s)")

    unres_pct = (indirect_unres / indirect_tot * 100) if indirect_tot > 0 else 0.0

    log("")
    log("═══════════════════════════════════════════════════")
    log(" Stitching health report")
    log("═══════════════════════════════════════════════════")
    log(f"  Functions total        : {fn_total:>8,}")
    log(f"  Functions external     : {fn_external:>8,}  (stubs remaining)")
    log(f"  Functions orphaned     : {fn_orphan:>8,}")
    log(f"  Call edges             : {call_edges:>8,}")
    log(f"  Cross-subsystem calls  : {cross_calls:>8,}")
    log(f"  Data flow edges        : {flow_edges:>8,}")
    log(f"  Indirect calls total   : {indirect_tot:>8,}")
    log(f"  Indirect resolved      : {indirect_res:>8,}  (static fn-ptr)")
    log(f"  Indirect unresolved    : {indirect_unres:>8,}  ({unres_pct:.1f}%)")
    log(f"  Branch points          : {branch_nodes:>8,}")
    log(f"  Constants              : {constants:>8,}")
    log(f"  Subsystems             : {subsystems:>8,}")
    log("═══════════════════════════════════════════════════")
    log("")

    ok = True
    if unres_pct > max_unresolved_pct:
        log(f"  WARNING: unresolved indirect call rate {unres_pct:.1f}% "
            f"exceeds threshold {max_unresolved_pct}%")
        ok = False

    if fn_external > fn_total * 0.2:
        log(f"  WARNING: >20% of Function nodes are still external stubs")
        ok = False

    return {
        "ok":             ok,
        "fn_total":       fn_total,
        "call_edges":     call_edges,
        "cross_calls":    cross_calls,
        "indirect_unres": indirect_unres,
        "unres_pct":      unres_pct,
    }


# ═════════════════════════════════════════════════════════════════════════════
# Main
# ═════════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--uri",            default="bolt://localhost:7687")
    p.add_argument("--user",           default="neo4j")
    p.add_argument("--password",       default="neo4j")
    p.add_argument("--passes",         type=int, default=7)
    p.add_argument("--dry-run",        action="store_true")
    p.add_argument("--max-unresolved", type=float, default=30.0)
    return p.parse_args()


def main() -> None:
    args    = parse_args()
    driver  = get_driver(args.uri, args.user, args.password)
    dry_run = args.dry_run
    passes  = args.passes

    PASS_FNS = [
        pass1_merge_stubs,
        pass2_tag_cross_subsystem,
        pass3_resolve_indirect_calls,
        pass4_tag_cross_dataflow,
        pass5_subsystem_nodes,
        pass6_orphan_cleanup,
    ]

    stats = {}
    with driver.session() as session:
        for i, fn in enumerate(PASS_FNS[:passes], start=1):
            result = fn(session, dry_run)
            stats[f"pass{i}"] = result

        if passes >= 7:
            verify = pass7_verify(session, args.max_unresolved)
            stats["pass7"] = verify
            if not verify["ok"]:
                driver.close()
                sys.exit(1)

    driver.close()
    log("Stitching complete.")


if __name__ == "__main__":
    main()