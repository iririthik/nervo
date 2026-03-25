#!/usr/bin/env python3
"""
04_load_neo4j.py — bulk load nodes and edges into Neo4j

What this does
--------------
Reads nodes_all.json, edges_all.json, and constants.json produced by
fix_ids.py and 07_extract_constants.py, then loads everything into Neo4j
using the Bolt driver in batched transactions.

Load order matters:
  1. Constraints + indexes      (must exist before any data lands)
  2. Function nodes             (everything else references these)
  3. Parameter nodes            (reference Function by name)
  4. BranchPoint nodes          (reference Function by name)
  5. Constant nodes             (standalone — no relationships)
  6. CallEdge relationships     (Function → Function)
  7. DataFlowEdge relationships (Function → Function with arg/param metadata)
  8. IndirectCall nodes         (reference Function by name)
  9. FnPtrAssignment nodes      (reference target Function)
  10. IndirectCallEdge rels     (Function → IndirectCall)

Trust hierarchy
---------------
  source="gcc"   → highest trust (compiled, config-aware)
  source="joern" → high trust (structural, from AST)
  (no source)    → treat as joern

When a CallEdge exists from both sources for the same (caller, callee),
the GCC edge is kept and marked resolvedBy="gcc".  The Joern edge is
merged in — its line number fills in if GCC didn't have one.

Usage
-----
    python3 04_load_neo4j.py \\
        --nodes-dir /opt/nervo/out/json \\
        --edges-dir /opt/nervo/out/json \\
        --constants /opt/nervo/out/constants.json \\
        --uri bolt://localhost:7687 \\
        --user neo4j --password neo4j

Options
-------
  --batch-size N    nodes/edges per transaction  (default: 500)
  --wipe            drop all existing data first (use with care)
  --dry-run         parse and validate but do not write to Neo4j
"""

import argparse
import json
import sys
from pathlib import Path


# ── lazy neo4j import so --dry-run works without the driver installed ─────────
def get_driver(uri: str, user: str, password: str):
    try:
        from neo4j import GraphDatabase
        driver = GraphDatabase.driver(uri, auth=(user, password))
        driver.verify_connectivity()
        return driver
    except ImportError:
        print("[04_load] ERROR: neo4j Python driver not installed. "
              "Run: pip install neo4j", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[04_load] ERROR: cannot connect to Neo4j at {uri}: {e}",
              file=sys.stderr)
        sys.exit(1)


# ═════════════════════════════════════════════════════════════════════════════
# Schema — constraints and indexes
# ═════════════════════════════════════════════════════════════════════════════

SCHEMA_STATEMENTS = [
    # uniqueness constraints (also create backing indexes)
    "CREATE CONSTRAINT fn_name_unique IF NOT EXISTS "
    "FOR (f:Function) REQUIRE f.name IS UNIQUE",

    "CREATE CONSTRAINT const_name_unique IF NOT EXISTS "
    "FOR (c:Constant) REQUIRE c.name IS UNIQUE",

    # lookup indexes
    "CREATE INDEX fn_file_idx IF NOT EXISTS FOR (f:Function) ON (f.file)",
    "CREATE INDEX param_fn_idx IF NOT EXISTS FOR (p:Parameter) ON (p.functionName)",
    "CREATE INDEX branch_fn_idx IF NOT EXISTS FOR (b:BranchPoint) ON (b.function)",
    "CREATE INDEX indirect_caller_idx IF NOT EXISTS "
    "FOR (i:IndirectCall) ON (i.callerFunction)",
    "CREATE INDEX fnptr_target_idx IF NOT EXISTS "
    "FOR (a:FnPtrAssign) ON (a.targetFn)",
]


def apply_schema(session) -> None:
    print("[04_load] Applying schema constraints and indexes...", file=sys.stderr)
    for stmt in SCHEMA_STATEMENTS:
        try:
            session.run(stmt)
        except Exception as e:
            # constraint/index may already exist — not fatal
            print(f"[04_load]   schema warning: {e}", file=sys.stderr)
    print("[04_load] Schema ready", file=sys.stderr)


# ═════════════════════════════════════════════════════════════════════════════
# Wipe
# ═════════════════════════════════════════════════════════════════════════════

def wipe_database(session) -> None:
    print("[04_load] Wiping existing data...", file=sys.stderr)
    session.run("MATCH (n) DETACH DELETE n")
    print("[04_load] Database wiped", file=sys.stderr)


# ═════════════════════════════════════════════════════════════════════════════
# Generic batch loader
# ═════════════════════════════════════════════════════════════════════════════

def batch_run(session, cypher: str, rows: list[dict], batch_size: int,
              label: str) -> int:
    """
    Run a parameterised Cypher statement in batches.
    Returns total rows processed.
    """
    total = 0
    for i in range(0, len(rows), batch_size):
        chunk = rows[i : i + batch_size]
        session.run(cypher, rows=chunk)
        total += len(chunk)
        print(f"\r[04_load]   {label}: {total}/{len(rows)}", end="", file=sys.stderr)
    print(file=sys.stderr)
    return total


# ═════════════════════════════════════════════════════════════════════════════
# Node loaders
# ═════════════════════════════════════════════════════════════════════════════

def load_functions(session, nodes: list[dict], batch_size: int) -> None:
    """
    MERGE on name so re-runs are idempotent.
    GCC-sourced stub nodes fill in only missing properties.
    """
    rows = [
        {
            "name":       n.get("name", ""),
            "fullName":   n.get("fullName", n.get("name", "")),
            "file":       n.get("file", ""),
            "line":       n.get("line", -1),
            "signature":  n.get("signature", ""),
            "isExternal": n.get("isExternal", False),
            "subsystem":  n.get("subsystem", ""),
            "gid":        n.get("id"),
        }
        for n in nodes
        if n.get("nodeType") == "Function" and n.get("name")
    ]

    cypher = """
UNWIND $rows AS row
MERGE (f:Function {name: row.name})
ON CREATE SET
    f.fullName   = row.fullName,
    f.file       = row.file,
    f.line       = row.line,
    f.signature  = row.signature,
    f.isExternal = row.isExternal,
    f.subsystem  = row.subsystem,
    f.gid        = row.gid
ON MATCH SET
    f.fullName   = CASE WHEN f.fullName IS NULL OR f.fullName = ''
                        THEN row.fullName ELSE f.fullName END,
    f.file       = CASE WHEN f.file IS NULL OR f.file = ''
                        THEN row.file ELSE f.file END,
    f.line       = CASE WHEN f.line IS NULL OR f.line = -1
                        THEN row.line ELSE f.line END,
    f.gid        = CASE WHEN f.gid IS NULL THEN row.gid ELSE f.gid END
"""
    batch_run(session, cypher, rows, batch_size, "Functions")


def load_parameters(session, nodes: list[dict], batch_size: int) -> None:
    rows = [
        {
            "functionName": n.get("functionName", ""),
            "name":         n.get("name", ""),
            "position":     n.get("position", -1),
            "typeFullName": n.get("typeFullName", ""),
        }
        for n in nodes
        if n.get("nodeType") == "Parameter" and n.get("functionName")
    ]

    cypher = """
UNWIND $rows AS row
MERGE (p:Parameter {functionName: row.functionName, position: row.position})
ON CREATE SET
    p.name         = row.name,
    p.typeFullName = row.typeFullName
"""
    batch_run(session, cypher, rows, batch_size, "Parameters")


def load_branch_points(session, nodes: list[dict], batch_size: int) -> None:
    rows = [
        {
            "function":          n.get("function", ""),
            "branchType":        n.get("branchType", "if"),
            "conditionOp":       n.get("conditionOp"),
            "conditionLHS":      n.get("conditionLHS"),
            "conditionRHS":      n.get("conditionRHS"),
            "conditionRHSValue": n.get("conditionRHSValue"),
            "rawCondition":      n.get("rawCondition"),
            "source":            n.get("source", "joern"),
            # GCC-sourced BranchPoints carry these resolved fields:
            "conditionRHSLabel": n.get("conditionRHSLabel"),
            "lhsArgPos":         n.get("lhsArgPos", -1),
        }
        for n in nodes
        if n.get("nodeType") == "BranchPoint" and n.get("function") and n.get("conditionLHS") is not None and n.get("conditionOp") is not None 
    ]

    # also accept GCC BranchCondition records mixed into nodes list
    gcc_branches = [
        {
            "function":          r.get("function", ""),
            "branchType":        "if",
            "conditionOp":       r.get("conditionOp"),
            "conditionLHS":      r.get("conditionLHS"),
            "conditionRHS":      str(r.get("conditionRHSValue", "")),
            "conditionRHSValue": r.get("conditionRHSValue"),
            "rawCondition":      None,
            "source":            "gcc",
            "conditionRHSLabel": r.get("conditionRHSLabel", ""),
            "lhsArgPos":         r.get("lhsArgPos", -1),
        }
        for r in nodes
        if r.get("nodeType") == "BranchCondition" and r.get("function") and r.get("conditionLHS") is not None and r.get("conditionOp") is not None 
    ]
    rows.extend(gcc_branches)

    cypher = """
UNWIND $rows AS row
MERGE (b:BranchPoint {
    function:     row.function,
    conditionLHS: row.conditionLHS,
    conditionOp:  row.conditionOp
})
ON CREATE SET b.conditionRHSValue = row.conditionRHSValue
ON CREATE SET
    b.branchType        = row.branchType,
    b.conditionRHS      = row.conditionRHS,
    b.rawCondition      = row.rawCondition,
    b.source            = row.source,
    b.conditionRHSLabel = row.conditionRHSLabel,
    b.lhsArgPos         = row.lhsArgPos
ON MATCH SET
    b.source            = CASE WHEN row.source = 'gcc' THEN 'gcc' ELSE b.source END,
    b.conditionRHSLabel = CASE WHEN row.conditionRHSLabel IS NOT NULL
                               THEN row.conditionRHSLabel ELSE b.conditionRHSLabel END,
    b.lhsArgPos         = CASE WHEN row.lhsArgPos >= 0
                               THEN row.lhsArgPos ELSE b.lhsArgPos END
"""
    batch_run(session, cypher, rows, batch_size, "BranchPoints")


def load_constants(session, constants: list[dict], batch_size: int) -> None:
    rows = [
        {
            "name":   c.get("name", ""),
            "value":  (lambda v: None if v is None or not isinstance(v, (int, float)) else (None if v > 9223372036854775807 or v < -9223372036854775808 else int(v)))(c.get("value", 0)),
            "source": c.get("source", ""),
        }
        for c in constants
        if c.get("name")
    ]

    cypher = """
UNWIND $rows AS row
MERGE (c:Constant {name: row.name})
ON CREATE SET
    c.value  = row.value,
    c.source = row.source
"""
    batch_run(session, cypher, rows, batch_size, "Constants")


def load_indirect_calls(session, nodes: list[dict], batch_size: int) -> None:
    rows = [
        {
            "callerFunction": n.get("callerFunction", ""),
            "callExpression": n.get("callExpression", ""),
            "file":           n.get("file", ""),
            "line":           n.get("line", -1),
        }
        for n in nodes
        if n.get("nodeType") in ("IndirectCall", "IndirectCallEdge")
           and n.get("callerFunction")
    ]

    cypher = """
UNWIND $rows AS row
MERGE (i:IndirectCall {
    callerFunction: row.callerFunction,
    callExpression: row.callExpression
})
ON CREATE SET
    i.file  = row.file,
    i.line  = row.line,
    i.state = 'unresolved'
"""
    batch_run(session, cypher, rows, batch_size, "IndirectCalls")


def load_fnptr_assignments(session, nodes: list[dict], batch_size: int) -> None:
    rows = [
        {
            "structType": n.get("structType"),
            "fieldName":  n.get("fieldName", ""),
            "targetFn":   n.get("targetFn", ""),
            "sourceFile": n.get("sourceFile", n.get("file", "")),
            "line":       n.get("line", -1),
            "arrayIndex": n.get("arrayIndex"),
            "source":     n.get("source", "joern"),
        }
        for n in nodes
        if n.get("nodeType") in ("FnPtrAssignment",)
           and n.get("targetFn")
    ]

    cypher = """
UNWIND $rows AS row
MERGE (a:FnPtrAssign {
    fieldName:  row.fieldName,
    targetFn:   row.targetFn
})
ON CREATE SET
    a.structType = row.structType,
    a.sourceFile = row.sourceFile,
    a.line       = row.line,
    a.source     = row.source,
    a.arrayIndex = row.arrayIndex
ON MATCH SET
    a.source     = CASE WHEN row.source = 'gcc' THEN 'gcc' ELSE a.source END,
    a.arrayIndex = CASE WHEN row.arrayIndex IS NOT NULL
                        THEN row.arrayIndex ELSE a.arrayIndex END
"""
    batch_run(session, cypher, rows, batch_size, "FnPtrAssignments")


# ═════════════════════════════════════════════════════════════════════════════
# Edge loaders
# ═════════════════════════════════════════════════════════════════════════════

def load_call_edges(session, edges: list[dict], batch_size: int) -> None:
    """
    MERGE on (callerFn, calleeFn).
    GCC source wins — if the edge already exists from Joern, we upgrade
    resolvedBy to 'gcc' when a GCC version comes in.
    """
    rows = [
        {
            "callerFn":  e.get("callerFn", ""),
            "calleeFn":  e.get("calleeFn", ""),
            "file":      e.get("file", ""),
            "line":      e.get("line", -1),
            "source":    e.get("source", "joern"),
        }
        for e in edges
        if e.get("edgeType") == "CallEdge"
           and e.get("callerFn") and e.get("calleeFn")
    ]

    cypher = """
UNWIND $rows AS row
MATCH (caller:Function {name: row.callerFn})
MATCH (callee:Function {name: row.calleeFn})
MERGE (caller)-[r:CALLS]->(callee)
ON CREATE SET
    r.file       = row.file,
    r.line       = row.line,
    r.resolvedBy = row.source
ON MATCH SET
    r.resolvedBy = CASE WHEN row.source = 'gcc' THEN 'gcc' ELSE r.resolvedBy END,
    r.line       = CASE WHEN r.line IS NULL OR r.line = -1
                        THEN row.line ELSE r.line END
"""
    batch_run(session, cypher, rows, batch_size, "CallEdges")


def load_dataflow_edges(session, edges: list[dict], batch_size: int) -> None:
    rows = [
        {
            "callerFn":      e.get("callerFn", ""),
            "calleeFn":      e.get("calleeFn", ""),
            "callerArgPos":  e.get("callerArgPos", -1),
            "calleeParamPos":e.get("calleeParamPos", -1),
            "callerArgCode": e.get("callerArgCode", ""),
            "calleeParamName":e.get("calleeParamName", ""),
        }
        for e in edges
        if e.get("edgeType") == "DataFlowEdge"
           and e.get("callerFn") and e.get("calleeFn")
    ]

    cypher = """
UNWIND $rows AS row
MATCH (caller:Function {name: row.callerFn})
MATCH (callee:Function {name: row.calleeFn})
MERGE (caller)-[r:FLOWS_TO {
    callerArgPos:   row.callerArgPos,
    calleeParamPos: row.calleeParamPos
}]->(callee)
ON CREATE SET
    r.callerArgCode    = row.callerArgCode,
    r.calleeParamName  = row.calleeParamName
"""
    batch_run(session, cypher, rows, batch_size, "DataFlowEdges")


def load_indirect_call_edges(session, edges: list[dict],
                             batch_size: int) -> None:
    rows = [
        {
            "callerFn":     e.get("callerFn", ""),
            "callExpr":     e.get("callExpression", ""),
            "file":         e.get("file", ""),
            "line":         e.get("line", -1),
            "argCount":     e.get("argCount", 0),
        }
        for e in edges
        if e.get("edgeType") == "IndirectCallEdge" and e.get("callerFn")
    ]

    cypher = """
UNWIND $rows AS row
MATCH (caller:Function {name: row.callerFn})
MATCH (ic:IndirectCall {
    callerFunction: row.callerFn,
    callExpression: row.callExpr
})
MERGE (caller)-[r:INDIRECT_CALL]->(ic)
ON CREATE SET
    r.file     = row.file,
    r.line     = row.line,
    r.argCount = row.argCount
"""
    batch_run(session, cypher, rows, batch_size, "IndirectCallEdges")


def load_fnptr_resolve_edges(session, nodes: list[dict],
                             batch_size: int) -> None:
    """
    Link FnPtrAssign nodes → target Function nodes.
    Also connects IndirectCall nodes to their resolved Function
    when arrayIndex matches.
    """
    rows = [
        {
            "fieldName":  n.get("fieldName", ""),
            "targetFn":   n.get("targetFn", ""),
            "arrayIndex": n.get("arrayIndex"),
            "source":     n.get("source", "joern"),
        }
        for n in nodes
        if n.get("nodeType") == "FnPtrAssignment" and n.get("targetFn")
    ]

    cypher = """
UNWIND $rows AS row
MATCH (a:FnPtrAssign {fieldName: row.fieldName, targetFn: row.targetFn})
MATCH (f:Function {name: row.targetFn})
MERGE (a)-[r:ASSIGNS_TO]->(f)
ON CREATE SET
    r.resolvedBy = row.source,
    r.arrayIndex = row.arrayIndex
"""
    batch_run(session, cypher, rows, batch_size, "FnPtrAssign→Function edges")


def load_branch_fn_edges(session, batch_size: int) -> None:
    """
    Connect BranchPoint nodes to their containing Function.
    Run after both are loaded.
    """
    print("[04_load]   BranchPoint→Function edges...", end="", file=sys.stderr)
    with session.begin_transaction() as tx:
        tx.run("""
MATCH (b:BranchPoint)
MATCH (f:Function {name: b.function})
MERGE (f)-[:HAS_BRANCH]->(b)
""")
    print(" done", file=sys.stderr)


def load_param_fn_edges(session, batch_size: int) -> None:
    """Connect Function → Parameter nodes."""
    print("[04_load]   Function→Parameter edges...", end="", file=sys.stderr)
    with session.begin_transaction() as tx:
        tx.run("""
MATCH (p:Parameter)
MATCH (f:Function {name: p.functionName})
MERGE (f)-[:HAS_PARAMETER]->(p)
""")
    print(" done", file=sys.stderr)


# ═════════════════════════════════════════════════════════════════════════════
# Main
# ═════════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--nodes-dir",  required=True)
    p.add_argument("--edges-dir",  required=True)
    p.add_argument("--constants",  required=True)
    p.add_argument("--uri",        default="bolt://localhost:7687")
    p.add_argument("--user",       default="neo4j")
    p.add_argument("--password",   default="neo4j")
    p.add_argument("--batch-size", type=int, default=500)
    p.add_argument("--wipe",       action="store_true")
    p.add_argument("--dry-run",    action="store_true")
    return p.parse_args()


def load_json(path: Path) -> list:
    if not path.exists():
        print(f"[04_load] ERROR: file not found: {path}", file=sys.stderr)
        sys.exit(1)
    with open(path) as f:
        return json.load(f)


def main() -> None:
    args = parse_args()
    nodes_dir = Path(args.nodes_dir)
    edges_dir = Path(args.edges_dir)
    batch     = args.batch_size

    nodes     = load_json(nodes_dir / "nodes_all.json")
    edges     = load_json(edges_dir / "edges_all.json")
    constants = load_json(Path(args.constants))

    print(f"[04_load] nodes={len(nodes)}  edges={len(edges)}  "
          f"constants={len(constants)}", file=sys.stderr)

    if args.dry_run:
        print("[04_load] Dry run — not writing to Neo4j", file=sys.stderr)
        return

    driver = get_driver(args.uri, args.user, args.password)

    with driver.session() as session:
        if args.wipe:
            wipe_database(session)

        apply_schema(session)

        print("[04_load] Loading nodes...", file=sys.stderr)
        load_functions(session, nodes, batch)
        load_parameters(session, nodes, batch)
        load_branch_points(session, nodes, batch)
        load_constants(session, constants, batch)
        load_indirect_calls(session, nodes, batch)
        load_fnptr_assignments(session, nodes, batch)

        print("[04_load] Loading edges...", file=sys.stderr)
        load_call_edges(session, edges, batch)
        load_dataflow_edges(session, edges, batch)
        load_indirect_call_edges(session, edges, batch)
        load_fnptr_resolve_edges(session, nodes, batch)

        print("[04_load] Wiring structural relationships...", file=sys.stderr)
        load_branch_fn_edges(session, batch)
        load_param_fn_edges(session, batch)

    driver.close()
    print("[04_load] Done.", file=sys.stderr)


if __name__ == "__main__":
    main()
