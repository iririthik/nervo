#!/usr/bin/env python3
"""
fix_ids.py — assign globally unique node IDs and merge GCC plugin output

What this does
--------------
Joern processes each subsystem separately and assigns node IDs that are
only unique within that subsystem.  Two subsystems can both emit a Function
node with id=42 — this breaks Neo4j loading.

This script:
  1. Reads all nodes_*.json files from --json-dir
  2. Assigns a globally unique integer `id` to every node
  3. Reads all edges_*.json files from --json-dir
  4. Reads --gcc-merged (gcc_merged.json) and converts GCC records into
     the same node/edge format that 04_load_neo4j.py expects:
       - CallEdge        → edge   with edgeType="CallEdge", source="gcc"
       - FnPtrAssignment → node   with nodeType="FnPtrAssignment"
       - BranchCondition → node   with nodeType="BranchCondition"
     GCC records that reference functions not seen by Joern get stub
     Function nodes so that 04_load_neo4j.py can still create the edges.
  5. Writes nodes_all.json and edges_all.json into --json-dir

Output files consumed by 04_load_neo4j.py:
  nodes_all.json  — flat list of all node dicts, each with a unique "id"
  edges_all.json  — flat list of all edge dicts

Usage
-----
    python3 fix_ids.py \\
        --json-dir  /opt/nervo/out/json \\
        --gcc-merged /opt/nervo/out/gcc_merged.json
"""

import argparse
import json
import sys
from pathlib import Path
from collections import defaultdict


# ─────────────────────────────────────────────────────────────────────────────

def load_json_file(path: Path) -> list:
    try:
        with open(path) as f:
            data = json.load(f)
        if not isinstance(data, list):
            print(f"[fix_ids] WARNING: {path.name} is not a JSON array — skipped",
                  file=sys.stderr)
            return []
        return data
    except json.JSONDecodeError as e:
        print(f"[fix_ids] WARNING: could not parse {path.name}: {e}", file=sys.stderr)
        return []
    except OSError as e:
        print(f"[fix_ids] WARNING: could not read {path.name}: {e}", file=sys.stderr)
        return []


# ─────────────────────────────────────────────────────────────────────────────
# Collect nodes from all nodes_*.json files
# ─────────────────────────────────────────────────────────────────────────────

def collect_nodes(json_dir: Path) -> list[dict]:
    node_files = sorted(json_dir.glob("nodes_*.json"))

    # exclude the output file itself in case of re-runs
    node_files = [f for f in node_files if f.name != "nodes_all.json"]

    if not node_files:
        print(f"[fix_ids] ERROR: no nodes_*.json files found in {json_dir}",
              file=sys.stderr)
        sys.exit(1)

    print(f"[fix_ids] Node files: {len(node_files)}", file=sys.stderr)

    all_nodes = []
    for f in node_files:
        records = load_json_file(f)
        print(f"[fix_ids]   {f.name}: {len(records)} records", file=sys.stderr)
        all_nodes.extend(records)

    return all_nodes


# ─────────────────────────────────────────────────────────────────────────────
# Collect edges from all edges_*.json files
# ─────────────────────────────────────────────────────────────────────────────

def collect_edges(json_dir: Path) -> list[dict]:
    edge_files = sorted(json_dir.glob("edges_*.json"))
    edge_files = [f for f in edge_files if f.name != "edges_all.json"]

    if not edge_files:
        print(f"[fix_ids] WARNING: no edges_*.json files found in {json_dir}",
              file=sys.stderr)
        return []

    print(f"[fix_ids] Edge files: {len(edge_files)}", file=sys.stderr)

    all_edges = []
    for f in edge_files:
        records = load_json_file(f)
        print(f"[fix_ids]   {f.name}: {len(records)} records", file=sys.stderr)
        all_edges.extend(records)

    return all_edges


# ─────────────────────────────────────────────────────────────────────────────
# Assign globally unique IDs to all nodes
# ─────────────────────────────────────────────────────────────────────────────

def assign_global_ids(nodes: list[dict]) -> list[dict]:
    """
    Add a globally unique integer `id` field to every node.
    Any existing `id` is overwritten to guarantee uniqueness.
    """
    for gid, node in enumerate(nodes):
        node["id"] = gid
    return nodes


# ─────────────────────────────────────────────────────────────────────────────
# Build a set of function names already known from Joern nodes
# ─────────────────────────────────────────────────────────────────────────────

def known_functions(nodes: list[dict]) -> set[str]:
    return {
        n["name"]
        for n in nodes
        if n.get("nodeType") == "Function" and n.get("name")
    }


# ─────────────────────────────────────────────────────────────────────────────
# Convert GCC merged records into nodes + edges
# ─────────────────────────────────────────────────────────────────────────────

def convert_gcc_records(
    gcc_records: list[dict],
    known_fns: set[str],
) -> tuple[list[dict], list[dict]]:
    """
    Convert the three GCC record types into the node/edge dicts that
    04_load_neo4j.py understands.

    Returns:
        extra_nodes  — FnPtrAssignment nodes, BranchCondition nodes,
                       and stub Function nodes for callers/callees not
                       seen by Joern
        extra_edges  — CallEdge dicts sourced from GCC
    """
    extra_nodes: list[dict] = []
    extra_edges: list[dict] = []

    # track stub functions we've already added so we don't duplicate them
    stub_fns_added: set[str] = set(known_fns)

    def ensure_function_stub(name: str) -> None:
        """Add a minimal stub Function node if the function isn't in the graph."""
        if name and name not in stub_fns_added:
            extra_nodes.append({
                "nodeType":   "Function",
                "name":       name,
                "fullName":   name,
                "file":       "",
                "line":       -1,
                "signature":  "",
                "isExternal": True,
                "subsystem":  "",
                "source":     "gcc_stub",
            })
            stub_fns_added.add(name)

    counts = defaultdict(int)

    for rec in gcc_records:
        rtype = rec.get("type")

        # ── CallEdge ─────────────────────────────────────────────────────
        if rtype == "CallEdge":
            caller = rec.get("callerFn", "")
            callee = rec.get("calleeFn", "")
            if not caller or not callee:
                continue

            ensure_function_stub(caller)
            ensure_function_stub(callee)

            extra_edges.append({
                "edgeType": "CallEdge",
                "callerFn": caller,
                "calleeFn": callee,
                "file":     rec.get("file", ""),
                "line":     rec.get("line", -1),
                "source":   "gcc",
            })
            counts["CallEdge"] += 1

        # ── FnPtrAssignment ───────────────────────────────────────────────
        elif rtype == "FnPtrAssignment":
            target = rec.get("targetFn", "")
            if not target:
                continue

            ensure_function_stub(target)

            extra_nodes.append({
                "nodeType":   "FnPtrAssignment",
                "structType": rec.get("structType"),
                "fieldName":  rec.get("fieldName", ""),
                "targetFn":   target,
                "sourceFile": rec.get("sourceFile", rec.get("file", "")),
                "line":       rec.get("line", -1),
                "arrayIndex": rec.get("arrayIndex"),
                "source":     "gcc",
            })
            counts["FnPtrAssignment"] += 1

        # ── BranchCondition ───────────────────────────────────────────────
        elif rtype == "BranchCondition":
            fn = rec.get("function", "")
            if not fn:
                continue

            ensure_function_stub(fn)

            extra_nodes.append({
                "nodeType":          "BranchCondition",
                "function":          fn,
                "conditionLHS":      rec.get("conditionLHS", ""),
                "conditionOp":       rec.get("conditionOp", ""),
                "conditionRHSValue": rec.get("conditionRHSValue"),
                "conditionRHSLabel": rec.get("conditionRHSLabel", ""),
                "lhsArgPos":         rec.get("lhsArgPos", -1),
                "source":            "gcc",
            })
            counts["BranchCondition"] += 1

    print(
        f"[fix_ids] GCC records converted — "
        f"CallEdges: {counts['CallEdge']}  "
        f"FnPtrAssignments: {counts['FnPtrAssignment']}  "
        f"BranchConditions: {counts['BranchCondition']}  "
        f"Stubs added: {len(stub_fns_added) - len(known_fns)}",
        file=sys.stderr,
    )

    return extra_nodes, extra_edges


# ─────────────────────────────────────────────────────────────────────────────
# Deduplication helpers
# ─────────────────────────────────────────────────────────────────────────────

def dedup_call_edges(edges: list[dict]) -> list[dict]:
    """
    Deduplicate CallEdges on (callerFn, calleeFn).
    GCC source wins over joern when both exist for the same pair.
    """
    seen: dict[tuple, dict] = {}
    for e in edges:
        if e.get("edgeType") != "CallEdge":
            continue
        key = (e.get("callerFn", ""), e.get("calleeFn", ""))
        if key not in seen:
            seen[key] = e
        elif e.get("source") == "gcc" and seen[key].get("source") != "gcc":
            seen[key] = e

    non_call = [e for e in edges if e.get("edgeType") != "CallEdge"]
    return non_call + list(seen.values())


def dedup_fnptr_nodes(nodes: list[dict]) -> list[dict]:
    """
    Deduplicate FnPtrAssignment nodes on (fieldName, targetFn, arrayIndex).
    GCC source wins.
    """
    seen: dict[tuple, dict] = {}
    other: list[dict] = []

    for n in nodes:
        if n.get("nodeType") != "FnPtrAssignment":
            other.append(n)
            continue
        key = (n.get("fieldName", ""), n.get("targetFn", ""), n.get("arrayIndex"))
        if key not in seen:
            seen[key] = n
        elif n.get("source") == "gcc" and seen[key].get("source") != "gcc":
            seen[key] = n

    return other + list(seen.values())


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--json-dir",   required=True,
                   help="Directory containing nodes_*.json and edges_*.json")
    p.add_argument("--gcc-merged", required=True,
                   help="Path to gcc_merged.json produced by 06_merge_plugin_output.py")
    return p.parse_args()


def main() -> None:
    args     = parse_args()
    json_dir = Path(args.json_dir)
    gcc_path = Path(args.gcc_merged)

    if not json_dir.is_dir():
        print(f"[fix_ids] ERROR: json-dir not found: {json_dir}", file=sys.stderr)
        sys.exit(1)

    # ── 1. collect Joern nodes + edges ────────────────────────────────────
    joern_nodes = collect_nodes(json_dir)
    joern_edges = collect_edges(json_dir)

    print(
        f"[fix_ids] Joern totals — nodes: {len(joern_nodes)}  "
        f"edges: {len(joern_edges)}",
        file=sys.stderr,
    )

    # ── 2. load GCC merged records ────────────────────────────────────────
    if gcc_path.exists():
        gcc_records = load_json_file(gcc_path)
        print(f"[fix_ids] GCC merged records: {len(gcc_records)}", file=sys.stderr)
    else:
        print(f"[fix_ids] WARNING: gcc_merged.json not found at {gcc_path} — "
              f"skipping GCC merge", file=sys.stderr)
        gcc_records = []

    # ── 3. convert GCC records → nodes + edges ────────────────────────────
    known_fns   = known_functions(joern_nodes)
    gcc_nodes, gcc_edges = convert_gcc_records(gcc_records, known_fns)

    # ── 4. merge and deduplicate ──────────────────────────────────────────
    all_nodes = joern_nodes + gcc_nodes
    all_edges = joern_edges + gcc_edges

    all_edges = dedup_call_edges(all_edges)
    all_nodes = dedup_fnptr_nodes(all_nodes)

    # ── 5. assign globally unique IDs ─────────────────────────────────────
    all_nodes = assign_global_ids(all_nodes)

    # ── 6. write output ───────────────────────────────────────────────────
    nodes_out = json_dir / "nodes_all.json"
    edges_out = json_dir / "edges_all.json"

    with open(nodes_out, "w") as f:
        json.dump(all_nodes, f, indent=2)

    with open(edges_out, "w") as f:
        json.dump(all_edges, f, indent=2)

    # ── summary ───────────────────────────────────────────────────────────
    node_counts: dict[str, int] = defaultdict(int)
    for n in all_nodes:
        node_counts[n.get("nodeType", "unknown")] += 1

    edge_counts: dict[str, int] = defaultdict(int)
    for e in all_edges:
        edge_counts[e.get("edgeType", "unknown")] += 1

    print(f"\n[fix_ids] ── Output ──────────────────────────────────", file=sys.stderr)
    print(f"[fix_ids]   nodes_all.json : {len(all_nodes)} nodes", file=sys.stderr)
    for nt, count in sorted(node_counts.items()):
        print(f"[fix_ids]     {nt:<25} {count}", file=sys.stderr)

    print(f"[fix_ids]   edges_all.json : {len(all_edges)} edges", file=sys.stderr)
    for et, count in sorted(edge_counts.items()):
        print(f"[fix_ids]     {et:<25} {count}", file=sys.stderr)

    print(f"[fix_ids] Done.", file=sys.stderr)


if __name__ == "__main__":
    main()