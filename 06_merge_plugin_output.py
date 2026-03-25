#!/usr/bin/env python3
"""
06_merge_plugin_output.py — deduplicate and merge GCC plugin TU output

Problem
-------
The GCC plugin emits one JSON file per translation unit (TU).  A large kernel
build produces thousands of TU files.  The same call edge can appear in
multiple TUs (e.g. an inlined function gets compiled into every file that
includes it).  Before anything else touches this data, we need one clean,
deduplicated, merged JSON file.

What this script does
---------------------
1. Discovers all *.json TU files in --plugin-out directory.
2. Loads and validates each file.
3. Deduplicates:
     - CallEdge:         unique on (callerFn, calleeFn, file)
     - FnPtrAssignment:  unique on (structType, fieldName, targetFn, arrayIndex)
     - BranchCondition:  unique on (function, conditionLHS, conditionOp, conditionRHSValue)
4. Applies trust rules:
     - If both Joern and GCC emit the same FnPtrAssignment, GCC wins
       (it has the resolved arrayIndex; Joern may have null)
     - BranchCondition from GCC always has resolved RHS integer values —
       never reconstruct from strings
5. Writes one clean gcc_merged.json to --merged-out.

Output format
-------------
[
  { "type": "CallEdge",         "callerFn": ..., "calleeFn": ..., ... },
  { "type": "FnPtrAssignment",  "structType": ..., "fieldName": ..., ... },
  { "type": "BranchCondition",  "function": ..., "conditionOp": ..., ... },
  ...
]

Usage
-----
    python3 06_merge_plugin_output.py \\
        --linux-src  /opt/linux \\
        --plugin-out /opt/nervo/out \\
        --merged-out /opt/nervo/out/gcc_merged.json
"""

import argparse
import json
import os
import sys
from pathlib import Path
from collections import defaultdict


# ── record type keys used for deduplication ───────────────────────────────────

def call_edge_key(r: dict) -> tuple:
    """Unique key for a CallEdge — same call from same file is one edge."""
    return (
        r.get("callerFn", ""),
        r.get("calleeFn", ""),
        r.get("file", ""),
    )

def fnptr_key(r: dict) -> tuple:
    """
    Unique key for a FnPtrAssignment.
    arrayIndex is part of the key — net_families[2] and net_families[10]
    are different assignments even though the structType+fieldName match.
    """
    return (
        r.get("structType") or "",
        r.get("fieldName", ""),
        r.get("targetFn", ""),
        r.get("arrayIndex"),   # None means no index — kept as-is
    )

def branch_key(r: dict) -> tuple:
    """Unique key for a BranchCondition."""
    return (
        r.get("function", ""),
        r.get("conditionLHS", ""),
        r.get("conditionOp", ""),
        r.get("conditionRHSValue"),
    )


# ── validation ────────────────────────────────────────────────────────────────

REQUIRED_FIELDS = {
    "CallEdge":        {"callerFn", "calleeFn", "file"},
    "FnPtrAssignment": {"fieldName", "targetFn", "sourceFile"},
    "BranchCondition": {"function", "conditionOp", "conditionLHS",
                        "conditionRHSValue"},
}

def validate_record(record: dict, tu_file: str) -> bool:
    """Return True if the record has all required fields for its type."""
    rtype = record.get("type")
    if rtype not in REQUIRED_FIELDS:
        return False  # unknown type — skip silently

    required = REQUIRED_FIELDS[rtype]
    missing = required - set(record.keys())
    if missing:
        print(
            f"[06_merge] WARNING: {tu_file}: {rtype} missing fields {missing} — skipped",
            file=sys.stderr,
        )
        return False

    # BranchCondition: conditionRHSValue must be an integer (GCC resolved it)
    if rtype == "BranchCondition":
        val = record.get("conditionRHSValue")
        if val is None or not isinstance(val, (int, float)):
            print(
                f"[06_merge] WARNING: {tu_file}: BranchCondition has "
                f"non-integer conditionRHSValue={val!r} — skipped",
                file=sys.stderr,
            )
            return False

    return True


# ── merge logic ───────────────────────────────────────────────────────────────

def merge_fnptr(existing: dict, incoming: dict) -> dict:
    """
    GCC plugin wins on arrayIndex.
    If existing has arrayIndex=None and incoming has a real index, take incoming.
    Otherwise keep existing (first-seen with a real index wins).
    """
    if existing.get("arrayIndex") is None and incoming.get("arrayIndex") is not None:
        return incoming
    return existing


def process_tu_files(tu_files: list[Path]) -> dict:
    """
    Load, validate, deduplicate all TU JSON files.
    Returns a dict:
      {
        "call_edges":    { key: record },
        "fnptr_assigns": { key: record },
        "branch_conds":  { key: record },
      }
    """
    call_edges:    dict[tuple, dict] = {}
    fnptr_assigns: dict[tuple, dict] = {}
    branch_conds:  dict[tuple, dict] = {}

    total_raw    = 0
    total_skip   = 0
    total_errors = 0

    for tu_path in tu_files:
        try:
            with open(tu_path) as f:
                records = json.load(f)
        except json.JSONDecodeError as e:
            print(f"[06_merge] WARNING: could not parse {tu_path}: {e}", file=sys.stderr)
            total_errors += 1
            continue
        except OSError as e:
            print(f"[06_merge] WARNING: could not read {tu_path}: {e}", file=sys.stderr)
            total_errors += 1
            continue

        if not isinstance(records, list):
            print(f"[06_merge] WARNING: {tu_path}: expected JSON array — skipped", file=sys.stderr)
            total_errors += 1
            continue

        for record in records:
            total_raw += 1

            if not validate_record(record, str(tu_path)):
                total_skip += 1
                continue

            rtype = record.get("type")

            if rtype == "CallEdge":
                key = call_edge_key(record)
                if key not in call_edges:
                    call_edges[key] = record

            elif rtype == "FnPtrAssignment":
                key = fnptr_key(record)
                if key in fnptr_assigns:
                    fnptr_assigns[key] = merge_fnptr(fnptr_assigns[key], record)
                else:
                    fnptr_assigns[key] = record

            elif rtype == "BranchCondition":
                key = branch_key(record)
                if key not in branch_conds:
                    branch_conds[key] = record

    print(
        f"[06_merge] Raw records: {total_raw}  "
        f"Skipped: {total_skip}  "
        f"Parse errors: {total_errors}",
        file=sys.stderr,
    )

    return {
        "call_edges":    call_edges,
        "fnptr_assigns": fnptr_assigns,
        "branch_conds":  branch_conds,
    }


# ── stats helpers ─────────────────────────────────────────────────────────────

def top_callers(call_edges: dict, n: int = 10) -> list[tuple[str, int]]:
    counts: dict[str, int] = defaultdict(int)
    for r in call_edges.values():
        counts[r.get("callerFn", "")] += 1
    return sorted(counts.items(), key=lambda x: -x[1])[:n]

def top_fnptr_structs(fnptr_assigns: dict, n: int = 10) -> list[tuple[str, int]]:
    counts: dict[str, int] = defaultdict(int)
    for r in fnptr_assigns.values():
        st = r.get("structType") or "<no struct>"
        counts[st] += 1
    return sorted(counts.items(), key=lambda x: -x[1])[:n]


# ═════════════════════════════════════════════════════════════════════════════
# CLI
# ═════════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--linux-src",  required=True,
                   help="Root of the kernel source tree")
    p.add_argument("--plugin-out", required=True,
                   help="Directory containing per-TU *.json files from the GCC plugin")
    p.add_argument("--merged-out", required=True,
                   help="Output path for gcc_merged.json")
    p.add_argument("--stats", action="store_true",
                   help="Print extra statistics after merging")
    return p.parse_args()


def main() -> None:
    args   = parse_args()
    plugin_out = Path(args.plugin_out)
    merged_out = Path(args.merged_out)

    if not plugin_out.is_dir():
        print(f"[06_merge] ERROR: plugin-out not found: {plugin_out}", file=sys.stderr)
        sys.exit(1)

    # ── discover TU JSON files ────────────────────────────────────────────
    # The plugin emits files named after the mangled source path, e.g.:
    #   _opt_linux_net_ipv4_tcp.c.json
    # We exclude well-known non-TU files that live in the same directory.
    exclude_names = {
        "gcc_merged.json",
        "nervo_compiled_files.txt",
        "nodes_all.json",
        "edges_all.json",
        "id_registry.json",
        "constants.json",
    }

    tu_files = [
        f for f in plugin_out.glob("*.json")
        if f.name not in exclude_names
           and not f.name.startswith("nodes_")
           and not f.name.startswith("edges_")
    ]

    if not tu_files:
        print(f"[06_merge] ERROR: no TU JSON files found in {plugin_out}", file=sys.stderr)
        sys.exit(1)

    print(f"[06_merge] TU files found: {len(tu_files)}", file=sys.stderr)

    # ── merge ─────────────────────────────────────────────────────────────
    merged = process_tu_files(tu_files)

    call_edges    = merged["call_edges"]
    fnptr_assigns = merged["fnptr_assigns"]
    branch_conds  = merged["branch_conds"]

    # ── assemble final list ───────────────────────────────────────────────
    output: list[dict] = (
        list(call_edges.values())    +
        list(fnptr_assigns.values()) +
        list(branch_conds.values())
    )

    # ── write ─────────────────────────────────────────────────────────────
    merged_out.parent.mkdir(parents=True, exist_ok=True)
    with open(merged_out, "w") as f:
        json.dump(output, f, indent=2)

    print(
        f"[06_merge] Merged output: {merged_out}",
        file=sys.stderr,
    )
    print(
        f"[06_merge] CallEdges: {len(call_edges)}  "
        f"FnPtrAssignments: {len(fnptr_assigns)}  "
        f"BranchConditions: {len(branch_conds)}  "
        f"Total: {len(output)}",
        file=sys.stderr,
    )

    # ── optional stats ────────────────────────────────────────────────────
    if args.stats:
        print("\n[06_merge] Top 10 callers by call edge count:", file=sys.stderr)
        for fn, count in top_callers(call_edges):
            print(f"  {fn:<50} {count}", file=sys.stderr)

        print("\n[06_merge] Top 10 struct types by fn-ptr assignment count:", file=sys.stderr)
        for st, count in top_fnptr_structs(fnptr_assigns):
            print(f"  {st:<50} {count}", file=sys.stderr)
        print("", file=sys.stderr)


if __name__ == "__main__":
    main()
