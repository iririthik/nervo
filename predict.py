#!/usr/bin/env python3
"""
predict.py — syscall path predictor

Takes a syscall expression like:
    socket(AF_INET, SOCK_STREAM, 0)

and traces the kernel execution path through the Neo4j graph.

Usage
-----
    python3 predict.py \\
        --syscall 'socket(AF_INET, SOCK_STREAM, 0)' \\
        --uri bolt://localhost:7687 \\
        --user neo4j --password neo4j

Options
-------
  --max-depth N     stop at this call depth            (default: 30)
  --max-steps N     stop after this many total steps   (default: 500)
  --compact         print only architectural spine
  --no-dynamic      disable bpftrace fallback
  --json            machine-readable JSON output
"""

import argparse
import importlib.util
import json
import re
import sys
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ═════════════════════════════════════════════════════════════════════════════
# Data structures
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class PathStep:
    depth:        int
    function:     str
    via:          str
    resolved:     dict
    pruned:       bool = False
    prune_reason: str  = ""


@dataclass
class PredictResult:
    syscall:         str
    raw_args:        list[str]
    resolved_args:   dict[str, int]
    path:            list[PathStep]
    pruned_branches: list[PathStep]
    unresolved:      list[str]
    dynamic_hits:    list[str]


# ═════════════════════════════════════════════════════════════════════════════
# Syscall expression parser
# ═════════════════════════════════════════════════════════════════════════════

def parse_syscall(expr: str) -> tuple[str, list[str]]:
    expr = expr.strip()
    m = re.match(r'^(\w+)\s*\((.*)\)\s*$', expr, re.DOTALL)
    if not m:
        raise ValueError(f"Cannot parse syscall expression: {expr!r}")
    name     = m.group(1)
    args_raw = [a.strip() for a in m.group(2).split(',') if a.strip()]
    return name, args_raw


def resolve_args(raw_args: list[str], constants: dict[str, int]) -> dict[str, int]:
    resolved: dict[str, int] = {}
    for i, arg in enumerate(raw_args):
        key = f"arg{i}"
        try:
            resolved[key] = int(arg, 0)
        except ValueError:
            if arg in constants:
                resolved[key]  = constants[arg]
                resolved[arg]  = constants[arg]
            else:
                resolved[key] = None
    return resolved


# ═════════════════════════════════════════════════════════════════════════════
# Neo4j query helpers
# ═════════════════════════════════════════════════════════════════════════════

class Graph:
    def __init__(self, driver):
        self._driver  = driver
        self._session = driver.session()

    def close(self):
        self._session.close()

    def get_constants(self) -> dict[str, int]:
        result = self._session.run(
            "MATCH (c:Constant) RETURN c.name AS name, c.value AS value"
        )
        return {r["name"]: r["value"] for r in result
                if r["name"] and r["value"] is not None}

    def function_exists(self, name: str) -> bool:
        r = self._session.run(
            "MATCH (f:Function {name: $name}) RETURN count(f) AS n", name=name
        ).single()
        return r and r["n"] > 0

    def direct_callees(self, fn_name: str) -> list[dict]:
        result = self._session.run("""
MATCH (f:Function {name: $name})-[r:CALLS]->(callee:Function)
RETURN callee.name      AS callee,
       r.file           AS file,
       r.line           AS line,
       r.resolvedBy     AS resolvedBy,
       r.crossSubsystem AS crossSubsystem
""", name=fn_name)
        return result.data()

    def branch_points(self, fn_name: str) -> list[dict]:
        result = self._session.run("""
MATCH (f:Function {name: $name})-[:HAS_BRANCH]->(b:BranchPoint)
RETURN b.conditionLHS      AS lhs,
       b.conditionOp       AS op,
       b.conditionRHSValue AS rhsValue,
       b.conditionRHSLabel AS rhsLabel,
       b.lhsArgPos         AS lhsArgPos,
       b.source            AS source
""", name=fn_name)
        return result.data()

    def indirect_calls(self, fn_name: str) -> list[dict]:
        result = self._session.run("""
MATCH (f:Function {name: $name})-[:INDIRECT_CALL]->(ic:IndirectCall)
OPTIONAL MATCH (ic)-[r:RESOLVES_TO]->(target:Function)
RETURN ic.callExpression AS ptr,
       ic.state          AS state,
       ic.file           AS file,
       ic.line           AS line,
       target.name       AS resolvedTarget,
       r.resolvedBy      AS resolvedBy,
       r.arrayIndex      AS arrayIndex
""", name=fn_name)
        return result.data()

    def flows_to(self, caller: str, callee: str) -> list[dict]:
        result = self._session.run("""
MATCH (a:Function {name: $caller})-[r:FLOWS_TO]->(b:Function {name: $callee})
RETURN r.callerArgPos    AS callerArgPos,
       r.calleeParamPos  AS calleeParamPos,
       r.callerArgCode   AS callerArgCode,
       r.calleeParamName AS calleeParamName
""", caller=caller, callee=callee)
        return result.data()

    def bulk_caller_counts(self, threshold: int = 20) -> set[str]:
        """
        Return the set of functions that have MORE than `threshold` distinct
        callers in the graph.  These are infrastructure/glue functions
        (spin_lock, kmalloc, IS_ERR, etc.) — not architectural call targets.

        We compute this once at traversal start and cache it.
        The query is O(edges) and fast on any reasonable graph.
        """
        result = self._session.run("""
MATCH (caller:Function)-[:CALLS]->(callee:Function)
WITH callee, count(DISTINCT caller) AS n
WHERE n > $threshold
RETURN callee.name AS name
""", threshold=threshold)
        return {r["name"] for r in result if r["name"]}

    def fnptr_candidates(self, field_name: str, array_index=None) -> list[dict]:
        if array_index is not None:
            result = self._session.run("""
MATCH (a:FnPtrAssign {fieldName: $field, arrayIndex: $idx})-[:ASSIGNS_TO]->(f:Function)
RETURN f.name AS targetFn, a.source AS source
LIMIT 1
""", field=field_name, idx=array_index)
        else:
            result = self._session.run("""
MATCH (a:FnPtrAssign {fieldName: $field})-[:ASSIGNS_TO]->(f:Function)
RETURN f.name AS targetFn, a.source AS source
ORDER BY CASE a.source WHEN 'gcc' THEN 0 ELSE 1 END
LIMIT 1
""", field=field_name)
        return result.data()


# ═════════════════════════════════════════════════════════════════════════════
# Branch evaluator
# ═════════════════════════════════════════════════════════════════════════════

OPS = {
    "==": lambda a, b: a == b,
    "!=": lambda a, b: a != b,
    "<":  lambda a, b: a <  b,
    "<=": lambda a, b: a <= b,
    ">":  lambda a, b: a >  b,
    ">=": lambda a, b: a >= b,
}

def evaluate_branch(branch: dict, resolved: dict) -> bool | None:
    op        = branch.get("op")
    lhs_name  = branch.get("lhs")
    rhs_val   = branch.get("rhsValue")
    lhs_pos   = branch.get("lhsArgPos", -1)

    if op not in OPS or rhs_val is None:
        return None

    lhs_val = None
    if lhs_name and lhs_name in resolved:
        lhs_val = resolved[lhs_name]
    if lhs_val is None and lhs_pos >= 0:
        lhs_val = resolved.get(f"arg{lhs_pos}")
    if lhs_val is None:
        return None

    try:
        return OPS[op](int(lhs_val), int(rhs_val))
    except (TypeError, ValueError):
        return None


# ═════════════════════════════════════════════════════════════════════════════
# Argument propagation
# ═════════════════════════════════════════════════════════════════════════════

def propagate_args(caller_resolved: dict, flows: list[dict]) -> dict:
    callee_resolved: dict = {}

    for flow in flows:
        caller_pos = flow.get("callerArgPos", -1)
        callee_pos = flow.get("calleeParamPos", -1)
        param_name = flow.get("calleeParamName", "")
        if caller_pos < 0 or callee_pos < 0:
            continue
        val = caller_resolved.get(f"arg{caller_pos}")
        if val is None:
            continue
        callee_resolved[f"arg{callee_pos}"] = val
        if param_name:
            callee_resolved[param_name] = val

    # carry named values (AF_INET, SOCK_STREAM etc) through
    for k, v in caller_resolved.items():
        if not k.startswith("arg") and k not in callee_resolved:
            callee_resolved[k] = v

    # fix for FLOWS_TO position mismatch: if a callee param name exists
    # as a named key in the caller, prefer that over the position mapping.
    # This corrects cases like sock_create->__sock_create where the extra
    # net argument shifts all positions by one.
    for flow in flows:
        param_name = flow.get("calleeParamName", "")
        if param_name and param_name in caller_resolved:
            callee_resolved[param_name] = caller_resolved[param_name]
            callee_resolved[f"arg{flow.get('calleeParamPos', -1)}"] = caller_resolved[param_name]

    return callee_resolved


# ═════════════════════════════════════════════════════════════════════════════
# Field name / array index extraction
# ═════════════════════════════════════════════════════════════════════════════

def extract_field_name(call_expr: str) -> str | None:
    m = re.search(r'->(\w+)\s*\(', call_expr)
    if m:
        return m.group(1)
    m = re.match(r'^\*?(\w+)\s*\(', call_expr)
    if m:
        return m.group(1)
    return None

def match_array_index(call_expr: str, resolved: dict, graph_index):
    m = re.search(r'\[(\w+)\]', call_expr)
    if m:
        var = m.group(1)
        if var in resolved and resolved[var] is not None:
            return resolved[var]
    m = re.search(r'\[(\d+)\]', call_expr)
    if m:
        return int(m.group(1))
    # for sk->sk_prot->X calls, use the carried socket type as array index
    # this lets us select tcp_prot (type=1) vs udp_prot (type=2) correctly
    if "sk_prot" in call_expr or "->prot->" in call_expr:
        t = resolved.get("type")
        if t is not None:
            return t
    return graph_index


# ═════════════════════════════════════════════════════════════════════════════
# Core traversal — iterative BFS, cannot loop
#
# Uses an explicit queue instead of recursion.
# visited set is keyed on function name only — once a function is visited
# it is never visited again regardless of argument values.
# Hard limits on depth and total steps prevent any fan-out explosion.
# ═════════════════════════════════════════════════════════════════════════════

def traverse(
    graph:              Graph,
    entry_fn:           str,
    entry_resolved:     dict,
    max_depth:          int  = 30,
    max_steps:          int  = 500,
    dynamic_resolve          = None,
    infra_threshold:    int  = 20,
) -> tuple[list[PathStep], list[PathStep], list[str], list[str]]:
    """
    Iterative BFS traversal.

    infra_threshold — functions with more than this many distinct callers
                      in the graph are treated as infrastructure and skipped.
                      Tune lower (e.g. 10) for stricter filtering,
                      higher (e.g. 50) to follow more of the allocator path.

    Returns:
        path             — ordered list of PathStep
        pruned_branches  — branches that were cut
        unresolved       — indirect call sites with no target
        dynamic_hits     — sites resolved via bpftrace
    """
    # ── build infrastructure set dynamically from the graph ───────────────
    # Functions with many callers are glue (spin_lock, kmalloc, IS_ERR …).
    # We never follow them — they produce noise without adding path insight.
    infra: set[str] = graph.bulk_caller_counts(infra_threshold)
    print(f"[traverse] infrastructure functions filtered: {len(infra)}", file=__import__('sys').stderr)

    path:            list[PathStep] = []
    pruned_branches: list[PathStep] = []
    unresolved:      list[str]      = []
    dynamic_hits:    list[str]      = []

    # visited: function name → depth first seen at
    # once seen, never revisit
    visited: dict[str, int] = {}

    # queue items: (fn_name, depth, via, resolved_dict)
    queue: deque = deque()
    queue.append((entry_fn, 0, "syscall entry", entry_resolved))

    while queue:
        if len(path) >= max_steps:
            break

        fn_name, depth, via, resolved = queue.popleft()

        # hard guards
        if depth > max_depth:
            continue
        if fn_name in visited:
            continue
        visited[fn_name] = depth

        # record step
        path.append(PathStep(
            depth=depth, function=fn_name, via=via, resolved=dict(resolved)
        ))

        # ── branch evaluation ─────────────────────────────────────────────
        branches       = graph.branch_points(fn_name)
        pruned_callees: set[str] = set()
        for branch in branches:
            if evaluate_branch(branch, resolved) is False:
                rhs_label = branch.get("rhsLabel", "")
                if rhs_label:
                    pruned_callees.add(rhs_label)

        # ── direct callees ────────────────────────────────────────────────
        for callee_row in graph.direct_callees(fn_name):
            callee_name = callee_row["callee"]

            if callee_name in visited:
                continue

            if callee_name in infra:
                continue

            if callee_name in pruned_callees:
                pruned_branches.append(PathStep(
                    depth=depth + 1,
                    function=callee_name,
                    via="pruned: branch mismatch",
                    resolved=dict(resolved),
                    pruned=True,
                    prune_reason="branch condition excluded",
                ))
                continue

            flows           = graph.flows_to(fn_name, callee_name)
            callee_resolved = propagate_args(resolved, flows)
            via_str         = "direct call"
            if callee_row.get("crossSubsystem"):
                via_str = "direct call [cross-subsystem]"

            queue.append((callee_name, depth + 1, via_str, callee_resolved))

        # ── indirect calls ────────────────────────────────────────────────
        for ic in graph.indirect_calls(fn_name):
            ptr       = ic.get("ptr", "")
            target    = ic.get("resolvedTarget")
            array_idx = ic.get("arrayIndex")

            if target and target not in visited and target not in infra:
                flows           = graph.flows_to(fn_name, target)
                callee_resolved = propagate_args(resolved, flows)
                via_str         = f"fn_ptr: {ptr} [static_fnptr]"
                queue.append((target, depth + 1, via_str, callee_resolved))
                continue

            # try to resolve from graph by field name
            field_name = extract_field_name(ptr)
            if field_name:
                resolved_idx = match_array_index(ptr, resolved, array_idx)
                candidates   = graph.fnptr_candidates(field_name, resolved_idx)
                if candidates:
                    # take only the best candidate (GCC-sourced wins)
                    cand        = candidates[0]
                    callee_name = cand["targetFn"]
                    if callee_name not in visited:
                        flows           = graph.flows_to(fn_name, callee_name)
                        callee_resolved = propagate_args(resolved, flows)
                        via_str         = f"fn_ptr: {ptr} [graph]"
                        queue.append((callee_name, depth + 1, via_str, callee_resolved))
                    continue

            # dynamic capture fallback
            if dynamic_resolve:
                resolved_fn = dynamic_resolve(
                    call_site=ptr, syscall=fn_name, args=resolved
                )
                if resolved_fn and resolved_fn not in visited:
                    dynamic_hits.append(ptr)
                    flows           = graph.flows_to(fn_name, resolved_fn)
                    callee_resolved = propagate_args(resolved, flows)
                    queue.append((resolved_fn, depth + 1,
                                  f"fn_ptr: {ptr} [dynamic]", callee_resolved))
                    continue

            # genuinely unresolved
            if ptr not in unresolved:
                unresolved.append(ptr)
            path.append(PathStep(
                depth=depth + 1,
                function=f"[UNRESOLVED] {ptr}",
                via="indirect — no target found",
                resolved={},
            ))

    return path, pruned_branches, unresolved, dynamic_hits


# ═════════════════════════════════════════════════════════════════════════════
# Noise filter for compact output
# ═════════════════════════════════════════════════════════════════════════════

_NOISE_PREFIXES = (
    "__builtin_", "_raw_", "refcount_", "atomic_", "this_cpu_",
    "READ_ONCE", "WRITE_ONCE", "unlikely", "likely", "IS_ERR", "PTR_ERR",
    "ERR_PTR", "BUILD_BUG", "WARN_", "BUG_", "pr_", "_printk",
    "spin_lock", "spin_unlock", "mutex_lock", "mutex_unlock",
    "rcu_read_lock", "rcu_read_unlock", "__rcu_read",
    "down_write", "up_write", "down_read", "up_read",
    "get_current", "current_", "jiffies", "kmalloc", "kfree", "kzalloc",
    "SOCK_INODE", "iput", "inode_", "alloc_inode", "new_inode",
)
_NOISE_EXACT = {
    "before", "after", "check_net", "get_next_ino",
}

def _is_noise(fn: str) -> bool:
    if fn in _NOISE_EXACT:
        return True
    for p in _NOISE_PREFIXES:
        if fn.startswith(p):
            return True
    return False


# ═════════════════════════════════════════════════════════════════════════════
# Output formatters
# ═════════════════════════════════════════════════════════════════════════════

def format_pretty(result: PredictResult) -> str:
    import sys as _sys, re as _re
    _tty = _sys.stdout.isatty()
    def _c(code, s): return f"{code}{s}\033[0m" if _tty else s
    DIM="\\033[2m"; BOLD="\\033[1m"; YLW="\\033[0;33m"
    RED="\\033[0;31m"; CYN="\\033[0;36m"; GRN="\\033[0;32m"; MAG="\\033[0;35m"

    lines = []
    EQ = "═" * 70

    arg_parts = []
    for i, raw in enumerate(result.raw_args):
        val = result.resolved_args.get(f"arg{i}")
        arg_parts.append(f"{raw}={val}" if val is not None else raw)

    lines.append(_c(BOLD, EQ))
    lines.append(_c(BOLD, f"  {result.syscall}({', '.join(arg_parts)})"))
    lines.append(_c(DIM, EQ))
    lines.append("")

    steps = [s for s in result.path if not s.pruned]

    def has_children(idx):
        return idx + 1 < len(steps) and steps[idx + 1].depth > steps[idx].depth

    pruned_by_parent = {}
    for ps in result.pruned_branches:
        parent = next((s.function for s in reversed(steps)
                       if s.depth == ps.depth - 1), "?")
        pruned_by_parent.setdefault((parent, ps.depth), []).append(ps)
    printed_pruned = set()

    open_stack = []
    INDENT = "  "

    for idx, step in enumerate(steps):
        depth, fn, via = step.depth, step.function, step.via
        pad = INDENT * depth

        while open_stack and open_stack[-1][0] >= depth:
            d, _ = open_stack.pop()
            lines.append(INDENT * d + "}")

        ann = ""
        if "fn_ptr" in via:
            expr = _re.sub(r'\[(graph|static_fnptr|dynamic)\]', '', via.split("fn_ptr:")[-1]).strip()
            src  = "graph" if "[graph]" in via else "static" if "[static_fnptr]" in via else "dynamic"
            ann  = _c(MAG, f"  /* fn_ptr → {expr} [{src}] */")
        elif "cross-subsystem" in via:
            ann = _c(CYN, "  /* cross-subsystem */")

        if fn.startswith("[UNRESOLVED]"):
            expr = fn.replace("[UNRESOLVED]", "").strip()
            lines.append(pad + _c(RED, f"[UNRESOLVED] {expr}();") + _c(DIM, "  /* no target */"))
            continue

        pk = (steps[idx-1].function if idx > 0 else "?", depth)
        if pk in pruned_by_parent and pk not in printed_pruned:
            printed_pruned.add(pk)
            names = ", ".join(p.function for p in pruned_by_parent[pk])
            lines.append(pad + _c(YLW, f"✂  /* alt path pruned → {names} */"))

        is_leaf = not has_children(idx)
        if is_leaf:
            line = f"{pad}{_c(GRN, fn)}();{ann}" if depth > 0 else _c(BOLD, f"{fn}();") + ann
        else:
            line = (f"{pad}{fn}() {{{ann}" if depth > 0
                    else _c(BOLD, f"{fn}() {{") + ann)
            open_stack.append((depth, fn))
        lines.append(line)

    while open_stack:
        d, _ = open_stack.pop()
        lines.append(INDENT * d + "}")

    if result.pruned_branches:
        lines.append("")
        lines.append(_c(YLW, "── Pruned alternative paths " + "─" * 42))
        by_parent = {}
        for ps in result.pruned_branches:
            p = next((s.function for s in reversed(steps) if s.depth == ps.depth-1), "?")
            by_parent.setdefault(p, []).append(ps.function)
        for p, fns in by_parent.items():
            lines.append(f"  {_c(DIM, p)}() excluded:")
            for fn in fns:
                lines.append(f"    {_c(YLW,'✂')}  {fn}()")

    if result.unresolved:
        lines.append("")
        lines.append(_c(RED, "── Unresolved indirect call sites " + "─" * 36))
        for u in result.unresolved:
            lines.append(f"  {_c(RED,'?')}  {u}")

    lines.append("")
    lines.append(_c(DIM, "─" * 70))
    lines.append(f"  Steps: {len(result.path)}   Pruned: {len(result.pruned_branches)}"
                 f"   Unresolved: {len(result.unresolved)}"
                 + (f"   Dynamic: {len(result.dynamic_hits)}" if result.dynamic_hits else ""))
    lines.append(_c(DIM, "─" * 70))
    return "\\n".join(lines)


def format_ftrace(result: PredictResult) -> str:
    """
    Render the predicted call path in Linux function_graph tracer style:

        |  __sys_socket() {
        |    __sock_create() {
        |      security_socket_create();          /* direct */
        |    }
        |    inet_create();                       /* fn_ptr: pf->create [static] */
        |  }

    Annotations:
      green  — direct call (leaf)
      magenta — fn_ptr resolved (static or graph)
      cyan   — fn_ptr resolved (dynamic / bpftrace)
      red    — UNRESOLVED indirect call site
      yellow — pruned alternative path
    """
    import sys as _sys, re as _re
    _tty = _sys.stdout.isatty()

    # ── ANSI helpers ──────────────────────────────────────────────────────
    RST  = "\033[0m"
    BOLD = "\033[1m"
    DIM  = "\033[2m"
    GRN  = "\033[0;32m"
    RED  = "\033[0;31m"
    YLW  = "\033[0;33m"
    CYN  = "\033[0;36m"
    MAG  = "\033[0;35m"
    WHT  = "\033[0;37m"

    def c(code, s):
        return f"{code}{s}{RST}" if _tty else s

    PIPE      = c(DIM, "|")
    UNIT_W    = 2     # spaces per depth level
    COL_PIPE  = 2     # column where the pipe lives

    lines = []

    # ── header ────────────────────────────────────────────────────────────
    arg_parts = []
    for i, raw in enumerate(result.raw_args):
        val = result.resolved_args.get(f"arg{i}")
        arg_parts.append(f"{raw}={val}" if val is not None else raw)

    sep = c(DIM, "─" * 70)
    lines.append(sep)
    lines.append(c(BOLD, f"  {result.syscall}({', '.join(arg_parts)})"))
    lines.append(c(DIM,  f"  function_graph trace  (static prediction)"))
    lines.append(sep)
    lines.append("")

    steps     = [s for s in result.path if not s.pruned]
    n         = len(steps)

    # ── build a child-set so we know which functions are non-leaves ───────
    non_leaves: set[int] = set()
    for idx in range(n - 1):
        if steps[idx + 1].depth > steps[idx].depth:
            non_leaves.add(idx)

    def pad(depth: int) -> str:
        return "  " * depth

    def via_annotation(via: str) -> str:
        if "fn_ptr" not in via:
            return ""
        expr = _re.sub(r'\s*\[(graph|static_fnptr|dynamic)\]\s*', '', via.split("fn_ptr:")[-1]).strip()
        if "[dynamic]" in via:
            tag = c(CYN, f"/* fn_ptr → {expr} [dynamic] */")
        elif "[graph]" in via:
            tag = c(MAG, f"/* fn_ptr → {expr} [graph] */")
        else:
            tag = c(MAG, f"/* fn_ptr → {expr} [static] */")
        return "  " + tag

    # track open scopes for close-brace emission
    # each entry: (depth, fn_name)
    open_stack: list[tuple[int, str]] = []

    # pruned-branch lookup (parent_fn, depth) → [pruned_names]
    pruned_by: dict[tuple, list[str]] = {}
    for ps in result.pruned_branches:
        parent = next((s.function for s in reversed(steps)
                       if s.depth == ps.depth - 1), "?")
        pruned_by.setdefault((parent, ps.depth), []).append(ps.function)
    printed_pruned: set = set()

    for idx, step in enumerate(steps):
        depth, fn, via = step.depth, step.function, step.via
        p = pad(depth)

        # close any open scopes that are deeper than current
        while open_stack and open_stack[-1][0] >= depth:
            d, _ = open_stack.pop()
            lines.append(f"{pad(d)}{PIPE}  " + c(WHT, "}"))

        # pruned-path notice
        pk = (steps[idx - 1].function if idx > 0 else "?", depth)
        if pk in pruned_by and pk not in printed_pruned:
            printed_pruned.add(pk)
            names = ", ".join(pruned_by[pk])
            lines.append(f"{p}{PIPE}  " + c(YLW, f"/* ✂ alt path pruned → {names} */"))

        ann = via_annotation(via)

        # UNRESOLVED
        if fn.startswith("[UNRESOLVED]"):
            expr = fn.replace("[UNRESOLVED]", "").strip()
            lines.append(
                f"{p}{PIPE}  "
                + c(RED, f"{expr}();")
                + c(DIM, "  /* UNRESOLVED */")
            )
            continue

        is_leaf = idx not in non_leaves

        if is_leaf:
            name_part = c(GRN, f"{fn}();") if depth > 0 else c(BOLD, f"{fn}();")
            lines.append(f"{p}{PIPE}  {name_part}{ann}")
        else:
            name_part = c(BOLD, f"{fn}() {{") if depth == 0 else f"{fn}() {{"
            lines.append(f"{p}{PIPE}  {name_part}{ann}")
            open_stack.append((depth, fn))

    # close any remaining open scopes
    while open_stack:
        d, _ = open_stack.pop()
        lines.append(f"{pad(d)}{PIPE}  " + c(WHT, "}"))

    # ── unresolved summary ────────────────────────────────────────────────
    if result.unresolved:
        lines.append("")
        lines.append(c(RED, "── Unresolved indirect call sites " + "─" * 36))
        for u in result.unresolved:
            lines.append(f"  {c(RED, '?')}  {u}")

    # ── pruned summary ────────────────────────────────────────────────────
    if result.pruned_branches:
        lines.append("")
        lines.append(c(YLW, "── Pruned branches (argument-gated) " + "─" * 34))
        by_p: dict[str, list[str]] = {}
        for ps in result.pruned_branches:
            par = next((s.function for s in reversed(steps)
                        if s.depth == ps.depth - 1), "?")
            by_p.setdefault(par, []).append(ps.function)
        for par, fns in by_p.items():
            lines.append(f"  {c(DIM, par)}() excluded:")
            for fn in fns:
                lines.append(f"    {c(YLW, '✂')}  {fn}()")

    # ── footer ────────────────────────────────────────────────────────────
    lines.append("")
    lines.append(c(DIM, "─" * 70))
    lines.append(
        f"  Steps: {len(result.path)}"
        f"   Pruned: {len(result.pruned_branches)}"
        f"   Unresolved: {len(result.unresolved)}"
        + (f"   Dynamic: {len(result.dynamic_hits)}" if result.dynamic_hits else "")
    )
    lines.append(c(DIM, "─" * 70))
    return "\n".join(lines)


def format_compact(result: PredictResult,
                   file_prefixes: list[str] = None) -> str:
    """
    Print only the architectural spine:
      - entry point (depth 0)
      - fn-ptr dispatch hops  ← these are the interesting decisions
      - direct callees of dispatch hops
      - everything that is noise-filtered is dropped
    """
    if file_prefixes is None:
        file_prefixes = ["net/socket", "net/ipv4/", "net/core/"]

    lines = []
    SEP = "─" * 61
    EQ  = "═" * 61

    lines.append(EQ)
    lines.append("  SYSCALL PATH PREDICTION  (compact)")
    lines.append(EQ)

    arg_parts = []
    for i, raw in enumerate(result.raw_args):
        val = result.resolved_args.get(f"arg{i}")
        arg_parts.append(f"{raw}={val}" if val is not None else raw)
    lines.append(f"  Call     : {result.syscall}({', '.join(result.raw_args)})")
    lines.append(f"  Resolved : {', '.join(arg_parts)}")
    lines.append(SEP)

    # track which depths had a dispatch so we show their direct children
    dispatch_depths: set[int] = set()
    last_dispatch_depth = -1

    for step in result.path:
        if step.pruned:
            continue

        fn    = step.function
        via   = step.via
        depth = step.depth

        is_entry    = (depth == 0)
        is_dispatch = (via not in ("direct call", "syscall entry")
                       and not via.startswith("pruned"))
        is_child_of_dispatch = (depth - 1) in dispatch_depths

        if not (is_entry or is_dispatch or is_child_of_dispatch):
            continue
        if _is_noise(fn):
            continue

        if is_dispatch:
            dispatch_depths.add(depth)

        indent = "  " * depth
        if depth == 0:
            lines.append(f"▶ {fn}()")
        else:
            via_str = f"  ← {via}" if is_dispatch else ""
            lines.append(f"{indent}└─ {fn}(){via_str}")

    lines.append(SEP)
    lines.append(f"  Total steps  : {len(result.path)}")
    lines.append(f"  Pruned paths : {len(result.pruned_branches)}")
    lines.append(f"  Unresolved   : {len(result.unresolved)}")
    if result.dynamic_hits:
        lines.append(f"  Dynamic hits : {len(result.dynamic_hits)}")
    lines.append(EQ)
    return "\n".join(lines)


def format_json(result: PredictResult) -> str:
    return json.dumps({
        "syscall":      result.syscall,
        "rawArgs":      result.raw_args,
        "resolvedArgs": result.resolved_args,
        "path": [
            {
                "depth":    s.depth,
                "function": s.function,
                "via":      s.via,
                "resolved": {k: v for k, v in s.resolved.items()
                             if v is not None},
                "pruned":   s.pruned,
            }
            for s in result.path
        ],
        "prunedBranches": [
            {"depth": s.depth, "function": s.function, "reason": s.prune_reason}
            for s in result.pruned_branches
        ],
        "unresolved":  result.unresolved,
        "dynamicHits": result.dynamic_hits,
    }, indent=2)


# ═════════════════════════════════════════════════════════════════════════════
# CLI
# ═════════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--syscall",         required=True)
    p.add_argument("--uri",             default="bolt://localhost:7687")
    p.add_argument("--user",            default="neo4j")
    p.add_argument("--password",        default="neo4j")
    p.add_argument("--dynamic-capture", default=None)
    p.add_argument("--max-depth",       type=int, default=30)
    p.add_argument("--max-steps",       type=int, default=500)
    p.add_argument("--no-dynamic",      action="store_true")
    p.add_argument("--infra-threshold", type=int, default=20,
                   help="Functions with more callers than this are treated as "
                        "infrastructure and skipped (default: 20). "
                        "Lower = stricter filtering.")
    p.add_argument("--compact",         action="store_true",
                   help="Print only fn-ptr dispatch hops and their direct callees")
    p.add_argument("--ftrace",          action="store_true",
                   help="Print output in Linux function_graph tracer style")
    p.add_argument("--json",            action="store_true")
    return p.parse_args()


def get_driver(uri: str, user: str, password: str):
    try:
        from neo4j import GraphDatabase
        driver = GraphDatabase.driver(uri, auth=(user, password))
        driver.verify_connectivity()
        return driver
    except ImportError:
        print("[predict] ERROR: neo4j driver not installed.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[predict] ERROR: cannot connect to Neo4j: {e}", file=sys.stderr)
        sys.exit(1)


def load_dynamic_capture(script_path: str | None):
    if not script_path:
        return None
    try:
        spec = importlib.util.spec_from_file_location("dynamic_capture", script_path)
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.resolve
    except Exception as e:
        print(f"[predict] WARNING: could not load dynamic_capture: {e}",
              file=sys.stderr)
        return None


def main() -> None:
    args = parse_args()

    try:
        syscall_name, raw_args = parse_syscall(args.syscall)
    except ValueError as e:
        print(f"[predict] ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    driver = get_driver(args.uri, args.user, args.password)
    graph  = Graph(driver)

    constants     = graph.get_constants()
    resolved_args = resolve_args(raw_args, constants)

    print(f"[predict] Syscall: {syscall_name}({', '.join(raw_args)})",
          file=sys.stderr)
    for i, raw in enumerate(raw_args):
        print(f"[predict]   arg{i}: {raw} = {resolved_args.get(f'arg{i}')}",
              file=sys.stderr)

    # find entry function
    candidates = [
        f"sys_{syscall_name}",
        f"__sys_{syscall_name}",
        f"__x64_sys_{syscall_name}",
        f"__arm64_sys_{syscall_name}",
        syscall_name,
    ]
    entry_fn = None
    for cand in candidates:
        if graph.function_exists(cand):
            entry_fn = cand
            break

    if not entry_fn:
        print(f"[predict] ERROR: no entry function found. Tried: {candidates}",
              file=sys.stderr)
        graph.close(); driver.close()
        sys.exit(1)

    print(f"[predict] Entry: {entry_fn}", file=sys.stderr)

    dynamic_resolve = None
    if not args.no_dynamic and args.dynamic_capture:
        dynamic_resolve = load_dynamic_capture(args.dynamic_capture)

    # ── iterative traversal ───────────────────────────────────────────────
    path, pruned_branches, unresolved, dynamic_hits = traverse(
        graph            = graph,
        entry_fn         = entry_fn,
        entry_resolved   = resolved_args,
        max_depth        = args.max_depth,
        max_steps        = args.max_steps,
        dynamic_resolve  = dynamic_resolve,
        infra_threshold  = args.infra_threshold,
    )

    result = PredictResult(
        syscall        = syscall_name,
        raw_args       = raw_args,
        resolved_args  = {k: v for k, v in resolved_args.items()
                          if v is not None},
        path           = path,
        pruned_branches= pruned_branches,
        unresolved     = unresolved,
        dynamic_hits   = dynamic_hits,
    )

    graph.close()
    driver.close()

    if args.json:
        print(format_json(result))
    elif args.compact:
        print(format_compact(result))
    elif args.ftrace:
        print(format_ftrace(result))
    else:
        print(format_pretty(result))


if __name__ == "__main__":
    main()