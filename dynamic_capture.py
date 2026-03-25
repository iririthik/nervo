#!/usr/bin/env python3
"""
dynamic_capture.py — eBPF/ftrace runtime resolver for Nervo

Triggered by predict.py when traversal hits an UNRESOLVED indirect call.
Plants a bpftrace probe at the call site, executes the syscall with the
exact argument values being predicted, observes which function actually
runs, and returns its name.

Also handles:
  - Edge staleness model (validUntil TTL per dynamic edge)
  - Periodic checkup (re-verify all stale edges)
  - Manual probe arming (nervo.sh capture start)
  - Marking all dynamic edges stale on kernel version bump

Interface used by predict.py
-----------------------------
    resolved_fn = dynamic_capture.resolve(
        call_site = "ops->create",
        syscall   = "sys_socket",
        args      = {"arg0": 2, "arg1": 1, "arg2": 0, "family": 2},
    )
    # returns "inet_create" or None on timeout

Requirements
------------
  - bpftrace installed and on PATH
  - CAP_BPF or root (for probe placement)
  - The kernel must have been compiled with the same .config used for the graph
  - Kernel 5.8+ for full eBPF support

Usage (standalone / nervo.sh integration)
------------------------------------------
    # arm a probe manually:
    python3 dynamic_capture.py --arm --syscall 'socket(AF_INET, SOCK_STREAM, 0)'

    # re-verify stale edges:
    python3 dynamic_capture.py --checkup

    # mark all dynamic edges stale (called automatically on kernel version bump):
    python3 dynamic_capture.py --mark-all-stale
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


# ── TTL constants ─────────────────────────────────────────────────────────────
TTL_DEFAULT_DAYS  = 7    # core syscall paths
TTL_AFTER_BUMP    = 1    # after kernel version change
PROBE_TIMEOUT_SEC = 5    # max seconds to wait for bpftrace to observe the call


# ═════════════════════════════════════════════════════════════════════════════
# Neo4j helpers (optional — only used in standalone / checkup mode)
# ═════════════════════════════════════════════════════════════════════════════

def _get_driver(uri: str, user: str, password: str):
    try:
        from neo4j import GraphDatabase
        driver = GraphDatabase.driver(uri, auth=(user, password))
        driver.verify_connectivity()
        return driver
    except ImportError:
        print("[dynamic] ERROR: neo4j driver not installed.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[dynamic] ERROR: cannot connect to Neo4j: {e}", file=sys.stderr)
        sys.exit(1)


# ═════════════════════════════════════════════════════════════════════════════
# bpftrace probe builder
# ═════════════════════════════════════════════════════════════════════════════

def _build_bpftrace_script(call_site: str, syscall_fn: str) -> str:
    """
    Build a bpftrace script that:
    1. Instruments the kernel function `syscall_fn` entry
    2. At entry, sets a flag so we know we're inside the right syscall
    3. Instruments all kprobes matching the call site pattern
    4. When the flag is set AND we hit a probe, print the function name
    5. Exits after first hit

    We use a global map as a flag — set on syscall entry, cleared on return.
    This prevents false positives from other processes making the same syscall.
    """

    # extract the base function/field name from the call site expression
    # "ops->create"            → try to probe common struct_ops callbacks
    # "net_families[family]"   → too indirect, probe the syscall and watch
    field_name = _extract_field_name(call_site)

    # Build a wildcard kprobe to catch any function that could be the target
    # bpftrace supports kprobe wildcards: kprobe:*create*
    # We make this conservative — only match short names to avoid false hits
    wildcard = f"*{field_name}*" if field_name and len(field_name) > 3 else "*"

    script = f"""
#!/usr/bin/env bpftrace
// Nervo dynamic capture: resolving call site: {call_site}
// Watching: {syscall_fn} → {wildcard}

@in_syscall[tid] = 0;

kprobe:{syscall_fn}
{{
    @in_syscall[tid] = 1;
}}

kretprobe:{syscall_fn}
{{
    delete(@in_syscall[tid]);
}}

kprobe:{wildcard}
{{
    if (@in_syscall[tid] == 1) {{
        printf("NERVO_HIT:%s\\n", func);
        @in_syscall[tid] = 0;
        exit();
    }}
}}

interval:s:{PROBE_TIMEOUT_SEC}
{{
    printf("NERVO_TIMEOUT\\n");
    exit();
}}
"""
    return script


def _extract_field_name(call_site: str) -> str | None:
    """
    Extract the field name from a call site expression.
    'ops->create(sock)'         → 'create'
    'net_families[2]->create'   → 'create'
    'sk->sk_prot->connect'      → 'connect'
    'callback_fn(args)'         → 'callback_fn'
    """
    # ->field pattern
    m = re.search(r'->(\w+)\s*[\(\[]?', call_site)
    if m:
        return m.group(1)
    # plain name(
    m = re.match(r'^\*?(\w+)\s*\(', call_site)
    if m:
        return m.group(1)
    return None


# ═════════════════════════════════════════════════════════════════════════════
# syscall trigger builder
# ═════════════════════════════════════════════════════════════════════════════

def _build_syscall_trigger(syscall_fn: str, args: dict[str, Any]) -> str:
    """
    Build a small C program that calls the syscall with the exact argument
    values from `args` so bpftrace has something to observe.

    We generate:
        #include <sys/socket.h>
        #include <unistd.h>
        int main() { syscall(SYS_socket, 2, 1, 0); return 0; }

    Falls back to a Python subprocess call if the syscall name is recognised.
    """
    # strip leading sys_ or __sys_ to get the bare name
    bare = re.sub(r'^(__x64_|__arm64_|__)?sys_|^__', '', syscall_fn)

    # positional args sorted by position
    pos_args = sorted(
        [(int(k[3:]), v) for k, v in args.items()
         if k.startswith("arg") and v is not None],
        key=lambda x: x[0],
    )
    arg_vals = [str(v) for _, v in pos_args]

    # Python trigger using ctypes (avoids needing a C compiler at runtime)
    trigger_code = f"""
import ctypes, ctypes.util
import sys

libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)

# get syscall number for {bare}
import ctypes.util
NR = None
try:
    import subprocess
    r = subprocess.run(
        ['python3', '-c',
         'import sys; from ctypes import CDLL; '
         'print(CDLL(None).syscall.__doc__)'],
        capture_output=True, text=True,
    )
except Exception:
    pass

# fallback: use known numbers for common syscalls
KNOWN = {{
    'socket':   41,
    'connect':  42,
    'bind':     49,
    'listen':   50,
    'read':      0,
    'write':     1,
    'open':      2,
    'close':     3,
    'mmap':      9,
    'sendto':   44,
    'recvfrom': 45,
}}
nr = KNOWN.get('{bare}')
if nr is not None:
    libc.syscall(nr, {', '.join(arg_vals) if arg_vals else '0'})
else:
    # generic: try to call by name via ctypes
    fn = getattr(libc, '{bare}', None)
    if fn:
        fn({', '.join(arg_vals) if arg_vals else '0'})
"""
    return trigger_code


# ═════════════════════════════════════════════════════════════════════════════
# Core resolve function — this is the interface predict.py calls
# ═════════════════════════════════════════════════════════════════════════════

def resolve(
    call_site: str,
    syscall:   str,
    args:      dict[str, Any],
) -> str | None:
    """
    Plants a bpftrace probe at call_site.
    Triggers the syscall with the resolved argument values.
    Returns the function name that was actually called, or None on timeout.

    Parameters
    ----------
    call_site   expression for the indirect call (e.g. "ops->create")
    syscall     the containing kernel function (e.g. "sys_socket")
    args        resolved argument values (e.g. {"arg0": 2, "family": 2})
    """
    # check bpftrace is available
    if not _bpftrace_available():
        print(f"[dynamic] WARNING: bpftrace not found — cannot resolve {call_site}",
              file=sys.stderr)
        return None

    print(f"[dynamic] Probing: {call_site} in {syscall} args={args}", file=sys.stderr)

    bpf_script   = _build_bpftrace_script(call_site, syscall)
    trigger_code = _build_syscall_trigger(syscall, args)

    with tempfile.TemporaryDirectory() as tmpdir:
        script_path  = Path(tmpdir) / "nervo_probe.bt"
        trigger_path = Path(tmpdir) / "nervo_trigger.py"

        script_path.write_text(bpf_script)
        trigger_path.write_text(trigger_code)

        # start bpftrace in background
        try:
            bpf_proc = subprocess.Popen(
                ["bpftrace", str(script_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except FileNotFoundError:
            print("[dynamic] ERROR: bpftrace not found on PATH", file=sys.stderr)
            return None

        # give bpftrace a moment to attach probes
        time.sleep(0.5)

        # fire the trigger
        try:
            subprocess.run(
                ["python3", str(trigger_path)],
                timeout=PROBE_TIMEOUT_SEC,
                capture_output=True,
            )
        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            print(f"[dynamic] WARNING: trigger failed: {e}", file=sys.stderr)

        # read bpftrace output
        try:
            stdout, _ = bpf_proc.communicate(timeout=PROBE_TIMEOUT_SEC + 1)
            output = stdout.decode(errors="replace")
        except subprocess.TimeoutExpired:
            bpf_proc.kill()
            output = ""

        # parse the output
        for line in output.splitlines():
            m = re.match(r"NERVO_HIT:(\S+)", line)
            if m:
                resolved_fn = m.group(1)
                print(f"[dynamic] Resolved: {call_site} → {resolved_fn}",
                      file=sys.stderr)
                return resolved_fn

        if "NERVO_TIMEOUT" in output:
            print(f"[dynamic] Timeout: could not resolve {call_site} within "
                  f"{PROBE_TIMEOUT_SEC}s", file=sys.stderr)
        else:
            print(f"[dynamic] No hit for {call_site}", file=sys.stderr)

        return None


# ═════════════════════════════════════════════════════════════════════════════
# Staleness management
# ═════════════════════════════════════════════════════════════════════════════

def mark_all_stale(uri: str, user: str, password: str) -> int:
    """Mark every dynamic RESOLVES_TO edge as stale."""
    driver = _get_driver(uri, user, password)
    with driver.session() as s:
        result = s.run("""
MATCH ()-[r:RESOLVES_TO {resolvedBy: 'dynamic'}]->()
WHERE r.state <> 'stale'
SET r.state = 'stale'
RETURN count(r) AS n
""")
        n = result.single()["n"]
    driver.close()
    print(f"[dynamic] Marked {n} dynamic edges as stale", file=sys.stderr)
    return n


def checkup(uri: str, user: str, password: str) -> dict:
    """
    Re-verify all stale dynamic edges.
    For each stale edge: re-run resolve() and update the edge.
    """
    driver = _get_driver(uri, user, password)
    stats  = {"verified": 0, "still_stale": 0, "failed": 0}

    with driver.session() as s:
        stale_edges = s.run("""
MATCH (ic:IndirectCall)-[r:RESOLVES_TO {resolvedBy: 'dynamic', state: 'stale'}]
      ->(f:Function)
RETURN ic.callExpression AS callSite,
       ic.callerFunction AS callerFn,
       f.name            AS resolvedFn,
       id(r)             AS relId
LIMIT 1000
""").data()

    print(f"[dynamic] Stale edges to re-verify: {len(stale_edges)}", file=sys.stderr)

    for edge in stale_edges:
        call_site   = edge["callSite"]
        caller_fn   = edge["callerFn"]
        resolved_fn = edge["resolvedFn"]

        # re-run the probe
        new_fn = resolve(
            call_site=call_site,
            syscall=caller_fn,
            args={},
        )

        with driver.session() as s:
            if new_fn == resolved_fn:
                # still points to the same function — refresh TTL
                new_ttl = int(time.time()) + TTL_DEFAULT_DAYS * 86400
                s.run("""
MATCH ()-[r:RESOLVES_TO]->()
WHERE id(r) = $relId
SET r.state = 'verified', r.validUntil = $ttl
""", relId=edge["relId"], ttl=new_ttl)
                stats["verified"] += 1

            elif new_fn is not None:
                # target changed — update the edge
                s.run("""
MATCH (ic:IndirectCall {callExpression: $ptr})
MATCH (newTarget:Function {name: $fn})
MATCH ()-[r:RESOLVES_TO]->()
WHERE id(r) = $relId
DELETE r
MERGE (ic)-[r2:RESOLVES_TO]->(newTarget)
SET r2.resolvedBy = 'dynamic',
    r2.validUntil = $ttl,
    r2.state = 'verified'
""", ptr=call_site, fn=new_fn,
     relId=edge["relId"],
     ttl=int(time.time()) + TTL_DEFAULT_DAYS * 86400)
                print(f"[dynamic] Edge updated: {call_site} → {new_fn} "
                      f"(was {resolved_fn})", file=sys.stderr)
                stats["verified"] += 1

            else:
                # probe failed — keep stale, don't delete
                stats["still_stale"] += 1

    driver.close()

    print(f"[dynamic] Checkup done: "
          f"verified={stats['verified']}  "
          f"still_stale={stats['still_stale']}  "
          f"failed={stats['failed']}",
          file=sys.stderr)
    return stats


def arm(syscall_expr: str, uri: str, user: str, password: str) -> None:
    """
    Manually arm a bpftrace probe for a given syscall expression.
    Equivalent to running predict but only for the dynamic capture step.
    """
    from predict import parse_syscall
    syscall_name, raw_args = parse_syscall(syscall_expr)

    driver = _get_driver(uri, user, password)
    with driver.session() as s:
        constants = {
            r["name"]: r["value"]
            for r in s.run("MATCH (c:Constant) RETURN c.name AS name, c.value AS value")
            if r["name"] and r["value"] is not None
        }
    driver.close()

    from predict import resolve_args
    resolved = resolve_args(raw_args, constants)

    # find the entry function
    candidates = [
        f"sys_{syscall_name}",
        f"__sys_{syscall_name}",
        syscall_name,
    ]
    entry = None
    driver2 = _get_driver(uri, user, password)
    with driver2.session() as s:
        for cand in candidates:
            r = s.run("MATCH (f:Function {name:$n}) RETURN count(f) AS c", n=cand).single()
            if r and r["c"] > 0:
                entry = cand
                break
    driver2.close()

    if not entry:
        print(f"[dynamic] ERROR: no entry function for {syscall_name}", file=sys.stderr)
        sys.exit(1)

    print(f"[dynamic] Arming probe for: {syscall_expr} → {entry}", file=sys.stderr)
    result = resolve(call_site=f"{entry}:indirect_calls", syscall=entry, args=resolved)
    if result:
        print(f"[dynamic] Captured: {result}", file=sys.stderr)
    else:
        print(f"[dynamic] No hit captured", file=sys.stderr)


# ═════════════════════════════════════════════════════════════════════════════
# Helpers
# ═════════════════════════════════════════════════════════════════════════════

def _bpftrace_available() -> bool:
    try:
        subprocess.run(["bpftrace", "--version"],
                       capture_output=True, check=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


# ═════════════════════════════════════════════════════════════════════════════
# CLI (used by nervo.sh capture / checkup / --mark-all-stale)
# ═════════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--arm",            action="store_true",
                   help="Arm a probe for --syscall manually")
    p.add_argument("--checkup",        action="store_true",
                   help="Re-verify all stale dynamic edges")
    p.add_argument("--mark-all-stale", action="store_true",
                   help="Mark all dynamic edges stale (called on kernel version bump)")
    p.add_argument("--syscall",        default=None,
                   help="Syscall expression for --arm")
    p.add_argument("--uri",            default="bolt://localhost:7687")
    p.add_argument("--neo4j-uri",      default=None,
                   help="Alias for --uri (used by nervo.sh)")
    p.add_argument("--user",           default="neo4j")
    p.add_argument("--neo4j-user",     default=None)
    p.add_argument("--password",       default="neo4j")
    p.add_argument("--neo4j-pass",     default=None)
    return p.parse_args()


def main() -> None:
    args = parse_args()

    uri  = args.neo4j_uri  or args.uri
    user = args.neo4j_user or args.user
    pwd  = args.neo4j_pass or args.password

    if args.mark_all_stale:
        mark_all_stale(uri, user, pwd)

    elif args.checkup:
        checkup(uri, user, pwd)

    elif args.arm:
        if not args.syscall:
            print("[dynamic] ERROR: --arm requires --syscall", file=sys.stderr)
            sys.exit(1)
        arm(args.syscall, uri, user, pwd)

    else:
        print("[dynamic] No action specified. Use --arm, --checkup, or --mark-all-stale",
              file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
