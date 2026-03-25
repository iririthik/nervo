#!/usr/bin/env python3
"""
07_extract_constants.py — parse kernel headers into Constant nodes

Purpose
-------
predict.py receives syscall expressions like:
    socket(AF_INET, SOCK_STREAM, 0)

Before it can trace anything, it needs to resolve those symbolic names
to their actual integer values:
    AF_INET     = 2
    SOCK_STREAM = 1

This script reads kernel header files and extracts every #define and enum
constant into a flat JSON list.  These become Constant nodes in Neo4j —
no relationships, just a name→value lookup.

Sources we parse
----------------
1. #define constants:
       #define AF_INET   2
       #define SOCK_STREAM 1
       #define IPPROTO_TCP 6

2. Enum constants:
       enum {
           AF_UNSPEC = 0,
           AF_INET   = 2,
           ...
       };

3. Chained #define (one constant defined in terms of another):
       #define PF_INET AF_INET
   We resolve chains up to a configurable depth.

Headers we scan (in priority order)
-------------------------------------
  include/uapi/linux/socket.h
  include/uapi/asm-generic/socket.h
  include/linux/socket.h
  include/uapi/linux/in.h
  include/uapi/linux/net.h
  include/linux/net.h
  include/uapi/linux/if_ether.h
  include/uapi/linux/if_packet.h
  include/linux/fs.h
  include/uapi/linux/fcntl.h
  include/uapi/linux/mman.h
  include/uapi/linux/signal.h
  include/uapi/asm-generic/errno-base.h
  include/uapi/asm-generic/errno.h
  ...plus any *.h under include/uapi/ (recursive)

Output
------
  [ { "name": "AF_INET", "value": 2, "source": "include/uapi/linux/socket.h" }, ... ]

Usage
-----
    python3 07_extract_constants.py /opt/linux
    python3 07_extract_constants.py /opt/linux --out /opt/nervo/out/constants.json
    python3 07_extract_constants.py /opt/linux --stats
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from collections import defaultdict


# ── header priority list ──────────────────────────────────────────────────────
# Scanned first so their definitions win in case of name conflicts.
PRIORITY_HEADERS = [
    "include/uapi/linux/socket.h",
    "include/uapi/asm-generic/socket.h",
    "include/linux/socket.h",
    "include/uapi/linux/in.h",
    "include/uapi/linux/in6.h",
    "include/uapi/linux/net.h",
    "include/linux/net.h",
    "include/uapi/linux/if_ether.h",
    "include/uapi/linux/if_packet.h",
    "include/linux/fs.h",
    "include/uapi/linux/fcntl.h",
    "include/uapi/linux/mman.h",
    "include/uapi/linux/signal.h",
    "include/uapi/asm-generic/errno-base.h",
    "include/uapi/asm-generic/errno.h",
    "include/uapi/linux/errno.h",
    "include/uapi/linux/ioctl.h",
    "include/uapi/linux/capability.h",
    "include/uapi/linux/prctl.h",
    "include/uapi/linux/ptrace.h",
    "include/uapi/linux/stat.h",
    "include/uapi/linux/sched.h",
]


# ── regex patterns ────────────────────────────────────────────────────────────

# Simple: #define NAME 42  or  #define NAME 0x2a
RE_DEFINE_INT = re.compile(
    r"^\s*#\s*define\s+([A-Z_][A-Z0-9_]*)\s+"
    r"((?:0[xX][0-9a-fA-F]+|-?\d+))\s*(?:/\*.*\*/)?\s*$"
)

# Chained: #define PF_INET AF_INET
RE_DEFINE_REF = re.compile(
    r"^\s*#\s*define\s+([A-Z_][A-Z0-9_]*)\s+([A-Z_][A-Z0-9_]*)\s*$"
)

# Enum: value = integer  (inside an enum block)
RE_ENUM_ENTRY = re.compile(
    r"^\s*([A-Z_][A-Z0-9_]*)\s*=\s*((?:0[xX][0-9a-fA-F]+|-?\d+))\s*,?"
)

# Start / end of enum block
RE_ENUM_START = re.compile(r"\benum\b")
RE_ENUM_END   = re.compile(r"\}")


# ─────────────────────────────────────────────────────────────────────────────

def parse_int(s: str) -> int | None:
    """Parse decimal or hex integer string."""
    try:
        return int(s, 0)
    except (ValueError, TypeError):
        return None


def parse_header(path: Path) -> tuple[dict[str, int], dict[str, str]]:
    """
    Parse one header file.

    Returns:
        resolved:   name → int value   (directly resolved)
        references: name → ref_name    (chained defines to resolve later)
    """
    resolved:   dict[str, int] = {}
    references: dict[str, str] = {}

    try:
        text = path.read_text(errors="replace")
    except OSError:
        return resolved, references

    lines = text.splitlines()
    in_enum   = False
    enum_auto = 0       # auto-increment counter for enum entries without explicit value

    for line in lines:
        # strip inline comments
        clean = re.sub(r"/\*.*?\*/", "", line)
        clean = re.sub(r"//.*$",    "", clean)

        # ── enum tracking ────────────────────────────────────────────────
        if not in_enum and RE_ENUM_START.search(clean):
            in_enum   = True
            enum_auto = 0
            continue

        if in_enum:
            if RE_ENUM_END.search(clean):
                in_enum   = False
                enum_auto = 0
                continue

            m = RE_ENUM_ENTRY.match(clean)
            if m:
                name  = m.group(1)
                val   = parse_int(m.group(2))
                if val is not None:
                    resolved[name] = val
                    enum_auto = val + 1
            elif clean.strip() and clean.strip() != "{":
                # entry with no explicit value — use auto-increment
                auto_m = re.match(r"^\s*([A-Z_][A-Z0-9_]*)\s*,?", clean)
                if auto_m:
                    resolved[auto_m.group(1)] = enum_auto
                    enum_auto += 1
            continue

        # ── #define with integer value ────────────────────────────────────
        m = RE_DEFINE_INT.match(clean)
        if m:
            name = m.group(1)
            val  = parse_int(m.group(2))
            if val is not None and name not in resolved:
                resolved[name] = val
            continue

        # ── #define referencing another name ──────────────────────────────
        m = RE_DEFINE_REF.match(clean)
        if m:
            name = m.group(1)
            ref  = m.group(2)
            if name not in resolved:
                references[name] = ref
            continue

    return resolved, references


def resolve_chains(
    resolved:   dict[str, int],
    references: dict[str, str],
    max_depth:  int = 8,
) -> dict[str, int]:
    """
    Resolve chained defines:
        PF_INET → AF_INET → 2
    Iterates up to max_depth times until no new resolutions occur.
    """
    changed = True
    depth   = 0
    while changed and depth < max_depth:
        changed = False
        depth  += 1
        for name, ref in list(references.items()):
            if name in resolved:
                continue
            if ref in resolved:
                resolved[name] = resolved[ref]
                changed = True
    return resolved


def discover_headers(linux_src: Path) -> list[Path]:
    """
    Build the ordered list of headers to scan:
    priority headers first (if they exist), then all *.h under include/uapi/
    that weren't already in the priority list.
    """
    seen: set[Path] = set()
    ordered: list[Path] = []

    # priority list
    for rel in PRIORITY_HEADERS:
        p = linux_src / rel
        if p.exists():
            ordered.append(p)
            seen.add(p.resolve())

    # everything else under include/uapi/ recursively
    uapi = linux_src / "include" / "uapi"
    if uapi.is_dir():
        for p in sorted(uapi.rglob("*.h")):
            rp = p.resolve()
            if rp not in seen:
                ordered.append(p)
                seen.add(rp)

    return ordered


# ═════════════════════════════════════════════════════════════════════════════

def extract_constants(
    linux_src:  str,
    out_path:   str,
    print_stats: bool = False,
) -> list[dict]:

    root = Path(linux_src).resolve()
    if not root.is_dir():
        print(f"[07_constants] ERROR: linux_src not found: {root}", file=sys.stderr)
        sys.exit(1)

    headers = discover_headers(root)
    print(f"[07_constants] Scanning {len(headers)} header files...", file=sys.stderr)

    # accumulate across all headers
    all_resolved:   dict[str, int]  = {}
    all_references: dict[str, str]  = {}
    source_map:     dict[str, str]  = {}   # name → relative header path

    for header in headers:
        rel = str(header.relative_to(root))
        resolved, references = parse_header(header)

        for name, val in resolved.items():
            if name not in all_resolved:
                all_resolved[name] = val
                source_map[name]   = rel

        for name, ref in references.items():
            if name not in all_references and name not in all_resolved:
                all_references[name] = ref
                source_map[name]     = rel

    # resolve chains across all headers
    total_before = len(all_resolved)
    resolve_chains(all_resolved, all_references)
    total_after = len(all_resolved)

    print(
        f"[07_constants] Direct: {total_before}  "
        f"Chain-resolved: {total_after - total_before}  "
        f"Still unresolved: {len(all_references) - (total_after - total_before)}",
        file=sys.stderr,
    )

    # build output list
    output = [
        {
            "name":   name,
            "value":  val,
            "source": source_map.get(name, ""),
        }
        for name, val in sorted(all_resolved.items())
    ]

    # write
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w") as f:
        json.dump(output, f, indent=2)

    print(f"[07_constants] Written {len(output)} constants → {out}", file=sys.stderr)

    # stats
    if print_stats:
        # group by source header
        by_source: dict[str, int] = defaultdict(int)
        for entry in output:
            by_source[entry["source"]] += 1

        print("\n[07_constants] Top 15 headers by constant count:", file=sys.stderr)
        for hdr, count in sorted(by_source.items(), key=lambda x: -x[1])[:15]:
            print(f"  {hdr:<60} {count}", file=sys.stderr)

        # show a few well-known ones as a sanity check
        known = ["AF_INET", "AF_INET6", "SOCK_STREAM", "SOCK_DGRAM",
                 "IPPROTO_TCP", "IPPROTO_UDP", "O_RDONLY", "O_WRONLY",
                 "ENOENT", "EACCES", "SIGKILL"]
        print("\n[07_constants] Sanity check — well-known constants:", file=sys.stderr)
        for name in known:
            val = all_resolved.get(name)
            src = source_map.get(name, "?")
            status = f"{val}" if val is not None else "NOT FOUND"
            print(f"  {name:<20} = {status:<8}  ({src})", file=sys.stderr)
        print("", file=sys.stderr)

    return output


# ═════════════════════════════════════════════════════════════════════════════
# CLI
# ═════════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("linux_src",
                   help="Root of the kernel source tree")
    p.add_argument("--out", default=None,
                   help="Output path for constants.json "
                        "(default: <linux_src>/../nervo_out/constants.json)")
    p.add_argument("--stats", action="store_true",
                   help="Print per-header counts and sanity checks")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    out = args.out
    if out is None:
        out = str(Path(args.linux_src).parent / "nervo_out" / "constants.json")

    extract_constants(
        linux_src   = args.linux_src,
        out_path    = out,
        print_stats = args.stats,
    )


if __name__ == "__main__":
    main()
