#!/usr/bin/env python3
"""
derive_subsystems.py — build the subsystem list from the GCC plugin manifest

The GCC plugin writes one absolute path per compiled translation unit into
nervo_compiled_files.txt.  This script reads that manifest and derives the
unique top-level subsystem directories that Joern should parse.

Why this exists
---------------
We must NEVER hardcode a subsystem list.  The correct list is whatever the
kernel's real .config actually compiled.  Subsystems disabled via CONFIG_*
must not appear — Joern would parse dead code and produce phantom edges.

Output
------
One subsystem path per line, printed to stdout.  nervo.sh redirects this
into subsystems.txt which 03_run_pipeline.sh consumes.

Usage
-----
    python3 derive_subsystems.py <linux_src> <compiled_files.txt>
    python3 derive_subsystems.py <linux_src> <compiled_files.txt> --min-files 3
    python3 derive_subsystems.py <linux_src> <compiled_files.txt> --depth 2

Arguments
---------
  linux_src           root of the kernel source tree (e.g. /opt/linux)
  compiled_files.txt  manifest produced by nervo_gcc_plugin.c

Options
-------
  --depth N       how many directory levels define a "subsystem" (default: 1)
                  depth=1 → net/, mm/, fs/, drivers/
                  depth=2 → net/ipv4/, net/ipv6/, drivers/net/, etc.
  --min-files N   skip subsystems with fewer than N compiled files (default: 1)
  --exclude       comma-separated directory prefixes to skip
                  (default: arch/,scripts/,tools/,usr/,samples/)
  --stats         print a summary to stderr after the list
"""

import argparse
import os
import sys
from collections import defaultdict
from pathlib import Path


# ── defaults ──────────────────────────────────────────────────────────────────

DEFAULT_DEPTH    = 1
DEFAULT_MIN      = 1
DEFAULT_EXCLUDES = {
    "arch",      # architecture-specific — too broad and often not portable
    "scripts",   # build tooling, not kernel code
    "tools",     # userspace tools
    "usr",       # initramfs
    "samples",   # example code
}


# ═════════════════════════════════════════════════════════════════════════════
# core logic
# ═════════════════════════════════════════════════════════════════════════════

def load_manifest(manifest_path: str) -> list[str]:
    """Read the compiled-files manifest and return a list of absolute paths."""
    path = Path(manifest_path)
    if not path.exists():
        print(f"[derive] ERROR: manifest not found: {manifest_path}", file=sys.stderr)
        sys.exit(1)

    lines = []
    with open(path) as f:
        for raw in f:
            line = raw.strip()
            if line:
                lines.append(line)

    if not lines:
        print(f"[derive] ERROR: manifest is empty: {manifest_path}", file=sys.stderr)
        sys.exit(1)

    return lines


def make_relative(abs_path: str, linux_src: str) -> str | None:
    """
    Turn an absolute compiled-file path into a path relative to linux_src.
    Returns None if the file is not under linux_src.
    """
    try:
        return str(Path(abs_path).relative_to(linux_src))
    except ValueError:
        return None


def subsystem_key(rel_path: str, depth: int) -> str | None:
    """
    Extract the subsystem key at the requested depth.

      rel_path = "net/ipv4/tcp.c", depth=1  →  "net"
      rel_path = "net/ipv4/tcp.c", depth=2  →  "net/ipv4"
      rel_path = "mm/slub.c",      depth=1  →  "mm"
      rel_path = "init/main.c",    depth=1  →  "init"

    Returns None for files that live directly in the root (no subdirectory).
    """
    parts = Path(rel_path).parts  # e.g. ("net", "ipv4", "tcp.c")
    if len(parts) <= 1:
        # file sits directly in the root (e.g. "Makefile") — not a subsystem
        return None
    # take at most `depth` directory components, excluding the filename
    dir_parts = parts[:-1]  # strip filename
    key_parts = dir_parts[:depth]
    return str(Path(*key_parts))


def derive_subsystems(
    linux_src:   str,
    manifest:    str,
    depth:       int       = DEFAULT_DEPTH,
    min_files:   int       = DEFAULT_MIN,
    excludes:    set[str]  = DEFAULT_EXCLUDES,
    print_stats: bool      = False,
) -> list[str]:
    """
    Main entry point.  Returns a sorted list of absolute subsystem paths.
    """
    linux_src = str(Path(linux_src).resolve())

    compiled = load_manifest(manifest)

    # count files per subsystem key
    counts: dict[str, int]          = defaultdict(int)
    examples: dict[str, list[str]]  = defaultdict(list)

    skipped_outside = 0
    skipped_exclude = 0
    skipped_no_dir  = 0

    for abs_path in compiled:
        rel = make_relative(abs_path, linux_src)
        if rel is None:
            skipped_outside += 1
            continue

        key = subsystem_key(rel, depth)
        if key is None:
            skipped_no_dir += 1
            continue

        # check exclusions against the top-level component
        top = Path(key).parts[0]
        if top in excludes:
            skipped_exclude += 1
            continue

        counts[key] += 1
        if len(examples[key]) < 3:
            examples[key].append(rel)

    # filter by minimum file count
    valid = {k: v for k, v in counts.items() if v >= min_files}

    if not valid:
        print(
            f"[derive] WARNING: no subsystems found with depth={depth} "
            f"min_files={min_files}. Check your manifest and linux_src.",
            file=sys.stderr,
        )

    # build absolute paths and sort
    result = sorted(
        str(Path(linux_src) / key) for key in valid
    )

    # ── stats ──────────────────────────────────────────────────────────────
    if print_stats:
        total_compiled = len(compiled)
        print(
            f"\n[derive] Manifest stats",
            file=sys.stderr,
        )
        print(
            f"  Total compiled files : {total_compiled}",
            file=sys.stderr,
        )
        print(
            f"  Outside linux_src    : {skipped_outside}",
            file=sys.stderr,
        )
        print(
            f"  Excluded prefixes    : {skipped_exclude}",
            file=sys.stderr,
        )
        print(
            f"  Root-level files     : {skipped_no_dir}",
            file=sys.stderr,
        )
        print(
            f"  Subsystems found     : {len(valid)}  "
            f"(depth={depth}, min_files={min_files})",
            file=sys.stderr,
        )
        print(f"\n  Top 10 by file count:", file=sys.stderr)
        for k, v in sorted(valid.items(), key=lambda x: -x[1])[:10]:
            ex = ", ".join(examples[k])
            print(f"    {k:<40} {v:>5} files  e.g. {ex}", file=sys.stderr)
        print("", file=sys.stderr)

    return result


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
    p.add_argument("compiled_files",
                   help="nervo_compiled_files.txt produced by the GCC plugin")
    p.add_argument("--depth", type=int, default=DEFAULT_DEPTH,
                   help=f"Directory depth for subsystem grouping (default: {DEFAULT_DEPTH})")
    p.add_argument("--min-files", type=int, default=DEFAULT_MIN,
                   help=f"Min compiled files to include a subsystem (default: {DEFAULT_MIN})")
    p.add_argument("--exclude", type=str, default=",".join(sorted(DEFAULT_EXCLUDES)),
                   help="Comma-separated top-level dirs to exclude "
                        f"(default: {','.join(sorted(DEFAULT_EXCLUDES))})")
    p.add_argument("--stats", action="store_true",
                   help="Print summary statistics to stderr")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    excludes = set(e.strip().rstrip("/") for e in args.exclude.split(",") if e.strip())

    subsystems = derive_subsystems(
        linux_src   = args.linux_src,
        manifest    = args.compiled_files,
        depth       = args.depth,
        min_files   = args.min_files,
        excludes    = excludes,
        print_stats = args.stats,
    )

    for path in subsystems:
        print(path)


if __name__ == "__main__":
    main()