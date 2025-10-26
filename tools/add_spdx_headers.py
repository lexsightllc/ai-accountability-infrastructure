#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0

"""Insert SPDX-License-Identifier headers into source files.

This script is idempotent: it will not add a new header if one already exists.
"""
from __future__ import annotations

import argparse
import io
import os
import subprocess
from pathlib import Path
from typing import Iterable, Optional, Sequence, Tuple

SPDX_LINE = "SPDX-License-Identifier: MPL-2.0"

LINE_COMMENT_MAP = {
    ".py": "#",
    ".pyi": "#",
    ".sh": "#",
    ".bash": "#",
    ".fish": "#",
    ".cfg": "#",
    ".conf": "#",
    ".ini": "#",
    ".toml": "#",
    ".yaml": "#",
    ".yml": "#",
    ".mk": "#",
    ".make": "#",
    ".gradle": "#",
    ".ps1": "#",
    ".psm1": "#",
    ".rb": "#",
    ".pl": "#",
    ".pm": "#",
    ".sql": "#",
    ".tf": "#",
    ".tfvars": "#",
    ".service": "#",
    ".socket": "#",
    ".env": "#",
    ".txt": "#",
    ".rst": "#",
}

BLOCK_COMMENT_MAP = {
    ".js": ("/*", "*/"),
    ".ts": ("/*", "*/"),
    ".jsx": ("/*", "*/"),
    ".tsx": ("/*", "*/"),
    ".css": ("/*", "*/"),
    ".scss": ("/*", "*/"),
    ".less": ("/*", "*/"),
    ".c": ("/*", "*/"),
    ".h": ("/*", "*/"),
    ".hpp": ("/*", "*/"),
    ".hh": ("/*", "*/"),
    ".cc": ("/*", "*/"),
    ".cpp": ("/*", "*/"),
    ".cxx": ("/*", "*/"),
    ".go": ("/*", "*/"),
    ".java": ("/*", "*/"),
    ".kt": ("/*", "*/"),
    ".swift": ("/*", "*/"),
}

HTML_COMMENT_MAP = {
    ".html",
    ".htm",
    ".xml",
    ".xsd",
    ".xsl",
    ".xslt",
    ".vue",
    ".md",
    ".markdown",
}

SPECIAL_LINE_NAMES = {
    "Dockerfile": "#",
    "Makefile": "#",
    "CMakeLists.txt": "#",
}

SKIP_DIRECTORIES = {
    "node_modules",
    "vendor",
    "third_party",
    "sbom",
    "assets",
    "schemas",
    "schema",
    "data",
    "logs",
    "log",
    "docs/api-reference/generated",
}

BINARY_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".bmp",
    ".ico",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".tgz",
    ".mp4",
    ".mp3",
    ".wav",
    ".ttf",
    ".otf",
    ".woff",
    ".woff2",
    ".so",
    ".dll",
    ".exe",
    ".bin",
    ".db",
    ".sqlite",
}

ALWAYS_SKIP = {
    "LICENSE",
    "NOTICE",
    "THIRD_PARTY_NOTICES.md",
    "package-lock.json",
}


def is_binary(path: Path) -> bool:
    if path.suffix.lower() in BINARY_EXTENSIONS:
        return True
    try:
        with path.open("rb") as fh:
            chunk = fh.read(1024)
        return b"\0" in chunk
    except OSError:
        return True


def should_skip(path: Path) -> bool:
    if path.name in ALWAYS_SKIP:
        return True
    parts = path.parts
    for skip in SKIP_DIRECTORIES:
        skip_parts = Path(skip).parts
        if len(parts) >= len(skip_parts) and tuple(parts[: len(skip_parts)]) == skip_parts:
            return True
    return False


def detect_comment_style(path: Path) -> Optional[str]:
    if path.name in SPECIAL_LINE_NAMES:
        return SPECIAL_LINE_NAMES[path.name]
    ext = path.suffix.lower()
    if ext in LINE_COMMENT_MAP:
        return LINE_COMMENT_MAP[ext]
    if ext in HTML_COMMENT_MAP:
        return "HTML"
    if ext in BLOCK_COMMENT_MAP:
        return "BLOCK"
    return None


def build_header(path: Path) -> Optional[str]:
    ext = path.suffix.lower()
    style = detect_comment_style(path)
    if style is None:
        return None
    if style == "HTML":
        return f"<!-- {SPDX_LINE} -->\n\n"
    if style == "BLOCK":
        start, end = BLOCK_COMMENT_MAP[ext]
        return f"{start} {SPDX_LINE} {end}\n\n"
    prefix = style
    return f"{prefix} {SPDX_LINE}\n"


def insert_header(path: Path) -> bool:
    if should_skip(path) or is_binary(path):
        return False
    header = build_header(path)
    if header is None:
        return False
    try:
        original = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return False
    if SPDX_LINE in original.splitlines():
        return False

    lines = original.splitlines()
    new_content: str
    if lines and lines[0].startswith("#!"):
        shebang = lines[0]
        rest = "\n".join(lines[1:])
        new_content = f"{shebang}\n{header}{rest}\n" if rest else f"{shebang}\n{header}"
    else:
        new_content = f"{header}{original}" if original else header

    path.write_text(new_content, encoding="utf-8")
    return True


def process_files(files: Iterable[Path]) -> Sequence[Path]:
    modified: list[Path] = []
    for file_path in files:
        if file_path.is_dir():
            continue
        if insert_header(file_path):
            modified.append(file_path)
    return modified


def iter_targets(paths: Sequence[str]) -> Iterable[Path]:
    if not paths:
        result = subprocess.run(["git", "ls-files"], check=True, capture_output=True, text=True)
        for raw in result.stdout.splitlines():
            candidate = Path(raw.strip())
            if candidate.exists():
                yield candidate
        return
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            for sub in p.rglob("*"):
                if sub.is_file():
                    yield sub
        else:
            yield p


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Insert MPL-2.0 SPDX headers into files")
    parser.add_argument("paths", nargs="*", help="Paths to process; defaults to tracked files")
    args = parser.parse_args(argv)

    targets = list(iter_targets(args.paths))
    modified = process_files(targets)
    if modified:
        print(f"Updated {len(modified)} files with SPDX headers.")
        for path in modified:
            print(f"  {path}")
    else:
        print("No files required SPDX header updates.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
