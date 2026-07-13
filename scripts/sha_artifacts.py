"""Compute LF-canonical SHA256s for the shipped operator-facing release
artefacts tracked by ``release-artifacts.sha256``.

WHY: ``.gitattributes`` pins ``*.sh``, ``*.html``, ``*.json``, ``*.md`` to
``eol=lf``, so the bytes GitHub serves via ``raw.githubusercontent.com`` (i.e.
what an operator sees after a fresh ``git clone``) match the working-tree
bytes on Windows dev hosts — provided the dev host didn't accidentally
introduce CRLFs. This helper prints the SHA256 of every manifest entry so a
contributor can patch ``release-artifacts.sha256`` after editing a shipped
artefact, then run ``python scripts/verify_manifest.py`` to confirm parity at
the released tag post-push.

USAGE
-----
    python scripts/sha_artifacts.py                 # all manifest entries
    python scripts/sha_artifacts.py installer/prompt.sh installer/panel_install.sh

Exit codes: 0 = every listed path exists & is LF-canonical (or --no-crlf-warn
silenced), 1 = at least one file had CRLF bytes (the SHA would NOT match the
git blob — run ``git add --renormalize <path> && git checkout -- <path>``
before patching the manifest).
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "release-artifacts.sha256"


def _default_entries() -> list[str]:
    """Parse release-artifacts.sha256 and return the ordered list of paths."""
    paths: list[str] = []
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(maxsplit=1)
        if len(parts) == 2:
            paths.append(parts[1])
    return paths


def _sha256_lf(rel: str, *, warn_crlf: bool) -> tuple[str, int, int]:
    raw = (REPO_ROOT / rel).read_bytes()
    crlf = raw.count(b"\r\n")
    lf_only = raw.count(b"\n") - crlf
    if crlf and warn_crlf:
        sys.stderr.write(
            f"[warn] {rel}: {crlf} CRLF bytes found — SHA256 below will NOT "
            f"match the git blob (raw.githubusercontent.com serves LF-only). "
            f"Run `git add --renormalize {rel} && git checkout -- {rel}` "
            f"then recompute.\n"
        )
    return hashlib.sha256(raw).hexdigest(), crlf, lf_only


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "paths",
        nargs="*",
        help="Optional subset of manifest paths to recompute (default: all).",
    )
    parser.add_argument(
        "--no-crlf-warn",
        action="store_true",
        help="Suppress the CRLF-warning stderr write (still emits SHA on stdout).",
    )
    args = parser.parse_args(argv)

    entries = args.paths or _default_entries()
    if not entries:
        sys.stderr.write("[error] release-artifacts.sha256 has no path entries.\n")
        return 1

    saw_crlf = False
    for rel in entries:
        sha, crlf, lf_only = _sha256_lf(rel, warn_crlf=not args.no_crlf_warn)
        if crlf:
            saw_crlf = True
        print(f"{sha}  {rel}   (bytes_lf_only={lf_only} crlf={crlf})")
    return 1 if saw_crlf else 0


if __name__ == "__main__":
    raise SystemExit(main())
