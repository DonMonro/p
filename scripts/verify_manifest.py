"""One-shot manifest verifier — re-fetches every artifact at the v1.0.0 tag
from raw.githubusercontent.com and recomputes SHA256, comparing to the
previously-baked hashes in release-artifacts.sha256.

Run:  python scripts/verify_manifest.py
Exit code 0 = every entry matches; non-zero on the first mismatch.
"""
from __future__ import annotations

import hashlib
import sys
import urllib.request
from pathlib import Path

REPO_OWNER = "DonMonro"
REPO_NAME = "p"
TAG = "v1.0.0"
RAW = f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/{TAG}/"

MANIFEST = Path(__file__).resolve().parents[1] / "release-artifacts.sha256"
TIMEOUT_SECONDS = 30


def _fetch(url: str) -> bytes:
    """Fetch URL bytes, raising urllib.error.URLError on failure."""
    with urllib.request.urlopen(url, timeout=TIMEOUT_SECONDS) as r:  # noqa: S310 — controlled URL
        return r.read()


def main() -> int:
    text = MANIFEST.read_text(encoding="utf-8")
    entries: list[tuple[str, str]] = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        digest, _, path = s.partition("  ")
        digest = digest.strip()
        path = path.strip()
        if not digest or not path or len(digest) != 64:
            print(f"[malformed] {line!r}", file=sys.stderr)
            return 2
        entries.append((digest, path))

    print(f"Verifying {len(entries)} manifest entries against {RAW}...")
    failures: list[str] = []
    for idx, (expected, path) in enumerate(entries, 1):
        url = RAW + path
        try:
            data = _fetch(url)
        except Exception as exc:  # noqa: BLE001 — network errors must not abort the loop
            failures.append(f"FETCH FAIL {path}: {exc!r}")
            print(f"[{idx:2}/{len(entries)}] FETCH FAIL  {path}  ({exc!r})")
            continue
        actual = hashlib.sha256(data).hexdigest()
        ok = actual == expected
        marker = "OK   " if ok else "MISMATCH"
        print(f"[{idx:2}/{len(entries)}] {marker}  {path}  (exp={expected[:12]} act={actual[:12]} nbytes={len(data)})")
        if not ok:
            failures.append(f"SHA MISMATCH {path}: expected {expected}, got {actual}")

    if failures:
        print("\n=== FAILURES ===", file=sys.stderr)
        for f in failures:
            print(f" - {f}", file=sys.stderr)
        return 1
    print(f"\nAll {len(entries)} entries verified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
