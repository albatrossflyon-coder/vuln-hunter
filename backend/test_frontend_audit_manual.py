"""Frontend lockfile must carry the fixed next/postcss/sharp versions.

npm audit on 2026-10-13 flagged the pinned next@16.2.6 tree three times (next
itself: critical RCE/cache-poisoning advisories, plus its nested postcss@8.4.31
and sharp@0.34.5). The fix is the 16.3.0 bump; this test pins the minimum
versions that clear those three advisories so the tree cannot silently regress.
Reads frontend/package-lock.json only -- offline, no npm/network needed.
"""

import json
import sys
from pathlib import Path

LOCK = Path(__file__).resolve().parent.parent / "frontend" / "package-lock.json"

MIN_NEXT = "16.3.0"
MIN_SHARP = "0.35.5"
MIN_POSTCSS = "8.5.23"


def _parse(version):
    core, _, _pre = version.partition("-")
    return tuple(int(p) for p in core.split(".")), bool(_pre)


def _gte(version, minimum):
    got, got_pre = _parse(version)
    want, want_pre = _parse(minimum)
    if got != want:
        return got > want
    return not got_pre


def main():
    if sys.stdout.encoding != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8")

    packages = json.loads(LOCK.read_text())["packages"]

    next_ver = packages["node_modules/next"]["version"]
    assert _gte(next_ver, MIN_NEXT), f"next {next_ver} < {MIN_NEXT}"
    print(f"PASS: next {next_ver} >= {MIN_NEXT}")

    sharp_ver = packages["node_modules/sharp"]["version"]
    assert _gte(sharp_ver, MIN_SHARP), f"sharp {sharp_ver} < {MIN_SHARP}"
    print(f"PASS: sharp {sharp_ver} >= {MIN_SHARP}")

    postcss_versions = sorted(
        entry["version"]
        for name, entry in packages.items()
        if name == "node_modules/postcss" or name.endswith("/node_modules/postcss")
    )
    assert postcss_versions, "no postcss entries found in the lockfile"
    for version in postcss_versions:
        assert _gte(version, MIN_POSTCSS), f"postcss {version} < {MIN_POSTCSS}"
    print(f"PASS: postcss {', '.join(postcss_versions)} >= {MIN_POSTCSS}")


if __name__ == "__main__":
    main()
