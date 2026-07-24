"""Standalone regression check for main._resolve_repo_dir (path validation on
every repo_path-accepting endpoint). Run directly: python test_resolve_repo_dir.py
No pytest dependency — kept as a plain assert script since it's one function.
"""

from pathlib import Path

from fastapi import HTTPException

from main import _resolve_repo_dir

HERE = Path(__file__).parent.resolve()

# A valid directory resolves to its canonical absolute form.
assert _resolve_repo_dir(str(HERE)) == str(HERE)

# A relative path with traversal segments normalizes cleanly to the real dir
# instead of being rejected outright or passed through unresolved.
assert _resolve_repo_dir(str(HERE / ".." / "backend")) == str(HERE)

# A path that doesn't exist is rejected with a 400, not silently accepted.
try:
    _resolve_repo_dir(str(HERE / "does-not-exist-at-all"))
    raise AssertionError("expected HTTPException for nonexistent path")
except HTTPException as e:
    assert e.status_code == 400

# A file (not a directory) is rejected the same way.
try:
    _resolve_repo_dir(str(HERE / "main.py"))
    raise AssertionError("expected HTTPException for a file, not a directory")
except HTTPException as e:
    assert e.status_code == 400

print("test_resolve_repo_dir: all checks passed")
