"""Test PHP config selection in scanner.run_scan.

Run directly: python test_php_config_selection.py
Tests that p/php is included when PHP files exist, excluded when they don't.
"""

import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import scanner


def _mock_semgrep_result(returncode=0, stdout='{"results": []}'):
    """Create a mock subprocess.CompletedProcess for semgrep."""
    mock = MagicMock(spec=subprocess.CompletedProcess)
    mock.returncode = returncode
    mock.stdout = stdout
    mock.stderr = ""
    return mock


def test_php_config_included_when_php_files_exist():
    """When target contains *.php files, p/php should be in the semgrep configs."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = Path(tmpdir)
        # Create a PHP file with unsanitized eval of $_GET
        php_file = repo / "vuln.php"
        php_file.write_text('<?php eval($_GET["cmd"]); ?>\n', encoding="utf-8")

        captured_configs = []

        def capture_cmd(*args, **kwargs):
            # Find --config arguments
            cmd = args[0] if args else kwargs.get("args", [])
            configs = []
            i = 0
            while i < len(cmd):
                if cmd[i] == "--config" and i + 1 < len(cmd):
                    configs.append(cmd[i + 1])
                i += 1
            captured_configs.extend(configs)
            return _mock_semgrep_result()

        with patch("subprocess.run", side_effect=capture_cmd):
            scanner.run_scan(str(repo))

        assert "p/php" in captured_configs, f"Expected p/php in configs, got {captured_configs}"
        print("PASS: p/php included when PHP files exist")


def test_php_config_excluded_when_no_php_files():
    """When target has no *.php files, p/php should NOT be in the semgrep configs."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = Path(tmpdir)
        # Create only Python files
        py_file = repo / "safe.py"
        py_file.write_text('print("hello")\n', encoding="utf-8")

        captured_configs = []

        def capture_cmd(*args, **kwargs):
            cmd = args[0] if args else kwargs.get("args", [])
            configs = []
            i = 0
            while i < len(cmd):
                if cmd[i] == "--config" and i + 1 < len(cmd):
                    configs.append(cmd[i + 1])
                i += 1
            captured_configs.extend(configs)
            return _mock_semgrep_result()

        with patch("subprocess.run", side_effect=capture_cmd):
            scanner.run_scan(str(repo))

        assert "p/php" not in captured_configs, f"Did not expect p/php in configs, got {captured_configs}"
        print("PASS: p/php excluded when no PHP files exist")


def test_explicit_configs_not_modified():
    """When caller explicitly provides configs, PHP detection should not modify them."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = Path(tmpdir)
        php_file = repo / "vuln.php"
        php_file.write_text('<?php eval($_GET["cmd"]); ?>\n', encoding="utf-8")

        captured_configs = []

        def capture_cmd(*args, **kwargs):
            cmd = args[0] if args else kwargs.get("args", [])
            configs = []
            i = 0
            while i < len(cmd):
                if cmd[i] == "--config" and i + 1 < len(cmd):
                    configs.append(cmd[i + 1])
                i += 1
            captured_configs.extend(configs)
            return _mock_semgrep_result()

        with patch("subprocess.run", side_effect=capture_cmd):
            scanner.run_scan(str(repo), configs=["p/security-audit"])

        assert captured_configs == ["p/security-audit"], f"Expected only explicit config, got {captured_configs}"
        print("PASS: explicit configs not modified by PHP detection")


def test_diff_scan_with_php_files():
    """Diff scan with changed PHP files should include p/php."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = Path(tmpdir)
        # Create a PHP file
        php_file = repo / "vuln.php"
        php_file.write_text('<?php eval($_GET["cmd"]); ?>\n', encoding="utf-8")

        captured_configs = []

        def capture_cmd(*args, **kwargs):
            cmd = args[0] if args else kwargs.get("args", [])
            configs = []
            i = 0
            while i < len(cmd):
                if cmd[i] == "--config" and i + 1 < len(cmd):
                    configs.append(cmd[i + 1])
                i += 1
            captured_configs.extend(configs)
            return _mock_semgrep_result()

        with patch("subprocess.run", side_effect=capture_cmd):
            scanner.run_scan(str(repo), files=[str(php_file)])

        assert "p/php" in captured_configs, f"Expected p/php in configs for diff scan, got {captured_configs}"
        print("PASS: p/php included in diff scan when PHP files changed")


def test_diff_scan_without_php_files():
    """Diff scan with only non-PHP files should not include p/php."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = Path(tmpdir)
        py_file = repo / "safe.py"
        py_file.write_text('print("hello")\n', encoding="utf-8")

        captured_configs = []

        def capture_cmd(*args, **kwargs):
            cmd = args[0] if args else kwargs.get("args", [])
            configs = []
            i = 0
            while i < len(cmd):
                if cmd[i] == "--config" and i + 1 < len(cmd):
                    configs.append(cmd[i + 1])
                i += 1
            captured_configs.extend(configs)
            return _mock_semgrep_result()

        with patch("subprocess.run", side_effect=capture_cmd):
            scanner.run_scan(str(repo), files=[str(py_file)])

        assert "p/php" not in captured_configs, f"Did not expect p/php in configs, got {captured_configs}"
        print("PASS: p/php excluded in diff scan when no PHP files changed")


if __name__ == "__main__":
    test_php_config_included_when_php_files_exist()
    test_php_config_excluded_when_no_php_files()
    test_explicit_configs_not_modified()
    test_diff_scan_with_php_files()
    test_diff_scan_without_php_files()
    print("\nAll PHP config selection tests passed!")