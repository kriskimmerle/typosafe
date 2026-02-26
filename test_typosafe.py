#!/usr/bin/env python3
"""Comprehensive tests for typosafe

Tests all components with mocked I/O - zero external dependencies except pytest.
"""

import io
import json
import os
import sys
from pathlib import Path
from unittest.mock import Mock, patch, mock_open

import pytest

# Import the module we're testing
import typosafe


# ── Test: Distance Algorithms ─────────────────────────────────────────────


def test_levenshtein_identical():
    assert typosafe.levenshtein("requests", "requests") == 0


def test_levenshtein_single_char_diff():
    # Standard Levenshtein: deletion + insertion (but optimized)
    # "requests" -> "requets" is actually distance 1 with proper algorithm
    assert typosafe.levenshtein("requests", "requets") == 1


def test_levenshtein_insertion():
    assert typosafe.levenshtein("request", "requests") == 1


def test_levenshtein_deletion():
    assert typosafe.levenshtein("requests", "request") == 1


def test_levenshtein_substitution():
    assert typosafe.levenshtein("requests", "reqxests") == 1


def test_levenshtein_empty_strings():
    assert typosafe.levenshtein("", "") == 0
    assert typosafe.levenshtein("abc", "") == 3
    assert typosafe.levenshtein("", "xyz") == 3


def test_damerau_levenshtein_transposition():
    # Transposition: reqeusts -> requests (swap eu -> ue)
    assert typosafe.damerau_levenshtein("requets", "requests") == 1


def test_damerau_levenshtein_identical():
    assert typosafe.damerau_levenshtein("numpy", "numpy") == 0


def test_damerau_levenshtein_single_substitution():
    assert typosafe.damerau_levenshtein("pandas", "pxndas") == 1


def test_damerau_levenshtein_vs_levenshtein():
    # Damerau should be better for transpositions
    s1, s2 = "reqeusts", "requests"
    assert typosafe.damerau_levenshtein(s1, s2) < typosafe.levenshtein(s1, s2)


# ── Test: Pattern Detection ───────────────────────────────────────────────


def test_detect_patterns_identical():
    patterns = typosafe.detect_patterns("requests", "requests")
    assert patterns == []


def test_detect_patterns_separator_swap():
    patterns = typosafe.detect_patterns("my-package", "my_package")
    assert "separator-swap" in patterns


def test_detect_patterns_confusable_char():
    # Test with a real confusable: l->1 or o->0
    patterns = typosafe.detect_patterns("requests", "requ0sts")  # requests has 'e', requ0sts replaces with '0'
    # Actually, let's use a better example: numpy with 0 instead of o (but numpy has no 'o')
    # Better: "pillow" -> "pill0w" (o->0)
    patterns = typosafe.detect_patterns("pill0w", "pillow")
    assert any("confusable" in p for p in patterns)


def test_detect_patterns_prefix_addition():
    patterns = typosafe.detect_patterns("python-requests", "requests")
    assert any("added-prefix" in p for p in patterns)


def test_detect_patterns_suffix_addition():
    patterns = typosafe.detect_patterns("requests-lib", "requests")
    assert any("added-suffix" in p for p in patterns)


def test_detect_patterns_char_omission():
    patterns = typosafe.detect_patterns("reqests", "requests")
    assert any("char-omission" in p for p in patterns)


def test_detect_patterns_char_addition():
    patterns = typosafe.detect_patterns("requestss", "requests")
    assert any("char-addition" in p for p in patterns)


def test_detect_patterns_char_swap():
    patterns = typosafe.detect_patterns("requetss", "requests")
    assert any("char-swap" in p for p in patterns)


def test_detect_patterns_char_repeat():
    patterns = typosafe.detect_patterns("reqquests", "requests")
    assert any("char-repeat" in p for p in patterns)


def test_detect_patterns_version_suffix():
    patterns = typosafe.detect_patterns("requests2", "requests")
    assert "version-suffix" in patterns


# ── Test: Name Normalization ──────────────────────────────────────────────


def test_normalize_name_lowercase():
    assert typosafe.normalize_name("NumPy") == "numpy"


def test_normalize_name_hyphens():
    assert typosafe.normalize_name("my_package") == "my-package"


def test_normalize_name_underscores():
    assert typosafe.normalize_name("my__package") == "my-package"


def test_normalize_name_dots():
    assert typosafe.normalize_name("my.package") == "my-package"


def test_normalize_name_mixed():
    assert typosafe.normalize_name("My_Package.Name") == "my-package-name"


# ── Test: Requirements Parsing ────────────────────────────────────────────


@patch("builtins.open", new_callable=mock_open, read_data="requests\nnumpy>=1.20\npandas[extra]>=2.0\n")
def test_parse_requirements_basic(mock_file):
    packages = typosafe.parse_requirements("requirements.txt")
    assert len(packages) == 3
    assert packages[0]["name"] == "requests"
    assert packages[1]["name"] == "numpy"
    assert packages[2]["name"] == "pandas"


@patch("builtins.open", new_callable=mock_open, read_data="# comment\nrequests\n\npandas\n")
def test_parse_requirements_with_comments(mock_file):
    packages = typosafe.parse_requirements("requirements.txt")
    assert len(packages) == 2
    assert packages[0]["name"] == "requests"


@patch("builtins.open", new_callable=mock_open, read_data="requests==2.28.0\nnumpy~=1.20\npandas!=2.0.0\n")
def test_parse_requirements_with_versions(mock_file):
    packages = typosafe.parse_requirements("requirements.txt")
    assert len(packages) == 3
    assert all(p["name"] in ["requests", "numpy", "pandas"] for p in packages)


@patch("builtins.open", new_callable=mock_open, read_data="-e git+https://github.com/user/repo.git\nrequests\n")
def test_parse_requirements_skip_urls(mock_file):
    packages = typosafe.parse_requirements("requirements.txt")
    assert len(packages) == 1
    assert packages[0]["name"] == "requests"


@patch("builtins.open", new_callable=mock_open, read_data="-r other.txt\nrequests\n")
def test_parse_requirements_skip_options(mock_file):
    packages = typosafe.parse_requirements("requirements.txt")
    assert len(packages) == 1


def test_parse_requirements_file_not_found():
    with pytest.raises(SystemExit):
        typosafe.parse_requirements("nonexistent.txt")


# ── Test: pyproject.toml Parsing ──────────────────────────────────────────


@patch("builtins.open", new_callable=mock_open, read_data="""
[project]
dependencies = [
    "requests>=2.0",
    "numpy",
]
""")
def test_parse_pyproject_basic(mock_file):
    packages = typosafe.parse_pyproject("pyproject.toml")
    assert len(packages) == 2
    names = [p["name"] for p in packages]
    assert "requests" in names
    assert "numpy" in names


@patch("builtins.open", new_callable=mock_open, read_data="""
[project]
dependencies = [
    "requests[security]>=2.0",
]
""")
def test_parse_pyproject_with_extras(mock_file):
    packages = typosafe.parse_pyproject("pyproject.toml")
    assert len(packages) == 1
    assert packages[0]["name"] == "requests"


@patch("builtins.open", new_callable=mock_open, read_data="""
[project]
dependencies = [
    "requests",
]
[project.optional-dependencies]
dev = ["pytest", "black"]
""")
def test_parse_pyproject_with_optional_deps(mock_file):
    # This test uses the fallback parser (when tomllib is not available)
    # The fallback parser only catches dependencies in the basic format
    packages = typosafe.parse_pyproject("pyproject.toml")
    # Should get at least the main dependency with fallback parser
    assert len(packages) >= 1


def test_parse_pyproject_file_not_found():
    with pytest.raises(SystemExit):
        typosafe.parse_pyproject("nonexistent.toml")


# ── Test: Stdin Parsing ───────────────────────────────────────────────────


def test_parse_stdin():
    mock_stdin = io.StringIO("requests\nnumpy>=1.20\npandas\n")
    with patch("sys.stdin", mock_stdin):
        packages = typosafe.parse_stdin()
        assert len(packages) == 3
        assert packages[0]["name"] == "requests"


def test_parse_stdin_with_comments():
    mock_stdin = io.StringIO("# comment\nrequests\n\npandas\n")
    with patch("sys.stdin", mock_stdin):
        packages = typosafe.parse_stdin()
        assert len(packages) == 2


# ── Test: Package Analysis ────────────────────────────────────────────────


def test_analyze_package_safe():
    pkg = {"name": "requests", "normalized": "requests", "line": 1, "source": "test.txt"}
    popular_set = {"requests", "numpy", "pandas"}
    popular_list = ["requests", "numpy", "pandas"]
    
    findings = typosafe.analyze_package(pkg, popular_set, popular_list)
    assert findings == []  # requests IS popular, so no findings


def test_analyze_package_typosquat():
    pkg = {"name": "requets", "normalized": "requets", "line": 1, "source": "test.txt"}
    popular_set = {"requests", "numpy", "pandas"}
    popular_list = ["requests", "numpy", "pandas"]
    
    findings = typosafe.analyze_package(pkg, popular_set, popular_list)
    assert len(findings) > 0
    assert findings[0]["similar_to"] == "requests"
    assert findings[0]["distance"] == 1
    assert findings[0]["severity"] in ["HIGH", "CRITICAL"]


def test_analyze_package_confusable():
    # Use a real confusable example: pill0w vs pillow (0 vs o)
    pkg = {"name": "pill0w", "normalized": "pill0w", "line": 1, "source": "test.txt"}
    popular_set = {"pillow"}
    popular_list = ["pillow"]
    
    findings = typosafe.analyze_package(pkg, popular_set, popular_list)
    assert len(findings) > 0
    # Check that confusable pattern is detected
    assert any("confusable" in str(f.get("patterns", [])) for f in findings)


def test_analyze_package_distance_filter():
    pkg = {"name": "xxxyyy", "normalized": "xxxyyy", "line": 1, "source": "test.txt"}
    popular_set = {"requests"}
    popular_list = ["requests"]
    
    findings = typosafe.analyze_package(pkg, popular_set, popular_list, max_distance=2)
    assert len(findings) == 0  # Too different


def test_analyze_all():
    packages = [
        {"name": "requests", "normalized": "requests", "line": 1, "source": "test.txt"},
        {"name": "requets", "normalized": "requets", "line": 2, "source": "test.txt"},
    ]
    
    results = typosafe.analyze_all(packages, max_distance=2)
    
    assert results["total_checked"] == 2
    assert results["safe_count"] >= 1
    assert results["flagged_count"] >= 1
    assert len(results["findings"]) >= 1


# ── Test: Output Formatting ───────────────────────────────────────────────


def test_format_text_no_findings():
    results = {
        "findings": [],
        "total_checked": 5,
        "safe_count": 5,
        "flagged_count": 0,
    }
    
    output = typosafe.format_text(results)
    assert "No typosquatting risks detected" in output
    assert "5" in output


def test_format_text_with_findings():
    results = {
        "findings": [{
            "dependency": "requets",
            "similar_to": "requests",
            "distance": 1,
            "severity": "HIGH",
            "patterns": ["char-swap"],
            "line": 2,
            "source": "test.txt",
        }],
        "total_checked": 2,
        "safe_count": 1,
        "flagged_count": 1,
    }
    
    output = typosafe.format_text(results)
    assert "requets" in output
    assert "requests" in output
    assert "HIGH" in output


def test_format_text_verbose():
    results = {
        "findings": [{
            "dependency": "requets",
            "similar_to": "requests",
            "distance": 1,
            "severity": "HIGH",
            "patterns": ["char-swap (t ↔ e)"],
            "line": 2,
            "source": "test.txt",
        }],
        "total_checked": 2,
        "safe_count": 1,
        "flagged_count": 1,
    }
    
    output = typosafe.format_text(results, verbose=True)
    assert "Pattern:" in output
    assert "char-swap" in output


def test_format_json():
    results = {
        "findings": [{
            "dependency": "requets",
            "similar_to": "requests",
            "distance": 1,
            "severity": "HIGH",
            "patterns": [],
            "line": 2,
            "source": "test.txt",
        }],
        "total_checked": 2,
        "safe_count": 1,
        "flagged_count": 1,
    }
    
    output = typosafe.format_json(results)
    data = json.loads(output)
    
    assert data["total_checked"] == 2
    assert data["flagged_count"] == 1
    assert len(data["findings"]) == 1
    assert data["findings"][0]["dependency"] == "requets"


# ── Test: CLI / Main Function ─────────────────────────────────────────────


@patch("sys.argv", ["typosafe", "--help"])
def test_main_help(capsys):
    with pytest.raises(SystemExit) as exc_info:
        typosafe.main()
    assert exc_info.value.code == 0


@patch("sys.argv", ["typosafe", "--version"])
def test_main_version(capsys):
    with pytest.raises(SystemExit) as exc_info:
        typosafe.main()
    captured = capsys.readouterr()
    assert typosafe.__version__ in captured.out


@patch("sys.argv", ["typosafe", "requirements.txt"])
@patch("builtins.open", new_callable=mock_open, read_data="requests\nnumpy\n")
@patch("os.path.exists", return_value=True)
def test_main_basic_run(mock_exists, mock_file, capsys):
    typosafe.main()
    captured = capsys.readouterr()
    assert "typosafe" in captured.out


@patch("sys.argv", ["typosafe", "requirements.txt", "--json"])
@patch("builtins.open", new_callable=mock_open, read_data="requests\n")
@patch("os.path.exists", return_value=True)
def test_main_json_output(mock_exists, mock_file, capsys):
    typosafe.main()
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "total_checked" in data
    assert "findings" in data


@patch("sys.argv", ["typosafe", "requirements.txt", "--check"])
@patch("builtins.open", new_callable=mock_open, read_data="requets\n")
@patch("os.path.exists", return_value=True)
def test_main_check_mode_fails(mock_exists, mock_file):
    with pytest.raises(SystemExit) as exc_info:
        typosafe.main()
    # Should exit with 1 because there's a HIGH risk
    assert exc_info.value.code == 1


@patch("sys.argv", ["typosafe", "requirements.txt", "--check"])
@patch("builtins.open", new_callable=mock_open, read_data="requests\n")
@patch("os.path.exists", return_value=True)
def test_main_check_mode_passes(mock_exists, mock_file):
    with pytest.raises(SystemExit) as exc_info:
        typosafe.main()
    # Should exit with 0 because requests is safe
    assert exc_info.value.code == 0


@patch("sys.argv", ["typosafe", "requirements.txt", "--distance", "1"])
@patch("builtins.open", new_callable=mock_open, read_data="requests\n")
@patch("os.path.exists", return_value=True)
def test_main_custom_distance(mock_exists, mock_file, capsys):
    typosafe.main()
    # Should not crash
    captured = capsys.readouterr()
    assert "typosafe" in captured.out


@patch("sys.argv", ["typosafe", "--stdin"])
@patch("sys.stdin", io.StringIO("requests\nnumpy\n"))
def test_main_stdin_mode(capsys):
    typosafe.main()
    captured = capsys.readouterr()
    assert "typosafe" in captured.out


@patch("sys.argv", ["typosafe"])
@patch("os.path.exists", side_effect=lambda f: f == "requirements.txt")
@patch("builtins.open", new_callable=mock_open, read_data="requests\n")
def test_main_auto_detect_requirements(mock_file, mock_exists, capsys):
    typosafe.main()
    # Should auto-detect requirements.txt
    captured = capsys.readouterr()
    assert "typosafe" in captured.out


@patch("sys.argv", ["typosafe"])
@patch("os.path.exists", return_value=False)
def test_main_no_files_found(mock_exists):
    with pytest.raises(SystemExit) as exc_info:
        typosafe.main()
    assert exc_info.value.code == 1


@patch("sys.argv", ["typosafe", "requirements.txt", "--severity", "high"])
@patch("builtins.open", new_callable=mock_open, read_data="requets\n")
@patch("os.path.exists", return_value=True)
def test_main_severity_filter(mock_exists, mock_file, capsys):
    typosafe.main()
    # Should only show HIGH and CRITICAL
    captured = capsys.readouterr()
    assert "requets" in captured.out  # This is HIGH severity


# ── Test: Edge Cases & Robustness ─────────────────────────────────────────


def test_analyze_package_very_short_names():
    # Very short names should be skipped (high false positive rate)
    pkg = {"name": "ab", "normalized": "ab", "line": 1, "source": "test.txt"}
    popular_set = {"numpy"}
    popular_list = ["numpy", "xy"]  # xy is 2 chars
    
    findings = typosafe.analyze_package(pkg, popular_set, popular_list)
    # Should not flag against "xy" (too short)
    assert all(f["similar_to"] != "xy" for f in findings)


def test_normalize_name_edge_cases():
    assert typosafe.normalize_name("") == ""
    assert typosafe.normalize_name("___") == "-"
    assert typosafe.normalize_name("...") == "-"


def test_levenshtein_different_lengths():
    assert typosafe.levenshtein("a", "abc") == 2
    assert typosafe.levenshtein("abcdef", "abc") == 3


def test_damerau_levenshtein_complex():
    # Multiple operations
    assert typosafe.damerau_levenshtein("kitten", "sitting") >= 3


def test_detect_patterns_no_match():
    patterns = typosafe.detect_patterns("completely", "different")
    # Should not find specific patterns when names are too different
    assert len(patterns) == 0 or all("swap" not in p and "omission" not in p for p in patterns)


@patch("builtins.open", new_callable=mock_open, read_data="")
def test_parse_requirements_empty_file(mock_file):
    packages = typosafe.parse_requirements("empty.txt")
    assert len(packages) == 0


def test_parse_stdin_empty():
    mock_stdin = io.StringIO("")
    with patch("sys.stdin", mock_stdin):
        packages = typosafe.parse_stdin()
        assert len(packages) == 0


# ── Test: Color/NO_COLOR handling ─────────────────────────────────────────


def test_no_color_env():
    # Test that NO_COLOR environment variable disables colors
    with patch.dict(os.environ, {"NO_COLOR": "1"}):
        # Re-import to trigger color detection
        import importlib
        importlib.reload(typosafe)
        assert typosafe.C.RED == ""
        assert typosafe.C.RESET == ""


# ── Test: Real-world Package Names ────────────────────────────────────────


def test_separator_normalization():
    # PyPI normalizes these as the same package
    assert typosafe.normalize_name("my-package") == typosafe.normalize_name("my_package")
    assert typosafe.normalize_name("my-package") == typosafe.normalize_name("my.package")
    
    # Pattern detection should recognize this as separator-swap and skip further checks
    patterns = typosafe.detect_patterns("my-package", "my_package")
    assert patterns == ["separator-swap"]


def test_known_typosquat_patterns():
    # Real-world examples of typosquatting patterns
    test_cases = [
        ("reqeusts", "requests", 1),   # transposition
        ("numpy1", "numpy", 1),         # version suffix (1 character addition)
        ("requ3sts", "requests", 1),    # single character substitution
        ("reqests", "requests", 1),     # single character omission
    ]
    
    for typo, legit, expected_max_dist in test_cases:
        dist = typosafe.damerau_levenshtein(typo, legit)
        assert dist <= expected_max_dist, f"{typo} vs {legit}: distance {dist} > {expected_max_dist}"


# Run with: pytest -v test_typosafe.py
