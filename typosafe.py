#!/usr/bin/env python3
"""typosafe - Supply Chain Typosquatting Detector

Checks your Python dependencies (requirements.txt, pyproject.toml) against the
top 1000 most popular PyPI packages to detect potential typosquatting attacks.
Uses Levenshtein distance to flag packages suspiciously similar to popular ones.

Usage:
    typosafe requirements.txt
    typosafe pyproject.toml
    typosafe requirements.txt --verbose
    typosafe requirements.txt --json
    typosafe requirements.txt --check
    typosafe --stdin < requirements.txt

Author: github.com/kriskimmerle
License: MIT
"""

__version__ = "1.0.0"

import argparse
import json
import os
import re
import sys
import textwrap

# ── ANSI colors ────────────────────────────────────────────────────────────

class C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

NO_COLOR = os.environ.get("NO_COLOR") is not None or not sys.stdout.isatty()
if NO_COLOR:
    for attr in ("RED", "GREEN", "YELLOW", "BLUE", "CYAN", "BOLD", "DIM", "RESET"):
        setattr(C, attr, "")


# ── Levenshtein Distance ──────────────────────────────────────────────────

def levenshtein(s1, s2):
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)

    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            # Insertions, deletions, substitutions
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row

    return prev_row[-1]


def damerau_levenshtein(s1, s2):
    """Compute Damerau-Levenshtein distance (includes transpositions)."""
    len1 = len(s1)
    len2 = len(s2)

    # Create matrix
    d = [[0] * (len2 + 1) for _ in range(len1 + 1)]
    for i in range(len1 + 1):
        d[i][0] = i
    for j in range(len2 + 1):
        d[0][j] = j

    for i in range(1, len1 + 1):
        for j in range(1, len2 + 1):
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            d[i][j] = min(
                d[i - 1][j] + 1,       # deletion
                d[i][j - 1] + 1,       # insertion
                d[i - 1][j - 1] + cost  # substitution
            )
            # Transposition
            if i > 1 and j > 1 and s1[i - 1] == s2[j - 2] and s1[i - 2] == s2[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + cost)

    return d[len1][len2]


# ── Squatting Pattern Detection ───────────────────────────────────────────

def detect_patterns(dep_name, popular_name):
    """Detect specific typosquatting patterns between dependency and popular package."""
    patterns = []
    dn = dep_name.lower()
    pn = popular_name.lower()

    # Separator confusion: hyphens vs underscores vs dots
    dn_norm = dn.replace("-", "").replace("_", "").replace(".", "")
    pn_norm = pn.replace("-", "").replace("_", "").replace(".", "")
    if dn_norm == pn_norm and dn != pn:
        patterns.append("separator-swap")
        return patterns  # This is actually fine in PyPI (normalized), skip further checks

    # Character substitution (l/1, 0/o, etc.)
    confusables = {
        "l": "1", "1": "l",
        "o": "0", "0": "o",
        "i": "l", "l": "i",
        "rn": "m", "m": "rn",
    }
    for orig, sub in confusables.items():
        if orig in pn and sub in dn:
            test = dn.replace(sub, orig, 1)
            if test == pn:
                patterns.append(f"confusable-char ({sub}→{orig})")

    # Prefix/suffix additions
    common_prefixes = ["python-", "py-", "python_", "py_", "lib", "the-"]
    common_suffixes = ["-python", "-py", "_python", "_py", "-lib", "-dev", "-sdk", "-api", "-client", "-core"]
    for prefix in common_prefixes:
        if dn.startswith(prefix) and dn[len(prefix):] == pn:
            patterns.append(f"added-prefix ({prefix})")
        if pn.startswith(prefix) and pn[len(prefix):] == dn:
            patterns.append(f"removed-prefix ({prefix})")
    for suffix in common_suffixes:
        if dn.endswith(suffix) and dn[:-len(suffix)] == pn:
            patterns.append(f"added-suffix ({suffix})")
        if pn.endswith(suffix) and pn[:-len(suffix)] == dn:
            patterns.append(f"removed-suffix ({suffix})")

    # Character omission (missing a letter)
    if len(dn) == len(pn) - 1:
        for i in range(len(pn)):
            if pn[:i] + pn[i + 1:] == dn:
                patterns.append(f"char-omission (missing '{pn[i]}' at pos {i})")
                break

    # Character addition
    if len(dn) == len(pn) + 1:
        for i in range(len(dn)):
            if dn[:i] + dn[i + 1:] == pn:
                patterns.append(f"char-addition (extra '{dn[i]}' at pos {i})")
                break

    # Character swap (transposition)
    if len(dn) == len(pn):
        diffs = [(i, dn[i], pn[i]) for i in range(len(dn)) if dn[i] != pn[i]]
        if len(diffs) == 2:
            (i1, a1, b1), (i2, a2, b2) = diffs
            if a1 == b2 and a2 == b1:
                patterns.append(f"char-swap ('{a1}' ↔ '{a2}' at pos {i1},{i2})")

    # Repeated character
    if len(dn) == len(pn) + 1:
        for i in range(len(dn) - 1):
            if dn[i] == dn[i + 1]:
                without_dup = dn[:i] + dn[i + 1:]
                if without_dup == pn:
                    patterns.append(f"char-repeat (doubled '{dn[i]}' at pos {i})")
                    break

    # Version suffix (e.g., requests2)
    if re.match(r'^' + re.escape(pn) + r'\d+$', dn):
        patterns.append("version-suffix")

    return patterns


# ── Dependency Parsing ────────────────────────────────────────────────────

def normalize_name(name):
    """Normalize package name per PEP 503."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirements(filepath):
    """Parse requirements.txt and return list of package names."""
    packages = []
    try:
        with open(filepath) as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                # Skip empty lines, comments, options
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                # Skip URLs
                if "://" in line:
                    continue
                # Strip extras: package[extra1,extra2]
                name = re.split(r"[\[;@><=!~]", line)[0].strip()
                if name:
                    packages.append({"name": name, "normalized": normalize_name(name), "line": line_num, "source": filepath})
    except FileNotFoundError:
        print(f"Error: File not found: {filepath}", file=sys.stderr)
        sys.exit(1)
    return packages


def parse_pyproject(filepath):
    """Parse pyproject.toml for dependencies."""
    packages = []
    try:
        # Try tomllib (3.11+) first, fall back to basic parsing
        try:
            import tomllib
            with open(filepath, "rb") as f:
                data = tomllib.load(f)
            deps = data.get("project", {}).get("dependencies", [])
            for i, dep in enumerate(deps):
                name = re.split(r"[\[;@><=!~\s]", dep)[0].strip()
                if name:
                    packages.append({"name": name, "normalized": normalize_name(name), "line": i + 1, "source": filepath})

            # Also check optional dependencies
            opt_deps = data.get("project", {}).get("optional-dependencies", {})
            for group, group_deps in opt_deps.items():
                for dep in group_deps:
                    name = re.split(r"[\[;@><=!~\s]", dep)[0].strip()
                    if name:
                        packages.append({"name": name, "normalized": normalize_name(name), "line": 0, "source": f"{filepath} [{group}]"})

        except ImportError:
            # Fallback: basic TOML parsing for dependencies
            in_deps = False
            with open(filepath) as f:
                for line_num, line in enumerate(f, 1):
                    stripped = line.strip()
                    if stripped == "dependencies = [":
                        in_deps = True
                        continue
                    if in_deps:
                        if stripped == "]":
                            in_deps = False
                            continue
                        # Parse "package>=1.0",
                        match = re.match(r'["\']([^"\']+)["\']', stripped)
                        if match:
                            dep = match.group(1)
                            name = re.split(r"[\[;@><=!~\s]", dep)[0].strip()
                            if name:
                                packages.append({"name": name, "normalized": normalize_name(name), "line": line_num, "source": filepath})
    except FileNotFoundError:
        print(f"Error: File not found: {filepath}", file=sys.stderr)
        sys.exit(1)
    return packages


def parse_stdin():
    """Parse package names from stdin."""
    packages = []
    for line_num, line in enumerate(sys.stdin, 1):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        if "://" in line:
            continue
        name = re.split(r"[\[;@><=!~]", line)[0].strip()
        if name:
            packages.append({"name": name, "normalized": normalize_name(name), "line": line_num, "source": "stdin"})
    return packages


# ── Analysis ──────────────────────────────────────────────────────────────

def analyze_package(pkg, popular_set, popular_list, max_distance=2):
    """Analyze a single package for typosquatting risk."""
    name = pkg["normalized"]
    findings = []

    # If the package IS a popular package, it's safe
    if name in popular_set:
        return findings

    # Check against all popular packages
    for popular in popular_list:
        # Skip self
        if name == popular:
            continue

        # Quick length filter: if lengths differ by more than max_distance, skip
        if abs(len(name) - len(popular)) > max_distance:
            continue

        # Skip very short names (high false positive rate)
        if len(popular) <= 2:
            continue

        dist = damerau_levenshtein(name, popular)

        if dist <= max_distance and dist > 0:
            # Determine severity
            patterns = detect_patterns(name, popular)

            # Separator swaps are normalized by PyPI — not a real risk
            if patterns == ["separator-swap"]:
                continue

            if dist == 1:
                severity = "HIGH"
            else:
                severity = "MEDIUM"

            # Boost severity for specific patterns
            if any("confusable" in p for p in patterns):
                severity = "CRITICAL"
            if any("version-suffix" in p for p in patterns):
                severity = "HIGH"

            findings.append({
                "dependency": pkg["name"],
                "similar_to": popular,
                "distance": dist,
                "severity": severity,
                "patterns": patterns,
                "line": pkg["line"],
                "source": pkg["source"],
            })

    # Sort by distance (closest = most suspicious)
    findings.sort(key=lambda f: (f["distance"], f["similar_to"]))

    return findings


def analyze_all(packages, max_distance=2):
    """Analyze all packages and return findings."""
    popular_set = {normalize_name(p) for p in TOP_PACKAGES}
    popular_list = [normalize_name(p) for p in TOP_PACKAGES]

    all_findings = []
    safe_count = 0
    checked_count = 0

    for pkg in packages:
        checked_count += 1
        findings = analyze_package(pkg, popular_set, popular_list, max_distance)
        if findings:
            all_findings.extend(findings)
        elif pkg["normalized"] in popular_set:
            safe_count += 1
        else:
            safe_count += 1  # No match found = not suspicious

    return {
        "findings": all_findings,
        "total_checked": checked_count,
        "safe_count": safe_count,
        "flagged_count": len(set(f["dependency"] for f in all_findings)),
    }


# ── Output Formatters ─────────────────────────────────────────────────────

def format_text(results, verbose=False):
    """Format results as human-readable text."""
    lines = []
    lines.append(f"\n{C.BOLD}typosafe v{__version__}{C.RESET} — Supply Chain Typosquatting Detector\n")

    findings = results["findings"]

    if not findings:
        lines.append(f"{C.GREEN}✓ No typosquatting risks detected{C.RESET}")
        lines.append(f"  Checked {results['total_checked']} packages against top {len(TOP_PACKAGES)} popular PyPI packages")
        lines.append("")
        return "\n".join(lines)

    # Group by dependency
    by_dep = {}
    for f in findings:
        dep = f["dependency"]
        if dep not in by_dep:
            by_dep[dep] = []
        by_dep[dep].append(f)

    # Sort by highest severity finding
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    sorted_deps = sorted(by_dep.items(),
                         key=lambda x: min(severity_order.get(f["severity"], 3) for f in x[1]))

    for dep, dep_findings in sorted_deps:
        first = dep_findings[0]
        sev = first["severity"]
        if sev == "CRITICAL":
            icon = f"{C.RED}🚨"
            sev_str = f"{C.RED}CRITICAL{C.RESET}"
        elif sev == "HIGH":
            icon = f"{C.RED}⚠"
            sev_str = f"{C.RED}HIGH{C.RESET}"
        else:
            icon = f"{C.YELLOW}⚠"
            sev_str = f"{C.YELLOW}MEDIUM{C.RESET}"

        source_info = f" (line {first['line']})" if first["line"] else ""
        lines.append(f"{icon}{C.RESET} [{sev_str}] {C.BOLD}{dep}{C.RESET}{source_info}")

        for f in dep_findings:
            dist_str = f"distance={f['distance']}"
            lines.append(f"  → Similar to {C.CYAN}{f['similar_to']}{C.RESET} ({dist_str})")

            if verbose and f["patterns"]:
                for p in f["patterns"]:
                    lines.append(f"    {C.DIM}Pattern: {p}{C.RESET}")

        lines.append("")

    # Summary
    criticals = len([f for f in findings if f["severity"] == "CRITICAL"])
    highs = len([f for f in findings if f["severity"] == "HIGH"])
    mediums = len([f for f in findings if f["severity"] == "MEDIUM"])

    lines.append(f"{C.BOLD}── Summary ──{C.RESET}")
    lines.append(f"  Packages checked: {results['total_checked']}")
    lines.append(f"  Packages flagged: {results['flagged_count']}")
    if criticals:
        lines.append(f"  {C.RED}Critical: {criticals}{C.RESET}")
    if highs:
        lines.append(f"  {C.RED}High: {highs}{C.RESET}")
    if mediums:
        lines.append(f"  {C.YELLOW}Medium: {mediums}{C.RESET}")
    lines.append(f"  Reference: top {len(TOP_PACKAGES)} popular PyPI packages")
    lines.append("")

    return "\n".join(lines)


def format_json(results):
    """Format results as JSON."""
    output = {
        "version": __version__,
        "total_checked": results["total_checked"],
        "flagged_count": results["flagged_count"],
        "safe_count": results["safe_count"],
        "reference_packages": len(TOP_PACKAGES),
        "findings": results["findings"],
    }
    return json.dumps(output, indent=2)


# ── CLI ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="typosafe",
        description="Supply Chain Typosquatting Detector — check your Python dependencies for potential typosquatting attacks.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            examples:
              typosafe requirements.txt              Check requirements file
              typosafe pyproject.toml                Check pyproject.toml dependencies
              typosafe requirements.txt --verbose    Show attack pattern details
              typosafe requirements.txt --json       JSON output for automation
              typosafe requirements.txt --check      CI mode: exit 1 if risks found
              typosafe --stdin < requirements.txt    Read from stdin
              typosafe req.txt --distance 1          Strict mode: only flag distance=1
        """),
    )

    parser.add_argument("files", nargs="*", help="Requirements files to check (requirements.txt or pyproject.toml)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed pattern analysis")
    parser.add_argument("--json", dest="json_output", action="store_true", help="JSON output")
    parser.add_argument("--check", action="store_true", help="CI mode: exit 1 if any HIGH/CRITICAL risks found")
    parser.add_argument("--stdin", action="store_true", help="Read package names from stdin")
    parser.add_argument("--distance", type=int, default=2, metavar="N",
                        help="Maximum edit distance to flag (default: 2)")
    parser.add_argument("--severity", choices=["medium", "high", "critical"], default="medium",
                        help="Minimum severity to show (default: medium)")
    parser.add_argument("--version", action="version", version=f"typosafe {__version__}")

    args = parser.parse_args()

    if not args.files and not args.stdin:
        # Auto-detect
        for candidate in ["requirements.txt", "pyproject.toml"]:
            if os.path.exists(candidate):
                args.files = [candidate]
                break
        if not args.files:
            parser.print_help()
            sys.exit(1)

    # Parse dependencies
    all_packages = []
    if args.stdin:
        all_packages = parse_stdin()
    else:
        for filepath in args.files:
            if filepath.endswith(".toml"):
                all_packages.extend(parse_pyproject(filepath))
            else:
                all_packages.extend(parse_requirements(filepath))

    if not all_packages:
        print("No packages found to check.", file=sys.stderr)
        sys.exit(1)

    # Analyze
    results = analyze_all(all_packages, max_distance=args.distance)

    # Filter by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    min_sev = severity_order.get(args.severity.upper(), 2)
    results["findings"] = [f for f in results["findings"]
                           if severity_order.get(f["severity"], 3) <= min_sev]

    # Output
    if args.json_output:
        print(format_json(results))
    else:
        print(format_text(results, verbose=args.verbose))

    # Check mode
    if args.check:
        has_risk = any(f["severity"] in ("HIGH", "CRITICAL") for f in results["findings"])
        sys.exit(1 if has_risk else 0)


# ── Top 1000 Popular PyPI Packages (updated 2026-02-01) ───────────────────
# Source: https://hugovk.github.io/top-pypi-packages/

TOP_PACKAGES = {
    'boto3', 'urllib3', 'botocore', 'packaging', 'certifi', 'typing-extensions', 'requests', 'setuptools',
    'idna', 'charset-normalizer', 'aiobotocore', 'python-dateutil', 'grpcio-status', 'six', 's3transfer', 'numpy',
    'cryptography', 'pyyaml', 'cffi', 'pydantic', 'fsspec', 's3fs', 'pycparser', 'pluggy',
    'protobuf', 'click', 'pygments', 'pandas', 'attrs', 'pydantic-core', 'pytest', 'markupsafe',
    'jmespath', 'h11', 'pip', 'platformdirs', 'anyio', 'iniconfig', 'rsa', 'awscli',
    'pytz', 'filelock', 'annotated-types', 'jinja2', 'importlib-metadata', 'pyasn1', 'zipp', 'wheel',
    'httpx', 'tzdata', 'pyjwt', 'httpcore', 'pathspec', 'google-auth', 'typing-inspection', 'opentelemetry-proto',
    'aiohttp', 'google-api-core', 'jsonschema', 'colorama', 'pyasn1-modules', 'python-dotenv', 'virtualenv', 'multidict',
    'yarl', 'opentelemetry-exporter-otlp-proto-grpc', 'googleapis-common-protos', 'requests-oauthlib', 'wrapt', 'tomli', 'rich', 'opentelemetry-sdk',
    'frozenlist', 'pyarrow', 'grpcio', 'tqdm', 'sqlalchemy', 'propcache', 'greenlet', 'aiosignal',
    'rpds-py', 'opentelemetry-exporter-otlp-proto-http', 'referencing', 'markdown-it-py', 'scipy', 'psutil', 'yandexcloud', 'pyparsing',
    'pillow', 'jsonschema-specifications', 'mdurl', 'cachetools', 'oauthlib', 'et-xmlfile', 'openpyxl', 'trove-classifiers',
    'aiohappyeyeballs', 'starlette', 'opentelemetry-exporter-otlp', 'grpcio-tools', 'opentelemetry-exporter-otlp-proto-common', 'uvicorn', 'distlib', 'tomlkit',
    'tenacity', 'fastapi', 'soupsieve', 'google-genai', 'beautifulsoup4', 'lxml', 'opentelemetry-semantic-conventions', 'websocket-client',
    'sniffio', 'regex', 'pyopenssl', 'requests-toolbelt', 'opentelemetry-api', 'docutils', 'pynacl', 'shellingham',
    'mypy-extensions', 'proto-plus', 'exceptiongroup', 'more-itertools', 'werkzeug', 'sortedcontainers', 'google-cloud-storage', 'psycopg2-binary',
    'flask', 'isodate', 'decorator', 'websockets', 'networkx', 'msgpack', 'coverage', 'langchain',
    'huggingface-hub', 'scikit-learn', 'hatchling', 'azure-core', 'wcwidth', 'pexpect', 'ptyprocess', 'msal',
    'bcrypt', 'joblib', 'poetry-core', 'gitpython', 'snowflake-connector-python', 'dnspython', 'distro', 'python-multipart',
    'async-timeout', 'openai', 'azure-identity', 'threadpoolctl', 'asn1crypto', 'google-cloud-core', 'ruamel-yaml', 'tabulate',
    'cloudpickle', 'redis', 'deprecated', 'smmap', 'itsdangerous', 'paramiko', 'gitdb', 'pydantic-settings',
    'matplotlib', 'prompt-toolkit', 'fonttools', 'alembic', 'keyring', 'google-resumable-media', 'ruff', 'chardet',
    'typer', 'google-crc32c', 'annotated-doc', 'pytest-asyncio', 'blinker', 'jiter', 'tzlocal', 'opentelemetry-instrumentation',
    'pyproject-hooks', 'google-api-python-client', 'kubernetes', 'kiwisolver', 'google-cloud-bigquery', 'nodeenv', 'dill', 'backoff',
    'build', 'google-auth-oauthlib', 'zstandard', 'jaraco-classes', 'secretstorage', 'langsmith', 'setuptools-scm', 'jeepney',
    'pytest-cov', 'jsonpointer', 'cycler', 'msal-extensions', 'prometheus-client', 'defusedxml', 'rapidfuzz', 'orjson',
    'fastjsonschema', 'types-requests', 'uritemplate', 'textual', 'google-auth-httplib2', 'httplib2', 'identify', 'azure-storage-blob',
    'cfgv', 'pre-commit', 'contourpy', 'jaraco-context', 'jaraco-functools', 'transformers', 'marshmallow', 'docker',
    'sympy', 'mako', 'ipython', 'sqlparse', 'tokenizers', 'editables', 'tornado', 'py4j',
    'xmltodict', 'traitlets', 'importlib-resources', 'cython', 'mpmath', 'pyzmq', 'babel', 'jedi',
    'toml', 'black', 'parso', 'mypy', 'aiofiles', 'google-cloud-secret-manager', 'hf-xet', 'jsonpatch',
    'executing', 'nest-asyncio', 'matplotlib-inline', 'typedload', 'opentelemetry-util-http', 'asttokens', 'watchfiles', 'email-validator',
    'uv', 'opentelemetry-instrumentation-requests', 'ply', 'opentelemetry-exporter-prometheus', 'aliyun-python-sdk-core', 'grpc-google-iam-v1', 'stack-data', 'durationpy',
    'sentry-sdk', 'pure-eval', 'uvloop', 'langchain-core', 'gunicorn', 'awswrangler', 'tiktoken', 'docstring-parser',
    'gcsfs', 'asgiref', 'python-json-logger', 'webencodings', 'opensearch-py', 'markdown', 'dbt-core', 'google-cloud-batch',
    'pymongo', 'cachecontrol', 'grpcio-health-checking', 'termcolor', 'aioitertools', 'httptools', 'google-cloud-aiplatform', 'watchdog',
    'pytest-xdist', 'pymysql', 'isort', 'typing-inspect', 'google-analytics-admin', 'execnet', 'dbt-adapters', 'pkginfo',
    'debugpy', 'ruamel-yaml-clib', 'torch', 'requests-aws4auth', 'msrest', 'mcp', 'databricks-sdk', 'jsonpath-ng',
    'mccabe', 'dbt-common', 'pycryptodome', 'installer', 'botocore-stubs', 'httpx-sse', 'types-awscrt', 'h2',
    'hyperframe', 'hpack', 'sse-starlette', 'types-s3transfer', 'dulwich', 'snowflake-sqlalchemy', 'boto3-stubs', 'shapely',
    'multiprocess', 'pandas-stubs', 'datadog', 'notebook', 'azure-common', 'slack-sdk', 'jupyter-core', 'pycodestyle',
    'requests-file', 'future', 'crashtest', 'lz4', 'poetry', 'pendulum', 'litellm', 'pytest-mock',
    'pygithub', 'arrow', 'ipykernel', 'comm', 'jupyter-client', 'pysocks', 'datasets', 'rfc3339-validator',
    'dataclasses-json', 'scramp', 'argcomplete', 'invoke', 'wsproto', 'cleo', 'smart-open', 'xxhash',
    'semver', 'deepdiff', 'tinycss2', 'xlsxwriter', 'sphinx', 'py', 'mistune', 'backports-tarfile',
    'mypy-boto3-s3', 'google-cloud-monitoring', 'simplejson', 'loguru', 'safetensors', 'zope-interface', 'cattrs', 'narwhals',
    'selenium', 'text-unidecode', 'nvidia-nccl-cu12', 'bleach', 'typeguard', 'google-cloud-vision', 'humanfriendly', 'poetry-plugin-export',
    'google-cloud-compute', 'authlib', 'elasticsearch', 'google-cloud-tasks', 'events', 'toolz', 'google-cloud-speech', 'google-cloud-bigtable',
    'nbformat', 'lark', 'google-cloud-dlp', 'python-slugify', 'google-cloud-kms', 'typer-slim', 'google-cloud-workflows', 'pyspark',
    'graphql-core', 'google-cloud-language', 'databricks-sql-connector', 'google-cloud-resource-manager', 'google-cloud-logging', 'faker', 'redshift-connector', 'google-cloud-videointelligence',
    'pyflakes', 'brotli', 'google-cloud-dataform', 'numba', 'tree-sitter', 'deprecation', 'structlog', 'google-cloud-os-login',
    'ray', 'xlrd', 'nbconvert', 'argon2-cffi', 'argon2-cffi-bindings', 'nltk', 'trio', 'mysql-connector-python',
    'pycryptodomex', 'google-cloud-redis', 'pytokens', 'confluent-kafka', 'nbclient', 'jupyterlab', 'pymupdf', 'pbs-installer',
    'ipython-pygments-lexers', 'altair', 'google-cloud-pubsub', 'types-protobuf', 'inflection', 'croniter', 'jupyter-server', 'google-cloud-memcache',
    'aenum', 'apache-beam', 'outcome', 'flake8', 'plotly', 'types-pyyaml', 'json5', 'colorlog',
    'flatbuffers', 'pg8000', 'nvidia-cublas-cu12', 'librt', 'findpython', 'nvidia-cusparse-cu12', 'triton', 'pandocfilters',
    'absl-py', 'opencv-python', 'responses', 'jupyterlab-pygments', 'llvmlite', 'nvidia-nvjitlink-cu12', 'portalocker', 'astroid',
    'azure-keyvault-secrets', 'anthropic', 'google-cloud-appengine-logging', 'overrides', 'langchain-openai', 'pyrsistent', 'opentelemetry-instrumentation-fastapi', 'nvidia-cudnn-cu12',
    'nvidia-cufft-cu12', 'nvidia-cuda-nvrtc-cu12', 'coloredlogs', 'nvidia-cuda-cupti-cu12', 'nvidia-cusolver-cu12', 'asyncpg', 'appdirs', 'sqlalchemy-bigquery',
    'humanize', 'nvidia-curand-cu12', 'types-python-dateutil', 'jupyterlab-server', 'db-dtypes', 'nvidia-cuda-runtime-cu12', 'webcolors', 'pylint',
    'async-lru', 'psycopg2', 'kombu', 'seaborn', 'widgetsnbextension', 'mypy-boto3-sts', 'polars', 'send2trash',
    'jupyterlab-widgets', 'flask-cors', 'imageio', 'fqdn', 'adal', 'opentelemetry-instrumentation-asgi', 'google-ads', 'psycopg',
    'ipywidgets', 'isoduration', 'uri-template', 'trio-websocket', 'nvidia-nvtx-cu12', 'pymssql', 'mypy-boto3-iam', 'click-plugins',
    'jsonschema-path', 'rfc3986-validator', 'thrift', 'xgboost', 'orderly-set', 'ecdsa', 'aws-lambda-powertools', 'semgrep',
    'rich-toolkit', 'mmh3', 'antlr4-python3-runtime', 'celery', 'aws-sam-translator', 'mypy-boto3-batch', 'sqlglot', 'azure-mgmt-core',
    'terminado', 'gevent', 'opensearch-protobufs', 'setproctitle', 'tf-keras-nightly', 'zeep', 'azure-storage-file-datalake', 'retry',
    'cfn-lint', 'langchain-community', 'jupyter-events', 'delta-spark', 'google-cloud-audit-log', 'jupyter-server-terminals', 'google-cloud-bigquery-datatransfer', 'oauth2client',
    'notebook-shim', 'ijson', 'billiard', 'lazy-object-proxy', 'sentencepiece', 'google-cloud-texttospeech', 'tldextract', 'pytest-timeout',
    'freezegun', 'snowflake-snowpark-python', 'sshtunnel', 'pyodbc', 'google-cloud-orchestration-airflow', 'fastavro', 'click-didyoumean', 'dateparser',
    'google-cloud-run', 'langchain-text-splitters', 'ordered-set', 'google-cloud-dataproc-metastore', 'google-pasta', 'oss2', 'dbt-protos', 'psycopg-binary',
    'google-cloud-bigquery-storage', 'apache-airflow-providers-common-sql', 'google-cloud-automl', 'nvidia-cusparselt-cu12', 'h5py', 'amqp', 'libcst', 'vine',
    'django', 'tree-sitter-languages', 'jupyter-lsp', 'pandas-gbq', 'dask', 'pyee', 'pytest-runner', 'prettytable',
    'mashumaro', 'llama-parse', 'google-cloud-dataflow-client', 'click-repl', 'aiosqlite', 'mdit-py-plugins', 'azure-storage-queue', 'gspread',
    'gcloud-aio-storage', 'mlflow-skinny', 'rfc3986', 'uuid-utils', 'tensorboard', 'playwright', 'langchain-google-vertexai', 'mlflow',
    'python-docx', 'pyperclip', 'types-pytz', 'pypdf', 'diskcache', 'sendgrid', 'llama-cloud-services', 'langgraph',
    'pdfminer-six', 'rfc3987-syntax', 'nh3', 'torchvision', 'universal-pathlib', 'mergedeep', 'graphql-relay', 'nvidia-cufile-cu12',
    'onnxruntime', 'pywin32', 'streamlit', 'python-telegram-bot', 'types-urllib3', 'entrypoints', 'retrying', 'pathable',
    'graphene', 'mock', 'statsmodels', 'graphviz', 'moto', 'google-cloud-dataproc', 'simple-salesforce', 'duckdb',
    'snowballstemmer', 'agate', 'python-jose', 'pydata-google-auth', 'semantic-version', 'pytimeparse', 'zope-event', 'ml-dtypes',
    'pbr', 'flask-sqlalchemy', 'elastic-transport', 'html5lib', 'azure-datalake-store', 'ujson', 'beartype', 'patsy',
    'schema', 'pytzdata', 'omegaconf', 'hvac', 'great-expectations', 'pycountry', 'opentelemetry-instrumentation-wsgi', 'ddtrace',
    'pypdf2', 'purecloudplatformclientv2', 'msrestazure', 'pyroaring', 'opentelemetry-instrumentation-urllib3', 'progressbar2', 'tableauserverclient', 'google-cloud-spanner',
    'tomli-w', 'yamllint', 'readme-renderer', 'pytest-rerunfailures', 'frozendict', 'databricks-sqlalchemy', 'bs4', 'parsedatetime',
    'validators', 'unidecode', 'passlib', 'kafka-python', 'pytest-metadata', 'linkify-it-py', 'pybind11', 'opentelemetry-instrumentation-dbapi',
    'aws-requests-auth', 'ninja', 'ormsgpack', 'lockfile', 'holidays', 'fastapi-cli', 'tox', 'cramjam',
    'msgspec', 'scikit-image', 'tblib', 'peewee', 'python-utils', 'uc-micro-py', 'google-cloud-firestore', 'pkgutil-resolve-name',
    'polars-runtime-32', 'gremlinpython', 'tensorflow', 'opentelemetry-instrumentation-urllib', 'bracex', 'dacite', 'openapi-spec-validator', 'imagesize',
    'bytecode', 'opentelemetry-instrumentation-django', 'azure-cosmos', 'sphinxcontrib-serializinghtml', 'apache-airflow-providers-fab', 'alabaster', 'twine', 'astronomer-cosmos',
    'types-setuptools', 'langgraph-prebuilt', 'opentelemetry-instrumentation-flask', 'dbt-semantic-interfaces', 'leather', 'envier', 'oscrypto', 'fastmcp',
    'opencv-python-headless', 'flask-limiter', 'python-magic', 'azure-batch', 'pyproj', 'hyperlink', 'gcloud-aio-auth', 'checkov',
    'opentelemetry-instrumentation-psycopg2', 'wandb', 'mysqlclient', 'types-certifi', 'pydantic-extra-types', 'python-http-client', 'langgraph-sdk', 'langgraph-checkpoint',
    'opentelemetry-instrumentation-threading', 'pipenv', 'aioboto3', 'gcloud-aio-bigquery', 'nvidia-nvshmem-cu12', 'pydeck', 'gast', 'inflect',
    'sagemaker', 'texttable', 'dbt-extractor', 'griffe', 'fakeredis', 'apache-airflow-providers-cncf-kubernetes', 'wcmatch', 'apache-airflow-providers-snowflake',
    'fastuuid', 'phonenumbers', 'sphinxcontrib-htmlhelp', 'sqlalchemy-utils', 'sphinxcontrib-qthelp', 'sphinxcontrib-devhelp', 'sphinxcontrib-applehelp', 'ua-parser',
    'reportlab', 'curl-cffi', 'google-cloud-datacatalog', 'tritonclient', 'pyright', 'accelerate', 'opt-einsum', 'gym-notices',
    'looker-sdk', 'bitarray', 'jira', 'sphinxcontrib-jsmath', 'pip-tools', 'tensorboard-data-server', 'pathos', 'apache-airflow-providers-databricks',
    'weaviate-client', 'grpc-interceptor', 'lazy-loader', 'azure-mgmt-resource', 'jsonref', 'flit-core', 'stevedore', 'strictyaml',
    'posthog', 'openapi-schema-validator', 'azure-mgmt-storage', 'swe-rex', 'apscheduler', 'jsonpickle', 'smdebug-rulesconfig', 'sagemaker-studio',
    'pox', 'ppft', 'azure-monitor-opentelemetry-exporter', 'google-cloud-translate', 'pyexasol', 'userpath', 'limits', 'azure-servicebus',
    'rich-click', 'einops', 'murmurhash', 'oracledb', 'databricks-labs-blueprint', 'backports-zstd', 'junitparser', 'spacy',
    'statsd', 'id', 'cssselect2', 'partd', 'filetype', 'opentelemetry-instrumentation-httpx', 'blis', 'datadog-api-client',
    'amazon-ion', 'google-cloud-build', 'kubernetes-asyncio', 'google-cloud-container', 'aiohttp-retry', 'thinc', 'jpype1', 'requests-mock',
    'cymbal', 'locket', 'singer-sdk', 'aws-xray-sdk', 'geopandas', 'argparse', 'opencensus', 'cron-descriptor',
    'click-option-group', 'pypdfium2', 'cached-property', 'cbor2', 'pathlib-abc', 'google-cloud-dataplex', 'tifffile', 'levenshtein',
    'preshed', 'keras', 'srsly', 'flask-login', 'emoji', 'pinecone', 'daff', 'cyclopts',
    'opencensus-context', 'stripe', 'cssselect', 'natsort', 'valkey-glide-sync', 'strenum', 'types-toml', 'catalogue',
    'markdownify', 'fasteners', 'pytest-html', 'pdfplumber', 'djangorestframework', 'pymdown-extensions', 'sentence-transformers', 'makefun',
    'pyspnego', 'keyrings-google-artifactregistry-auth', 'fire', 'wasabi', 'sqlalchemy-spanner', 'apache-airflow-providers-mysql', 'geographiclib', 'apache-airflow',
    'apache-airflow-providers-ssh', 'pydeequ', 'google-cloud-storage-transfer', 'pathvalidate', 'pickleshare', 'grpcio-gcp', 'pinotdb', 'geopy',
    'onnx', 'watchtower', 'eval-type-backport', 'apache-airflow-providers-google', 'astunparse', 'spacy-legacy', 'ua-parser-builtins', 'backcall',
    'spacy-loggers', 'snowplow-tracker', 'hypothesis', 'deltalake', 'pydot', 'sglang', 'maxminddb', 'databricks-cli',
    'time-machine', 'py-cpuinfo', 'python-daemon', 'temporalio', 'python-gnupg', 'bidict', 'cmake', 'docopt',
    'cloudpathlib', 'confection', 'pyotp', 'azure-keyvault-keys', 'opentelemetry-instrumentation-logging', 'jaydebeapi', 'azure-mgmt-containerservice', 'fastparquet',
    'google-generativeai', 'unidiff', 'jax', 'pyiceberg', 'pyathena', 'hiredis', 'types-cachetools', 'sh',
    'immutabledict', 'torchaudio', 'simpleeval', 'parse', 'rich-rst', 'joserfc', 'google-ai-generativelanguage', 'ldap3',
    'python-pptx', 'azure-storage-file-share', 'lupa', 'jwcrypto', 'av', 'pydub', 'fuzzywuzzy', 'langcodes',
    'pytesseract', 'resolvelib', 'rich-argparse', 'datetime', 'python-gitlab', 'configparser', 'parameterized', 'docker-pycreds',
    'geoip2', 'thrift-sasl', 'incremental', 'boltons', 'avro', 'pyogrio', 'openapi-pydantic', 'yfinance',
    'bandit', 'python-socketio', 'azure-kusto-data', 'opentelemetry-distro', 'yt-dlp', 'libclang', 'factory-boy', 'pyproject-api',
    'azure-keyvault-certificates', 'python-engineio', 'gql', 'apache-airflow-providers-common-compat', 'configargparse', 'realtime', 'apache-airflow-providers-http', 'wtforms',
    'imbalanced-learn', 'apispec', 'psycopg-pool', 'office365-rest-python-client', 'jupyter-console', 'flask-wtf', 'trino', 'jupyter',
    'asynctest', 'simple-websocket', 'uv-build', 'django-cors-headers', 'pywavelets', 'azure-mgmt-containerregistry', 'pika', 'adlfs',
    'gradio', 'grpclib', 'questionary', 'fastapi-cloud-cli', 'ftfy', 'atlassian-python-api', 'types-cffi', 'xarray',
    'pytest-env', 'azure-mgmt-msi', 'timm', 'py-key-value-aio', 'connexion', 'soundfile', 'pgvector', 'orbax-checkpoint',
    'scp', 'azure-mgmt-cosmosdb', 'ratelimit', 'langdetect', 'mkdocs', 'py-key-value-shared', 'pybase64', 'diff-cover',
}


if __name__ == "__main__":
    main()
