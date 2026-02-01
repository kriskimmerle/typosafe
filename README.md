# typosafe

**Supply Chain Typosquatting Detector** — Check your Python dependencies for potential typosquatting attacks. Compares your `requirements.txt` or `pyproject.toml` against the top 1000 most popular PyPI packages using edit distance to catch suspicious near-matches.

Zero dependencies. Pure Python stdlib. Single file.

## Why?

Typosquatting is the #1 supply chain attack vector for Python packages:

- **73% increase** in malicious PyPI packages (2026 Sonatype report)
- **+75% OSS malware** year-over-year
- Attackers register packages like `reqeusts`, `numpyy`, `djnago` — one character off from popular packages
- A single `pip install` of a typosquatted package can execute arbitrary code

Existing tools scan PyPI globally for typosquats, but **none check YOUR actual dependencies** against popular packages. You might already have a typosquatted package in your `requirements.txt` and not know it.

**typosafe** checks what you're actually installing.

## Install

```bash
# Download
curl -O https://raw.githubusercontent.com/kriskimmerle/typosafe/main/typosafe.py
chmod +x typosafe.py

# Or clone
git clone https://github.com/kriskimmerle/typosafe.git
cd typosafe
```

No dependencies needed. Works with Python 3.7+.

## Usage

### Basic Check

```bash
typosafe requirements.txt
```

```
typosafe v1.0.0 — Supply Chain Typosquatting Detector

⚠ [HIGH] reqeusts (line 3)
  → Similar to requests (distance=1)

⚠ [HIGH] djnago (line 8)
  → Similar to django (distance=1)

── Summary ──
  Packages checked: 15
  Packages flagged: 2
  High: 2
  Reference: top 1000 popular PyPI packages
```

### Verbose Mode

```bash
typosafe requirements.txt --verbose
```

Shows specific attack patterns detected:
- **char-swap** — Adjacent characters transposed (`reqeusts` → `requests`)
- **char-omission** — Missing character (`rquests` → `requests`)
- **char-addition** — Extra character (`numpyy` → `numpy`)
- **char-repeat** — Doubled character (`pyjwtt` → `pyjwt`)
- **confusable-char** — Look-alike substitution (`l` → `1`, `o` → `0`)
- **version-suffix** — Number appended (`requests2` → `requests`)
- **added-prefix/suffix** — Common prefix/suffix added (`python-requests`)

### pyproject.toml Support

```bash
typosafe pyproject.toml
```

Parses `[project.dependencies]` and `[project.optional-dependencies]`. Uses `tomllib` on Python 3.11+, falls back to basic parsing on older versions.

### CI Mode

```bash
# Exit 1 if any HIGH or CRITICAL risks found
typosafe requirements.txt --check

# Perfect for CI/CD pipelines
```

### JSON Output

```bash
typosafe requirements.txt --json
```

### Stdin

```bash
pip freeze | typosafe --stdin
cat requirements.txt | typosafe --stdin
```

### Auto-Detection

```bash
# Looks for requirements.txt or pyproject.toml in current directory
typosafe
```

### Strict Mode

```bash
# Only flag distance=1 matches (fewer false positives)
typosafe requirements.txt --distance 1
```

## Severity Levels

| Level | Distance | Meaning |
|-------|----------|---------|
| **CRITICAL** | Any | Confusable character substitution (l→1, o→0) |
| **HIGH** | 1 | Single edit away from a popular package |
| **MEDIUM** | 2 | Two edits away (more likely coincidence) |

## Detection Techniques

typosafe uses Damerau-Levenshtein distance (includes transpositions) plus pattern-specific detection:

1. **Edit distance** — How many character changes to reach a popular package name
2. **Pattern analysis** — What kind of typo it looks like (swap, omission, addition, etc.)
3. **Confusable characters** — Visually similar substitutions (0/o, l/1, rn/m)
4. **Separator normalization** — Ignores pip-normalized separator differences (hyphens/underscores/dots are equivalent on PyPI)

## CI/CD Integration

### GitHub Actions

```yaml
name: Supply Chain Check
on: [push, pull_request]

jobs:
  typosafe:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Check for typosquats
        run: |
          curl -sO https://raw.githubusercontent.com/kriskimmerle/typosafe/main/typosafe.py
          python3 typosafe.py requirements.txt --check
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: typosafe
        name: typosafe
        entry: python3 typosafe.py
        language: system
        files: requirements.*\.txt$|pyproject\.toml$
        pass_filenames: true
```

## CLI Reference

```
typosafe [OPTIONS] [FILES...]

Arguments:
  FILES                 Requirements files (requirements.txt or pyproject.toml)

Options:
  -v, --verbose         Show detailed pattern analysis
  --json                JSON output for automation
  --check               CI mode: exit 1 if any HIGH/CRITICAL risks found
  --stdin               Read package names from stdin
  --distance N          Max edit distance to flag (default: 2)
  --severity LEVEL      Minimum severity: medium, high, critical (default: medium)
  --version             Show version
  -h, --help            Show help
```

## Reference Data

The bundled package list contains the top 1000 most downloaded PyPI packages (updated 2026-02-01), sourced from [hugovk/top-pypi-packages](https://hugovk.github.io/top-pypi-packages/). This covers the vast majority of packages attackers target for typosquatting.

## Limitations

- Only checks against the bundled top 1000 popular packages (covers most attack targets)
- False positives possible for legitimately similar package names (distance=2)
- Does not check if the flagged package actually exists on PyPI (offline analysis)
- Does not analyze package code — only name similarity

## License

MIT
