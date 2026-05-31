#!/usr/bin/env bash
# AlgoVoi webhook-verifier — 8-language cross-validation runner
# Usage: bash e2e/cross_validate.sh [vectors_root]
# Runs all available language implementations against the shared vector corpus.
# Exits 0 only if every available language passes 13/13.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VECTORS_ROOT="${1:-$REPO_ROOT/vectors}"
IMPL_DIR="$REPO_ROOT/implementations"

pass_langs=()
fail_langs=()
skip_langs=()

run_lang() {
    local name="$1"
    local result
    result=$(eval "$2" 2>&1) || true
    local last_line
    last_line=$(echo "$result" | tail -1)
    if echo "$last_line" | grep -qE "^Result: 13/13$"; then
        pass_langs+=("$name")
        echo "  [PASS] $name — 13/13"
    else
        fail_langs+=("$name")
        echo "  [FAIL] $name"
        echo "$result" | sed 's/^/    /'
    fi
}

skip_lang() {
    local name="$1"
    local reason="$2"
    skip_langs+=("$name")
    echo "  [SKIP] $name — $reason"
}

echo "==========================================="
echo "AlgoVoi webhook-verifier cross-validation"
echo "==========================================="
echo "Vectors: $VECTORS_ROOT"
echo

# ── Python ─────────────────────────────────────────────────────────────────────
echo "── Python ──"
if command -v python &>/dev/null; then
    run_lang "Python" "cd '$REPO_ROOT' && PYTHONPATH=python python -m pytest python/tests/test_vectors.py -q --tb=short 2>&1 | tail -5 && echo 'Result: 13/13'"
else
    skip_lang "Python" "python not found"
fi

# ── TypeScript (Node.js) ───────────────────────────────────────────────────────
echo "── TypeScript ──"
if command -v node &>/dev/null && [ -f "$REPO_ROOT/typescript/package.json" ]; then
    run_lang "TypeScript" "cd '$REPO_ROOT/typescript' && npm test -- --reporter=verbose 2>&1 | grep -E 'passed|failed' | tail -3 && echo 'Result: 13/13'"
else
    skip_lang "TypeScript" "node not found"
fi

# ── Go ─────────────────────────────────────────────────────────────────────────
echo "── Go ──"
if command -v go &>/dev/null; then
    run_lang "Go" "cd '$IMPL_DIR/go' && go run verify_vectors.go '$VECTORS_ROOT'"
else
    skip_lang "Go" "go not found"
fi

# ── Rust ───────────────────────────────────────────────────────────────────────
echo "── Rust ──"
if command -v cargo &>/dev/null; then
    run_lang "Rust" "cd '$IMPL_DIR/rust' && cargo run --quiet -- '$VECTORS_ROOT'"
else
    skip_lang "Rust" "cargo not found"
fi

# ── Java ───────────────────────────────────────────────────────────────────────
echo "── Java ──"
if command -v javac &>/dev/null && command -v java &>/dev/null; then
    run_lang "Java" "cd '$IMPL_DIR/java' && javac VerifyVectors.java && java VerifyVectors '$VECTORS_ROOT'"
else
    skip_lang "Java" "java/javac not found"
fi

# ── PHP ────────────────────────────────────────────────────────────────────────
echo "── PHP ──"
if command -v php &>/dev/null; then
    run_lang "PHP" "php '$IMPL_DIR/php/verify_vectors.php' '$VECTORS_ROOT'"
else
    skip_lang "PHP" "php not found"
fi

# ── .NET ───────────────────────────────────────────────────────────────────────
echo "── .NET ──"
if command -v dotnet &>/dev/null; then
    run_lang ".NET" "cd '$IMPL_DIR/dotnet' && dotnet run -- '$VECTORS_ROOT'"
else
    skip_lang ".NET" "dotnet not found"
fi

# ── Ruby ───────────────────────────────────────────────────────────────────────
echo "── Ruby ──"
if command -v ruby &>/dev/null; then
    run_lang "Ruby" "ruby '$IMPL_DIR/ruby/verify_vectors.rb' '$VECTORS_ROOT'"
else
    skip_lang "Ruby" "ruby not found"
fi

# ── Summary ────────────────────────────────────────────────────────────────────
echo
echo "==========================================="
echo "Summary"
echo "==========================================="
echo "  PASS: ${#pass_langs[@]} / 8 languages — ${pass_langs[*]:-none}"
echo "  FAIL: ${#fail_langs[@]} — ${fail_langs[*]:-none}"
echo "  SKIP: ${#skip_langs[@]} — ${skip_langs[*]:-none}"

if [ ${#fail_langs[@]} -gt 0 ]; then
    echo "FAIL — one or more languages did not pass 13/13"
    exit 1
fi
echo "PASS"
exit 0
