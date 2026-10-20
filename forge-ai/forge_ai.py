"""
Forge AI — Automated Code-Patching Agent (Stage 4)

Reads the vulnerable target-app/app.py, identifies exploited vulnerabilities
from Red AI's attack_log.json, calls Claude to generate a secure rewrite of
the affected function(s), and writes the proposed patch to app_patched.py.

SAFETY: If the Claude API call fails, the script reports the failure loudly
and exits. It does NOT fall back to a hardcoded patch — real failures must
be visible, never hidden.
"""

import argparse
import difflib
import json
import os
import re
import sys
from datetime import datetime, timezone

from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET_APP = os.path.join(ROOT_DIR, "target-app", "app.py")
PATCHED_APP = os.path.join(ROOT_DIR, "target-app", "app_patched.py")
ATTACK_LOG = os.path.join(ROOT_DIR, "red-ai", "attack_log.json")
PATCH_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "patches")

# Load .env from the project root
load_dotenv(os.path.join(ROOT_DIR, ".env"))


# ---------------------------------------------------------------------------
# Attack log analysis
# ---------------------------------------------------------------------------
def analyze_attack_log(log_path: str) -> list[str]:
    """
    Read the attack log and determine which vulnerability categories
    have been successfully exploited.
    Returns a list of vulnerability types (e.g. ['sql_injection']).
    """
    if not os.path.exists(log_path):
        print(f"WARNING: Attack log not found at {log_path}")
        return ["sql_injection"]  # reasonable default

    with open(log_path, "r") as f:
        entries = json.load(f)

    vuln_types = set()

    for entry in entries:
        if not entry.get("success"):
            continue
        payload = entry.get("payload", {})
        username = str(payload.get("username", ""))
        password = str(payload.get("password", ""))
        combined = username + password

        # Classify by payload signatures
        sqli_indicators = ["'", "--", "OR", "UNION", "SELECT", "/*", "*/", "1=1"]
        if any(ind in combined for ind in sqli_indicators):
            vuln_types.add("sql_injection")

    if not vuln_types:
        print("No successful exploits found in attack log.")
        return []

    return sorted(vuln_types)


# ---------------------------------------------------------------------------
# Source code extraction
# ---------------------------------------------------------------------------
def read_source(path: str) -> str:
    """Read and return the full source of the target app."""
    if not os.path.exists(path):
        print(f"FATAL: Target source not found at {path}")
        sys.exit(1)
    with open(path, "r") as f:
        return f.read()


def extract_vulnerable_function(source: str, vuln_type: str) -> tuple[str, int, int]:
    """
    Extract the specific vulnerable function from the source code.
    Returns (function_source, start_line, end_line).
    """
    lines = source.split("\n")

    if vuln_type == "sql_injection":
        marker = "VULNERABILITY 1: SQL Injection"
    elif vuln_type == "xss":
        marker = "VULNERABILITY 2: Reflected XSS"
    elif vuln_type == "path_traversal":
        marker = "VULNERABILITY 3: Path Traversal"
    else:
        print(f"Unknown vulnerability type: {vuln_type}")
        return source, 0, len(lines)

    # Find the comment marker, then extract the function below it
    start = None
    for i, line in enumerate(lines):
        if marker in line:
            start = i
            break

    if start is None:
        print(f"Could not locate '{marker}' in source.")
        return source, 0, len(lines)

    # Find the next section marker or end of file
    end = len(lines)
    for i in range(start + 1, len(lines)):
        if lines[i].startswith("# ---- VULNERABILITY") or lines[i].startswith("# ------"):
            end = i
            break

    return "\n".join(lines[start:end]), start, end


# ---------------------------------------------------------------------------
# Claude API — patch generation (NO FALLBACK)
# ---------------------------------------------------------------------------
def get_claude_client():
    """Initialise the Anthropic client. Fails loudly if key is missing."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("=" * 60)
        print("  FATAL: ANTHROPIC_API_KEY not set in .env")
        print("=" * 60)
        print("  Forge AI requires a working Claude API key.")
        print("  Add ANTHROPIC_API_KEY to your .env file and try again.")
        print("=" * 60)
        sys.exit(1)

    import anthropic

    workspace_id = os.environ.get("ANTHROPIC_WORKSPACE_ID")
    default_headers = {}
    if workspace_id:
        default_headers["anthropic-workspace-id"] = workspace_id

    return anthropic.Anthropic(
        api_key=api_key,
        default_headers=default_headers or None,
    )


def generate_patch(
    client,
    full_source: str,
    vuln_function: str,
    vuln_type: str,
    attack_samples: list[dict],
) -> tuple[str, str]:
    """
    Call Claude to generate a patched version of the full app source.

    Returns (patched_full_source, explanation).

    SAFETY: This function does NOT catch exceptions.
    If the API call fails, the exception propagates and the script exits
    with a clear error — no silent fallback to a hardcoded patch.
    """
    attack_examples = json.dumps(attack_samples[:5], indent=2)

    prompt = f"""You are Forge AI, an expert secure code reviewer and patcher.

## Context
A Flask/SQLite web application has a **{vuln_type.replace('_', ' ')}** vulnerability that has been actively exploited.

## Vulnerable function (extract)
```python
{vuln_function}
```

## Full application source
```python
{full_source}
```

## Successful attack payloads (from Red AI's attack log)
```json
{attack_examples}
```

## Your task
Rewrite the FULL application source code with the {vuln_type.replace('_', ' ')} vulnerability FIXED.

Requirements:
1. **Fix only the {vuln_type.replace('_', ' ')} vulnerability** — do not modify any other endpoint or function.
2. For SQL injection: use parameterized queries (SQLite `?` placeholders). Never concatenate user input into SQL.
3. **Preserve all existing behavior**: same routes, same response format, same HTML output for valid requests.
4. **Preserve all comments and docstrings** unrelated to the vulnerability.
5. Update the vulnerability comment to indicate it has been PATCHED (e.g., change "⚠️ VULNERABLE" to "✅ PATCHED").
6. Keep the same imports unless a new one is strictly needed for the fix.
7. Do NOT add any new endpoints, middleware, or dependencies.

## Output format
Respond with EXACTLY two sections separated by the delimiter `---EXPLANATION---`:

**Section 1**: The complete, runnable Python source code (the full patched app.py). No markdown fences.

**Section 2** (after the delimiter): A short plain-English explanation (3-5 sentences) of what was changed and why.

Example structure:
```
<full patched python code here>
---EXPLANATION---
<explanation here>
```

Begin."""

    # Model preference — try currently supported active models
    models = [
        os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-6"),
        "claude-sonnet-4-6",
        "claude-haiku-4-5",
    ]

    last_error = None
    for model_name in models:
        try:
            print(f"[Forge AI] Calling Claude ({model_name})...")
            response = client.messages.create(
                model=model_name,
                max_tokens=4096,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = response.content[0].text
            break
        except Exception as e:
            last_error = e
            print(f"[Forge AI] Model {model_name} failed: {e}")
            continue
    else:
        # ALL models failed — exit loudly, no fallback
        print()
        print("=" * 60)
        print("  FATAL: Claude API call FAILED")
        print("=" * 60)
        print(f"  Last error: {last_error}")
        print()
        print("  Forge AI does NOT fall back to hardcoded patches.")
        print("  Fix the API issue and re-run.")
        print("=" * 60)
        sys.exit(1)

    # Parse the response into code + explanation
    if "---EXPLANATION---" in raw:
        parts = raw.split("---EXPLANATION---", 1)
        patched_code = parts[0].strip()
        explanation = parts[1].strip()
    else:
        # Model returned code without the separator — treat entire response as code
        patched_code = raw.strip()
        explanation = "(Claude did not provide a separate explanation section.)"

    # Strip any markdown fences Claude may have wrapped around the code
    patched_code = re.sub(r"^```python\s*\n?", "", patched_code)
    patched_code = re.sub(r"\n?```\s*$", "", patched_code)

    # Ensure file ends with newline
    if not patched_code.endswith("\n"):
        patched_code += "\n"

    return patched_code, explanation


# ---------------------------------------------------------------------------
# Diff display
# ---------------------------------------------------------------------------
def show_diff(original: str, patched: str, label: str = "app.py") -> str:
    """Generate and return a unified diff between original and patched."""
    orig_lines = original.splitlines(keepends=True)
    patch_lines = patched.splitlines(keepends=True)
    diff = difflib.unified_diff(
        orig_lines, patch_lines,
        fromfile=f"target-app/{label} (original)",
        tofile=f"target-app/{label} (patched)",
        lineterm="",
    )
    return "".join(diff)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Forge AI — Code Patching Agent")
    parser.add_argument(
        "--vuln",
        default=None,
        help="Vulnerability type to patch (auto-detected from attack log if omitted)",
    )
    parser.add_argument(
        "--source",
        default=TARGET_APP,
        help=f"Path to the target source file (default: {TARGET_APP})",
    )
    parser.add_argument(
        "--output",
        default=PATCHED_APP,
        help=f"Path for the patched output (default: {PATCHED_APP})",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("  FORGE AI — Automated Code-Patching Agent")
    print("=" * 60)

    # 1. Analyze attack log
    print("\n[1/5] Analyzing attack log for exploited vulnerabilities...")
    vuln_types = analyze_attack_log(ATTACK_LOG)
    if not vuln_types:
        print("No vulnerabilities to patch. Exiting.")
        sys.exit(0)

    target_vuln = args.vuln if args.vuln else vuln_types[0]
    print(f"      Detected exploited vulns: {vuln_types}")
    print(f"      Targeting: {target_vuln}")

    # 2. Read source & extract vulnerable function
    print(f"\n[2/5] Reading source from {args.source}...")
    full_source = read_source(args.source)
    vuln_func, start_line, end_line = extract_vulnerable_function(full_source, target_vuln)
    print(f"      Vulnerable function: lines {start_line + 1}–{end_line}")

    # 3. Collect attack samples for context
    print("\n[3/5] Collecting successful attack samples...")
    attack_samples = []
    if os.path.exists(ATTACK_LOG):
        with open(ATTACK_LOG, "r") as f:
            all_entries = json.load(f)
        attack_samples = [e["payload"] for e in all_entries if e.get("success")][:5]
    print(f"      {len(attack_samples)} successful payloads to share with Claude.")

    # 4. Generate patch via Claude (NO FALLBACK — fails loudly)
    print("\n[4/5] Generating patch via Claude...")
    client = get_claude_client()
    patched_source, explanation = generate_patch(
        client, full_source, vuln_func, target_vuln, attack_samples
    )

    # 5. Write patched file and show results
    print(f"\n[5/5] Writing patched source to {args.output}...")
    with open(args.output, "w") as f:
        f.write(patched_source)

    # Save explanation alongside
    os.makedirs(PATCH_DIR, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    explanation_file = os.path.join(PATCH_DIR, f"patch_{target_vuln}_{ts}.md")
    with open(explanation_file, "w") as f:
        f.write(f"# Forge AI Patch — {target_vuln}\n\n")
        f.write(f"**Generated**: {datetime.now(timezone.utc).isoformat()}\n\n")
        f.write(f"## Explanation\n\n{explanation}\n\n")
        f.write(f"## Diff\n\n```diff\n{show_diff(full_source, patched_source)}\n```\n")

    # Show results
    diff_text = show_diff(full_source, patched_source)

    print("\n" + "=" * 60)
    print("  PATCH GENERATED SUCCESSFULLY")
    print("=" * 60)
    print(f"\n  Vulnerability : {target_vuln}")
    print(f"  Patched file  : {args.output}")
    print(f"  Explanation   : {explanation_file}")
    print(f"\n  --- Explanation ---\n")
    for line in explanation.split("\n"):
        print(f"  {line}")
    print(f"\n  --- Diff ---\n")
    print(diff_text)
    print("\n" + "=" * 60)
    print("  IMPORTANT: The patch has NOT been applied to the live app.")
    print("  Review the diff above, then run Sentinel AI (Stage 5) to")
    print("  validate it before replacing app.py.")
    print("=" * 60)


if __name__ == "__main__":
    main()
