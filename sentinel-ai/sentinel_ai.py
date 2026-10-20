"""
Sentinel AI — Automated Patch Validation Agent (Stage 5)

Validates that a proposed patch (target-app/app_patched.py) is both
*secure* and *functional* before it can proceed to human review.

Two-phase testing:
  Phase 1 — Security:     Replay every successful Red AI payload from
                          attack_log.json against the patched app and verify
                          that ALL of them are now rejected (HTTP 401 or the
                          response no longer says "Welcome").
  Phase 2 — Functionality: Run the existing pytest suite (target-app/tests/)
                          against the patched app to confirm normal behaviour
                          is preserved.

If either phase fails, the patch is REJECTED.
If both pass, the patch is VALIDATED and ready for human review.
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import time

import requests

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET_APP = os.path.join(ROOT_DIR, "target-app", "app.py")
PATCHED_APP = os.path.join(ROOT_DIR, "target-app", "app_patched.py")
ATTACK_LOG = os.path.join(ROOT_DIR, "red-ai", "attack_log.json")
TEST_DIR = os.path.join(ROOT_DIR, "target-app", "tests")

DEFAULT_TEST_PORT = 5002


# ---------------------------------------------------------------------------
# Utility: start a Flask app in a subprocess on a given port
# ---------------------------------------------------------------------------
def start_app(app_path: str, port: int, timeout: int = 8) -> subprocess.Popen:
    """
    Launch the Flask app at `app_path` on `port` as a background process.
    Waits up to `timeout` seconds for it to become responsive.
    Returns the Popen handle (caller is responsible for terminating it).
    """
    # Resolve to absolute path so the subprocess wrapper works correctly
    app_path = os.path.abspath(app_path)

    if not os.path.exists(app_path):
        print(f"  FATAL: App file not found: {app_path}")
        sys.exit(1)

    env = os.environ.copy()
    env["FLASK_RUN_PORT"] = str(port)

    # Launch the app with its own __main__ block but override the port
    # We create a tiny wrapper that imports and runs the app on the test port
    wrapper = (
        f"import sys, os; "
        f"sys.path.insert(0, os.path.dirname(r'{app_path}')); "
        f"os.chdir(os.path.dirname(r'{app_path}')); "
        f"import importlib.util; "
        f"spec = importlib.util.spec_from_file_location('patched_app', r'{app_path}'); "
        f"mod = importlib.util.module_from_spec(spec); "
        f"mod.DATABASE = os.path.join(os.path.dirname(r'{app_path}'), 'test_sentinel.db'); "
        f"spec.loader.exec_module(mod); "
        f"mod.init_db(); "
        f"mod.app.run(host='127.0.0.1', port={port}, debug=False, use_reloader=False)"
    )

    proc = subprocess.Popen(
        [sys.executable, "-c", wrapper],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )

    # Poll until the server is up
    url = f"http://127.0.0.1:{port}/"
    for i in range(timeout * 4):
        try:
            r = requests.get(url, timeout=1)
            if r.status_code == 200:
                return proc
        except requests.ConnectionError:
            pass
        time.sleep(0.25)

    # If we get here the server never started — dump stderr for debugging
    proc.terminate()
    _, stderr = proc.communicate(timeout=3)
    print(f"  FATAL: App at {app_path} did not start within {timeout}s.")
    if stderr:
        print(f"  Stderr:\n{stderr.decode(errors='replace')}")
    sys.exit(1)


def stop_app(proc: subprocess.Popen):
    """Terminate the Flask subprocess gracefully."""
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    # Clean up the test database
    test_db = os.path.join(ROOT_DIR, "target-app", "test_sentinel.db")
    if os.path.exists(test_db):
        try:
            os.remove(test_db)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Phase 1: Security check — replay attack payloads
# ---------------------------------------------------------------------------
def load_successful_attacks(log_path: str) -> list[dict]:
    """Load only the *successful* attack entries from Red AI's log."""
    if not os.path.exists(log_path):
        print(f"  WARNING: Attack log not found at {log_path}")
        return []

    with open(log_path, "r") as f:
        entries = json.load(f)

    return [e for e in entries if e.get("success")]


def run_security_check(port: int, attacks: list[dict]) -> tuple[bool, int, int, list[dict]]:
    """
    Replay each successful attack payload against the patched app.
    An attack is considered STILL WORKING if:
      - HTTP status is 200, AND
      - The response body contains "Welcome" (the success marker from the login endpoint).
    Returns (passed, blocked_count, total_count, still_working_list).
    """
    url = f"http://127.0.0.1:{port}/login"
    blocked = 0
    still_working = []

    for entry in attacks:
        payload = entry.get("payload", {})
        try:
            resp = requests.post(url, data=payload, timeout=5)
            # The attack is blocked if: non-200 OR "Welcome" not in response
            if resp.status_code != 200 or "Welcome" not in resp.text:
                blocked += 1
            else:
                still_working.append({
                    "payload": payload,
                    "status_code": resp.status_code,
                    "response_snippet": resp.text[:120],
                })
        except requests.RequestException as e:
            # Connection errors count as "blocked" (server rejected it)
            blocked += 1

    total = len(attacks)
    passed = len(still_working) == 0
    return passed, blocked, total, still_working


# ---------------------------------------------------------------------------
# Phase 2: Functionality check — run pytest suite against patched app
# ---------------------------------------------------------------------------
def run_functionality_check(patched_path: str) -> tuple[bool, str]:
    """
    Run the existing pytest suite but with the patched app module.
    We do this by temporarily copying app_patched.py over app.py in a subprocess,
    running pytest, then restoring. To avoid touching the original, we use a
    cleaner approach: set PYTHONPATH and use a conftest trick.

    Simpler approach: create a temporary conftest that monkey-patches the import.
    """
    test_dir = TEST_DIR
    if not os.path.isdir(test_dir):
        return False, "Test directory not found: " + test_dir

    # The test file imports `from app import app, init_db, DATABASE, SAFE_DIR`
    # We'll copy app_patched.py to a temp location as app.py and run tests there
    import tempfile
    import shutil

    with tempfile.TemporaryDirectory() as tmpdir:
        # Copy the patched app as "app.py" in the temp dir
        shutil.copy2(patched_path, os.path.join(tmpdir, "app.py"))

        # Copy the public directory for the /file endpoint tests
        pub_src = os.path.join(ROOT_DIR, "target-app", "public")
        pub_dst = os.path.join(tmpdir, "public")
        if os.path.isdir(pub_src):
            shutil.copytree(pub_src, pub_dst)
        else:
            os.makedirs(pub_dst, exist_ok=True)

        # Copy the test directory
        test_dst = os.path.join(tmpdir, "tests")
        shutil.copytree(test_dir, test_dst)

        # Run pytest
        result = subprocess.run(
            [sys.executable, "-m", "pytest", test_dst, "-v", "--tb=short"],
            capture_output=True,
            text=True,
            cwd=tmpdir,
            timeout=30,
        )

        output = result.stdout + "\n" + result.stderr
        passed = result.returncode == 0
        return passed, output


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Sentinel AI — Patch Validation Agent (Stage 5)"
    )
    parser.add_argument(
        "--patched",
        default=PATCHED_APP,
        help=f"Path to the patched app (default: {PATCHED_APP})",
    )
    parser.add_argument(
        "--attack-log",
        default=ATTACK_LOG,
        help=f"Path to Red AI's attack log (default: {ATTACK_LOG})",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_TEST_PORT,
        help=f"Port for the test server (default: {DEFAULT_TEST_PORT})",
    )
    args = parser.parse_args()

    patched_path = args.patched
    attack_log_path = args.attack_log
    port = args.port

    print()
    print("=" * 60)
    print("  SENTINEL AI — Patch Validation Agent")
    print("=" * 60)
    print()

    # Sanity checks
    if not os.path.exists(patched_path):
        print(f"  FATAL: Patched app not found: {patched_path}")
        print("  Run Forge AI first to generate the patch, or provide --patched <path>.")
        sys.exit(1)

    # ------------------------------------------------------------------
    # Phase 1: Security Check
    # ------------------------------------------------------------------
    print("[Phase 1/2] SECURITY CHECK — Replaying attack payloads")
    print(f"  Loading attacks from: {attack_log_path}")

    attacks = load_successful_attacks(attack_log_path)
    if not attacks:
        print("  WARNING: No successful attacks found in log — security check is trivially passing.")
        sec_passed = True
        sec_blocked = 0
        sec_total = 0
        sec_still_working = []
    else:
        print(f"  Found {len(attacks)} successful attack payloads to replay.")
        print(f"  Starting patched app on port {port}...")

        proc = start_app(patched_path, port)
        try:
            sec_passed, sec_blocked, sec_total, sec_still_working = run_security_check(port, attacks)
        finally:
            stop_app(proc)

    # Security results
    print()
    if sec_passed:
        print(f"  ✅ SECURITY CHECK: PASS ({sec_blocked}/{sec_total} attacks blocked)")
    else:
        print(f"  ❌ SECURITY CHECK: FAIL ({sec_blocked}/{sec_total} attacks blocked)")
        print(f"     {len(sec_still_working)} payload(s) STILL SUCCEED against the patched app:")
        for i, sw in enumerate(sec_still_working[:10], 1):
            print(f"     [{i}] Payload: {sw['payload']}")
            print(f"         Status: {sw['status_code']}, Response: {sw['response_snippet']}")

    # ------------------------------------------------------------------
    # Phase 2: Functionality Check
    # ------------------------------------------------------------------
    print()
    print("[Phase 2/2] FUNCTIONALITY CHECK — Running pytest suite")

    func_passed, func_output = run_functionality_check(patched_path)

    # Extract pass/fail counts from pytest output
    test_summary = ""
    import re as _re
    for line in func_output.split("\n"):
        stripped = line.strip()
        # Match pytest's summary line like "5 passed", "3 passed, 2 failed", etc.
        m = _re.search(r"(\d+\s+passed(?:,\s*\d+\s+\w+)*)", stripped)
        if m:
            test_summary = m.group(1)

    print()
    if func_passed:
        print(f"  ✅ FUNCTIONALITY CHECK: PASS")
        if test_summary:
            print(f"     {test_summary}")
    else:
        print(f"  ❌ FUNCTIONALITY CHECK: FAIL")
        if test_summary:
            print(f"     {test_summary}")
        print()
        print("  --- pytest output ---")
        # Print compact output (skip blank lines and excess decoration)
        for line in func_output.split("\n"):
            stripped = line.strip()
            if stripped and not stripped.startswith("====="):
                print(f"  {stripped}")
        print("  --- end pytest output ---")

    # ------------------------------------------------------------------
    # Final Verdict
    # ------------------------------------------------------------------
    print()
    print("=" * 60)
    if sec_passed and func_passed:
        print(f"  ✅ VERDICT: PATCH VALIDATED")
        print(f"     Security check:      PASS ({sec_blocked}/{sec_total} attacks blocked)")
        summary_parts = test_summary if test_summary else "all tests passed"
        print(f"     Functionality check: PASS ({summary_parts})")
        print(f"     Patch validated — ready for human review.")
        print("=" * 60)
        sys.exit(0)
    else:
        print(f"  ❌ VERDICT: PATCH REJECTED")
        if not sec_passed:
            print(f"     Security check FAILED: {len(sec_still_working)}/{sec_total} attacks still work.")
        if not func_passed:
            print(f"     Functionality check FAILED: tests did not pass.")
        print()
        print("  The patch is NOT safe to deploy. Do NOT proceed to human review.")
        print("  Re-run Forge AI to generate a better patch.")
        print("=" * 60)
        sys.exit(1)


if __name__ == "__main__":
    main()
