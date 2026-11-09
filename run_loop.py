#!/usr/bin/env python3
"""
AI Cyber Defense & Evolution System — Full Defense Loop Orchestrator

Runs the complete closed-loop defense lifecycle end-to-end:
  1. Pre-flight checks (port availability & environment configuration)
  2. Start background services (Target App on 5001 & Guardian WAF on 8080)
  3. Stage 2: Red AI (Adversarial attack wave)
  4. Stage 3: Guardian AI (Rule learning for any breached exploit payloads)
  5. Stage 4: Forge AI (Automated code patching via LLM reasoning)
  6. Stage 5: Sentinel AI (Two-phase patch security replay & regression validation)
  7. Stage 6: Memory AI (Persistent telemetry sync & defense strength metric)
  8. Stage 7: Approval Gate (Interactive human authorization & PR creation)

Safety & Cleanup:
  - All background services are reliably terminated upon completion or on Ctrl+C.
  - Only targets localhost (127.0.0.1).
  - Never prints secrets, API keys, or .env file contents.
"""

import argparse
from datetime import datetime, timezone
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
from typing import Dict, List, Optional, Tuple

from dotenv import load_dotenv
import requests

# ---------------------------------------------------------------------------
# Path Configuration
# ---------------------------------------------------------------------------
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
TARGET_APP_PATH = os.path.join(ROOT_DIR, "target-app", "app.py")
PATCHED_APP_PATH = os.path.join(ROOT_DIR, "target-app", "app_patched.py")
GUARDIAN_APP_PATH = os.path.join(ROOT_DIR, "guardian-ai", "guardian.py")
LEARN_RULE_PATH = os.path.join(ROOT_DIR, "guardian-ai", "learn_rule.py")
RED_AI_PATH = os.path.join(ROOT_DIR, "red-ai", "red_ai.py")
FORGE_AI_PATH = os.path.join(ROOT_DIR, "forge-ai", "forge_ai.py")
SENTINEL_AI_PATH = os.path.join(ROOT_DIR, "sentinel-ai", "sentinel_ai.py")
MEMORY_AI_PATH = os.path.join(ROOT_DIR, "memory-ai", "memory_ai.py")
APPROVAL_GATE_PATH = os.path.join(ROOT_DIR, "approval-gate", "approval_gate.py")
ATTACK_LOG_PATH = os.path.join(ROOT_DIR, "red-ai", "attack_log.json")

# Target URLs
TARGET_APP_URL = "http://127.0.0.1:5001"
GUARDIAN_URL = "http://127.0.0.1:8080"
SENTINEL_PORT = 5002

# Ports to check before starting
REQUIRED_PORTS = [5001, 8080, SENTINEL_PORT]


# ---------------------------------------------------------------------------
# Formatting & Output Helpers
# ---------------------------------------------------------------------------
def print_banner(text: str, char: str = "=") -> None:
    width = 76
    print()
    print(char * width)
    print(f"  {text}")
    print(char * width)


def print_stage_header(stage_num: int, total_stages: int, name: str) -> None:
    width = 76
    print()
    print("=" * width)
    print(f"  Stage {stage_num}/{total_stages}: {name}")
    print("=" * width)


# ---------------------------------------------------------------------------
# Pre-flight Checks
# ---------------------------------------------------------------------------
def get_process_using_port(port: int) -> str:
    """Use lsof to retrieve details on the process binding a port."""
    try:
        res = subprocess.run(
            ["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN"],
            capture_output=True,
            text=True,
            check=False,
        )
        lines = res.stdout.strip().splitlines()
        if len(lines) > 1:
            parts = lines[1].split()
            cmd_name = parts[0]
            pid = parts[1]
            user = parts[2] if len(parts) > 2 else "unknown"
            return f"PID {pid} ({cmd_name}, user: {user})"
    except Exception:
        pass
    return "unknown process"


def check_port_free(port: int) -> Tuple[bool, str]:
    """Test whether port is available on 127.0.0.1."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", port))
            return True, ""
        except OSError:
            proc_info = get_process_using_port(port)
            return False, proc_info


def run_preflight_checks() -> bool:
    """Validate port availability and environment configuration."""
    print_banner("PRE-FLIGHT CHECKS")

    # 1. Port checks
    print("  [1/2] Checking port availability (5001, 8080, 5002)...")
    ports_ok = True
    for port in REQUIRED_PORTS:
        free, proc_info = check_port_free(port)
        if free:
            print(f"        • Port {port:<4} : FREE")
        else:
            print(f"        • Port {port:<4} : IN USE by {proc_info}")
            ports_ok = False

    if not ports_ok:
        print("\n  ❌ Pre-flight failed: One or more required ports are already in use.")
        print("     Please stop the conflicting processes and try again.")
        return False

    # 2. Environment checks
    print("\n  [2/2] Checking environment configuration...")
    load_dotenv(os.path.join(ROOT_DIR, ".env"))

    groq_key_set = bool(os.environ.get("GROQ_API_KEY", "").strip())
    if groq_key_set:
        print("        • GROQ_API_KEY  : CONFIGURED")
    else:
        print("        • GROQ_API_KEY  : MISSING")
        print("\n  ⚠️  WARNING: GROQ_API_KEY is not set in the environment or .env file.")
        print("     Red AI and Guardian AI have built-in fallback mechanisms, but Forge AI")
        print("     strictly requires GROQ_API_KEY for code remediation (no fallback).")
        print("     Please set GROQ_API_KEY in your .env file before running the loop.")
        return False

    github_token_set = bool(os.environ.get("GITHUB_TOKEN", "").strip())
    if github_token_set:
        print("        • GITHUB_TOKEN  : CONFIGURED (Live PR mode enabled)")
    else:
        print("        • GITHUB_TOKEN  : NOT SET (Stage 7 will run in Simulation Mode)")

    print("\n  ✅ Pre-flight checks passed.")
    return True


# ---------------------------------------------------------------------------
# Background Service Management
# ---------------------------------------------------------------------------
class ServiceManager:
    """Manages the background execution and clean teardown of Flask services."""

    def __init__(self):
        self.target_proc: Optional[subprocess.Popen] = None
        self.guardian_proc: Optional[subprocess.Popen] = None
        self.target_log_file = None
        self.guardian_log_file = None

    def start_services(self) -> bool:
        """Launch Target App and Guardian AI and wait for health checks."""
        print_banner("STARTING BACKGROUND SERVICES")

        self.target_log_file = tempfile.NamedTemporaryFile(mode="w+", delete=False, prefix="target_app_", suffix=".log")
        self.guardian_log_file = tempfile.NamedTemporaryFile(mode="w+", delete=False, prefix="guardian_", suffix=".log")

        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"

        # 1. Start Target App on 5001
        print("  [1/2] Starting Target App on http://127.0.0.1:5001...")
        self.target_proc = subprocess.Popen(
            [sys.executable, TARGET_APP_PATH],
            cwd=ROOT_DIR,
            stdout=self.target_log_file,
            stderr=subprocess.STDOUT,
            env=env,
            text=True,
        )

        # 2. Start Guardian AI on 8080
        print("  [2/2] Starting Guardian AI WAF Proxy on http://127.0.0.1:8080...")
        self.guardian_proc = subprocess.Popen(
            [sys.executable, GUARDIAN_APP_PATH],
            cwd=ROOT_DIR,
            stdout=self.guardian_log_file,
            stderr=subprocess.STDOUT,
            env=env,
            text=True,
        )

        # 3. Wait for services to respond
        print("\n  Waiting for services to become responsive...")
        target_healthy = self._poll_health(TARGET_APP_URL, "Target App", self.target_proc, timeout=12.0)
        if not target_healthy:
            print("  ❌ Target App failed to become responsive.")
            self._print_service_log(self.target_log_file.name)
            return False

        guardian_healthy = self._poll_health(GUARDIAN_URL, "Guardian AI", self.guardian_proc, timeout=12.0)
        if not guardian_healthy:
            print("  ❌ Guardian AI failed to become responsive.")
            self._print_service_log(self.guardian_log_file.name)
            return False

        print("  ✅ Both background services are healthy and ready.")
        return True

    def _poll_health(self, url: str, name: str, proc: Optional[subprocess.Popen], timeout: float = 12.0) -> bool:
        start = time.time()
        while time.time() - start < timeout:
            if proc and proc.poll() is not None:
                return False
            try:
                resp = requests.get(url, timeout=1.0)
                if resp.status_code == 200:
                    return True
            except requests.RequestException:
                pass
            time.sleep(0.3)
        return False

    def _print_service_log(self, filepath: str) -> None:
        if os.path.exists(filepath):
            try:
                with open(filepath, "r") as f:
                    content = f.read().strip()
                if content:
                    print(f"\n  --- Service Log ({os.path.basename(filepath)}) ---")
                    for line in content.splitlines()[-20:]:
                        print(f"    {line}")
                    print("  --- End Log ---\n")
            except Exception:
                pass

    def stop_services(self) -> None:
        """Gracefully terminate background services and cleanup temporary logs."""
        print("\n  Shutting down background services...")
        for proc, name in [(self.guardian_proc, "Guardian AI"), (self.target_proc, "Target App")]:
            if proc and proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=3.0)
                    print(f"  • {name} stopped.")
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                    print(f"  • {name} killed.")

        # Clean temporary logs
        for f in [self.target_log_file, self.guardian_log_file]:
            if f:
                try:
                    f.close()
                except Exception:
                    pass
                if os.path.exists(f.name):
                    try:
                        os.unlink(f.name)
                    except OSError:
                        pass


# ---------------------------------------------------------------------------
# Pipeline Stage Execution
# ---------------------------------------------------------------------------
def count_attack_log_entries() -> int:
    """Return the total number of entries in attack_log.json."""
    if os.path.exists(ATTACK_LOG_PATH):
        try:
            with open(ATTACK_LOG_PATH, "r") as f:
                data = json.load(f)
                return len(data) if isinstance(data, list) else 0
        except Exception:
            pass
    return 0


def get_new_breaches(start_index: int) -> List[Dict]:
    """Retrieve successful breach payloads added since start_index."""
    if not os.path.exists(ATTACK_LOG_PATH):
        return []
    try:
        with open(ATTACK_LOG_PATH, "r") as f:
            data = json.load(f)
            new_entries = data[start_index:]
            return [e["payload"] for e in new_entries if e.get("success")]
    except Exception:
        return []


def get_all_breaches() -> List[Dict]:
    """Retrieve all successful breach payloads in attack_log.json."""
    if not os.path.exists(ATTACK_LOG_PATH):
        return []
    try:
        with open(ATTACK_LOG_PATH, "r") as f:
            data = json.load(f)
            return [e["payload"] for e in data if e.get("success")]
    except Exception:
        return []


def run_pipeline(skip_attack: bool, no_approval: bool) -> Tuple[bool, List[Dict[str, str]]]:
    """Execute stages 2 through 7 in sequential order."""
    stages_summary: List[Dict[str, str]] = []

    # -----------------------------------------------------------------------
    # Stage 2: Red AI (Attacker)
    # -----------------------------------------------------------------------
    print_stage_header(2, 7, "Red AI (Adversarial Attacker)")
    t0 = time.perf_counter()

    initial_log_count = count_attack_log_entries()
    if skip_attack:
        print("  ℹ️  Skipping attack wave (--skip-attack specified).")
        print(f"      Reusing existing attack records ({initial_log_count} historical entries).")
        elapsed = time.perf_counter() - t0
        stages_summary.append({"stage": "Stage 2: Red AI", "status": "SKIPPED (--skip-attack)", "time": f"{elapsed:.1f}s"})
        breaches = get_all_breaches()
    else:
        cmd = [
            sys.executable,
            RED_AI_PATH,
            "--vuln",
            "sql_injection",
            "--target",
            GUARDIAN_URL,
        ]
        res = subprocess.run(cmd, cwd=ROOT_DIR)
        elapsed = time.perf_counter() - t0
        if res.returncode != 0:
            stages_summary.append({"stage": "Stage 2: Red AI", "status": "FAILED", "time": f"{elapsed:.1f}s"})
            return False, stages_summary

        stages_summary.append({"stage": "Stage 2: Red AI", "status": "PASSED", "time": f"{elapsed:.1f}s"})
        breaches = get_new_breaches(initial_log_count)

    # -----------------------------------------------------------------------
    # Stage 3: Guardian AI (Learn Rule)
    # -----------------------------------------------------------------------
    print_stage_header(3, 7, "Guardian AI (WAF Rule Learning)")
    t0 = time.perf_counter()

    if breaches:
        # Deduplicate payloads
        unique_payloads = []
        seen = set()
        for p in breaches:
            key = json.dumps(p, sort_keys=True)
            if key not in seen:
                seen.add(key)
                unique_payloads.append(p)

        print(f"  Detected {len(unique_payloads)} unique breached payload(s) requiring WAF rules:")
        for idx, payload in enumerate(unique_payloads, 1):
            print(f"\n  [Learning Rule {idx}/{len(unique_payloads)}] Target: {payload}")
            cmd = [
                sys.executable,
                LEARN_RULE_PATH,
                "--payload",
                json.dumps(payload),
            ]
            res = subprocess.run(cmd, cwd=ROOT_DIR)
            if res.returncode != 0:
                elapsed = time.perf_counter() - t0
                stages_summary.append({"stage": "Stage 3: Guardian AI Learn", "status": "FAILED", "time": f"{elapsed:.1f}s"})
                return False, stages_summary

        elapsed = time.perf_counter() - t0
        stages_summary.append({"stage": "Stage 3: Guardian AI Learn", "status": f"PASSED ({len(unique_payloads)} rules)", "time": f"{elapsed:.1f}s"})
    else:
        print("  🛡️  Zero breaches detected. All attacks were blocked by Guardian WAF.")
        print("      No new detection rules needed.")
        elapsed = time.perf_counter() - t0
        stages_summary.append({"stage": "Stage 3: Guardian AI Learn", "status": "PASSED (Zero breaches)", "time": f"{elapsed:.1f}s"})

    # -----------------------------------------------------------------------
    # Stage 4: Forge AI (Code Patching)
    # -----------------------------------------------------------------------
    print_stage_header(4, 7, "Forge AI (Code Remediation via LLM)")
    t0 = time.perf_counter()

    cmd = [sys.executable, FORGE_AI_PATH]
    res = subprocess.run(cmd, cwd=ROOT_DIR)
    elapsed = time.perf_counter() - t0
    if res.returncode != 0:
        stages_summary.append({"stage": "Stage 4: Forge AI", "status": "FAILED", "time": f"{elapsed:.1f}s"})
        return False, stages_summary

    stages_summary.append({"stage": "Stage 4: Forge AI", "status": "PASSED", "time": f"{elapsed:.1f}s"})

    # -----------------------------------------------------------------------
    # Stage 5: Sentinel AI (Patch Validation)
    # -----------------------------------------------------------------------
    print_stage_header(5, 7, "Sentinel AI (Automated Patch Verification)")
    t0 = time.perf_counter()

    cmd = [
        sys.executable,
        SENTINEL_AI_PATH,
        "--patched",
        PATCHED_APP_PATH,
        "--port",
        str(SENTINEL_PORT),
    ]
    res = subprocess.run(cmd, cwd=ROOT_DIR)
    elapsed = time.perf_counter() - t0
    if res.returncode != 0:
        stages_summary.append({"stage": "Stage 5: Sentinel AI", "status": "FAILED", "time": f"{elapsed:.1f}s"})
        return False, stages_summary

    stages_summary.append({"stage": "Stage 5: Sentinel AI", "status": "PASSED", "time": f"{elapsed:.1f}s"})

    # -----------------------------------------------------------------------
    # Stage 6: Memory AI (Telemetry & State Store)
    # -----------------------------------------------------------------------
    print_stage_header(6, 7, "Memory AI (Telemetry & Defense Strength)")
    t0 = time.perf_counter()

    cmd = [sys.executable, MEMORY_AI_PATH]
    res = subprocess.run(cmd, cwd=ROOT_DIR)
    elapsed = time.perf_counter() - t0
    if res.returncode != 0:
        stages_summary.append({"stage": "Stage 6: Memory AI", "status": "FAILED", "time": f"{elapsed:.1f}s"})
        return False, stages_summary

    stages_summary.append({"stage": "Stage 6: Memory AI", "status": "PASSED", "time": f"{elapsed:.1f}s"})

    # -----------------------------------------------------------------------
    # Stage 7: Approval Gate (Human-in-the-Loop)
    # -----------------------------------------------------------------------
    print_stage_header(7, 7, "Approval Gate (Human-in-the-Loop Review)")
    t0 = time.perf_counter()

    if no_approval:
        print("  ℹ️  Stopping before Approval Gate (--no-approval specified).")
        print("      Candidate patch remains staged at target-app/app_patched.py.")
        elapsed = time.perf_counter() - t0
        stages_summary.append({"stage": "Stage 7: Approval Gate", "status": "SKIPPED (--no-approval)", "time": f"{elapsed:.1f}s"})
    else:
        # Interactive prompt requires direct stdin/stdout
        cmd = [sys.executable, APPROVAL_GATE_PATH]
        res = subprocess.run(cmd, cwd=ROOT_DIR)
        elapsed = time.perf_counter() - t0
        if res.returncode != 0:
            stages_summary.append({"stage": "Stage 7: Approval Gate", "status": "FAILED", "time": f"{elapsed:.1f}s"})
            return False, stages_summary

        stages_summary.append({"stage": "Stage 7: Approval Gate", "status": "PASSED", "time": f"{elapsed:.1f}s"})

    return True, stages_summary


# ---------------------------------------------------------------------------
# Summary Output
# ---------------------------------------------------------------------------
def print_summary(stages_summary: List[Dict[str, str]], overall_success: bool, total_time: float) -> None:
    width = 76
    print()
    print("=" * width)
    print("  DEFENSE LOOP EXECUTION SUMMARY")
    print("=" * width)
    print(f"  {'Stage':<38} {'Status':<24} {'Time':<10}")
    print("  " + "-" * (width - 4))
    for item in stages_summary:
        print(f"  {item['stage']:<38} {item['status']:<24} {item['time']:<10}")
    print("=" * width)
    if overall_success:
        print(f"  Result: ✅ SUCCESS (Full defense lifecycle completed)")
    else:
        print(f"  Result: ❌ FAILED (Pipeline halted due to error)")
    print(f"  Total Duration: {total_time:.1f}s")
    print("=" * width)
    print()


# ---------------------------------------------------------------------------
# Main Entrypoint
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="AI Cyber Defense & Evolution System — Full Loop Orchestrator"
    )
    parser.add_argument(
        "--skip-attack",
        action="store_true",
        help="Skip running Red AI attack wave; reuse existing attack_log.json",
    )
    parser.add_argument(
        "--no-approval",
        action="store_true",
        help="Stop after Stage 6 validation, skipping Stage 7 human approval",
    )
    args = parser.parse_args()

    overall_start = time.perf_counter()

    print_banner("AI CYBER DEFENSE & EVOLUTION SYSTEM — FULL ORCHESTRATOR")
    print(f"  Python Runtime : {sys.executable}")
    print(f"  Target Host    : 127.0.0.1 (Strict Localhost)")
    print(f"  Options        : skip_attack={args.skip_attack}, no_approval={args.no_approval}")

    # 1. Pre-flight checks
    if not run_preflight_checks():
        sys.exit(1)

    # 2. Services Management & Pipeline
    service_mgr = ServiceManager()
    overall_success = False
    stages_summary: List[Dict[str, str]] = []

    try:
        t_services = time.perf_counter()
        if not service_mgr.start_services():
            elapsed = time.perf_counter() - t_services
            stages_summary.append({"stage": "Services (Target & WAF)", "status": "FAILED", "time": f"{elapsed:.1f}s"})
            print("\n  ❌ Failed to start background services. Aborting pipeline.")
            sys.exit(1)

        elapsed = time.perf_counter() - t_services
        stages_summary.append({"stage": "Services (Target & WAF)", "status": "PASSED", "time": f"{elapsed:.1f}s"})

        # Run pipeline
        overall_success, pipeline_summary = run_pipeline(
            skip_attack=args.skip_attack,
            no_approval=args.no_approval,
        )
        stages_summary.extend(pipeline_summary)

    except KeyboardInterrupt:
        print("\n\n  ⚠️  Operation cancelled by user (Ctrl+C). Terminating pipeline...")
        overall_success = False
    except Exception as e:
        print(f"\n\n  ❌ Unexpected error during pipeline execution: {e}")
        overall_success = False
    finally:
        service_mgr.stop_services()
        total_time = time.perf_counter() - overall_start
        print_summary(stages_summary, overall_success, total_time)

    sys.exit(0 if overall_success else 1)


if __name__ == "__main__":
    main()
