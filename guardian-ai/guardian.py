"""
Guardian AI — Defensive Reverse Proxy WAF (Stage 3)

Listens on http://127.0.0.1:8080 and proxies traffic to the target app at http://127.0.0.1:5001.
Inspects incoming traffic against rules in rules.json:
- If a rule matches: blocks with HTTP 403 and logs to guardian_log.json.
- If no rules match: forwards cleanly to the target app and relays response.

Safety: Hard-restricted to forward ONLY to 127.0.0.1:5001. Refuses any other host.
"""

import json
import os
import re
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from flask import Flask, Response, jsonify, request

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Target Configuration & Strict Localhost Restriction
# ---------------------------------------------------------------------------
TARGET_HOST = "127.0.0.1"
TARGET_PORT = 5001
TARGET_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

# Hard-restriction check at startup
_parsed = urlparse(TARGET_URL)
if _parsed.hostname not in ("127.0.0.1", "localhost") or _parsed.port != 5001:
    print(f"FATAL: Guardian AI is hard-restricted to 127.0.0.1:5001. Invalid target: {TARGET_URL}")
    sys.exit(1)

RULES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules.json")
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "guardian_log.json")


def load_rules() -> list[dict]:
    """Dynamically load rules from rules.json so updates apply immediately."""
    if not os.path.exists(RULES_FILE):
        return []
    try:
        with open(RULES_FILE, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"[Guardian AI] Error reading rules.json: {e}")
        return []


def log_block(rule: dict, payload_sample: str) -> None:
    """Log blocked request to guardian_log.json."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "client_ip": request.remote_addr,
        "method": request.method,
        "path": request.path,
        "matched_rule": {
            "id": rule.get("id"),
            "name": rule.get("name"),
            "pattern": rule.get("pattern"),
        },
        "payload": payload_sample[:500],
    }

    logs = []
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r") as f:
                logs = json.load(f)
        except Exception:
            logs = []

    logs.append(entry)
    try:
        with open(LOG_FILE, "w") as f:
            json.dump(logs, f, indent=2)
    except Exception as e:
        print(f"[Guardian AI] Error writing to {LOG_FILE}: {e}")


def inspect_request(rules: list[dict]) -> tuple[bool, dict | None, str]:
    """
    Inspect all incoming request fields (query string, form data, raw body).
    Returns (is_blocked, matched_rule, offending_payload).
    """
    # Collect candidate text segments to test against rules
    candidates = []

    # 1. URL Path and Query string
    if request.query_string:
        candidates.append(request.query_string.decode("utf-8", errors="ignore"))
    for key, val in request.args.items():
        candidates.append(f"{key}={val}")

    # 2. Form data
    for key, val in request.form.items():
        candidates.append(f"{key}={val}")
        candidates.append(val)

    # 3. Raw Body (JSON or plain text)
    raw_body = request.get_data(as_text=True)
    if raw_body:
        candidates.append(raw_body)

    # Evaluate against rules
    for rule in rules:
        pattern_str = rule.get("pattern")
        if not pattern_str:
            continue

        try:
            regex = re.compile(pattern_str, re.IGNORECASE)
        except re.error as e:
            print(f"[Guardian AI] Invalid regex in rule {rule.get('id')}: {e}")
            continue

        for item in candidates:
            if regex.search(item):
                return True, rule, item

    return False, None, ""


# ---------------------------------------------------------------------------
# Proxy Handler — Catch-all for all HTTP methods and paths
# ---------------------------------------------------------------------------
@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
def proxy_request(path: str):
    # Cache raw body before inspecting request.form
    raw_body = request.get_data(cache=True)

    # 1. Inspection phase
    rules = load_rules()
    is_blocked, matched_rule, offending_payload = inspect_request(rules)

    if is_blocked and matched_rule:
        print(f"[Guardian AI] 🛡️  BLOCKED request to /{path} | Rule: '{matched_rule.get('name')}' | Pattern: {matched_rule.get('pattern')}")
        log_block(matched_rule, offending_payload)
        return (
            jsonify({
                "status": "blocked",
                "code": 403,
                "error": "Forbidden",
                "message": "Request blocked by Guardian AI WAF",
                "matched_rule": matched_rule.get("name"),
            }),
            403,
        )

    # 2. Forwarding phase — strictly to 127.0.0.1:5001
    dest_url = f"{TARGET_URL}/{path}"
    # Filter out client headers that requests manages
    excluded_headers = {"host", "content-length"}
    forward_headers = {k: v for k, v in request.headers if k.lower() not in excluded_headers}

    try:
        resp = requests.request(
            method=request.method,
            url=dest_url,
            params=request.args,
            data=raw_body,
            headers=forward_headers,
            allow_redirects=False,
            timeout=10,
        )
    except requests.ConnectionError:
        return (
            jsonify({
                "error": "Bad Gateway",
                "message": f"Guardian AI could not reach target app at {TARGET_URL}. Is target-app running on port 5001?",
            }),
            502,
        )
    except requests.RequestException as e:
        return jsonify({"error": "Proxy Error", "details": str(e)}), 500

    # Relay response back to client
    resp_headers = [(k, v) for k, v in resp.headers.items() if k.lower() not in ("content-length", "transfer-encoding", "content-encoding")]
    return Response(resp.content, status=resp.status_code, headers=resp_headers)


if __name__ == "__main__":
    print("=" * 60)
    print("  GUARDIAN AI — Defensive Reverse Proxy WAF")
    print("=" * 60)
    print("  Listening on  : http://127.0.0.1:8080")
    print(f"  Forwarding to : {TARGET_URL} (HARD-RESTRICTED)")
    print(f"  Active Rules  : {len(load_rules())} loaded from rules.json")
    print("=" * 60)
    app.run(host="127.0.0.1", port=8080, debug=False)
