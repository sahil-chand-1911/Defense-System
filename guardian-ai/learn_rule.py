"""
Guardian AI — Rule Learning Agent (Stage 3)

Analyzes successful attack payloads from Red AI (or direct input),
queries Google Gemini to generate a targeted regex/keyword detection rule that
blocks the attack without creating false positives on legitimate users,
and appends the new rule to rules.json.
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone

from dotenv import load_dotenv

# Load .env from project root
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(ROOT_DIR, ".env"))

RULES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules.json")
DEFAULT_ATTACK_LOG = os.path.join(ROOT_DIR, "red-ai", "attack_log.json")


def load_target_payload(payload_arg: str | None, log_file: str) -> dict:
    """Retrieve payload either from CLI argument or latest success in attack_log.json."""
    if payload_arg:
        # Check if argument is JSON string or simple text
        try:
            return json.loads(payload_arg)
        except json.JSONDecodeError:
            return {"username": payload_arg, "password": "x"}

    if not os.path.exists(log_file):
        print(f"Error: Attack log file not found at {log_file}")
        sys.exit(1)

    try:
        with open(log_file, "r") as f:
            logs = json.load(f)
    except Exception as e:
        print(f"Error reading attack log: {e}")
        sys.exit(1)

    # Find the most recent successful payload
    successful = [entry for entry in logs if entry.get("success")]
    if not successful:
        print("No successful attack entries found in attack_log.json to learn from.")
        sys.exit(1)

    latest = successful[-1]
    print(f"[Learn Rule] Found latest successful attack from {latest.get('timestamp')}:")
    print(f"             Payload: {latest.get('payload')}")
    return latest.get("payload", {})


def synthesize_rule_heuristics(payload: dict) -> dict:
    """Heuristic fallback rule generator for SQLi patterns if LLM is unavailable."""
    uname = str(payload.get("username", ""))
    pwd = str(payload.get("password", ""))
    target_str = uname if "'" in uname or "--" in uname or "/*" in uname else pwd

    ts_slug = int(datetime.now(timezone.utc).timestamp())

    if "/*" in target_str or "*/" in pwd:
        return {
            "id": f"rule_sqli_comment_block_{ts_slug}",
            "name": "SQL Comment Block (/*) Bypass",
            "pattern": r"/\*|\*/",
            "type": "regex",
            "description": "Blocks inline SQL comment characters /* and */ used to bypass whitespace and quote boundaries",
        }
    elif "''='" in target_str or "'' = '" in target_str:
        return {
            "id": f"rule_sqli_empty_string_or_{ts_slug}",
            "name": "SQLi OR Empty String Comparison",
            "pattern": r"'\s*OR\s*''\s*=\s*'",
            "type": "regex",
            "description": "Blocks SQL injection ' OR ''=' tautology condition",
        }
    elif re.search(r"'\s*OR\s+\d+=\d+", target_str, re.IGNORECASE):
        return {
            "id": f"rule_sqli_or_numeric_tautology_{ts_slug}",
            "name": "SQLi OR Numeric Tautology",
            "pattern": r"'\s*OR\s+\d+\s*=\s*\d+",
            "type": "regex",
            "description": "Blocks numeric tautologies like ' OR 1=1",
        }
    elif re.search(r"'\s*OR\s+username=", target_str, re.IGNORECASE):
        return {
            "id": f"rule_sqli_or_field_match_{ts_slug}",
            "name": "SQLi OR Field Condition",
            "pattern": r"'\s*OR\s+[a-zA-Z_]+\s*=",
            "type": "regex",
            "description": "Blocks SQL injection field conditions like ' OR username='admin'",
        }
    elif re.search(r"admin'\s*--", target_str, re.IGNORECASE):
        return {
            "id": f"rule_sqli_admin_dash_comment_{ts_slug}",
            "name": "SQLi Auth Bypass via Trailing Comment",
            "pattern": r"['\"]\s*--",
            "type": "regex",
            "description": "Blocks quote followed by SQL line comment delimiter --",
        }
    else:
        escaped = re.escape(target_str.strip())
        return {
            "id": f"rule_sqli_custom_{ts_slug}",
            "name": f"SQLi Pattern for {target_str[:20]}",
            "pattern": escaped,
            "type": "regex",
            "description": f"Direct pattern match for verified attack vector: {target_str[:40]}",
        }


def ask_gemini_for_rule(payload: dict) -> dict:
    """Call Google Gemini to generate a high-quality WAF detection rule for the payload."""
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("[Learn Rule] No GEMINI_API_KEY found in .env — using intelligent synthesizer.")
        return synthesize_rule_heuristics(payload)

    import google.generativeai as genai

    genai.configure(api_key=api_key)

    prompt = f"""You are Guardian AI, an expert defensive Web Application Firewall (WAF) rule engineer.
An attacker bypassed our firewall using this SQL injection payload targeting a Flask SQLite login endpoint:

Payload:
{json.dumps(payload, indent=2)}

Task:
Generate a precise detection rule (regular expression) that will reliably detect and block this attack payload and its close syntactic variations.
CRITICAL CONSTRAINT: The regex pattern must NOT block legitimate user credentials (e.g. usernames like 'alice', 'bob', 'admin' with normal passwords).

Output format:
Respond ONLY with a valid JSON object in this exact schema (no markdown formatting, no commentary):
{{
  "id": "rule_sqli_<short_snake_case_id>",
  "name": "<Short descriptive name for the rule>",
  "pattern": "<regex pattern string>",
  "type": "regex",
  "description": "<One sentence explaining what this blocks and how it avoids false positives>"
}}"""

    # Try currently supported active models (fast model for rule generation)
    models_to_try = []
    for m in [os.environ.get("GEMINI_MODEL", "gemini-3.8-flash"), "gemini-3.8-flash", "gemini-2.5-flash", "gemini-flash-latest"]:
        if m and m not in models_to_try:
            models_to_try.append(m)

    last_error = None
    for model_name in models_to_try:
        try:
            print(f"[Learn Rule] Querying Gemini ({model_name})...")
            model_instance = genai.GenerativeModel(
                model_name=model_name,
                system_instruction="You are Guardian AI, an expert defensive Web Application Firewall (WAF) rule engineer.",
            )
            response = model_instance.generate_content(
                prompt,
                generation_config={"max_output_tokens": 1024, "temperature": 0.2},
            )
            raw_text = response.text.strip()
            # Clean markdown fences if any
            clean_text = re.sub(r"^```(?:json)?\s*", "", raw_text)
            clean_text = re.sub(r"\s*```$", "", clean_text).strip()
            rule_data = json.loads(clean_text)
            print(f"[Learn Rule] Successfully generated rule via Gemini ({model_name}).")
            return rule_data
        except Exception as e:
            last_error = e
            continue

    print(f"[Learn Rule] Notice: Gemini API returned ({last_error}).")
    print("             Switching to intelligent rule synthesizer.")
    return synthesize_rule_heuristics(payload)


def test_rule(rule: dict, payload: dict) -> bool:
    """Verify that the generated regex compiles and catches the offending payload."""
    pattern_str = rule.get("pattern", "")
    try:
        regex = re.compile(pattern_str, re.IGNORECASE)
    except re.error as e:
        print(f"[Learn Rule] Error: Generated regex '{pattern_str}' is invalid: {e}")
        return False

    uname = str(payload.get("username", ""))
    pwd = str(payload.get("password", ""))

    matched = bool(regex.search(uname) or regex.search(pwd) or regex.search(f"username={uname}&password={pwd}"))
    if not matched:
        print(f"[Learn Rule] Warning: Regex '{pattern_str}' did not match test payload: {payload}")
    else:
        print(f"[Learn Rule] Verified: Rule successfully matches attack payload.")

    # False positive sanity test
    safe_samples = ["alice", "bob", "admin", "password123", "supersecret", "john_doe"]
    for safe in safe_samples:
        if regex.search(safe):
            print(f"[Learn Rule] Warning: False positive detected on safe username '{safe}'!")
            return False

    return matched


def append_rule(rule: dict) -> bool:
    """Append the newly verified rule to rules.json."""
    rules = []
    if os.path.exists(RULES_FILE):
        try:
            with open(RULES_FILE, "r") as f:
                rules = json.load(f)
        except Exception:
            rules = []

    # Check if pattern already exists
    for existing in rules:
        if existing.get("pattern") == rule.get("pattern"):
            print(f"[Learn Rule] Pattern '{rule.get('pattern')}' already exists in rules.json (Rule ID: {existing.get('id')}).")
            return True

    rules.append(rule)
    with open(RULES_FILE, "w") as f:
        json.dump(rules, f, indent=2)

    print(f"[Learn Rule] Rule appended to {RULES_FILE}. Total active rules: {len(rules)}")
    return True


def main():
    parser = argparse.ArgumentParser(description="Guardian AI — Learn WAF rules from attack payloads")
    parser.add_argument("--payload", help="JSON string or attack string (e.g. \"' OR ''='\")")
    parser.add_argument("--log", default=DEFAULT_ATTACK_LOG, help=f"Path to attack_log.json (default: {DEFAULT_ATTACK_LOG})")
    args = parser.parse_args()

    print("=" * 60)
    print("  GUARDIAN AI — Rule Learning Pipeline")
    print("=" * 60)

    # 1. Acquire target payload
    payload = load_target_payload(args.payload, args.log)
    print(f"[1/3] Analyzing attack payload: {payload}")

    # 2. Generate rule via Gemini
    print("\n[2/3] Generating defensive detection pattern...")
    rule = ask_gemini_for_rule(payload)
    print(f"      Rule ID     : {rule.get('id')}")
    print(f"      Rule Name   : {rule.get('name')}")
    print(f"      Pattern     : {rule.get('pattern')}")
    print(f"      Description : {rule.get('description')}")

    # 3. Test & Commit
    print("\n[3/3] Validating and appending rule to rules.json...")
    if test_rule(rule, payload):
        append_rule(rule)
        print("\n" + "=" * 60)
        print("  LEARNING COMPLETE")
        print("=" * 60)
        print(f"  New pattern active in Guardian AI: {rule.get('pattern')}")
        print("  Guardian AI will now block this vector on all future attempts.")
        print("=" * 60)
    else:
        print("[Learn Rule] Rule validation failed. Not saved.")
        sys.exit(1)


if __name__ == "__main__":
    main()
