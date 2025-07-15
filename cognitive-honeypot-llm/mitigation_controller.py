"""
mitigation_controller.py
------------------------
Applies iptables firewall rules when Mixtral LLM risk_score >= THRESHOLD.
Keeps a local JSON registry of blocked IPs to avoid duplicates.

Usage:
    from mitigation_controller import MitigationController
    controller = MitigationController(threshold=7.0)
    controller.enforce(llm_result_dict)
"""

import json
import os
import subprocess
from datetime import datetime
from typing import Dict

BLOCK_DB = "blocked_ips.json"
THRESHOLD_DEFAULT = 7.0

class MitigationController:
    def __init__(self, threshold: float = THRESHOLD_DEFAULT):
        self.threshold = threshold
        self.blocked = self._load_block_registry()

    # -----------------------------------------------------------------
    # Registry helpers
    # -----------------------------------------------------------------
    def _load_block_registry(self):
        if os.path.exists(BLOCK_DB):
            with open(BLOCK_DB, "r") as fp:
                try:
                    return json.load(fp)
                except json.JSONDecodeError:
                    return {}
        return {}

    def _save_block_registry(self):
        with open(BLOCK_DB, "w") as fp:
            json.dump(self.blocked, fp, indent=2)

    # -----------------------------------------------------------------
    # Firewall enforcement
    # -----------------------------------------------------------------
    @staticmethod
    def _iptables_block(ip_addr: str):
        cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip_addr, "-j", "DROP"]
        subprocess.run(cmd, check=False)

    # -----------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------
    def enforce(self, llm_result: Dict) -> bool:
        """
        llm_result expected shape:
        {
            "threat": "Brute Force",
            "risk_score": 8.2,
            "action": "Block IP",
            "rationale": "Repeated failed logins"
            "source_ip": "192.168.1.50"
        }
        Returns True if IP was newly blocked, False otherwise.
        """
        ip_addr = llm_result.get("source_ip")
        risk = llm_result.get("risk_score", 0)

        if ip_addr is None:
            print("[!] No source_ip in LLM result, skipping mitigation.")
            return False

        if risk < self.threshold:
            # Below threshold → no block
            return False

        if ip_addr in self.blocked:
            # Already blocked
            return False

        # Block and record
        self._iptables_block(ip_addr)
        self.blocked[ip_addr] = {
            "blocked_at": datetime.utcnow().isoformat() + "Z",
            "risk_score": risk,
            "threat": llm_result.get("threat"),
            "rationale": llm_result.get("rationale"),
        }
        self._save_block_registry()
        print(f"[+] Blocked IP {ip_addr} (score={risk})")
        return True


# ---------------------------------------------------------------------
# Example standalone usage
# ---------------------------------------------------------------------
if __name__ == "__main__":
    sample_output = {
        "threat": "Credential Stuffing",
        "risk_score": 8.7,
        "action": "Block IP",
        "rationale": "Multiple POST attempts with common passwords.",
        "source_ip": "192.168.1.50"
    }

    controller = MitigationController(threshold=7.0)
    controller.enforce(sample_output)
