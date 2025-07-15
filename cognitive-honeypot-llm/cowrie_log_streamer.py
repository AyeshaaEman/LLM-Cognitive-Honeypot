import time
import json
import os

LOG_FILE = '/var/log/cowrie/cowrie.json'  # Adjust path if different

def tail_log(file_path):
    """
    Generator function to tail a file like `tail -f`.
    """
    with open(file_path, 'r') as file:
        file.seek(0, os.SEEK_END)
        while True:
            line = file.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line.strip()

def is_relevant_event(log_line):
    """
    Filters for events of type 'cowrie.command.input'
    """
    try:
        data = json.loads(log_line)
        return data.get("eventid") == "cowrie.command.input"
    except json.JSONDecodeError:
        return False

def process_event(log_line):
    """
    Parses the log and extracts useful details for prompt generation.
    """
    data = json.loads(log_line)
    event = {
        "timestamp": data.get("timestamp"),
        "src_ip": data.get("src_ip"),
        "session": data.get("session"),
        "command": data.get("input")
    }
    print(f"[+] Captured Command: {event}")
    # You can forward this to parser or save it for batching

if __name__ == "__main__":
    print("[*] Starting Cowrie log streamer...")
    for line in tail_log(LOG_FILE):
        if is_relevant_event(line):
            process_event(line)
