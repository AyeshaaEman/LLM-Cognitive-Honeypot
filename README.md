# LLM-Driven Cognitive Honeypot

This repository contains the implementation of a modular, real-time honeypot system that uses large language models (LLMs) to infer malicious behavior and trigger automated IP blocking. The system integrates Cowrie for SSH session emulation and Mixtral (accessed via GroqCloud) for behavioral reasoning.

## ⚙️ Architecture Overview

```
Cowrie Honeypot → JSON Logs → Prompt Engine → Mixtral LLM → Risk Score → Firewall Action
```

## 🚀 How to Run

1. Clone the repository.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Set your `GROQCLOUD_API_KEY` in environment variables.
4. Start the honeypot system:
   ```bash
   python src/dashboard_app.py
   ```

## Tested Stack

- Python 3.10+
- Flask, Plotly, Requests
- GroqCloud (for LLM API)
- Cowrie honeypot
- iptables (Linux-based firewall)

## 📄 License

MIT License

---

> This project was built as part of a master's research initiative in intelligent cybersecurity defense systems.
