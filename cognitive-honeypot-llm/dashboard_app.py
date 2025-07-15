"""
dashboard_app.py
----------------
Flask dashboard for the LLM‑driven cognitive honeypot.

Endpoints:
    /           →  Home page with metrics & charts
    /logs       →  SSE stream of live attacker commands
    /blocked    →  JSON list of blocked IPs

Dependencies:
    Flask
    Flask-SSE  (for server‑sent events)   pip install flask flask-sse
    plotly     (for client‑side charts)   pip install plotly
"""

import json
import os
import sqlite3
from datetime import datetime

from flask import Flask, render_template_string, Response, jsonify
from flask_sse import sse

# -------------------------------------------------------------------
# Basic Flask setup
# -------------------------------------------------------------------
app = Flask(__name__)
app.register_blueprint(sse, url_prefix="/stream")

DB_PATH = "honeypot.db"

# -------------------------------------------------------------------
# Database helpers (SQLite for simplicity)
# -------------------------------------------------------------------
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        # Attacker commands
        c.execute("""CREATE TABLE IF NOT EXISTS events(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts TEXT,
                        session TEXT,
                        src_ip TEXT,
                        command TEXT)""")
        # Blocks
        c.execute("""CREATE TABLE IF NOT EXISTS blocks(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts TEXT,
                        src_ip TEXT,
                        risk REAL,
                        threat TEXT)""")
        conn.commit()

def insert_event(event):
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("INSERT INTO events (ts, session, src_ip, command) VALUES (?, ?, ?, ?)",
                  (event["timestamp"], event["session"], event["src_ip"], event["command"]))
        conn.commit()
        sse.publish({"data": event}, type='log')  # push to SSE stream

def insert_block(block):
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("INSERT INTO blocks (ts, src_ip, risk, threat) VALUES (?, ?, ?, ?)",
                  (block["blocked_at"], block["src_ip"], block["risk_score"], block["threat"]))
        conn.commit()
        sse.publish({"data": block}, type='block')

# -------------------------------------------------------------------
# Routes
# -------------------------------------------------------------------
@app.route("/")
def index():
    # Simple HTML with Plotly embed
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8"/>
      <title>Cognitive Honeypot Dashboard</title>
      <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
      <style>
        body { font-family: Arial, sans-serif; margin: 0 40px; }
        .section { margin-bottom: 40px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background: #f2f2f2; }
        #logbox { height: 240px; overflow-y: scroll; border: 1px solid #ccc; padding: 8px; }
      </style>
    </head>
    <body>
      <h1>Cognitive Honeypot – Live Dashboard</h1>

      <div class="section">
        <h2>Live Attacker Commands</h2>
        <div id="logbox"></div>
      </div>

      <div class="section">
        <h2>Blocked IPs</h2>
        <table id="block-table">
          <thead><tr><th>Time (UTC)</th><th>IP</th><th>Risk</th><th>Threat</th></tr></thead>
          <tbody></tbody>
        </table>
      </div>

      <div class="section">
        <h2>Risk Score Histogram</h2>
        <div id="risk-chart"></div>
      </div>

      <script>
        // ---------------- Server‑Sent Events (SSE) ----------------
        const logBox = document.getElementById('logbox');
        const blockTableBody = document.querySelector('#block-table tbody');
        let riskScores = [];

        // Live log stream
        const evtSource = new EventSource("/stream");
        evtSource.addEventListener("log", function(e) {
          const ev = JSON.parse(e.data).data;
          const line = `[${ev.timestamp}] ${ev.src_ip} $ ${ev.command}<br>`;
          logBox.innerHTML += line;
          logBox.scrollTop = logBox.scrollHeight;
        });

        evtSource.addEventListener("block", function(e) {
          const block = JSON.parse(e.data).data;
          const row = `<tr><td>${block.blocked_at}</td><td>${block.src_ip}</td>
                       <td>${block.risk_score.toFixed(1)}</td><td>${block.threat}</td></tr>`;
          blockTableBody.insertAdjacentHTML("afterbegin", row);
          riskScores.push(block.risk_score);
          drawHistogram();
        });

        // ---------------- Plotly Histogram ----------------
        function drawHistogram() {
          const data = [{ x: riskScores, type: 'histogram', nbinsx: 10 }];
          const layout = { xaxis: { title: 'Risk Score' },
                           yaxis: { title: 'Frequency' },
                           margin: { t: 20 } };
          Plotly.newPlot('risk-chart', data, layout);
        }
      </script>
    </body>
    </html>
    """
    return render_template_string(html)

@app.route("/blocked", methods=["GET"])
def get_blocked():
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT ts, src_ip, risk, threat FROM blocks ORDER BY ts DESC LIMIT 100")
        rows = c.fetchall()
    data = [{"time": t, "ip": ip, "risk": r, "threat": th} for t, ip, r, th in rows]
    return jsonify(data)

# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    # NB: for production, run via gunicorn or waitress
    app.run(host="0.0.0.0", port=8080, debug=False)
