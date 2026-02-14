"""
StreamRelay Demo — a minimal Flask app that demonstrates real-time
event delivery through StreamRelay.

Endpoints:
    GET  /              Serves the demo frontend
    POST /auth/token    Returns a JWT for the given identity
    POST /api/spinner   Starts a 0-100 progress counter
    POST /api/chat      Streams lorem ipsum words

Requires:
    pip install flask redis pyjwt

Usage:
    # 1. Start Redis and StreamRelay (docker compose up)
    # 2. Start this app:
    STREAMRELAY_SECRET="your-32-character-secret-here!!" python app.py
    # 3. Open http://localhost:5000
"""

import json
import os
import threading
import time

import jwt
import redis
from flask import Flask, jsonify, request, send_from_directory
from datetime import datetime, timezone, timedelta

app = Flask(__name__, static_folder=".", static_url_path="")

SECRET = os.environ.get("STREAMRELAY_SECRET", "dev-secret-change-me-32-chars!!")
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
CHANNEL_PREFIX = os.environ.get("CHANNEL_PREFIX", "streams")
STREAMRELAY_URL = os.environ.get("STREAMRELAY_URL", "http://localhost:8080")

r = redis.from_url(REDIS_URL)

LOREM = (
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
    "Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. "
    "Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris "
    "nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in "
    "reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla "
    "pariatur. Excepteur sint occaecat cupidatat non proident, sunt in "
    "culpa qui officia deserunt mollit anim id est laborum."
).split()


# --- Auth ---

@app.route("/auth/token", methods=["POST"])
def create_token():
    """Issue a JWT. In real life this would check credentials."""
    identity = request.json.get("identity", "demo-user")
    payload = {
        "sub": identity,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
    }
    token = jwt.encode(payload, SECRET, algorithm="HS256")
    return jsonify({"token": token, "identity": identity})


# --- Spinner ---

def _run_spinner(identity: str):
    """Publish progress 0-100 to Redis."""
    channel = f"{CHANNEL_PREFIX}:{identity}"
    for i in range(101):
        r.publish(channel, json.dumps({
            "type": "progress",
            "value": i,
        }))
        time.sleep(0.05)
    r.publish(channel, json.dumps({
        "type": "progress_done",
    }))


@app.route("/api/spinner", methods=["POST"])
def spinner():
    identity = request.json.get("identity", "demo-user")
    threading.Thread(target=_run_spinner, args=(identity,), daemon=True).start()
    return jsonify({"status": "started"})


# --- Chat ---

def _run_chat(identity: str):
    """Stream lorem ipsum words one at a time."""
    channel = f"{CHANNEL_PREFIX}:{identity}"
    # Stream 3 paragraphs.
    for _ in range(3):
        for word in LOREM:
            r.publish(channel, json.dumps({
                "type": "chat_token",
                "token": word,
            }))
            time.sleep(0.04)
        # Paragraph break.
        r.publish(channel, json.dumps({
            "type": "chat_token",
            "token": "\n\n",
        }))
        time.sleep(0.3)
    r.publish(channel, json.dumps({
        "type": "chat_done",
    }))


@app.route("/api/chat", methods=["POST"])
def chat():
    identity = request.json.get("identity", "demo-user")
    threading.Thread(target=_run_chat, args=(identity,), daemon=True).start()
    return jsonify({"status": "started"})


# --- Frontend ---

@app.route("/")
def index():
    return send_from_directory(".", "index.html")


# --- Config endpoint (so the frontend knows where StreamRelay is) ---

@app.route("/config")
def config():
    return jsonify({"streamrelay_url": STREAMRELAY_URL})


if __name__ == "__main__":
    print(f"\n  StreamRelay Demo")
    print(f"  Frontend:     http://localhost:5000")
    print(f"  StreamRelay:  {STREAMRELAY_URL}")
    print(f"  Redis:        {REDIS_URL}\n")
    app.run(port=5000, debug=True)
