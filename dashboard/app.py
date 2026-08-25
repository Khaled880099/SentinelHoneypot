from flask import Flask, jsonify, render_template
from flask_socketio import SocketIO

from config import DASHBOARD_HOST, DASHBOARD_PORT, DASHBOARD_SECRET_KEY
from log_collector import collector

app = Flask(__name__)
app.config["SECRET_KEY"] = DASHBOARD_SECRET_KEY
socketio = SocketIO(app, async_mode="threading", cors_allowed_origins=[])
collector.set_socketio(socketio)


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/stats")
def stats():
    return jsonify(collector.get_stats())


def run_dashboard():
    socketio.run(
        app,
        host=DASHBOARD_HOST,
        port=DASHBOARD_PORT,
        allow_unsafe_werkzeug=True,
    )
