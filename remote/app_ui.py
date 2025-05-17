import sys
import json
import logging
import uuid
import datetime
import os
import requests
from flask import Flask, render_template, request, jsonify, redirect, url_for
from sseclient import SSEClient

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Agent API configuration
AGENT_API_URL = os.getenv("AGENT_API_URL", "http://agent:8000")
HISTORY_FILE = "scan_history.json"

def load_history():
    """Đọc lịch sử quét từ file JSON."""
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r") as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"Error loading history: {e}")
            return []
    return []

def save_history(scan_data):
    """Lưu yêu cầu và phản hồi quét vào lịch sử."""
    history = load_history()
    history.append(scan_data)
    try:
        with open(HISTORY_FILE, "w") as f:
            json.dump(history, f, indent=2)
    except Exception as e:
        logging.error(f"Error saving history: {e}")

def send_request(request_data):
    """Send request to agent via SSE."""
    try:
        if request_data["type"] == "scan_request":
            endpoint = f"{AGENT_API_URL}/scan"
        elif request_data["type"] == "suggest_templates":
            endpoint = f"{AGENT_API_URL}/suggest"
        else:
            return {"type": "response", "status": "error", "errors": ["Invalid request type"]}

        response = requests.post(endpoint, json=request_data, stream=True)
        response.raise_for_status()
        
        client = SSEClient(response)
        for event in client.events():
            if event.event == "response":
                return json.loads(event.data)
        return {"type": "response", "status": "error", "errors": ["No response received"]}
    except requests.RequestException as e:
        logging.error(f"Error sending request to agent: {e}")
        return {"type": "response", "status": "error", "errors": [str(e)]}

@app.route("/", methods=["GET", "POST"])
def index():
    """Trang chủ: Form quét và lịch sử quét."""
    history = load_history()
    if request.method == "POST":
        target = request.form.get("target")
        templates = request.form.get("templates", "").split(",") if request.form.get("templates") else []
        templates = [t.strip() for t in templates if t.strip()]
        rate_limit = int(request.form.get("rate_limit", 50))
        vulnerability_type = request.form.get("vulnerability_type", "http")
        
        if vulnerability_type == "all":
            use_deepseek = False
            templates = []
        else:
            use_deepseek = request.form.get("use_deepseek") == "on"

        request_data = {
            "type": "scan_request",
            "target": target,
            "templates": templates,
            "rate_limit": rate_limit,
            "use_deepseek": use_deepseek,
            "vulnerability_type": vulnerability_type
        }

        logging.info("Gửi yêu cầu quét: %s", request_data)
        response = send_request(request_data)
        logging.info("Nhận phản hồi: %s", response)

        scan_data = {
            "scan_id": str(uuid.uuid4()),
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "request": request_data,
            "response": response
        }
        save_history(scan_data)

        return redirect(url_for("results", scan_id=scan_data["scan_id"]))

    return render_template("index1.html", history=history)

@app.route("/results/<scan_id>")
def results(scan_id):
    """Trang xem chi tiết kết quả quét."""
    history = load_history()
    scan_data = next((item for item in history if item["scan_id"] == scan_id), None)
    if not scan_data:
        return render_template("results1.html", error="Không tìm thấy kết quả quét")
    return render_template("results1.html", scan_data=scan_data)

@app.route("/suggest_templates", methods=["POST"])
def suggest_templates():
    """API gợi ý danh sách template từ DeepSeek."""
    target = request.json.get("target")
    vulnerability_type = request.json.get("vulnerability_type", "http")
    if not target:
        return jsonify({"status": "error", "errors": ["Missing target"]})

    if vulnerability_type == "all":
        return jsonify({
            "type": "suggest_response",
            "status": "success",
            "templates": []
        })

    request_data = {
        "type": "suggest_templates",
        "target": target,
        "vulnerability_type": vulnerability_type
    }
    response = send_request(request_data)
    return jsonify(response)

@app.route("/history")
def history():
    """Hiển thị toàn bộ lịch sử quét."""
    history = load_history()
    return render_template("history.html", history=history)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)