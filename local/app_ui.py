import sys
import json
import subprocess
import logging
import uuid
import datetime
import os
from flask import Flask, render_template, request, jsonify, redirect, url_for
from werkzeug.utils import secure_filename

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Đường dẫn lưu lịch sử quét
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

def send_request(request):
    """Gửi yêu cầu quét hoặc gợi ý đến agent.py qua stdio transport."""
    with subprocess.Popen(
        ["python", "agent3.py"], 
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True
    ) as proc:
        proc.stdin.write(json.dumps(request) + "\n")
        proc.stdin.flush()
        response = proc.stdout.readline().strip()
        return json.loads(response)

@app.route("/", methods=["GET", "POST"])
def index():
    """Trang chủ: Form quét và lịch sử quét."""
    history = load_history()
    if request.method == "POST":
        # Lấy dữ liệu từ form
        target = request.form.get("target")
        templates = request.form.get("templates", "").split(",") if request.form.get("templates") else []
        templates = [t.strip() for t in templates if t.strip()]
        rate_limit = int(request.form.get("rate_limit", 50))
        vulnerability_type = request.form.get("vulnerability_type", "http")
        
        # Xử lý trường hợp vulnerability_type="all"
        if vulnerability_type == "all":
            use_deepseek = False
            templates = []  # Không sử dụng template cụ thể
        else:
            use_deepseek = request.form.get("use_deepseek") == "on"

        # Tạo yêu cầu quét
        request_data = {
            "type": "scan_request",
            "target": target,
            "templates": templates,
            "rate_limit": rate_limit,
            "use_deepseek": use_deepseek,
            "vulnerability_type": vulnerability_type
        }

        # Gửi yêu cầu và nhận phản hồi
        logging.info("Gửi yêu cầu quét: %s", request_data)
        response = send_request(request_data)
        logging.info("Nhận phản hồi: %s", response)

        # Lưu vào lịch sử
        scan_data = {
            "scan_id": str(uuid.uuid4()),
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "request": request_data,
            "response": response
        }
        save_history(scan_data)

        # Chuyển hướng đến trang kết quả
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

    # Không gợi ý template nếu vulnerability_type="all"
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