import json
import sys
import subprocess
import os
import re

def run_nuclei(target, templates=None, severity=None, output_format="text"):
    """Thực thi lệnh Nuclei và trả về kết quả."""
    cmd = ["nuclei", "-u", target]
    
    if templates:
        cmd.extend(["-t", ",".join(templates)])
    if severity:
        cmd.extend(["-severity", ",".join(severity)])
    
    print(f"Running command: {' '.join(cmd)}", file=sys.stderr)  # Debug
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        output = []
        # Regex để parse dòng kết quả: [template-id] [protocol] [severity] target [metadata]
        pattern = r'\[(.*?)\]\s+\[(.*?)\]\s+\[(.*?)\]\s+(.*?)\s+(\[.*?\]|\(.*?\))?'
        for line in result.stdout.splitlines():
            match = re.search(pattern, line.strip())
            if match:
                template_id, protocol, severity, target, metadata = match.groups()
                vuln = {
                    "template_id": template_id,
                    "protocol": protocol,
                    "severity": severity,
                    "target": target,
                    "metadata": metadata if metadata else ""
                }
                output.append(vuln)
        return {"status": "success", "vulnerabilities": output}
    except subprocess.CalledProcessError as e:
        error_message = f"Nuclei error: {e.stderr}\nCommand: {' '.join(cmd)}"
        print(error_message, file=sys.stderr)
        return {"status": "error", "message": error_message}
    except FileNotFoundError:
        error_message = "Nuclei not found in PATH. Please ensure Nuclei is installed and accessible."
        print(error_message, file=sys.stderr)
        return {"status": "error", "message": error_message}
    except Exception as e:
        error_message = f"Unexpected error: {str(e)}"
        print(error_message, file=sys.stderr)
        return {"status": "error", "message": error_message}

def handle_request(request):
    """Xử lý yêu cầu JSON-RPC."""
    if not isinstance(request, dict) or "jsonrpc" not in request or request["jsonrpc"] != "2.0":
        return {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"}, "id": None}
    
    method = request.get("method")
    params = request.get("params", {})
    request_id = request.get("id")

    if method == "scan_vulnerabilities":
        target = params.get("target")
        templates = params.get("templates")
        severity = params.get("severity")
        
        if not target:
            return {"jsonrpc": "2.0", "error": {"code": -32602, "message": "Missing target"}, "id": request_id}
        
        result = run_nuclei(target, templates, severity)
        return {"jsonrpc": "2.0", "result": result, "id": request_id}
    
    return {"jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found"}, "id": request_id}

def main():
    """Chạy MCP Server, đọc từ stdin và ghi vào stdout."""
    print("MCP Server started", file=sys.stderr)
    for line in sys.stdin:
        print(f"Received request: {line.strip()}", file=sys.stderr)
        try:
            request = json.loads(line.strip())
            response = handle_request(request)
            print(json.dumps(response), flush=True)
        except json.JSONDecodeError:
            error_response = {"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}, "id": None}
            print(json.dumps(error_response), flush=True)

if __name__ == "__main__":
    main()