import subprocess
import json
import sys

def send_request(server_process, request):
    """Gửi yêu cầu JSON-RPC tới MCP Server và nhận phản hồi."""
    print(f"Sending request: {json.dumps(request)}", file=sys.stderr)  # Debug
    server_process.stdin.write(json.dumps(request) + '\n')
    server_process.stdin.flush()
    response = server_process.stdout.readline().strip()
    print(f"Received response: {response}", file=sys.stderr)  # Debug
    return json.loads(response)

def main():
    # Khởi động MCP Server
    try:
        server_process = subprocess.Popen(
            ['python', 'mcp_server.py'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            bufsize=1  # Line buffering
        )
    except FileNotFoundError:
        print("Error: mcp_server.py not found in current directory.", file=sys.stderr)
        return

    # Yêu cầu quét
    request = {
        "jsonrpc": "2.0",
        "method": "scan_vulnerabilities",
        "params": {
            "target": "http://juice-shop.herokuapp.com",
            # "templates": ["http/technologies/", "http/exposures/"],
            # "severity": ["info", "low", "medium", "high", "critical"]
        },
        "id": 1
    }

    # Gửi yêu cầu và nhận phản hồi
    try:
        response = send_request(server_process, request)
    except Exception as e:
        print(f"Error communicating with server: {str(e)}", file=sys.stderr)
        server_process.terminate()
        return
    
    # In kết quả
    if "error" in response:
        print(f"Error: {response['error']['message']}")
    elif "result" in response:
        result = response["result"]
        if result["status"] == "success":
            if result["vulnerabilities"]:
                print("Vulnerabilities found:")
                for vuln in result["vulnerabilities"]:
                    print(f"[{vuln.get('template_id', 'Unknown')}] "
                          f"[{vuln.get('protocol', 'Unknown')}] "
                          f"[{vuln.get('severity', 'Unknown')}] "
                          f"{vuln.get('target', 'Unknown')} "
                          f"{vuln.get('metadata', '')}")
            else:
                print("No vulnerabilities found.")
        else:
            print(f"Scan failed: {result.get('message', 'Unknown error')}")

    # Đóng server
    server_process.terminate()

if __name__ == "__main__":
    main()