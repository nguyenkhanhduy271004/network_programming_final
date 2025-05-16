import sys
import json
import subprocess
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def send_request(request):
    with subprocess.Popen(
        ["python", "agent.py"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True
    ) as proc:
        proc.stdin.write(json.dumps(request) + "\n")
        proc.stdin.flush()
        response = proc.stdout.readline().strip()
        return json.loads(response)

def main():
    request = {
        "type": "scan_request",
        "target": "http://testphp.vulnweb.com/",
        "rate_limit": 50,
        "use_deepseek": True      
}
    logging.info("Gửi yêu cầu quét: %s", request)
    response = send_request(request)
    logging.info("Nhận phản hồi: %s", response)

    if response["status"] == "success":
        print("Kết quả quét:")
        for result in response["results"]:
            print(f"- {result.get('info', {}).get('name', 'Unknown')} ({result.get('info', {}).get('severity', 'Unknown')}): {result.get('matched-at', 'Unknown')}")
    else:
        print("Lỗi:", response["errors"])

if __name__ == "__main__":
    main()