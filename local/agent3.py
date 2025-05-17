import sys
import json
import subprocess
import requests
import logging
import os
import re
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# DeepSeek API configuration
DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "sk-e0abe1db2f0c4c1ca45a917a99a714f7")
DEEPSEEK_MODEL = "deepseek-chat"

# Default templates if DeepSeek fails and use_deepseek=True
DEFAULT_TEMPLATES = ["http/technologies/", "http/exposures/", "http/vulnerabilities/"]

def clean_template_list(content):
    """Parse and clean DeepSeek response to extract list of template directories."""
    if not content:
        logging.error("DeepSeek returned empty content")
        return None
    # Log raw content for debugging
    logging.debug(f"Raw DeepSeek response: {content}")
    # Remove markdown backticks or other formatting
    content = re.sub(r'^```(json)?\s*\n|```$', '', content, flags=re.MULTILINE)
    content = content.strip()
    try:
        # Try to parse as JSON
        template_list = json.loads(content)
        if not isinstance(template_list, list):
            logging.error(f"DeepSeek response is not a list: {content}")
            return None
        # Validate template directories
        valid_templates = [t for t in template_list if isinstance(t, str) and t.endswith('/')]
        if not valid_templates:
            logging.error(f"No valid template directories in DeepSeek response: {content}")
            return None
        return valid_templates
    except json.JSONDecodeError:
        # Fallback: Parse as newline or comma-separated list
        templates = []
        for line in content.splitlines():
            line = line.strip()
            if line.endswith('/'):
                templates.append(line)
            elif ',' in line:
                templates.extend([t.strip() for t in line.split(',') if t.strip().endswith('/')])
        if not templates:
            logging.error(f"Failed to parse DeepSeek response as list: {content}")
            return None
        return templates

def call_deepseek(prompt):
    """Call DeepSeek API to suggest Nuclei template directories."""
    if not DEEPSEEK_API_KEY or len(DEEPSEEK_API_KEY) < 10:
        logging.error("Invalid or missing DEEPSEEK_API_KEY")
        return None

    session = requests.Session()
    retries = Retry(total=5, backoff_factor=2, status_forcelist=[429, 500, 502, 503, 504])
    session.mount("https://", HTTPAdapter(max_retries=retries))
    
    headers = {
        "Authorization": f"Bearer {DEEPSEEK_API_KEY}",
        "Content-Type": "application/json"
    }
    data = {
        "model": DEEPSEEK_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 500
    }
    try:
        response = session.post(DEEPSEEK_API_URL, headers=headers, json=data, timeout=60)
        response.raise_for_status()
        raw_content = response.json()["choices"][0]["message"]["content"]
        return clean_template_list(raw_content)
    except requests.exceptions.RequestException as e:
        logging.error(f"DeepSeek API error: {e}")
        if isinstance(e, requests.exceptions.HTTPError):
            logging.error(f"HTTP status: {e.response.status_code}, response: {e.response.text}")
        return None

def run_nuclei(target, templates=None, rate_limit=50):
    """Run Nuclei with specified parameters."""
    cmd = ["nuclei", "-u", target, "-rl", str(rate_limit), "-jsonl", "-silent"]
    
    valid_templates = []
    if templates:
        for template in templates:
            template = template.rstrip("/")
            template_path = os.path.join(os.path.expanduser("~"), "nuclei-templates", template)
            if os.path.exists(template_path):
                valid_templates.append(template)
            else:
                logging.warning(f"Template directory not found: {template}")
        
        if valid_templates:
            for template in valid_templates:
                cmd.extend(["-t", template])
        else:
            logging.warning("No valid templates provided, using all available Nuclei templates")
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True
        )
        results = []
        for line in result.stdout.splitlines():
            if line.strip():
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    logging.error(f"Failed to parse Nuclei output line: {line}")
        if not results:
            logging.info(f"No vulnerabilities found for target: {target}")
        return {"results": results, "errors": []}
    except subprocess.CalledProcessError as e:
        logging.error(f"Nuclei error: {e}, stderr: {e.stderr}")
        return {"results": [], "errors": [str(e), e.stderr]}

def process_request(request):
    """Process MCP scan request."""
    target = request.get("target")
    templates = request.get("templates", None)
    rate_limit = request.get("rate_limit", 50)
    use_deepseek = request.get("use_deepseek", True)
    vulnerability_type = request.get("vulnerability_type", "http")

    if not target:
        return {"type": "scan_response", "status": "error", "errors": ["Missing target"]}

    valid_templates = []
    if templates:
        valid_templates = templates  # Sử dụng templates người dùng cung cấp
    elif use_deepseek:
        prompt = (
            f"For the target {target}, suggest a JSON array of Nuclei template directories "
            f"suitable for scanning {vulnerability_type} vulnerabilities. "
            "Examples include [\"http/technologies/\", \"http/exposures/\", \"http/vulnerabilities/\"]. "
            "Ensure the response is a valid JSON array containing only directory paths ending with '/'. "
            "Do not include explanations or additional text outside the JSON array."
        )
        template_list = call_deepseek(prompt)
        if template_list:
            valid_templates.extend(template_list)
            logging.info(f"DeepSeek suggested templates for {vulnerability_type}: {template_list}")
        else:
            logging.warning("DeepSeek failed to suggest templates, using all available Nuclei templates")
            # Không thêm DEFAULT_TEMPLATES, để quét toàn bộ kho

    # Nếu không có template hợp lệ, quét toàn bộ kho template
    try:
        scan_result = run_nuclei(target, valid_templates, rate_limit)
        response = {
            "type": "scan_response",
            "status": "success" if not scan_result.get("errors") else "error",
            "results": scan_result.get("results", []),
            "errors": scan_result.get("errors", []),
            "templates_used": valid_templates if valid_templates else ["all Nuclei templates"]
        }
        return response
    except Exception as e:
        logging.error(f"Error during scan: {e}")
        return {"type": "scan_response", "status": "error", "errors": [str(e)]}

def main():
    logging.info("AI Agent started")
    for line in sys.stdin:
        try:
            request = json.loads(line.strip())
            if request.get("type") == "scan_request":
                response = process_request(request)
                print(json.dumps(response, ensure_ascii=False), flush=True)
            elif request.get("type") == "suggest_templates":
                target = request.get("target")
                vulnerability_type = request.get("vulnerability_type", "http")
                if not target:
                    response = {"type": "suggest_response", "status": "error", "errors": ["Missing target"]}
                else:
                    prompt = (
                        f"For the target {target}, provide a JSON array of Nuclei template directories "
                        f"suitable for scanning {vulnerability_type} vulnerabilities. "
                        "Examples include [\"http/technologies/\", \"http/exposures/\", \"http/vulnerabilities/\"]. "
                        "Ensure the response is a valid JSON array containing only directory paths ending with '/'. "
                        "Do not include explanations or additional text outside the JSON array."
                    )
                    template_list = call_deepseek(prompt)
                    if template_list:
                        response = {
                            "type": "suggest_response",
                            "status": "success",
                            "templates": template_list
                        }
                    else:
                        response = {
                            "type": "suggest_response",
                            "status": "success",
                            "templates": DEFAULT_TEMPLATES
                        }
                    print(json.dumps(response, ensure_ascii=False), flush=True)
            else:
                response = {"type": "response", "status": "error", "errors": ["Invalid request type"]}
                print(json.dumps(response, ensure_ascii=False), flush=True)
        except json.JSONDecodeError:
            print(json.dumps({"type": "response", "status": "error", "errors": ["Invalid JSON"]}, ensure_ascii=False), flush=True)
        except Exception as e:
            logging.error(f"Error processing request: {e}")
            print(json.dumps({"type": "response", "status": "error", "errors": [str(e)]}, ensure_ascii=False), flush=True)

if __name__ == "__main__":
    main()