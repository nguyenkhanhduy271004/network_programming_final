import sys
import json
import subprocess
import requests
import logging
import os
import yaml
import re
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# DeepSeek API configuration
DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "sk-e0abe1db2f0c4c1ca45a917a99a714f7")
DEEPSEEK_MODEL = "deepseek-chat"

def clean_yaml_content(content):
    """Remove markdown backticks and other unwanted formatting from YAML content."""
    if not content:
        return None
    # Remove ```yaml and ``` markers
    content = re.sub(r'^```yaml\s*\n|```$', '', content, flags=re.MULTILINE)
    # Remove any leading/trailing whitespace
    return content.strip()

def call_deepseek(prompt):
    """Call DeepSeek API to generate or parse data with retries and timeout."""
    # Configure session with retries and timeout
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    session.mount("https://", HTTPAdapter(max_retries=retries))
    
    headers = {
        "Authorization": f"Bearer {DEEPSEEK_API_KEY}",
        "Content-Type": "application/json"
    }
    data = {
        "model": DEEPSEEK_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 1000
    }
    try:
        response = session.post(DEEPSEEK_API_URL, headers=headers, json=data, timeout=30)
        response.raise_for_status()
        raw_content = response.json()["choices"][0]["message"]["content"]
        return clean_yaml_content(raw_content)
    except requests.exceptions.RequestException as e:
        logging.error(f"DeepSeek API error for URL {DEEPSEEK_API_URL}: {e}")
        return None

def validate_yaml_template(template_content):
    """Validate if the content is a valid Nuclei YAML template."""
    try:
        parsed_yaml = yaml.safe_load(template_content)
        required_fields = ['id', 'info']
        for field in required_fields:
            if field not in parsed_yaml:
                logging.error(f"Template missing required field: {field}")
                return False
        if 'http' not in parsed_yaml and 'dns' not in parsed_yaml and 'tcp' not in parsed_yaml:
            logging.error("Template missing scan request (http, dns, tcp, etc.)")
            return False
        return True
    except yaml.YAMLError as e:
        logging.error(f"YAML syntax error: {e}")
        return False

def run_nuclei(target, templates=None, rate_limit=50):
    """Run Nuclei with specified parameters."""
    cmd = ["nuclei", "-u", target, "-rl", str(rate_limit), "-jsonl", "-silent"]
    
    if templates:
        valid_templates = []
        for template in templates:
            template = template.rstrip("/")
            if os.path.exists(template):
                valid_templates.append(template)
            else:
                logging.warning(f"Template not found: {template}")
        
        if not valid_templates:
            logging.warning("No valid templates provided, using default template repository")
        else:
            for template in valid_templates:
                cmd.extend(["-t", template])
    
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

    if not target:
        return {"type": "scan_response", "status": "error", "errors": ["Missing target"]}

    valid_templates = templates if templates else []
    temp_template_path = None
    if use_deepseek:
        prompt = (
            "Generate a valid Nuclei YAML template to scan for XSS vulnerabilities for the target {target}. "
            "The template must include required fields: id, info (with name, author, severity, description), "
            "and an HTTP request with payloads and matcher to detect XSS. "
            "Example:\n"
            "id: xss-vuln\n"
            "info:\n"
            "  name: XSS Vulnerability Detection\n"
            "  author: test\n"
            "  severity: high\n"
            "  description: Detects XSS in search functionality\n"
            "http:\n"
            "  - method: GET\n"
            "    path:\n"
            "      - \"{{BaseURL}}/search.php?test={{payload}}\"\n"
            "    payloads:\n"
            "      payload:\n"
            "        - \"<script>alert(1)</script>\"\n"
            "        - \"';alert(1);'\"\n"
            "    matchers:\n"
            "      - type: word\n"
            "        words:\n"
            "          - \"<script>alert(1)</script>\"\n"
            "          - \"';alert(1);'\"\n"
            "        part: body\n"
        ).format(target=target)
        template_content = call_deepseek(prompt)
        if template_content:
            temp_template_path = "temp_template.yaml"
            try:
                if not validate_yaml_template(template_content):
                    logging.warning("Content from DeepSeek is invalid, using default template repository")
                else:
                    with open(temp_template_path, "w", encoding="utf-8") as f:
                        f.write(template_content)
                    if os.path.exists(temp_template_path):
                        valid_templates.append(temp_template_path)
                    else:
                        logging.error("Failed to create temp_template.yaml")
                        return {"type": "scan_response", "status": "error", "errors": ["Failed to create temp_template.yaml"]}
            except Exception as e:
                logging.error(f"Error saving temp_template.yaml: {e}")
                return {"type": "scan_response", "status": "error", "errors": [f"Error saving temp_template.yaml: {e}"]}
        else:
            logging.warning("Failed to generate template from DeepSeek, using default template repository")

    try:
        scan_result = run_nuclei(target, valid_templates, rate_limit)
        response = {
            "type": "scan_response",
            "status": "success" if not scan_result.get("errors") else "error",
            "results": scan_result.get("results", []),
            "errors": scan_result.get("errors", [])
        }
        return response
    finally:
        if temp_template_path and os.path.exists(temp_template_path):
            try:
                os.remove(temp_template_path)
                logging.info("Cleaned up temp_template.yaml")
            except Exception as e:
                logging.error(f"Error cleaning up temp_template.yaml: {e}")

def main():
    logging.info("AI Agent started")
    for line in sys.stdin:
        try:
            request = json.loads(line.strip())
            if request.get("type") == "scan_request":
                response = process_request(request)
                print(json.dumps(response, ensure_ascii=False), flush=True)
        except json.JSONDecodeError:
            print(json.dumps({"type": "scan_response", "status": "error", "errors": ["Invalid JSON"]}, ensure_ascii=False), flush=True)
        except Exception as e:
            logging.error(f"Error processing request: {e}")
            print(json.dumps({"type": "scan_response", "status": "error", "errors": [str(e)]}, ensure_ascii=False), flush=True)

if __name__ == "__main__":
    main()