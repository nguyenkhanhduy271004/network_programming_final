import sys
import json
import logging
import os
import re
from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse
import asyncio
from typing import List, Optional
import subprocess
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# DeepSeek API configuration
DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "sk-e0abe1db2f0c4c1ca45a917a99a714f7")
DEEPSEEK_MODEL = "deepseek-chat"

# Default templates if DeepSeek fails or no templates specified
DEFAULT_TEMPLATES = [
    "http/technologies/",
    "http/exposures/",
    "http/vulnerabilities/",
    "http/misconfiguration/",
    "http/cves/"
]

# FastAPI app
app = FastAPI()

# Pydantic models
class ScanRequest(BaseModel):
    type: str = "scan_request"
    target: str
    templates: Optional[List[str]] = None
    rate_limit: int = 50
    use_deepseek: bool = True
    vulnerability_type: str = "http"

class SuggestRequest(BaseModel):
    type: str = "suggest_templates"
    target: str
    vulnerability_type: str = "http"

def clean_template_list(content):
    """Parse and clean DeepSeek response to extract list of template directories."""
    if not content:
        logging.error("DeepSeek returned empty content")
        return None
    logging.debug(f"Raw DeepSeek response: {content}")
    content = re.sub(r'^```(json)?\s*\n|```$', '', content, flags=re.MULTILINE)
    content = content.strip()
    try:
        template_list = json.loads(content)
        if not isinstance(template_list, list):
            logging.error(f"DeepSeek response is not a list: {content}")
            return None
        valid_templates = [t for t in template_list if isinstance(t, str) and t.endswith('/')]
        if not valid_templates:
            logging.error(f"No valid template directories in DeepSeek response: {content}")
            return None
        return valid_templates
    except json.JSONDecodeError:
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
    # cmd = ["nuclei", "-u", target, "-rl", str(rate_limit)]
    cmd = ["nuclei", "-u", target]

    
    valid_templates = []
    templates_base_path = os.path.join(os.path.expanduser("~"), "nuclei-templates")
    
    if templates:
        for template in templates:
            template = template.rstrip("/")
            template_path = os.path.join(templates_base_path, template)
            if os.path.exists(template_path):
                valid_templates.append(template)
            else:
                logging.warning(f"Template directory not found: {template_path}")
    
    if valid_templates:
        # Combine valid templates into a single -t argument with comma-separated paths
        cmd.extend(["-t", ", ".join(valid_templates)])
    else:
        # Use specified template directories
        default_templates = [
            "http/technologies/",
            "http/exposures/",
            "http/vulnerabilities/",
            "http/misconfiguration/",
            "http/cves/"
        ]
        logging.info("No valid templates provided, using default HTTP-related templates")
        valid_default_templates = []
        for template in default_templates:
            template_path = os.path.join(templates_base_path, template.rstrip("/"))
            if os.path.exists(template_path):
                valid_default_templates.append(template)
            else:
                logging.warning(f"Default template directory not found: {template_path}")
        
        if valid_default_templates:
            cmd.extend(["-t", ",".join(valid_default_templates)])
        else:
            logging.error("No valid templates available for scan")
            return {"results": [], "errors": ["No valid templates available for scan"]}
    
    # Append -jsonl and -no-interactsh at the end
    cmd.extend(["-jsonl", "-no-interactsh"])
    
    try:
        logging.info(f"Executing Nuclei command: {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=900  # 15-minute timeout
        )
        results = []
        stderr_lines = result.stderr.splitlines()
        errors = []
        for line in stderr_lines:
            logging.debug(f"Nuclei stderr: {line}")
            if "Skipped" in line and "unresponsive" in line:
                errors.append(f"Target skipped: {line}")
            if "Could not find template" in line:
                errors.append(f"Template error: {line}")
        for line in result.stdout.splitlines():
            if line.strip():
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    logging.error(f"Failed to parse Nuclei output line: {line}")
                    errors.append(f"Invalid JSON output: {line}")
        if not results and not errors:
            logging.info(f"No vulnerabilities found for target: {target}")
        return {"results": results, "errors": errors}
    except subprocess.TimeoutExpired as e:
        logging.error(f"Nuclei timed out after {e.timeout} seconds: {e}")
        return {"results": [], "errors": ["Nuclei scan timed out"]}
    except subprocess.CalledProcessError as e:
        logging.error(f"Nuclei error: {e}, stderr: {e.stderr}")
        return {"results": [], "errors": [str(e), e.stderr]}
    """Run Nuclei with specified parameters."""
    cmd = ["nuclei", "-u", target, "-jsonl", "-no-interactsh"]
    
    valid_templates = []
    templates_base_path = os.path.join(os.path.expanduser("~"), "nuclei-templates")
    
    if templates:
        for template in templates:
            template = template.rstrip("/")
            template_path = os.path.join(templates_base_path, template)
            if os.path.exists(template_path):
                valid_templates.append(template)
            else:
                logging.warning(f"Template directory not found: {template_path}")
    
    if valid_templates:
        # Combine valid templates into a single -t argument with comma-separated paths
        cmd.extend(["-t", ",".join(valid_templates)])
    else:
        # Use specified template directories
        default_templates = [
            "http/technologies/",
            "http/exposures/",
            "http/vulnerabilities/",
            "http/misconfiguration/",
            "http/cves/"
        ]
        logging.info("No valid templates provided, using default HTTP-related templates")
        valid_default_templates = []
        for template in default_templates:
            template_path = os.path.join(templates_base_path, template.rstrip("/"))
            if os.path.exists(template_path):
                valid_default_templates.append(template)
            else:
                logging.warning(f"Default template directory not found: {template_path}")
        
        if valid_default_templates:
            cmd.extend(["-t", ",".join(valid_default_templates)])
        else:
            logging.error("No valid templates available for scan")
            return {"results": [], "errors": ["No valid templates available for scan"]}
    
    try:
        logging.info(f"Executing Nuclei command: {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=900  # 15-minute timeout
        )
        results = []
        stderr_lines = result.stderr.splitlines()
        errors = []
        for line in stderr_lines:
            logging.debug(f"Nuclei stderr: {line}")
            if "Skipped" in line and "unresponsive" in line:
                errors.append(f"Target skipped: {line}")
            if "Could not find template" in line:
                errors.append(f"Template error: {line}")
        for line in result.stdout.splitlines():
            if line.strip():
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    logging.error(f"Failed to parse Nuclei output line: {line}")
                    errors.append(f"Invalid JSON output: {line}")
        if not results and not errors:
            logging.info(f"No vulnerabilities found for target: {target}")
        return {"results": results, "errors": errors}
    except subprocess.TimeoutExpired as e:
        logging.error(f"Nuclei timed out after {e.timeout} seconds: {e}")
        return {"results": [], "errors": ["Nuclei scan timed out"]}
    except subprocess.CalledProcessError as e:
        logging.error(f"Nuclei error: {e}, stderr: {e.stderr}")
        return {"results": [], "errors": [str(e), e.stderr]}
    """Run Nuclei with specified parameters."""
    cmd = ["nuclei", "-u", target, "-rl", str(rate_limit), "-jsonl", "-no-interactsh"]
    
    valid_templates = []
    templates_base_path = os.path.join(os.path.expanduser("~"), "nuclei-templates")
    
    if templates:
        for template in templates:
            template = template.rstrip("/")
            template_path = os.path.join(templates_base_path, template)
            if os.path.exists(template_path):
                valid_templates.append(template)
            else:
                logging.warning(f"Template directory not found: {template_path}")
    
    if valid_templates:
        for template in valid_templates:
            cmd.extend(["-t", template])
    else:
        # Use default template directories
        logging.info("No valid templates provided, using default HTTP-related templates")
        for template in DEFAULT_TEMPLATES:
            template_path = os.path.join(templates_base_path, template.rstrip("/"))
            if os.path.exists(template_path):
                cmd.extend(["-t", template])
            else:
                logging.warning(f"Default template directory not found: {template_path}")
    
    if "-t" not in cmd:
        logging.error("No valid templates available for scan")
        return {"results": [], "errors": ["No valid templates available for scan"]}
    
    try:
        logging.info(f"Executing Nuclei command: {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=900  # 15-minute timeout
        )
        results = []
        stderr_lines = result.stderr.splitlines()
        errors = []
        for line in stderr_lines:
            logging.debug(f"Nuclei stderr: {line}")
            if "Skipped" in line and "unresponsive" in line:
                errors.append(f"Target skipped: {line}")
            if "Could not find template" in line:
                errors.append(f"Template error: {line}")
        for line in result.stdout.splitlines():
            if line.strip():
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    logging.error(f"Failed to parse Nuclei output line: {line}")
                    errors.append(f"Invalid JSON output: {line}")
        if not results and not errors:
            logging.info(f"No vulnerabilities found for target: {target}")
        return {"results": results, "errors": errors}
    except subprocess.TimeoutExpired as e:
        logging.error(f"Nuclei timed out after {e.timeout} seconds: {e}")
        return {"results": [], "errors": ["Nuclei scan timed out"]}
    except subprocess.CalledProcessError as e:
        logging.error(f"Nuclei error: {e}, stderr: {e.stderr}")
        return {"results": [], "errors": [str(e), e.stderr]}

def process_request(request):
    """Process MCP scan or suggest request."""
    if request.get("type") == "scan_request":
        target = request.get("target")
        templates = request.get("templates", None)
        rate_limit = request.get("rate_limit", 50)
        use_deepseek = request.get("use_deepseek", True)
        vulnerability_type = request.get("vulnerability_type", "http")

        if not target:
            return {"type": "scan_response", "status": "error", "errors": ["Missing target"]}

        valid_templates = []
        if templates:
            valid_templates = templates
        elif use_deepseek:
            prompt = (
                f"For the target {target}, suggest a JSON array of Nuclei template directories "
                f"suitable for scanning {vulnerability_type} vulnerabilities. "
                "Examples include [\"http/technologies/\", \"http/exposures/\", \"http/vulnerabilities/\", \"http/misconfiguration/\", \"http/cves/\"]. "
                "Ensure the response is a valid JSON array containing only directory paths ending with '/'. "
                "Do not include explanations or additional text outside the JSON array."
            )
            template_list = call_deepseek(prompt)
            if template_list:
                valid_templates.extend(template_list)
                logging.info(f"DeepSeek suggested templates for {vulnerability_type}: {template_list}")
            else:
                logging.warning("DeepSeek failed to suggest templates, using default templates")
                valid_templates.extend(DEFAULT_TEMPLATES)

        try:
            scan_result = run_nuclei(target, valid_templates, rate_limit)
            response = {
                "type": "scan_response",
                "status": "success" if not scan_result.get("errors") else "error",
                "results": scan_result.get("results", []),
                "errors": scan_result.get("errors", []),
                "templates_used": valid_templates if valid_templates else DEFAULT_TEMPLATES
            }
            return response
        except Exception as e:
            logging.error(f"Error during scan: {e}")
            return {"type": "scan_response", "status": "error", "errors": [str(e)]}
    
    elif request.get("type") == "suggest_templates":
        target = request.get("target")
        vulnerability_type = request.get("vulnerability_type", "http")
        if not target:
            return {"type": "suggest_response", "status": "error", "errors": ["Missing target"]}
        prompt = (
            f"For the target {target}, provide a JSON array of Nuclei template directories "
            f"suitable for scanning {vulnerability_type} vulnerabilities. "
            "Examples include [\"http/technologies/\", \"http/exposures/\", \"http/vulnerabilities/\", \"http/misconfiguration/\", \"http/cves/\"]. "
            "Ensure the response is a valid JSON array containing only directory paths ending with '/'. "
            "Do not include explanations or additional text outside the JSON array."
        )
        template_list = call_deepseek(prompt)
        if template_list:
            return {
                "type": "suggest_response",
                "status": "success",
                "templates": template_list
            }
        else:
            return {
                "type": "suggest_response",
                "status": "success",
                "templates": DEFAULT_TEMPLATES
            }
    else:
        return {"type": "response", "status": "error", "errors": ["Invalid request type"]}

async def stream_response(response_data):
    """Stream response as SSE events."""
    yield {"event": "response", "data": json.dumps(response_data)}

@app.post("/scan")
async def scan(request: ScanRequest):
    """Handle scan requests."""
    if request.type != "scan_request":
        raise HTTPException(status_code=400, detail="Invalid request type")
    response = process_request(request.model_dump())
    return EventSourceResponse(stream_response(response))

@app.post("/suggest")
async def suggest(request: SuggestRequest):
    """Handle template suggestion requests."""
    if request.type != "suggest_templates":
        raise HTTPException(status_code=400, detail="Invalid request type")
    response = process_request(request.model_dump())
    return EventSourceResponse(stream_response(response))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)