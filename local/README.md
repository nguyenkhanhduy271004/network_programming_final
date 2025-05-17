# Nuclei MCP - Security Vulnerability Scanner

A modern web application for scanning security vulnerabilities using Nuclei templates, with an AI-powered analysis feature using DeepSeek.

## Features

- 🔍 **Vulnerability Scanning**: Scan targets for various security vulnerabilities using Nuclei templates
- 🤖 **AI Analysis**: DeepSeek AI integration for detailed vulnerability analysis
- 📊 **Interactive UI**: Modern and responsive web interface
- 📝 **Template Management**: Suggest and manage Nuclei templates
- 📋 **Scan History**: Track and review past scan results
- ⚡ **Rate Limiting**: Configurable scan rate limits
- 🔒 **Multiple Scan Types**: Support for various vulnerability categories

## Prerequisites

- Python 3.8 or higher
- Nuclei scanner installed
- DeepSeek API access (optional)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/nuclei-mcp.git
cd nuclei-mcp
```

2. Install required Python packages:
```bash
pip install -r requirements.txt
```

3. Install Nuclei scanner:
```bash
# For Windows (using scoop)
scoop install nuclei

# For Linux/macOS
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
```

## Configuration

1. Create a `.env` file in the project root:
```env
DEEPSEEK_API_KEY=your_api_key_here
```

2. Configure scan settings in `config.json`:
```json
{
    "rate_limit": 150,
    "default_templates": ["cves", "vulnerabilities"],
    "use_deepseek": true
}
```

## Usage

### Web Interface

1. Start the web application:
```bash
python app_ui.py
```

2. Open your browser and navigate to `http://localhost:5000`

3. Enter the target URL and select scan options:
   - Choose vulnerability type
   - Set rate limit
   - Enable/disable DeepSeek analysis
   - Select specific templates

4. View scan results and history through the web interface

### Command Line Interface

For headless operation:
```bash
python app_no_ui.py --target https://example.com --type cves --rate-limit 150
```

## Project Structure

```
nuclei-mcp/
├── local/
│   ├── templates/          # HTML templates
│   ├── static/            # Static assets (CSS, JS)
│   ├── app_ui.py          # Web application
│   ├── app_no_ui.py       # CLI application
│   ├── agent.py           # Core scanning logic
│   ├── agent3.py          # Enhanced scanning features
│   └── requirements.txt   # Python dependencies
├── scan_history.json      # Scan results history
└── suggested_templates.json # Template suggestions
```

## API Endpoints

- `GET /`: Home page
- `GET /history`: Scan history
- `POST /scan`: Start new scan
- `GET /results/<scan_id>`: View scan results
- `POST /analyze_vulnerability`: Analyze vulnerability with DeepSeek
- `GET /suggest_templates`: Get template suggestions

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Security

- Always scan only authorized targets
- Keep your DeepSeek API key secure
- Review scan results carefully
- Follow responsible disclosure practices

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [ProjectDiscovery Nuclei](https://github.com/projectdiscovery/nuclei)
- [DeepSeek AI](https://deepseek.com)
- [Flask](https://flask.palletsprojects.com/) 