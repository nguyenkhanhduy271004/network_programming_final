# Nuclei MCP Remote Scanner

A professional-grade remote vulnerability scanning system that integrates Nuclei scanner with a modern web interface and AI-powered template suggestions using DeepSeek API.

## System Architecture

The system is built with a microservices architecture consisting of two main components:

1. **Web Interface (app_ui.py)**
   - Flask-based web application
   - RESTful API endpoints
   - Real-time scan monitoring
   - Comprehensive scan history management
   - Port: 5000

2. **Scanning Service (agent3.py)**
   - FastAPI-based microservice
   - Nuclei scanner integration
   - DeepSeek AI integration for intelligent template suggestions
   - Asynchronous scan processing
   - Port: 8000

## Core Features

- Advanced vulnerability scanning with Nuclei templates
- Real-time scan monitoring using Server-Sent Events (SSE)
- AI-powered template suggestions via DeepSeek API
- Comprehensive scan history and result management
- Customizable template selection and management
- Configurable rate limiting and scan parameters
- Support for multiple vulnerability categories
- Docker-based deployment for easy scaling

## System Requirements

- Docker Engine (version 20.10.0 or higher)
- Docker Compose (version 2.0.0 or higher)
- Nuclei templates (mounted at ~/.nuclei-templates)
- DeepSeek API credentials
- Minimum 2GB RAM
- 10GB free disk space

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/nuclei-mcp.git
cd nuclei-mcp/remote
```

2. Configure environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

3. Deploy using Docker Compose:
```bash
docker-compose up --build
```

## Configuration

### Environment Variables

- `AGENT_API_URL`: Scanning service endpoint (default: http://agent:8000)
- `DEEPSEEK_API_KEY`: DeepSeek API authentication key
- `DEEPSEEK_MODEL`: AI model selection (default: deepseek-chat)
- `SCAN_RATE_LIMIT`: Maximum requests per second (default: 50)
- `SCAN_TIMEOUT`: Maximum scan duration in seconds (default: 900)

### Docker Configuration

The system uses two Docker containers:
- `ui`: Web interface container
- `agent`: Scanning service container

## Usage Guide

1. Access the web interface:
   - URL: http://localhost:5000
   - Default credentials: Configure in .env file

2. Initiate a scan:
   - Enter target URL
   - Select vulnerability type
   - Configure rate limit
   - Choose template selection method
   - Enable/disable AI suggestions

3. Monitor scan progress:
   - Real-time results display
   - Progress indicators
   - Error reporting

4. Review results:
   - Detailed vulnerability reports
   - Historical scan data
   - Export functionality

## Project Structure

```
remote/
├── app_ui.py              # Web interface implementation
├── agent3.py             # Scanning service implementation
├── Dockerfile.ui         # Web interface container configuration
├── Dockerfile.agent      # Scanning service container configuration
├── docker-compose.yml    # Container orchestration
├── scan_history.json     # Scan results database
└── templates/            # Web interface templates
```

## API Documentation

### Web Interface Endpoints

- `GET /`: Main interface
- `GET /history`: Scan history
- `POST /scan`: Initiate scan
- `GET /results/<scan_id>`: Retrieve scan results
- `POST /suggest_templates`: Get template suggestions

### Scanning Service Endpoints

- `POST /scan`: Process scan request
- `POST /suggest`: Generate template suggestions
- `GET /status`: Service health check

## Security Considerations

- Implement proper API key management
- Configure appropriate access controls
- Monitor and adjust rate limits
- Regular template updates
- Secure communication between services
- Regular security audits
- Data retention policies

## Maintenance

- Regular template updates
- System health monitoring
- Log rotation
- Backup procedures
- Performance optimization

## License

[Specify your license here]

## Support

For technical support and feature requests, please open an issue in the repository. 