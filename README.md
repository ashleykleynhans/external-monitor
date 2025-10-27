# External Monitor

A Python-based URL monitoring tool that checks the health and SSL certificate validity of configured endpoints at regular intervals and sends notifications to Discord via webhooks.

## Features

- Monitor multiple URLs at configurable intervals (default: 2 minutes)
- SSL certificate validation
- HTTP status code checking
- Discord notifications via Slack-compatible webhooks
- Hostname tracking to identify which server is performing the monitoring

## Requirements

- Python 3.8+
- See `requirements.txt` for Python dependencies

## Installation

1. Clone this repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Copy and configure the config file:
   ```bash
   cp config.yml.example config.yml
   ```

4. Edit `config.yml` with your URLs and Discord webhook endpoint

## Configuration

Edit `config.yml` to specify:

- `webhook_url`: Your Discord webhook URL (Slack-compatible format)
- `urls`: List of URLs to monitor

Example:
```yaml
webhook_url: "https://discord.com/api/webhooks/your/webhook/url"
urls:
  - "https://example.com"
  - "https://api.example.com"
```

## Usage

Run the monitoring script:

```bash
python monitor.py
```

The script will continuously monitor the configured URLs and send notifications to Discord when issues are detected.

## Notifications

The monitoring system will send Discord notifications when:
- A URL returns a non-200 HTTP status code
- SSL certificate validation fails
- Connection errors occur

Each notification includes:
- The affected URL
- The hostname of the monitoring server
- Error details

## Testing

Run the test suite:

```bash
python -m pytest tests/
```

## License

MIT
