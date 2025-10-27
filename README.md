# External Monitor

A Python-based URL monitoring tool that checks the health and SSL certificate validity of configured endpoints at regular intervals and sends notifications to Discord via webhooks.

## Features

- Monitor multiple URLs at configurable intervals (default: 2 minutes)
- SSL certificate validation
- HTTP status code checking
- Discord notifications via Slack-compatible webhooks
- Hostname tracking to identify which server is performing the monitoring
- Daemon mode for running as a background service
- Graceful shutdown handling
- PID file management to prevent duplicate instances

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

The monitor can be run in two modes: as a daemon (background service) or in foreground mode.

### Daemon Mode (Recommended for Production)

Start the monitoring daemon:
```bash
./monitor.py start
```

Stop the daemon:
```bash
./monitor.py stop
```

Check daemon status:
```bash
./monitor.py status
```

Restart the daemon:
```bash
./monitor.py restart
```

### Foreground Mode (Recommended for Testing/Development)

Run the monitor in the foreground (Ctrl+C to stop):
```bash
./monitor.py foreground
```

### Advanced Options

Use a custom configuration file:
```bash
./monitor.py start --config /path/to/config.yml
```

Specify custom PID and log file locations:
```bash
./monitor.py start --pid-file /var/run/monitor.pid --log-file /var/log/monitor.log
```

View all available options:
```bash
./monitor.py --help
```

### Default File Locations

- **PID file**: `/tmp/url_monitor.pid`
- **Log file**: `/tmp/url_monitor.log`

### Viewing Logs

When running in daemon mode, logs are written to the log file:
```bash
tail -f /tmp/url_monitor.log
```

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
python3 -m pytest tests/
```

Run tests with verbose output:

```bash
python3 -m pytest tests/ -v
```

Run tests with coverage report:

```bash
python3 -m pytest tests/ --cov=monitor --cov-report=term-missing
```

## Troubleshooting

### Daemon Won't Start

If the daemon fails to start, check:
1. Whether another instance is already running: `./monitor.py status`
2. The log file for error messages: `cat /tmp/url_monitor.log`
3. That the config file is valid: `cat config.yml`

### Stale PID File

If the status command shows a process that's not running, the PID file is stale. Simply run:
```bash
./monitor.py start
```

The daemon will automatically clean up stale PID files.

### Permissions Issues

If you encounter permission errors with the default log/PID locations in `/tmp`, you can specify alternative locations:
```bash
./monitor.py start --pid-file ~/url_monitor.pid --log-file ~/url_monitor.log
```

### Manual Cleanup

To manually remove the PID file:
```bash
rm /tmp/url_monitor.pid
```

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

GPLv3 ensures that this software and any derivative works remain free and open source.
