# External Monitor

A Python-based URL monitoring tool that checks the health and SSL certificate validity of
configured endpoints at regular intervals and sends notifications to Discord via webhooks.

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

## Systemd Service Installation (Linux)

For production deployments on Linux systems with systemd, you can install the monitor as a system service.

### Installation Steps

1. **Create a dedicated user for the service:**
   ```bash
   sudo useradd -r -s /bin/false monitor
   ```

2. **Clone the repository to /opt:**
   ```bash
   cd /opt
   sudo git clone https://github.com/ashleykleynhans/external-monitor.git
   ```

3. **Create and configure the virtual environment:**
   ```bash
   cd /opt/external-monitor
   sudo python3 -m venv venv
   sudo venv/bin/pip install -r requirements.txt
   ```

4. **Configure the monitor:**
   ```bash
   sudo cp config.yml.example config.yml
   sudo nano config.yml  # Edit with your URLs and webhook
   ```

5. **Set proper ownership:**
   ```bash
   sudo chown -R monitor:monitor /opt/external-monitor
   ```

6. **Install and enable the systemd service:**
   ```bash
   sudo cp /opt/external-monitor/external-monitor.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable external-monitor
   sudo systemctl start external-monitor
   ```

### Managing the Systemd Service

Check service status:
```bash
sudo systemctl status external-monitor
```

Stop the service:
```bash
sudo systemctl stop external-monitor
```

Restart the service:
```bash
sudo systemctl restart external-monitor
```

View logs:
```bash
sudo journalctl -u external-monitor -f
```

View recent logs with timestamps:
```bash
sudo journalctl -u external-monitor -n 100 --no-pager
```

### Customizing the Service

If you need to customize the installation, edit `external-monitor.service` before copying it to `/etc/systemd/system/`:

- **User/Group**: Change `User=monitor` and `Group=monitor` to your preferred user
- **Installation Path**: Change `/opt/external-monitor` to your desired location
- **Config Location**: Modify the `--config` flag path
- **Virtual Environment**: Update the path to the venv Python binary

Example for custom installation path:
```ini
WorkingDirectory=/home/myuser/external-monitor
ExecStart=/home/myuser/external-monitor/venv/bin/python /home/myuser/external-monitor/monitor.py foreground --config /home/myuser/external-monitor/config.yml
```

After making changes, reload systemd:
```bash
sudo systemctl daemon-reload
sudo systemctl restart external-monitor
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

Run the test suite (coverage reports are automatically generated):

```bash
python3 -m pytest
```

The test configuration (`pytest.ini`) automatically includes:
- Verbose output
- Coverage measurement for `monitor.py`
- Terminal coverage report with missing lines
- HTML coverage report (opens `htmlcov/index.html` to view)
- Branch coverage analysis

View the HTML coverage report:
```bash
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
```

Run tests without coverage (faster):

```bash
python3 -m pytest --no-cov
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


## Community and Contributing

Pull requests and issues on [GitHub](https://github.com/ashleykleynhans/ipset)
are welcome. Bug fixes and new features are encouraged.

## Appreciate my work?

<a href="https://www.buymeacoffee.com/ashleyk" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 60px !important;width: 217px !important;" ></a>
