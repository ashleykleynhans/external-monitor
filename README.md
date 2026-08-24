# External Monitor

A Python-based URL monitoring tool that checks the health and SSL certificate validity of
configured endpoints at regular intervals and sends alerts to Alertmanager via webhooks.

## Features

- Monitor multiple URLs at configurable intervals (default: 2 minutes)
- SSL certificate validation
- HTTP status code checking with automatic redirect following
- False positive reduction - failures are confirmed across separate check cycles
  before alerting, so brief transient blips never page anyone
- DNS failure verification against public resolvers (DNS over HTTPS) to avoid
  alerting when the local network (not the target) is broken
- HTTP 429 responses treated as indeterminate rather than failures
- Per-URL configuration: expected status codes, custom headers, and timeouts
- Maintenance windows and a sentinel file to pause monitoring entirely
- Health check thresholds (default: 3 consecutive failing cycles before
  alerting, 2 successful cycles for recovery)
- Alert deduplication - alerts only sent on state changes (OK→FAIL, FAIL→OK)
- Resolved alerts sent automatically when URLs recover
- State persistence across daemon restarts (`/var/lib/external-monitor/state.json`)
- Alertmanager-compatible webhook notifications
- PagerDuty backup notifications (automatic failover when Alertmanager is down)
- Automatic severity classification (critical for 5xx/SSL errors, warning for 4xx)
- Hostname tracking to identify which server is performing the monitoring
- Daemon mode for running as a background service
- Graceful shutdown handling
- PID file management to prevent duplicate instances

## Requirements

- Python 3.8+
- See `requirements.txt` for Python dependencies

## Installation

1. Clone this repository
   ```bash
   mkdir -p /opt
   cd /opt
   git clone https://github.com/ashleykleynhans/external-monitor.git
   ```
2. Install dependencies:
   ```bash
   cd external-monitor
   python3 -m venv venv
   source venv/bin/activate
   pip3 install -r requirements.txt
   ```

3. Copy and configure the config file:
   ```bash
   cp config.yml.example config.yml
   ```

4. Edit `config.yml` with your URLs and Alertmanager webhook endpoint

## Configuration

Edit `config.yml` to specify:

- `webhook_url`: Your Alertmanager webhook URL (required)
- `pagerduty_integration_key`: Your PagerDuty Events API v2 integration key (optional - used as backup)
- `urls`: List of URLs to monitor. Each entry is either a plain URL string, or
  a mapping with per-URL settings:
  - `url` (required): the URL to check
  - `expected_status_codes`: HTTP status codes treated as healthy (default: `[200]`)
  - `headers`: extra HTTP headers, e.g. to get past a WAF or authenticate
  - `timeout`: per-URL timeout override in seconds

See `config.yml.example` for all available options, including false positive
reduction settings (`dns_verification`, `maintenance_windows`,
`maintenance_file`), thresholds, and cooldowns.

Example:
```yaml
webhook_url: "https://your-alertmanager.com/api/v1/alerts"
pagerduty_integration_key: "your-pagerduty-integration-key"  # Optional backup
urls:
  - "https://example.com"
  - url: "https://api.example.com/health"
    expected_status_codes: [200, 204]
    headers:
      Authorization: "Bearer your-token-here"
    timeout: 10
```

### PagerDuty Backup Notifications (Optional)

The monitor supports PagerDuty as a backup notification system. If the Alertmanager webhook is unreachable or returns an error, alerts will automatically be sent to PagerDuty instead.

To enable PagerDuty backup:
1. Create a service in PagerDuty
2. Add an "Events API v2" integration to your service
3. Copy the integration key
4. Add the key to `config.yml` as `pagerduty_integration_key`

When enabled, the monitor will:
- Try sending alerts to Alertmanager first
- If Alertmanager is down or returns an error (4xx/5xx), automatically failover to PagerDuty
- Send both "trigger" and "resolve" events to PagerDuty
- Use deduplication keys to ensure alerts are properly grouped

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

## Alertmanager Notifications

The monitoring system sends Alertmanager-compatible alerts when:
- A URL returns an HTTP status code outside its configured `expected_status_codes`
- SSL certificate validation fails
- Connection errors occur

### Alert Format

Alerts are sent in Alertmanager webhook format with:

**Labels:**
- `alertname`: "URLMonitorAlert"
- `severity`: "critical" (5xx/SSL errors) or "warning" (4xx errors)
- `url`: The failing URL
- `instance`: Hostname of the monitoring server
- `service`: "external-monitor"
- `status_code`: HTTP status code (when available)

**Annotations:**
- `summary`: Brief alert description
- `description`: Detailed error information

### Example Alert Payload

Alerts are sent to `{webhook_url}/{severity}` (e.g., `/alert/critical` or `/alert/warning`):

```json
{
  "alerts": [
    {
      "labels": {
        "alertname": "URLMonitorAlert",
        "severity": "critical",
        "url": "https://example.com",
        "instance": "monitor-server-1",
        "service": "external-monitor",
        "status_code": "500"
      },
      "annotations": {
        "summary": "URL Monitor Alert: https://example.com is down or unreachable",
        "description": "Internal Server Error"
      },
      "startsAt": "2025-10-28T10:30:00Z",
      "generatorURL": "http://monitor-server-1/external-monitor"
    }
  ]
}
```

This is sent as a POST request to the webhook URL with the severity appended (e.g., `https://your-webhook.com/alert/critical`).

### Alert State Management and Deduplication

The monitor implements intelligent alert deduplication to prevent alert fatigue:

**State Tracking:**
- The monitor maintains a persistent state file (`/var/lib/external-monitor/state.json`) that tracks the current status of each URL
- State persists across daemon restarts, ensuring consistent behavior
- When installed via the provided systemd unit, `StateDirectory=external-monitor` creates and owns this directory automatically

**Failure Confirmation (False Positive Reduction):**
- Each check cycle makes exactly one attempt per URL - there are no rapid in-cycle retries
- An alert fires only after `failure_threshold` consecutive failing *cycles* (default: 3), so brief transient blips never page anyone
- Recovery requires `recovery_threshold` consecutive successful cycles (default: 2)
- HTTP 429 (rate limited) responses are marked *indeterminate*: they count as neither success nor failure
- When local DNS resolution fails, the hostname is cross-checked against public DNS-over-HTTPS resolvers; if it resolves publicly, the failure is likely our own network and the check is marked indeterminate

**Maintenance Windows:**
- Configure `maintenance_windows` (time-of-day ranges, optionally filtered by weekday) to pause all checks and alerting during known change windows
- Overnight windows may wrap past midnight (e.g. `23:00` to `05:00`)
- Alternatively, create the `maintenance_file` to pause monitoring immediately (useful before deployments or maintenance); remove it to resume

**Alert Behavior:**
- **First Failure**: When a URL transitions from OK to FAIL (threshold reached), a "firing" alert is sent
- **Continued Failure**: If a URL remains down, no additional alerts are sent until the cooldown expires (prevents spam)
- **Recovery**: When a URL transitions from FAIL to OK, a "resolved" alert is sent automatically
- **Subsequent Checks**: Once recovered, the URL must fail again to trigger a new "firing" alert

**HTTP Redirect Handling:**
- The monitor automatically follows HTTP redirects (301, 302, etc.)
- The final status code after following redirects is evaluated against the configured `expected_status_codes`

**State File Location:**
- Default: `/var/lib/external-monitor/state.json`
- Contains URL status, severity level, and timestamp of first failure
- Automatically created and managed by the monitor

This ensures that:
1. You're notified immediately when a service goes down
2. You're not spammed with repeated alerts while it's down
3. You're notified when the service recovers
4. Alert history survives daemon restarts

### Upgrading from older versions

The state file moved from `/tmp/url_monitor_state.json` to `/var/lib/external-monitor/state.json` so state survives reboots and is not cleaned up by tmpfiles. When upgrading:

- With systemd, `StateDirectory=external-monitor` creates the directory automatically; for manual installs run:
  ```bash
  sudo mkdir -p /var/lib/external-monitor
  sudo chown monitor:monitor /var/lib/external-monitor
  ```
- Copy your old state file across to preserve alert cooldowns, or start fresh (worst case: one duplicate alert for a URL that is currently failing)
- The in-cycle retry settings (`retry_interval`) were removed; failures are now confirmed across separate check cycles instead

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
