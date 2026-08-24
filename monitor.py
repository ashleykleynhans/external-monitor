#!/usr/bin/env python3
"""
URL Monitoring Script
Monitors configured URLs for availability and SSL certificate validity.
Sends notifications to Alertmanager via webhook on failures, with optional
PagerDuty backup.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import time
import socket
import requests
import yaml
import logging
import sys
import os
import signal
import argparse
import atexit
import json
import shutil
from datetime import datetime
from typing import List, Dict, Optional
from urllib.parse import urlparse
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Default configuration values
DEFAULT_CHECK_INTERVAL = 120  # Check interval in seconds (2 minutes)
DEFAULT_TIMEOUT = 30  # Request timeout
DEFAULT_FAILURE_THRESHOLD = 3  # Consecutive failing check cycles before alerting
DEFAULT_RECOVERY_THRESHOLD = 2  # Consecutive successful check cycles before resolving
DEFAULT_ALERT_COOLDOWN = 1800  # Cooldown period in seconds before re-alerting (30 minutes)
DEFAULT_SUPPRESS_RESOLVED = False  # Whether to suppress resolved alerts during flapping
DEFAULT_DNS_VERIFICATION = True  # Cross-check DNS failures against public resolvers
DEFAULT_DNS_RESOLVERS = [
    "https://1.1.1.1/dns-query",  # IP-based so it works even when local DNS is broken
    "https://dns.google/resolve"
]
DEFAULT_PID_FILE = "/tmp/url_monitor.pid"
DEFAULT_LOG_FILE = "/tmp/url_monitor.log"
DEFAULT_STATE_FILE = "/var/lib/external-monitor/state.json"

# Weekday names accepted in maintenance window day lists
DAY_NAMES = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}

# Global flag for graceful shutdown
shutdown_requested = False


def setup_logging(log_file: str = None, foreground: bool = False):
    """
    Configure logging to write to both console and file.

    Args:
        log_file: Path to log file. If None, only console logging is used.
        foreground: If True, logs to both console and file. If False, only to file.
    """
    # Remove existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # Set formatter
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    if foreground:
        # Add console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        console_handler.setLevel(logging.INFO)
        logger.addHandler(console_handler)

    if log_file:
        # Add file handler
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.INFO)
        logger.addHandler(file_handler)

    logger.setLevel(logging.INFO)


def signal_handler(signum, frame):
    """Handle shutdown signals gracefully."""
    global shutdown_requested
    logger.info(f"Received signal {signum}, initiating graceful shutdown...")
    shutdown_requested = True


def write_pid_file(pid_file: str):
    """Write the process ID to a PID file."""
    pid = os.getpid()
    try:
        with open(pid_file, 'w') as f:
            f.write(str(pid))
        logger.info(f"PID {pid} written to {pid_file}")
    except Exception as e:
        logger.error(f"Failed to write PID file: {e}")
        raise


def remove_pid_file(pid_file: str):
    """Remove the PID file."""
    try:
        if os.path.exists(pid_file):
            os.remove(pid_file)
            logger.info(f"Removed PID file {pid_file}")
    except Exception as e:
        logger.error(f"Failed to remove PID file: {e}")


def read_pid_file(pid_file: str) -> Optional[int]:
    """Read the PID from the PID file."""
    try:
        if os.path.exists(pid_file):
            with open(pid_file, 'r') as f:
                return int(f.read().strip())
    except Exception as e:
        logger.error(f"Failed to read PID file: {e}")
    return None


def is_process_running(pid: int) -> bool:
    """Check if a process with the given PID is running."""
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def daemonize(pid_file: str, log_file: str):  # pragma: no cover
    """
    Daemonize the current process using double-fork method.
    """
    # Check if daemon is already running
    pid = read_pid_file(pid_file)
    if pid and is_process_running(pid):
        logger.error(f"Daemon is already running with PID {pid}")
        sys.exit(1)

    # First fork
    try:
        pid = os.fork()
        if pid > 0:
            # Parent process, exit
            sys.exit(0)
    except OSError as e:
        logger.error(f"First fork failed: {e}")
        sys.exit(1)

    # Decouple from parent environment
    os.chdir('/')
    os.setsid()
    os.umask(0)

    # Second fork
    try:
        pid = os.fork()
        if pid > 0:
            # Parent process, exit
            sys.exit(0)
    except OSError as e:
        logger.error(f"Second fork failed: {e}")
        sys.exit(1)

    # Redirect standard file descriptors
    sys.stdout.flush()
    sys.stderr.flush()

    # Reopen stdin, stdout, stderr
    si = open(os.devnull, 'r')
    so = open(log_file, 'a+')
    se = open(log_file, 'a+')

    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())

    # Reconfigure logging to use file handler
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(file_handler)
    logger.setLevel(logging.INFO)

    # Write PID file
    write_pid_file(pid_file)

    # Register cleanup function
    atexit.register(remove_pid_file, pid_file)

    logger.info("Daemon started successfully")


class URLMonitor:
    """Monitor URLs for availability and SSL certificate validity."""

    def __init__(self, config_path: str = "config.yml", state_file: str = None):
        """Initialize the monitor with configuration."""
        self.config = self._load_config(config_path)
        self.webhook_url = self.config.get("webhook_url")
        self.pagerduty_key = self.config.get("pagerduty_integration_key")
        self.urls = self.config.get("urls", [])
        self.hostname = socket.gethostname()

        # Load configurable values with defaults
        self.check_interval = self.config.get("check_interval", DEFAULT_CHECK_INTERVAL)
        self.timeout = self.config.get("timeout", DEFAULT_TIMEOUT)
        self.failure_threshold = self.config.get("failure_threshold", DEFAULT_FAILURE_THRESHOLD)
        self.recovery_threshold = self.config.get("recovery_threshold", DEFAULT_RECOVERY_THRESHOLD)
        self.alert_cooldown = self.config.get("alert_cooldown", DEFAULT_ALERT_COOLDOWN)
        self.suppress_resolved = self.config.get("suppress_resolved", DEFAULT_SUPPRESS_RESOLVED)

        # False positive reduction settings
        self.dns_verification = self.config.get("dns_verification", DEFAULT_DNS_VERIFICATION)
        self.dns_resolvers = self.config.get("dns_resolvers", DEFAULT_DNS_RESOLVERS)
        self.maintenance_windows = self._parse_maintenance_windows(self.config.get("maintenance_windows", []))
        self.maintenance_file = self.config.get("maintenance_file")
        self._maintenance_active = False

        # Use state_file parameter if provided, otherwise use config, otherwise use default
        self.state_file = state_file if state_file is not None else self.config.get("state_file", DEFAULT_STATE_FILE)
        self.state = self._load_state()

        # Normalize URLs so each entry carries its own check settings
        self.url_configs = [self._normalize_entry(entry) for entry in self.urls]

        # Prometheus textfile configuration
        self.prometheus_textfile_dir = self.config.get("prometheus_textfile_dir")

        if not self.webhook_url:
            raise ValueError("webhook_url is required in config.yml")
        if not self.urls:
            raise ValueError("At least one URL is required in config.yml")

        logger.info(f"Initialized monitor on host: {self.hostname}")
        logger.info(f"Monitoring {len(self.urls)} URL(s)")
        logger.info(f"Check interval: {self.check_interval}s, Timeout: {self.timeout}s")
        logger.info(
            f"Thresholds - Failure: {self.failure_threshold} consecutive cycles, "
            f"Recovery: {self.recovery_threshold} consecutive cycles"
        )
        logger.info(f"Alert cooldown: {self.alert_cooldown}s, Suppress resolved alerts: {self.suppress_resolved}")
        logger.info(f"DNS verification for failed resolutions: {'enabled' if self.dns_verification else 'disabled'}")
        if self.maintenance_windows:
            logger.info(f"Maintenance windows configured: {len(self.maintenance_windows)}")
        if self.maintenance_file:
            logger.info(f"Maintenance sentinel file: {self.maintenance_file}")
        if self.pagerduty_key:
            logger.info("PagerDuty backup notifications enabled")
        if self.prometheus_textfile_dir:
            logger.info(f"Prometheus textfile exporter enabled: {self.prometheus_textfile_dir}")

    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from YAML file."""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logger.error(f"Config file not found: {config_path}")
            raise
        except yaml.YAMLError as e:
            logger.error(f"Error parsing config file: {e}")
            raise

    def _normalize_entry(self, entry) -> Dict:
        """
        Normalize a URL config entry (plain string or mapping) into a dict
        carrying per-URL check settings.
        """
        if isinstance(entry, str):
            return {
                "url": entry,
                "expected_status_codes": [200],
                "headers": {},
                "timeout": None,
            }
        if isinstance(entry, dict):
            url = entry.get("url")
            if not url:
                raise ValueError(f"URL entry is missing the 'url' key: {entry}")
            codes = entry.get("expected_status_codes", [200])
            if isinstance(codes, int):
                codes = [codes]
            timeout = entry.get("timeout")
            return {
                "url": url,
                "expected_status_codes": list(codes),
                "headers": dict(entry.get("headers", {})),
                "timeout": float(timeout) if timeout else None,
            }
        raise ValueError(f"Invalid URL entry (must be a string or mapping): {entry}")

    @staticmethod
    def _parse_window_days(days) -> Optional[set]:
        """Parse day specifiers (ints 0-6 or names like 'mon') into weekday ints."""
        if days is None:
            return None
        parsed = set()
        for day in days:
            if isinstance(day, int):
                if not 0 <= day <= 6:
                    raise ValueError(f"Day index out of range (0-6): {day}")
                parsed.add(day)
            else:
                name = str(day).strip().lower()[:3]
                if name not in DAY_NAMES:
                    raise ValueError(f"Unknown day name: {day}")
                parsed.add(DAY_NAMES[name])
        return parsed

    def _parse_maintenance_windows(self, windows: List[Dict]) -> List[Dict]:
        """Parse and validate maintenance window definitions from config."""
        parsed = []
        for i, window in enumerate(windows):
            try:
                start_h, start_m = str(window["start"]).split(":")
                end_h, end_m = str(window["end"]).split(":")
                days = self._parse_window_days(window.get("days"))
                parsed.append({
                    "start": int(start_h) * 60 + int(start_m),
                    "end": int(end_h) * 60 + int(end_m),
                    "days": days
                })
            except (KeyError, ValueError, AttributeError) as e:
                raise ValueError(f"Invalid maintenance window #{i + 1} ({window}): {e}")
        return parsed

    def _in_maintenance(self, now: datetime = None) -> bool:
        """Check whether monitoring is paused by the sentinel file or a window."""
        if self.maintenance_file and os.path.exists(self.maintenance_file):
            return True

        now = now or datetime.now()
        current_minutes = now.hour * 60 + now.minute
        for window in self.maintenance_windows:
            if window["days"] is not None and now.weekday() not in window["days"]:
                continue
            if window["start"] <= window["end"]:
                if window["start"] <= current_minutes < window["end"]:
                    return True
            elif current_minutes >= window["start"] or current_minutes < window["end"]:
                # Overnight window (e.g. 23:00-04:00) wraps past midnight
                return True
        return False

    def _load_state(self) -> Dict:
        """Load state from JSON file."""
        try:
            with open(self.state_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.info("No existing state file found, starting fresh")
            return {}
        except json.JSONDecodeError as e:
            logger.warning(f"Invalid state file, starting fresh: {e}")
            return {}
        except Exception as e:
            logger.warning(f"Error loading state file, starting fresh: {e}")
            return {}

    def _save_state(self):
        """Save state to JSON file."""
        try:
            parent_dir = os.path.dirname(self.state_file)
            if parent_dir:
                os.makedirs(parent_dir, exist_ok=True)
            with open(self.state_file, 'w') as f:
                json.dump(self.state, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save state: {e}")

    def _write_prometheus_metrics(self):
        """Write metrics to Prometheus textfile format."""
        if not self.prometheus_textfile_dir:
            return

        try:
            # Create directory if it doesn't exist
            os.makedirs(self.prometheus_textfile_dir, exist_ok=True)

            # Write to /tmp first (always writable), then move atomically
            textfile_path = os.path.join(self.prometheus_textfile_dir, "url_monitor.prom")
            temp_file_path = f"/tmp/url_monitor_{os.getpid()}.prom.tmp"

            with open(temp_file_path, 'w') as f:
                # Write metrics header
                f.write("# HELP url_monitor_up Whether the URL is responding successfully (1 = up, 0 = down)\n")
                f.write("# TYPE url_monitor_up gauge\n")

                f.write("# HELP url_monitor_response_time_seconds HTTP response time in seconds\n")
                f.write("# TYPE url_monitor_response_time_seconds gauge\n")

                f.write("# HELP url_monitor_status_code HTTP status code returned\n")
                f.write("# TYPE url_monitor_status_code gauge\n")

                f.write("# HELP url_monitor_consecutive_failures Number of consecutive failures\n")
                f.write("# TYPE url_monitor_consecutive_failures gauge\n")

                # Write metrics for each URL
                for url in self.urls:
                    # Sanitize URL for label
                    url_label = url.replace('"', '\\"')

                    # Get state for this URL
                    url_state = self.state.get(url, {})
                    is_up = 0 if url_state.get("alerted", False) else 1
                    consecutive_failures = url_state.get("consecutive_failures", 0)

                    # Write up metric
                    f.write(f'url_monitor_up{{url="{url_label}",instance="{self.hostname}"}} {is_up}\n')

                    # Write consecutive failures metric
                    f.write(f'url_monitor_consecutive_failures{{url="{url_label}",instance="{self.hostname}"}} {consecutive_failures}\n')

            # Move the temp file to the final location (handles cross-filesystem moves)
            try:
                shutil.move(temp_file_path, textfile_path)
                logger.debug(f"Wrote Prometheus metrics to {textfile_path}")
            except Exception as e:
                # Clean up temp file if move failed
                try:
                    os.unlink(temp_file_path)
                except:
                    pass
                raise

        except Exception as e:
            logger.error(f"Failed to write Prometheus metrics: {e}")
            if "Permission denied" in str(e) or "Read-only file system" in str(e):
                logger.error(f"Please ensure {self.prometheus_textfile_dir} is writable by this process")

    @staticmethod
    def _is_dns_error(exception: Exception) -> bool:
        """Detect whether an exception was caused by a DNS resolution failure."""
        reason = getattr(exception, "reason", None)
        if isinstance(reason, socket.gaierror):
            return True
        markers = (
            "getaddrinfo",
            "name or service not known",
            "nodename nor servname",
            "temporary failure in name resolution",
            "no address associated with hostname",
        )
        message = str(reason or exception).lower()
        return any(marker in message for marker in markers)

    def _verify_dns_globally(self, hostname: str) -> Optional[bool]:
        """
        Cross-check DNS resolution against public resolvers (DNS over HTTPS).

        Returns True if any resolver confirms the hostname resolves,
        False if at least one reachable resolver says it does not exist,
        None if no resolver could be reached.
        """
        resolver_reachable = False
        for resolver in self.dns_resolvers:
            try:
                response = requests.get(
                    resolver,
                    params={"name": hostname, "type": "A"},
                    headers={"accept": "application/dns-json"},
                    timeout=10
                )
                if response.status_code != 200:
                    continue
                data = response.json()
                if data.get("Status") == 0 and data.get("Answer"):
                    return True
                # Resolver answered but reported no records for the name
                resolver_reachable = True
            except Exception as e:
                logger.debug(f"DNS verification via {resolver} failed: {e}")
        return False if resolver_reachable else None

    def check_url(self, url_config) -> Dict:
        """
        Check a URL for availability.
        Accepts either a plain URL string or a normalized config entry dict.
        Follows redirects automatically and reports the final status code.
        SSL validation is performed by requests library for all URLs in redirect chain.

        Results are classified so that conditions which are ambiguous
        (rate limiting, DNS failures contradicted by public resolvers) are
        marked "indeterminate" instead of counting as failures.

        Returns a dict with status and error information.
        """
        cfg = self._normalize_entry(url_config)
        url = cfg["url"]

        result = {
            "url": url,
            "success": True,
            "status_code": None,
            "error": None,
            "ssl_error": None,
            "error_class": None,
            "indeterminate": False,
            "retry_after": None
        }

        # Check HTTP response (SSL validation handled by requests library)
        try:
            headers = {
                'User-Agent': 'External Monitoring Tool; ExternalMonitor/v0.0.1; +https://github.com/ashleykleynhans/external-monitor'
            }
            headers.update(cfg["headers"])
            response = requests.get(
                url,
                timeout=cfg["timeout"] or self.timeout,
                verify=True,
                allow_redirects=True,
                headers=headers
            )
            result["status_code"] = response.status_code

            retry_after = response.headers.get("Retry-After")
            if isinstance(retry_after, str) and retry_after:
                result["retry_after"] = retry_after

            if response.status_code == 429:
                # Rate limited by the target: neither up nor down. Counting it
                # as failure would page on our own monitoring frequency.
                result["success"] = False
                result["indeterminate"] = True
                result["error_class"] = "rate_limited"
                retry_after = ", Retry-After: " + str(result["retry_after"]) if result["retry_after"] else ""
                result["error"] = f"HTTP 429 (rate limited{retry_after})"
            elif response.status_code not in cfg["expected_status_codes"]:
                result["success"] = False
                result["error_class"] = "http"
                result["error"] = f"HTTP {response.status_code}"

        except requests.exceptions.SSLError as e:
            result["success"] = False
            result["ssl_error"] = f"SSL Error: {str(e)}"
            result["error"] = f"SSL connection error: {str(e)}"
            result["error_class"] = "ssl"
        except requests.exceptions.ConnectionError as e:
            result["success"] = False
            result["error"] = f"Connection error: {str(e)}"
            if self._is_dns_error(e):
                result["error_class"] = "dns"
                # A local resolution failure often means OUR network is broken,
                # not the target. Cross-check against public resolvers before
                # letting it count toward an alert.
                if self.dns_verification:
                    hostname = urlparse(url).hostname
                    confirmed = self._verify_dns_globally(hostname)
                    if confirmed:
                        logger.warning(
                            f"DNS for {hostname} resolves via public resolvers but failed locally; "
                            "marking check indeterminate (likely local network issue)"
                        )
                        result["indeterminate"] = True
            else:
                result["error_class"] = "connection"
        except requests.exceptions.Timeout:
            result["success"] = False
            result["error"] = "Request timeout"
            result["error_class"] = "timeout"
        except Exception as e:
            result["success"] = False
            result["error"] = f"Unexpected error: {str(e)}"
            result["error_class"] = "unexpected"

        return result

    @staticmethod
    def _classify_severity(error_details: Dict) -> str:
        """Map an error to an alert severity (critical for 5xx/SSL, warning for 4xx)."""
        if error_details.get("ssl_error"):
            return "critical"
        status_code = error_details.get("status_code")
        if status_code and status_code >= 500:
            return "critical"
        if status_code and status_code >= 400:
            return "warning"
        return "critical"

    @staticmethod
    def _build_description(error_details: Dict) -> str:
        """Build a combined description from error details."""
        parts = []
        if error_details.get("error"):
            parts.append(error_details["error"])
        if error_details.get("ssl_error"):
            parts.append(f"SSL: {error_details['ssl_error']}")
        return " | ".join(parts) if parts else "URL is unreachable"

    def send_pagerduty_alert(self, url: str, error_details: Dict, severity: str, status: str = "firing"):
        """Send alert to PagerDuty Events API v2 as backup."""
        if not self.pagerduty_key:
            logger.warning("PagerDuty integration key not configured, skipping backup notification")
            return False

        pagerduty_url = "https://events.pagerduty.com/v2/enqueue"

        description = self._build_description(error_details)

        # Determine event action based on status
        event_action = "resolve" if status == "resolved" else "trigger"

        # Build PagerDuty Events API v2 payload
        payload = {
            "routing_key": self.pagerduty_key,
            "event_action": event_action,
            "dedup_key": f"external-monitor-{url}",
            "payload": {
                "summary": f"URL Monitor: {url} is {'recovered' if status == 'resolved' else 'down'}",
                "source": self.hostname,
                "severity": severity,
                "custom_details": {
                    "url": url,
                    "error": error_details.get("error", ""),
                    "ssl_error": error_details.get("ssl_error", ""),
                    "status_code": error_details.get("status_code", ""),
                    "service": "external-monitor"
                }
            }
        }

        try:
            logger.info(f"Sending PagerDuty backup notification for {url}")
            response = requests.post(
                pagerduty_url,
                json=payload,
                timeout=self.timeout,
                headers={"Content-Type": "application/json"}
            )
            if response.status_code == 202:
                logger.info(f"PagerDuty backup notification sent successfully for {url}")
                return True
            else:
                logger.error(f"PagerDuty API error: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            logger.error(f"Error sending PagerDuty notification: {e}")
            return False

    def send_discord_notification(self, url: str, error_details: Dict, status: str = "firing"):
        """Send notification to Alertmanager via webhook."""
        from datetime import datetime, timezone

        if status == "resolved":
            # For resolved alerts, send simpler payload
            severity = self.state.get(url, {}).get("severity", "critical")
            alert = {
                "status": "resolved",
                "labels": {
                    "alertname": "URLMonitorAlert",
                    "severity": severity,
                    "url": url,
                    "instance": self.hostname,
                    "service": "external-monitor",
                    "environment": "prod"
                },
                "annotations": {
                    "summary": f"URL Monitor Alert: {url} is now accessible",
                    "description": "URL has recovered and is now responding normally"
                },
                "endsAt": datetime.now(timezone.utc).isoformat(),
                "generatorURL": f"http://{self.hostname}/external-monitor"
            }
        else:
            # Build alert description for firing alerts
            description = self._build_description(error_details)

            # Determine severity based on error type
            severity = self._classify_severity(error_details)

            # Build Alertmanager-compatible payload
            alert = {
                "status": "firing",
                "labels": {
                    "alertname": "URLMonitorAlert",
                    "severity": severity,
                    "url": url,
                    "instance": self.hostname,
                    "service": "external-monitor",
                    "environment": "prod"
                },
                "annotations": {
                    "summary": f"URL Monitor Alert: {url} is down or unreachable",
                    "description": description
                },
                "startsAt": datetime.now(timezone.utc).isoformat(),
                "generatorURL": f"http://{self.hostname}/external-monitor"
            }

            # Add status code to labels if available
            if error_details.get("status_code"):
                alert["labels"]["status_code"] = str(error_details["status_code"])

        # Wrap alerts in payload object (Alertmanager webhook format)
        payload = {
            "alerts": [alert]
        }

        # Append severity to webhook URL (e.g., /alert/critical or /alert/warning)
        webhook_url = f"{self.webhook_url.rstrip('/')}/{severity}"

        try:
            logger.debug(f"Sending webhook payload to {webhook_url}: {payload}")
            response = requests.post(
                webhook_url,
                json=payload,
                timeout=self.timeout
            )
            logger.debug(f"Webhook response status: {response.status_code}")
            if response.status_code in (200, 204):
                logger.info(f"Notification sent for {url}")
            else:
                logger.error(
                    f"Failed to send notification: {response.status_code} - {response.text}"
                )
                # Try PagerDuty as backup if primary failed
                if self.pagerduty_key:
                    logger.warning(f"Alertmanager returned {response.status_code}, attempting PagerDuty backup")
                    self.send_pagerduty_alert(url, error_details, severity, status)
        except Exception as e:
            logger.error(f"Error sending notification to Alertmanager: {e}")
            # Try PagerDuty as backup if primary failed with exception
            if self.pagerduty_key:
                logger.warning("Alertmanager unavailable, attempting PagerDuty backup")
                self.send_pagerduty_alert(url, error_details, severity, status)

    def monitor_once(self):
        """
        Perform one monitoring check of all URLs.

        Each check cycle makes exactly one attempt per URL. Failures are
        confirmed across separate cycles (consecutive_failures counts failing
        cycles, not retries), so brief transient blips cannot trigger alerts.
        """
        if self._in_maintenance():
            if not self._maintenance_active:
                logger.info("Maintenance active, skipping monitoring checks")
                self._maintenance_active = True
            return

        if self._maintenance_active:
            logger.info("Maintenance ended, resuming monitoring checks")
            self._maintenance_active = False

        logger.info("Starting monitoring check...")

        for cfg in self.url_configs:
            url = cfg["url"]
            # Get previous state
            previous_state = self.state.get(url, {})
            consecutive_failures = previous_state.get("consecutive_failures", 0)
            consecutive_successes = previous_state.get("consecutive_successes", 0)
            is_alerted = previous_state.get("alerted", False)
            last_alert_time = previous_state.get("last_alert_time")

            # Single attempt per URL per cycle: failures are confirmed across
            # cycles rather than with rapid in-cycle retries.
            result = self.check_url(cfg)

            if result.get("indeterminate"):
                logger.warning(
                    f"INDETERMINATE: {url} - {result.get('error', 'Unknown error')}; "
                    "not counting toward failure or success thresholds"
                )
                # Preserve counters unchanged so ambiguous conditions (rate
                # limiting, suspected local network issues) cannot page anyone
                self.state[url] = {
                    "consecutive_failures": previous_state.get("consecutive_failures", 0),
                    "consecutive_successes": previous_state.get("consecutive_successes", 0),
                    "alerted": is_alerted,
                    "severity": previous_state.get("severity", "critical"),
                    "first_failure": previous_state.get("first_failure"),
                    "last_alert_time": last_alert_time
                }
                continue

            if result["success"]:
                logger.info(f"OK: {url} (HTTP {result['status_code']})")

                # Reset failure counter, increment success counter
                consecutive_failures = 0
                consecutive_successes += 1

                # Check if we should send a resolved alert
                if is_alerted and consecutive_successes >= self.recovery_threshold:
                    logger.info(f"URL recovered after {consecutive_successes} successful checks: {url}")
                    # Send resolved alert unless suppression is enabled
                    if not self.suppress_resolved:
                        self.send_discord_notification(url, {}, status="resolved")
                    else:
                        logger.info(f"Resolved alert suppressed for {url} (suppress_resolved=True)")
                    # Mark as no longer alerted
                    self.state[url] = {
                        "consecutive_failures": 0,
                        "consecutive_successes": consecutive_successes,
                        "alerted": False,
                        "last_alert_time": last_alert_time  # Preserve for cooldown
                    }
                elif is_alerted:
                    logger.info(f"URL passing ({consecutive_successes}/{self.recovery_threshold} needed for recovery): {url}")
                    self.state[url] = {
                        "consecutive_failures": 0,
                        "consecutive_successes": consecutive_successes,
                        "alerted": True,
                        "severity": previous_state.get("severity", "critical"),
                        "last_alert_time": last_alert_time
                    }
                else:
                    # Just update state without alert
                    self.state[url] = {
                        "consecutive_failures": 0,
                        "consecutive_successes": consecutive_successes,
                        "alerted": False,
                        "last_alert_time": last_alert_time
                    }
            else:
                logger.warning(f"FAIL: {url} - {result.get('error', 'Unknown error')}")

                # Reset success counter, count this failing cycle
                consecutive_successes = 0
                consecutive_failures += 1

                severity = self._classify_severity(result)

                # Alert once the failure threshold of consecutive cycles is reached,
                # provided we are not already alerted and the cooldown has elapsed
                should_alert = False
                current_time = datetime.now()

                if consecutive_failures >= self.failure_threshold and not is_alerted:
                    if last_alert_time:
                        last_alert_dt = datetime.fromisoformat(last_alert_time.replace('Z', '+00:00'))
                        time_since_alert = (current_time - last_alert_dt).total_seconds()

                        if time_since_alert >= self.alert_cooldown:
                            should_alert = True
                            logger.info(f"Cooldown period elapsed ({time_since_alert:.0f}s >= {self.alert_cooldown}s), will send alert")
                        else:
                            remaining = self.alert_cooldown - time_since_alert
                            logger.info(f"URL failing but still in cooldown period ({remaining:.0f}s remaining): {url}")
                    else:
                        # No previous alert, send immediately
                        should_alert = True
                elif consecutive_failures < self.failure_threshold:
                    logger.info(
                        f"{consecutive_failures}/{self.failure_threshold} failing checks toward alert threshold: {url}"
                    )

                if should_alert:
                    logger.warning(f"URL failed {consecutive_failures} consecutive check cycles, sending alert: {url}")
                    self.send_discord_notification(url, result, status="firing")
                    self.state[url] = {
                        "consecutive_failures": consecutive_failures,
                        "consecutive_successes": 0,
                        "alerted": True,
                        "severity": severity,
                        "first_failure": current_time.isoformat(),
                        "last_alert_time": current_time.isoformat()
                    }
                else:
                    # Below threshold, already alerted, or in cooldown; track state
                    if is_alerted:
                        logger.debug(f"URL still failing (already alerted): {url}")
                    self.state[url] = {
                        "consecutive_failures": consecutive_failures,
                        "consecutive_successes": 0,
                        "alerted": is_alerted,
                        "severity": severity,
                        "first_failure": previous_state.get("first_failure", current_time.isoformat()),
                        "last_alert_time": last_alert_time
                    }

        # Save state after processing all URLs
        self._save_state()

        # Write Prometheus metrics if configured
        self._write_prometheus_metrics()

    def run(self, daemon_mode: bool = True):
        """Run the monitoring loop continuously."""
        global shutdown_requested

        # Set up signal handlers
        signal.signal(signal.SIGTERM, signal_handler)
        # Only override SIGINT in daemon mode; let KeyboardInterrupt work in foreground
        if daemon_mode:
            signal.signal(signal.SIGINT, signal_handler)

        logger.info(f"Starting monitoring loop (check every {self.check_interval}s)...")

        while not shutdown_requested:
            try:
                self.monitor_once()
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")

            # Sleep in small increments to allow for responsive shutdown
            for _ in range(self.check_interval):
                if shutdown_requested:
                    break
                time.sleep(1)

        logger.info("Monitoring loop stopped gracefully")


def stop_daemon(pid_file: str):
    """Stop the daemon process."""
    pid = read_pid_file(pid_file)
    if not pid:
        print("No PID file found. Daemon may not be running.")
        return False

    if not is_process_running(pid):
        print(f"Process {pid} is not running. Cleaning up PID file.")
        remove_pid_file(pid_file)
        return False

    # Send SIGTERM to gracefully shut down
    try:
        print(f"Stopping daemon with PID {pid}...")
        os.kill(pid, signal.SIGTERM)

        # Wait for process to terminate
        for _ in range(30):  # Wait up to 30 seconds
            if not is_process_running(pid):
                print("Daemon stopped successfully.")
                remove_pid_file(pid_file)
                return True
            time.sleep(1)

        # If still running, force kill
        print("Daemon did not stop gracefully, forcing shutdown...")
        os.kill(pid, signal.SIGKILL)
        time.sleep(1)
        remove_pid_file(pid_file)
        print("Daemon stopped forcefully.")
        return True

    except Exception as e:
        print(f"Error stopping daemon: {e}")
        return False


def status_daemon(pid_file: str):
    """Check the status of the daemon."""
    pid = read_pid_file(pid_file)
    if not pid:
        print("Daemon is not running (no PID file found).")
        return False

    if is_process_running(pid):
        print(f"Daemon is running with PID {pid}.")
        return True
    else:
        print(f"PID file exists but process {pid} is not running.")
        remove_pid_file(pid_file)
        return False


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='URL Monitor Daemon')
    parser.add_argument(
        'command',
        choices=['start', 'stop', 'restart', 'status', 'foreground'],
        help='Command to execute'
    )
    parser.add_argument(
        '--config',
        default='config.yml',
        help='Path to configuration file (default: config.yml)'
    )
    parser.add_argument(
        '--pid-file',
        default=None,
        help=f'Path to PID file (default: value from config or {DEFAULT_PID_FILE})'
    )
    parser.add_argument(
        '--log-file',
        default=None,
        help=f'Path to log file (default: value from config or {DEFAULT_LOG_FILE})'
    )

    args = parser.parse_args()

    # Convert config path to absolute path before daemonizing
    # (daemon changes working directory to /)
    args.config = os.path.abspath(args.config)

    # Load config to get pid_file and log_file if not specified via command line
    try:
        with open(args.config, 'r') as f:
            config = yaml.safe_load(f)
    except Exception as e:
        print(f"Error loading config file: {e}")
        sys.exit(1)

    # Use command line args if provided, otherwise use config values, otherwise use defaults
    pid_file = args.pid_file if args.pid_file is not None else config.get('pid_file', DEFAULT_PID_FILE)
    log_file = args.log_file if args.log_file is not None else config.get('log_file', DEFAULT_LOG_FILE)

    if args.command == 'start':
        print("Starting daemon...")
        daemonize(pid_file, log_file)
        try:
            monitor = URLMonitor(args.config)
            monitor.run()
        except Exception as e:
            logger.error(f"Fatal error: {e}")
            raise

    elif args.command == 'stop':
        stop_daemon(pid_file)

    elif args.command == 'restart':
        print("Restarting daemon...")
        stop_daemon(pid_file)
        time.sleep(2)
        print("Starting daemon...")
        daemonize(pid_file, log_file)
        try:
            monitor = URLMonitor(args.config)
            monitor.run()
        except Exception as e:
            logger.error(f"Fatal error: {e}")
            raise

    elif args.command == 'status':
        status_daemon(pid_file)

    elif args.command == 'foreground':
        print("Running in foreground mode (Ctrl+C to stop)...")
        # Setup logging to write to both console and file
        setup_logging(log_file=log_file, foreground=True)
        try:
            monitor = URLMonitor(args.config)
            monitor.run(daemon_mode=False)
        except KeyboardInterrupt:
            logger.info("Monitoring stopped by user")
        except Exception as e:
            logger.error(f"Fatal error: {e}")
            raise
    else:  # pragma: no cover
        # This should never happen due to argparse choices constraint
        pass


if __name__ == "__main__":
    main()
