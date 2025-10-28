#!/usr/bin/env python3
"""
URL Monitoring Script
Monitors configured URLs for availability and SSL certificate validity.
Sends notifications to Discord via webhook on failures.

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
import ssl
import requests
import yaml
import logging
import sys
import os
import signal
import argparse
import atexit
import json
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

# Check interval in seconds (2 minutes)
CHECK_INTERVAL = 120

# Daemon configuration
PID_FILE = "/tmp/url_monitor.pid"
LOG_FILE = "/tmp/url_monitor.log"
STATE_FILE = "/tmp/url_monitor_state.json"

# Global flag for graceful shutdown
shutdown_requested = False


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

    def __init__(self, config_path: str = "config.yml", state_file: str = STATE_FILE):
        """Initialize the monitor with configuration."""
        self.config = self._load_config(config_path)
        self.webhook_url = self.config.get("webhook_url")
        self.urls = self.config.get("urls", [])
        self.hostname = socket.gethostname()
        self.state_file = state_file
        self.state = self._load_state()

        if not self.webhook_url:
            raise ValueError("webhook_url is required in config.yml")
        if not self.urls:
            raise ValueError("At least one URL is required in config.yml")

        logger.info(f"Initialized monitor on host: {self.hostname}")
        logger.info(f"Monitoring {len(self.urls)} URL(s)")

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
            with open(self.state_file, 'w') as f:
                json.dump(self.state, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save state: {e}")

    def check_ssl_certificate(self, hostname: str, port: int = 443) -> Optional[str]:
        """
        Check SSL certificate validity.
        Returns error message if invalid, None if valid.
        """
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    # Certificate is valid if we get here
                    return None
        except ssl.SSLError as e:
            return f"SSL Error: {str(e)}"
        except socket.timeout:
            return "SSL check timeout"
        except Exception as e:
            return f"SSL check failed: {str(e)}"

    def check_url(self, url: str) -> Dict:
        """
        Check a URL for availability and SSL validity.
        Returns a dict with status and error information.
        """
        result = {
            "url": url,
            "success": True,
            "status_code": None,
            "error": None,
            "ssl_error": None
        }

        parsed_url = urlparse(url)

        # Check SSL certificate if HTTPS
        if parsed_url.scheme == "https":
            ssl_error = self.check_ssl_certificate(parsed_url.hostname)
            if ssl_error:
                result["success"] = False
                result["ssl_error"] = ssl_error

        # Check HTTP response
        try:
            response = requests.get(url, timeout=10, verify=True)
            result["status_code"] = response.status_code

            if response.status_code != 200:
                result["success"] = False
                result["error"] = f"HTTP {response.status_code}"

        except requests.exceptions.SSLError as e:
            result["success"] = False
            result["error"] = f"SSL connection error: {str(e)}"
        except requests.exceptions.ConnectionError as e:
            result["success"] = False
            result["error"] = f"Connection error: {str(e)}"
        except requests.exceptions.Timeout:
            result["success"] = False
            result["error"] = "Request timeout"
        except Exception as e:
            result["success"] = False
            result["error"] = f"Unexpected error: {str(e)}"

        return result

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
            description_parts = []
            if error_details.get("error"):
                description_parts.append(error_details['error'])
            if error_details.get("ssl_error"):
                description_parts.append(f"SSL: {error_details['ssl_error']}")

            description = " | ".join(description_parts) if description_parts else "URL is unreachable"

            # Determine severity based on error type
            severity = "critical"
            if error_details.get("ssl_error"):
                severity = "critical"
            elif error_details.get("status_code") and error_details["status_code"] >= 500:
                severity = "critical"
            elif error_details.get("status_code") and error_details["status_code"] >= 400:
                severity = "warning"

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
                timeout=10
            )
            logger.debug(f"Webhook response status: {response.status_code}")
            if response.status_code in (200, 204):
                logger.info(f"Notification sent for {url}")
            else:
                logger.error(
                    f"Failed to send notification: {response.status_code} - {response.text}"
                )
        except Exception as e:
            logger.error(f"Error sending notification: {e}")

    def monitor_once(self):
        """Perform one monitoring check of all URLs."""
        logger.info("Starting monitoring check...")

        for url in self.urls:
            result = self.check_url(url)
            previous_state = self.state.get(url, {})
            was_failing = previous_state.get("failing", False)

            if result["success"]:
                logger.info(f"OK: {url} (HTTP {result['status_code']})")

                # If it was failing before, send a resolved alert
                if was_failing:
                    logger.info(f"URL recovered: {url}")
                    self.send_discord_notification(url, {}, status="resolved")
                    # Remove from state or mark as not failing
                    self.state[url] = {"failing": False}
            else:
                logger.warning(f"FAIL: {url}")

                # Only send alert if this is a new failure (state change)
                if not was_failing:
                    logger.info(f"New failure detected: {url}")

                    # Determine severity for state tracking
                    severity = "critical"
                    if result.get("ssl_error"):
                        severity = "critical"
                    elif result.get("status_code") and result["status_code"] >= 500:
                        severity = "critical"
                    elif result.get("status_code") and result["status_code"] >= 400:
                        severity = "warning"

                    self.send_discord_notification(url, result, status="firing")
                    self.state[url] = {
                        "failing": True,
                        "severity": severity,
                        "first_failure": datetime.now().isoformat()
                    }
                else:
                    logger.debug(f"URL still failing (no alert sent): {url}")

        # Save state after processing all URLs
        self._save_state()

    def run(self):
        """Run the monitoring loop continuously."""
        global shutdown_requested

        # Set up signal handlers
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)

        logger.info(f"Starting monitoring loop (check every {CHECK_INTERVAL}s)...")

        while not shutdown_requested:
            try:
                self.monitor_once()
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")

            # Sleep in small increments to allow for responsive shutdown
            for _ in range(CHECK_INTERVAL):
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
        default=PID_FILE,
        help=f'Path to PID file (default: {PID_FILE})'
    )
    parser.add_argument(
        '--log-file',
        default=LOG_FILE,
        help=f'Path to log file (default: {LOG_FILE})'
    )

    args = parser.parse_args()

    # Convert config path to absolute path before daemonizing
    # (daemon changes working directory to /)
    args.config = os.path.abspath(args.config)

    if args.command == 'start':
        print("Starting daemon...")
        daemonize(args.pid_file, args.log_file)
        try:
            monitor = URLMonitor(args.config)
            monitor.run()
        except Exception as e:
            logger.error(f"Fatal error: {e}")
            raise

    elif args.command == 'stop':
        stop_daemon(args.pid_file)

    elif args.command == 'restart':
        print("Restarting daemon...")
        stop_daemon(args.pid_file)
        time.sleep(2)
        print("Starting daemon...")
        daemonize(args.pid_file, args.log_file)
        try:
            monitor = URLMonitor(args.config)
            monitor.run()
        except Exception as e:
            logger.error(f"Fatal error: {e}")
            raise

    elif args.command == 'status':
        status_daemon(args.pid_file)

    elif args.command == 'foreground':
        print("Running in foreground mode (Ctrl+C to stop)...")
        try:
            monitor = URLMonitor(args.config)
            monitor.run()
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
