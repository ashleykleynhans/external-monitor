#!/usr/bin/env python3
"""
URL Monitoring Script
Monitors configured URLs for availability and SSL certificate validity.
Sends notifications to Discord via webhook on failures.
"""

import time
import socket
import ssl
import requests
import yaml
import logging
from datetime import datetime
from typing import List, Dict, Optional
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Check interval in seconds (2 minutes)
CHECK_INTERVAL = 120


class URLMonitor:
    """Monitor URLs for availability and SSL certificate validity."""

    def __init__(self, config_path: str = "config.yml"):
        """Initialize the monitor with configuration."""
        self.config = self._load_config(config_path)
        self.webhook_url = self.config.get("webhook_url")
        self.urls = self.config.get("urls", [])
        self.hostname = socket.gethostname()

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

    def send_discord_notification(self, url: str, error_details: Dict):
        """Send notification to Discord via webhook."""
        timestamp = datetime.utcnow().isoformat()

        # Build error message
        error_parts = []
        if error_details.get("status_code"):
            error_parts.append(f"Status Code: {error_details['status_code']}")
        if error_details.get("error"):
            error_parts.append(f"Error: {error_details['error']}")
        if error_details.get("ssl_error"):
            error_parts.append(f"SSL Error: {error_details['ssl_error']}")

        error_message = "\n".join(error_parts)

        # Discord webhook payload (Slack-compatible format)
        payload = {
            "embeds": [{
                "title": "URL Monitor Alert",
                "color": 15158332,  # Red color
                "fields": [
                    {
                        "name": "URL",
                        "value": url,
                        "inline": False
                    },
                    {
                        "name": "Monitoring Host",
                        "value": self.hostname,
                        "inline": True
                    },
                    {
                        "name": "Details",
                        "value": error_message,
                        "inline": False
                    }
                ],
                "timestamp": timestamp
            }]
        }

        try:
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=10
            )
            if response.status_code == 204:
                logger.info(f"Notification sent for {url}")
            else:
                logger.error(
                    f"Failed to send notification: {response.status_code}"
                )
        except Exception as e:
            logger.error(f"Error sending notification: {e}")

    def monitor_once(self):
        """Perform one monitoring check of all URLs."""
        logger.info("Starting monitoring check...")

        for url in self.urls:
            result = self.check_url(url)

            if result["success"]:
                logger.info(f"OK: {url} (HTTP {result['status_code']})")
            else:
                logger.warning(f"FAIL: {url}")
                self.send_discord_notification(url, result)

    def run(self):
        """Run the monitoring loop continuously."""
        logger.info(f"Starting monitoring loop (check every {CHECK_INTERVAL}s)...")

        while True:
            try:
                self.monitor_once()
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")

            time.sleep(CHECK_INTERVAL)


def main():
    """Main entry point."""
    try:
        monitor = URLMonitor()
        monitor.run()
    except KeyboardInterrupt:
        logger.info("Monitoring stopped by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        raise


if __name__ == "__main__":
    main()
