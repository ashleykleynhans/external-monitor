"""
Unit tests for URL Monitor
"""

import pytest
import tempfile
import os
import signal
import time
import requests
import yaml
from unittest.mock import Mock, patch, MagicMock, mock_open
from monitor import (
    URLMonitor,
    signal_handler,
    write_pid_file,
    remove_pid_file,
    read_pid_file,
    is_process_running,
    stop_daemon,
    status_daemon,
    setup_logging
)


@pytest.fixture
def config_file():
    """Create a temporary config file for testing."""
    config_content = """
webhook_url: "https://discord.com/api/webhooks/test/webhook"
urls:
  - "https://example.com"
  - "https://test.com"
"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
        f.write(config_content)
        config_path = f.name

    yield config_path

    # Cleanup
    os.unlink(config_path)


@pytest.fixture
def state_file():
    """Create a temporary state file for testing."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        state_path = f.name

    yield state_path

    # Cleanup
    if os.path.exists(state_path):
        os.unlink(state_path)


class TestURLMonitor:
    """Test cases for URLMonitor class."""

    def test_load_config(self, config_file):
        """Test configuration loading."""
        monitor = URLMonitor(config_file)
        assert monitor.webhook_url == "https://discord.com/api/webhooks/test/webhook"
        assert len(monitor.urls) == 2
        assert "https://example.com" in monitor.urls

    def test_missing_webhook_url(self):
        """Test that missing webhook_url raises an error."""
        config_content = """
urls:
  - "https://example.com"
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(config_content)
            config_path = f.name

        try:
            with pytest.raises(ValueError, match="webhook_url is required"):
                URLMonitor(config_path)
        finally:
            os.unlink(config_path)

    def test_missing_urls(self):
        """Test that missing URLs raises an error."""
        config_content = """
webhook_url: "https://discord.com/api/webhooks/test/webhook"
urls: []
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(config_content)
            config_path = f.name

        try:
            with pytest.raises(ValueError, match="At least one URL is required"):
                URLMonitor(config_path)
        finally:
            os.unlink(config_path)

    @patch('monitor.requests.get')
    def test_check_url_success(self, mock_get, config_file):
        """Test successful URL check."""
        monitor = URLMonitor(config_file)

        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        result = monitor.check_url("http://example.com")

        assert result["success"] is True
        assert result["status_code"] == 200
        assert result["error"] is None

    @patch('monitor.requests.get')
    def test_check_url_non_200_status(self, mock_get, config_file):
        """Test URL check with non-200 status code."""
        monitor = URLMonitor(config_file)

        # Mock 404 response
        mock_response = Mock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        result = monitor.check_url("http://example.com")

        assert result["success"] is False
        assert result["status_code"] == 404
        assert "HTTP 404" in result["error"]

    @patch('monitor.requests.get')
    def test_check_url_connection_error(self, mock_get, config_file):
        """Test URL check with connection error."""
        monitor = URLMonitor(config_file)

        # Mock connection error
        mock_get.side_effect = Exception("Connection refused")

        result = monitor.check_url("http://example.com")

        assert result["success"] is False
        assert result["error"] is not None

    @patch('monitor.requests.post')
    def test_send_discord_notification(self, mock_post, config_file):
        """Test Alertmanager notification sending."""
        monitor = URLMonitor(config_file)

        # Mock successful webhook post
        mock_response = Mock()
        mock_response.status_code = 204
        mock_post.return_value = mock_response

        error_details = {
            "status_code": 500,
            "error": "Internal Server Error",
            "ssl_error": None
        }

        monitor.send_discord_notification("https://example.com", error_details)

        # Verify webhook was called
        assert mock_post.called
        call_args = mock_post.call_args
        # Webhook URL should have /critical appended for 500 errors
        assert f"{monitor.webhook_url}/critical" == call_args[0][0]

        # Verify payload structure (Alertmanager format)
        payload = call_args[1]['json']
        assert 'alerts' in payload
        assert isinstance(payload['alerts'], list)
        assert len(payload['alerts']) == 1

        alert = payload['alerts'][0]
        assert 'labels' in alert
        assert 'annotations' in alert
        assert 'startsAt' in alert
        assert 'generatorURL' in alert

        # Verify labels
        assert alert['labels']['alertname'] == 'URLMonitorAlert'
        assert alert['labels']['severity'] == 'critical'
        assert alert['labels']['url'] == 'https://example.com'
        assert alert['labels']['instance'] == monitor.hostname
        assert alert['labels']['service'] == 'external-monitor'
        assert alert['labels']['environment'] == 'prod'
        assert alert['labels']['status_code'] == '500'

        # Verify annotations
        assert 'summary' in alert['annotations']
        assert 'description' in alert['annotations']
        assert 'https://example.com' in alert['annotations']['summary']

    @patch('monitor.socket.gethostname')
    def test_hostname_included(self, mock_hostname, config_file):
        """Test that hostname is captured."""
        mock_hostname.return_value = "test-server-123"
        monitor = URLMonitor(config_file)

        assert monitor.hostname == "test-server-123"

    @patch('monitor.requests.get')
    def test_check_url_https_ssl_check(self, mock_get, config_file):
        """Test that HTTPS URLs with valid SSL work correctly."""
        monitor = URLMonitor(config_file)

        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        result = monitor.check_url("https://example.com")

        # Verify request was made with verify=True (SSL validation enabled)
        mock_get.assert_called_once()
        call_kwargs = mock_get.call_args[1]
        assert call_kwargs['verify'] is True
        assert result["success"] is True

    @patch('monitor.requests.get')
    def test_check_url_https_ssl_error(self, mock_get, config_file):
        """Test SSL error detection from requests library."""
        monitor = URLMonitor(config_file)

        # Mock SSL error from requests library
        mock_get.side_effect = requests.exceptions.SSLError("Certificate verify failed")

        result = monitor.check_url("https://example.com")

        assert result["success"] is False
        assert result["ssl_error"] is not None
        assert "SSL Error" in result["ssl_error"]
        assert "SSL connection error" in result["error"]


class TestDaemonFunctions:
    """Test cases for daemon-related functions."""

    def test_write_pid_file(self):
        """Test writing PID file."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            pid_file = f.name

        try:
            write_pid_file(pid_file)
            assert os.path.exists(pid_file)

            with open(pid_file, 'r') as f:
                pid = int(f.read().strip())
            assert pid == os.getpid()
        finally:
            if os.path.exists(pid_file):
                os.unlink(pid_file)

    def test_remove_pid_file(self):
        """Test removing PID file."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            pid_file = f.name
            f.write(b"12345")

        assert os.path.exists(pid_file)
        remove_pid_file(pid_file)
        assert not os.path.exists(pid_file)

    def test_read_pid_file(self):
        """Test reading PID file."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            pid_file = f.name
            f.write("54321")

        try:
            pid = read_pid_file(pid_file)
            assert pid == 54321
        finally:
            os.unlink(pid_file)

    def test_read_pid_file_nonexistent(self):
        """Test reading non-existent PID file."""
        pid = read_pid_file("/tmp/nonexistent_pid_file.pid")
        assert pid is None

    def test_is_process_running_current(self):
        """Test checking if current process is running."""
        assert is_process_running(os.getpid()) is True

    def test_is_process_running_nonexistent(self):
        """Test checking if non-existent process is running."""
        # Use a very high PID that's unlikely to exist
        assert is_process_running(999999) is False

    @patch('monitor.shutdown_requested', False)
    def test_signal_handler(self):
        """Test signal handler sets shutdown flag."""
        import monitor
        monitor.shutdown_requested = False
        signal_handler(signal.SIGTERM, None)
        assert monitor.shutdown_requested is True

    @patch('monitor.read_pid_file')
    @patch('monitor.is_process_running')
    def test_status_daemon_running(self, mock_is_running, mock_read_pid):
        """Test daemon status when running."""
        mock_read_pid.return_value = 12345
        mock_is_running.return_value = True

        result = status_daemon("/tmp/test.pid")
        assert result is True

    @patch('monitor.read_pid_file')
    def test_status_daemon_not_running(self, mock_read_pid):
        """Test daemon status when not running."""
        mock_read_pid.return_value = None

        result = status_daemon("/tmp/test.pid")
        assert result is False

    @patch('monitor.read_pid_file')
    @patch('monitor.is_process_running')
    @patch('monitor.remove_pid_file')
    def test_status_daemon_stale_pid(self, mock_remove, mock_is_running, mock_read_pid):
        """Test daemon status with stale PID file."""
        mock_read_pid.return_value = 12345
        mock_is_running.return_value = False

        result = status_daemon("/tmp/test.pid")
        assert result is False
        mock_remove.assert_called_once()

    @patch('monitor.URLMonitor.monitor_once')
    @patch('monitor.time.sleep')
    def test_run_with_shutdown(self, mock_sleep, mock_monitor_once, config_file):
        """Test that run method respects shutdown flag."""
        import monitor
        monitor.shutdown_requested = False

        # Create a side effect that sets shutdown after first call
        def set_shutdown(*args):
            monitor.shutdown_requested = True

        mock_monitor_once.side_effect = set_shutdown

        url_monitor = URLMonitor(config_file)
        url_monitor.run()

        # Should have called monitor_once at least once
        assert mock_monitor_once.called

    @patch('monitor.URLMonitor.monitor_once')
    @patch('monitor.time.sleep')
    def test_run_foreground_mode(self, mock_sleep, mock_monitor_once, config_file):
        """Test that run method works in foreground mode (daemon_mode=False)."""
        import monitor
        monitor.shutdown_requested = False

        # Create a side effect that sets shutdown after first call
        def set_shutdown(*args):
            monitor.shutdown_requested = True

        mock_monitor_once.side_effect = set_shutdown

        url_monitor = URLMonitor(config_file)
        url_monitor.run(daemon_mode=False)

        # Should have called monitor_once at least once
        assert mock_monitor_once.called

    @patch('monitor.read_pid_file')
    @patch('monitor.is_process_running')
    def test_stop_daemon_not_running(self, mock_is_running, mock_read_pid):
        """Test stopping daemon that's not running."""
        mock_read_pid.return_value = None

        result = stop_daemon("/tmp/test.pid")
        assert result is False


class TestSSLCertificate:
    """Test cases for SSL certificate checking."""

    @patch('monitor.socket.create_connection')
    def test_ssl_certificate_valid(self, mock_conn, config_file):
        """Test valid SSL certificate."""
        monitor = URLMonitor(config_file)

        # Mock SSL connection
        mock_socket = MagicMock()
        mock_ssl_socket = MagicMock()
        mock_ssl_socket.getpeercert.return_value = {"subject": "test"}
        mock_socket.__enter__ = MagicMock(return_value=mock_ssl_socket)
        mock_socket.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value.__enter__ = MagicMock(return_value=mock_socket)
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)

        with patch('monitor.ssl.create_default_context') as mock_ssl_ctx:
            mock_ctx = MagicMock()
            mock_ctx.wrap_socket.return_value = mock_ssl_socket
            mock_ssl_ctx.return_value = mock_ctx

            result = monitor.check_ssl_certificate("example.com")
            assert result is None

    @patch('monitor.socket.create_connection')
    def test_ssl_certificate_ssl_error(self, mock_conn, config_file):
        """Test SSL certificate with SSL error."""
        import ssl
        monitor = URLMonitor(config_file)

        mock_conn.side_effect = ssl.SSLError("Certificate verify failed")

        result = monitor.check_ssl_certificate("example.com")
        assert result is not None
        assert "SSL Error" in result

    @patch('monitor.socket.create_connection')
    def test_ssl_certificate_timeout(self, mock_conn, config_file):
        """Test SSL certificate check timeout."""
        import socket
        monitor = URLMonitor(config_file)

        mock_conn.side_effect = socket.timeout("Connection timeout")

        result = monitor.check_ssl_certificate("example.com")
        assert result == "SSL check timeout"

    @patch('monitor.socket.create_connection')
    def test_ssl_certificate_generic_exception(self, mock_conn, config_file):
        """Test SSL certificate check with generic exception."""
        monitor = URLMonitor(config_file)

        mock_conn.side_effect = Exception("Generic error")

        result = monitor.check_ssl_certificate("example.com")
        assert result is not None
        assert "SSL check failed" in result


class TestURLCheckExceptions:
    """Test cases for different URL check exceptions."""

    @patch('monitor.requests.get')
    def test_check_url_ssl_exception(self, mock_get, config_file):
        """Test URL check with SSL exception."""
        import requests
        monitor = URLMonitor(config_file)

        mock_get.side_effect = requests.exceptions.SSLError("SSL error")

        result = monitor.check_url("https://example.com")
        assert result["success"] is False
        assert "SSL connection error" in result["error"]

    @patch('monitor.requests.get')
    def test_check_url_connection_exception(self, mock_get, config_file):
        """Test URL check with connection exception."""
        import requests
        monitor = URLMonitor(config_file)

        mock_get.side_effect = requests.exceptions.ConnectionError("Connection error")

        result = monitor.check_url("https://example.com")
        assert result["success"] is False
        assert "Connection error" in result["error"]

    @patch('monitor.requests.get')
    def test_check_url_timeout_exception(self, mock_get, config_file):
        """Test URL check with timeout exception."""
        import requests
        monitor = URLMonitor(config_file)

        mock_get.side_effect = requests.exceptions.Timeout()

        result = monitor.check_url("https://example.com")
        assert result["success"] is False
        assert result["error"] == "Request timeout"


class TestWebhookNotificationVariations:
    """Test cases for different webhook notification scenarios."""

    @patch('monitor.requests.post')
    def test_notification_with_only_error(self, mock_post, config_file):
        """Test notification with only error field."""
        monitor = URLMonitor(config_file)
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        error_details = {
            "status_code": None,
            "error": "Connection refused",
            "ssl_error": None
        }

        monitor.send_discord_notification("https://example.com", error_details)
        assert mock_post.called

        payload = mock_post.call_args[1]['json']
        assert 'alerts' in payload
        alert = payload['alerts'][0]
        assert "Connection refused" in alert['annotations']['description']

    @patch('monitor.requests.post')
    def test_notification_with_ssl_error(self, mock_post, config_file):
        """Test notification with SSL error."""
        monitor = URLMonitor(config_file)
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        error_details = {
            "status_code": None,
            "error": None,
            "ssl_error": "SSL certificate expired"
        }

        monitor.send_discord_notification("https://example.com", error_details)
        assert mock_post.called
        payload = mock_post.call_args[1]['json']
        alert = payload['alerts'][0]
        assert alert['labels']['severity'] == 'critical'
        assert "SSL" in alert['annotations']['description']

    @patch('monitor.requests.post')
    def test_notification_with_all_errors(self, mock_post, config_file):
        """Test notification with all error types."""
        monitor = URLMonitor(config_file)
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        error_details = {
            "status_code": 503,
            "error": "Service Unavailable",
            "ssl_error": "SSL certificate expired"
        }

        monitor.send_discord_notification("https://example.com", error_details)
        assert mock_post.called

        payload = mock_post.call_args[1]['json']
        alert = payload['alerts'][0]
        assert alert['labels']['severity'] == 'critical'
        assert alert['labels']['status_code'] == '503'
        assert "Service Unavailable" in alert['annotations']['description']
        assert "SSL" in alert['annotations']['description']

    @patch('monitor.requests.post')
    def test_notification_webhook_failure(self, mock_post, config_file):
        """Test notification when webhook fails."""
        monitor = URLMonitor(config_file)
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_post.return_value = mock_response

        error_details = {
            "status_code": 404,
            "error": "Not Found",
            "ssl_error": None
        }

        monitor.send_discord_notification("https://example.com", error_details)
        assert mock_post.called

    @patch('monitor.requests.post')
    def test_notification_webhook_exception(self, mock_post, config_file):
        """Test notification when webhook raises exception."""
        monitor = URLMonitor(config_file)
        mock_post.side_effect = Exception("Network error")

        error_details = {
            "status_code": 404,
            "error": "Not Found",
            "ssl_error": None
        }

        # Should not raise exception
        monitor.send_discord_notification("https://example.com", error_details)


class TestConfigLoading:
    """Test cases for config loading."""

    def test_config_file_not_found(self):
        """Test config file not found."""
        with pytest.raises(FileNotFoundError):
            URLMonitor("/nonexistent/config.yml")

    def test_config_invalid_yaml(self):
        """Test invalid YAML in config file."""
        import yaml
        config_content = """
webhook_url: "https://discord.com/api/webhooks/test/webhook"
urls:
  - "https://example.com"
  invalid yaml here: [
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(config_content)
            config_path = f.name

        try:
            with pytest.raises(yaml.YAMLError):
                URLMonitor(config_path)
        finally:
            os.unlink(config_path)


class TestMonitorOnce:
    """Test cases for monitor_once method."""

    @patch('monitor.URLMonitor.check_url')
    @patch('monitor.URLMonitor.send_discord_notification')
    @patch('monitor.URLMonitor._save_state')
    def test_monitor_once_all_success(self, mock_save, mock_notify, mock_check, config_file, state_file):
        """Test monitor_once with all URLs successful."""
        monitor = URLMonitor(config_file, state_file)
        mock_check.return_value = {
            "success": True,
            "status_code": 200,
            "error": None,
            "ssl_error": None
        }

        monitor.monitor_once()

        assert mock_check.call_count == 2  # 2 URLs in config
        mock_notify.assert_not_called()
        mock_save.assert_called_once()

    @patch('monitor.time.sleep')  # Mock sleep to avoid delays
    @patch('monitor.URLMonitor.check_url')
    @patch('monitor.URLMonitor.send_discord_notification')
    @patch('monitor.URLMonitor._save_state')
    def test_monitor_once_with_failure(self, mock_save, mock_notify, mock_check, mock_sleep, config_file, state_file):
        """Test monitor_once with one URL failing all retries (triggers alert)."""
        monitor = URLMonitor(config_file, state_file)

        def check_side_effect(url):
            if "example.com" in url:
                return {
                    "success": False,
                    "status_code": 500,
                    "error": "Server Error",
                    "ssl_error": None
                }
            return {
                "success": True,
                "status_code": 200,
                "error": None,
                "ssl_error": None
            }

        mock_check.side_effect = check_side_effect

        monitor.monitor_once()

        # example.com: 1 initial + 4 retries = 5 checks
        # test.com: 1 check
        # Total: 6 checks
        assert mock_check.call_count == 6

        # Should send alert after 5 consecutive failures
        assert mock_notify.call_count == 1

        # Verify alert was firing (not resolved)
        assert mock_notify.call_args[1]['status'] == 'firing'


class TestDaemonErrorPaths:
    """Test error paths in daemon functions."""

    def test_write_pid_file_error(self):
        """Test write_pid_file with permission error."""
        with pytest.raises(Exception):
            write_pid_file("/root/test_no_permission.pid")

    def test_remove_pid_file_nonexistent(self):
        """Test removing non-existent PID file."""
        # Should not raise exception
        remove_pid_file("/tmp/nonexistent_pid_12345.pid")

    @patch('monitor.os.remove')
    @patch('monitor.os.path.exists')
    def test_remove_pid_file_permission_error(self, mock_exists, mock_remove):
        """Test remove_pid_file with permission error."""
        mock_exists.return_value = True
        mock_remove.side_effect = PermissionError("Permission denied")

        # Should not raise exception, just log error
        remove_pid_file("/tmp/test.pid")

    def test_read_pid_file_invalid_content(self):
        """Test reading PID file with invalid content."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            pid_file = f.name
            f.write("not a number")

        try:
            pid = read_pid_file(pid_file)
            assert pid is None  # Should handle error gracefully
        finally:
            os.unlink(pid_file)

    @patch('monitor.read_pid_file')
    @patch('monitor.is_process_running')
    @patch('monitor.remove_pid_file')
    def test_stop_daemon_process_not_running(self, mock_remove, mock_is_running, mock_read_pid):
        """Test stop_daemon when process is not running."""
        mock_read_pid.return_value = 12345
        mock_is_running.return_value = False

        result = stop_daemon("/tmp/test.pid")
        assert result is False
        mock_remove.assert_called_once()

    @patch('monitor.read_pid_file')
    @patch('monitor.is_process_running')
    @patch('monitor.os.kill')
    @patch('monitor.time.sleep')
    @patch('monitor.remove_pid_file')
    def test_stop_daemon_graceful_shutdown(self, mock_remove, mock_sleep, mock_kill, mock_is_running, mock_read_pid):
        """Test stop_daemon with graceful shutdown."""
        mock_read_pid.return_value = 12345

        # First call returns True (running), subsequent calls return False (stopped)
        mock_is_running.side_effect = [True, False]

        result = stop_daemon("/tmp/test.pid")
        assert result is True
        mock_kill.assert_called_once_with(12345, signal.SIGTERM)
        mock_remove.assert_called_once()

    @patch('monitor.read_pid_file')
    @patch('monitor.is_process_running')
    @patch('monitor.os.kill')
    def test_stop_daemon_kill_exception(self, mock_kill, mock_is_running, mock_read_pid):
        """Test stop_daemon when kill raises exception."""
        mock_read_pid.return_value = 12345
        mock_is_running.return_value = True
        mock_kill.side_effect = Exception("Permission denied")

        result = stop_daemon("/tmp/test.pid")
        assert result is False


class TestRunLoopEdgeCases:
    """Test edge cases in run loop."""

    @patch('monitor.URLMonitor.monitor_once')
    @patch('monitor.time.sleep')
    def test_run_with_exception_in_monitor(self, mock_sleep, mock_monitor_once, config_file):
        """Test run loop handles exception in monitor_once."""
        import monitor
        monitor.shutdown_requested = False

        call_count = [0]

        def monitor_side_effect():
            call_count[0] += 1
            if call_count[0] == 1:
                raise Exception("Test exception")
            else:
                monitor.shutdown_requested = True

        mock_monitor_once.side_effect = monitor_side_effect

        url_monitor = URLMonitor(config_file)
        url_monitor.run()

        assert mock_monitor_once.call_count >= 2


class TestMainFunction:
    """Test main function and CLI arguments."""

    @patch('sys.argv', ['monitor.py', 'foreground', '--config', 'config.yml'])
    @patch('monitor.URLMonitor')
    def test_main_foreground(self, mock_monitor_class):
        """Test main with foreground command."""
        from monitor import main
        import sys

        mock_monitor = MagicMock()
        mock_monitor.run.side_effect = KeyboardInterrupt()
        mock_monitor_class.return_value = mock_monitor

        mock_config = {'webhook_url': 'http://test.com', 'urls': ['http://test.com']}

        with patch('os.path.abspath', return_value='/abs/path/config.yml'):
            with patch('builtins.open', mock_open(read_data='webhook_url: http://test.com')):
                with patch('yaml.safe_load', return_value=mock_config):
                    main()

        mock_monitor_class.assert_called_once()
        mock_monitor.run.assert_called_once()

    @patch('sys.argv', ['monitor.py', 'foreground', '--config', 'config.yml'])
    @patch('monitor.URLMonitor')
    def test_main_foreground_normal_exit(self, mock_monitor_class):
        """Test main foreground with normal exit."""
        from monitor import main

        mock_monitor = MagicMock()
        mock_monitor.run.return_value = None  # Normal completion
        mock_monitor_class.return_value = mock_monitor

        mock_config = {'webhook_url': 'http://test.com', 'urls': ['http://test.com']}

        with patch('os.path.abspath', return_value='/abs/path/config.yml'):
            with patch('builtins.open', mock_open(read_data='webhook_url: http://test.com')):
                with patch('yaml.safe_load', return_value=mock_config):
                    main()

        mock_monitor_class.assert_called_once()
        mock_monitor.run.assert_called_once()

    @patch('sys.argv', ['monitor.py', 'status'])
    @patch('monitor.status_daemon')
    def test_main_status(self, mock_status):
        """Test main with status command."""
        from monitor import main

        mock_status.return_value = True
        mock_config = {'webhook_url': 'http://test.com', 'urls': ['http://test.com']}

        with patch('os.path.abspath', return_value='/abs/path/config.yml'):
            with patch('builtins.open', mock_open(read_data='webhook_url: http://test.com')):
                with patch('yaml.safe_load', return_value=mock_config):
                    main()

        mock_status.assert_called_once()

    @patch('sys.argv', ['monitor.py', 'stop'])
    @patch('monitor.stop_daemon')
    def test_main_stop(self, mock_stop):
        """Test main with stop command."""
        from monitor import main

        mock_stop.return_value = True
        mock_config = {'webhook_url': 'http://test.com', 'urls': ['http://test.com']}

        with patch('os.path.abspath', return_value='/abs/path/config.yml'):
            with patch('builtins.open', mock_open(read_data='webhook_url: http://test.com')):
                with patch('yaml.safe_load', return_value=mock_config):
                    main()

        mock_stop.assert_called_once()

    @patch('sys.argv', ['monitor.py', 'restart'])
    @patch('monitor.stop_daemon')
    @patch('monitor.daemonize')
    @patch('monitor.URLMonitor')
    @patch('monitor.time.sleep')
    def test_main_restart(self, mock_sleep, mock_monitor_class, mock_daemonize, mock_stop):
        """Test main with restart command."""
        from monitor import main

        mock_stop.return_value = True
        mock_monitor = MagicMock()
        mock_monitor_class.return_value = mock_monitor
        mock_config = {'webhook_url': 'http://test.com', 'urls': ['http://test.com']}

        with patch('os.path.abspath', return_value='/abs/path/config.yml'):
            with patch('builtins.open', mock_open(read_data='webhook_url: http://test.com')):
                with patch('yaml.safe_load', return_value=mock_config):
                    # Mock run to exit immediately
                    mock_monitor.run.return_value = None
                    main()

        mock_stop.assert_called_once()
        mock_daemonize.assert_called_once()
        mock_monitor_class.assert_called_once()

    @patch('sys.argv', ['monitor.py', 'start'])
    @patch('monitor.daemonize')
    @patch('monitor.URLMonitor')
    def test_main_start(self, mock_monitor_class, mock_daemonize):
        """Test main with start command."""
        from monitor import main

        mock_monitor = MagicMock()
        mock_monitor_class.return_value = mock_monitor
        mock_monitor.run.return_value = None
        mock_config = {'webhook_url': 'http://test.com', 'urls': ['http://test.com']}

        with patch('os.path.abspath', return_value='/abs/path/config.yml'):
            with patch('builtins.open', mock_open(read_data='webhook_url: http://test.com')):
                with patch('yaml.safe_load', return_value=mock_config):
                    main()

        mock_daemonize.assert_called_once()
        mock_monitor_class.assert_called_once()
        mock_monitor.run.assert_called_once()

    @patch('sys.argv', ['monitor.py', 'foreground'])
    @patch('monitor.URLMonitor')
    def test_main_foreground_exception(self, mock_monitor_class):
        """Test main foreground with exception."""
        from monitor import main

        mock_monitor = MagicMock()
        mock_monitor.run.side_effect = Exception("Test error")
        mock_monitor_class.return_value = mock_monitor
        mock_config = {'webhook_url': 'http://test.com', 'urls': ['http://test.com']}

        with patch('os.path.abspath', return_value='/abs/path/config.yml'):
            with patch('builtins.open', mock_open(read_data='webhook_url: http://test.com')):
                with patch('yaml.safe_load', return_value=mock_config):
                    with pytest.raises(Exception):
                        main()

    @patch('sys.argv', ['monitor.py', 'start'])
    @patch('monitor.daemonize')
    @patch('monitor.URLMonitor')
    def test_main_start_exception(self, mock_monitor_class, mock_daemonize):
        """Test main start with exception."""
        from monitor import main

        mock_monitor = MagicMock()
        mock_monitor.run.side_effect = Exception("Fatal error")
        mock_monitor_class.return_value = mock_monitor
        mock_config = {'webhook_url': 'http://test.com', 'urls': ['http://test.com']}

        with patch('os.path.abspath', return_value='/abs/path/config.yml'):
            with patch('builtins.open', mock_open(read_data='webhook_url: http://test.com')):
                with patch('yaml.safe_load', return_value=mock_config):
                    with pytest.raises(Exception):
                        main()

    @patch('sys.argv', ['monitor.py', 'restart'])
    @patch('monitor.stop_daemon')
    @patch('monitor.daemonize')
    @patch('monitor.URLMonitor')
    @patch('monitor.time.sleep')
    def test_main_restart_exception(self, mock_sleep, mock_monitor_class, mock_daemonize, mock_stop):
        """Test main restart with exception."""
        from monitor import main

        mock_stop.return_value = True
        mock_monitor = MagicMock()
        mock_monitor.run.side_effect = Exception("Fatal error")
        mock_monitor_class.return_value = mock_monitor
        mock_config = {'webhook_url': 'http://test.com', 'urls': ['http://test.com']}

        with patch('os.path.abspath', return_value='/abs/path/config.yml'):
            with patch('builtins.open', mock_open(read_data='webhook_url: http://test.com')):
                with patch('yaml.safe_load', return_value=mock_config):
                    with pytest.raises(Exception):
                        main()

    @patch('sys.argv', ['monitor.py', 'start'])
    def test_main_config_load_error(self):
        """Test main with config loading error."""
        from monitor import main

        with patch('os.path.abspath', return_value='/abs/path/config.yml'):
            with patch('builtins.open', side_effect=FileNotFoundError("Config not found")):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 1


class TestLoggingSetup:
    """Test logging setup functionality."""

    def test_setup_logging_foreground_with_file(self):
        """Test setup_logging in foreground mode with log file."""
        import logging
        from monitor import logger

        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            log_file = f.name

        try:
            setup_logging(log_file=log_file, foreground=True)

            # Check that logger has both console and file handlers
            assert len(logger.handlers) == 2
            handler_types = [type(h).__name__ for h in logger.handlers]
            assert 'StreamHandler' in handler_types
            assert 'FileHandler' in handler_types

            # Test that logging works
            logger.info("Test message")

            # Verify log file was created and contains the message
            with open(log_file, 'r') as f:
                content = f.read()
                assert "Test message" in content
        finally:
            if os.path.exists(log_file):
                os.unlink(log_file)

    def test_setup_logging_foreground_without_file(self):
        """Test setup_logging in foreground mode without log file."""
        import logging
        from monitor import logger

        setup_logging(log_file=None, foreground=True)

        # Check that logger has only console handler
        assert len(logger.handlers) == 1
        assert type(logger.handlers[0]).__name__ == 'StreamHandler'

    def test_setup_logging_daemon_mode(self):
        """Test setup_logging in daemon mode (only file logging)."""
        import logging
        from monitor import logger

        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            log_file = f.name

        try:
            setup_logging(log_file=log_file, foreground=False)

            # Check that logger has only file handler
            assert len(logger.handlers) == 1
            assert type(logger.handlers[0]).__name__ == 'FileHandler'

            # Test that logging works
            logger.info("Daemon test message")

            # Verify log file was created and contains the message
            with open(log_file, 'r') as f:
                content = f.read()
                assert "Daemon test message" in content
        finally:
            if os.path.exists(log_file):
                os.unlink(log_file)


class TestNotificationEdgeCases:
    """Test edge cases in notifications."""

    @patch('monitor.requests.post')
    def test_notification_no_error_fields(self, mock_post, config_file):
        """Test notification with no error fields."""
        monitor = URLMonitor(config_file)
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        error_details = {
            "status_code": None,
            "error": None,
            "ssl_error": None
        }

        monitor.send_discord_notification("https://example.com", error_details)
        assert mock_post.called

        payload = mock_post.call_args[1]['json']
        alert = payload['alerts'][0]
        assert alert['annotations']['description'] == "URL is unreachable"

    @patch('monitor.requests.post')
    def test_notification_warning_severity(self, mock_post, config_file):
        """Test notification with warning severity for 4xx errors."""
        monitor = URLMonitor(config_file)
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        error_details = {
            "status_code": 404,
            "error": "Not Found",
            "ssl_error": None
        }

        monitor.send_discord_notification("https://example.com", error_details)
        assert mock_post.called

        payload = mock_post.call_args[1]['json']
        alert = payload['alerts'][0]
        assert alert['labels']['severity'] == 'warning'
        assert alert['labels']['status_code'] == '404'


class TestStopDaemonForcedKill:
    """Test forced kill scenario in stop_daemon."""

    @patch('monitor.read_pid_file')
    @patch('monitor.is_process_running')
    @patch('monitor.os.kill')
    @patch('monitor.time.sleep')
    @patch('monitor.remove_pid_file')
    def test_stop_daemon_forced_kill(self, mock_remove, mock_sleep, mock_kill, mock_is_running, mock_read_pid):
        """Test stop_daemon with forced kill after graceful shutdown fails."""
        mock_read_pid.return_value = 12345

        # Process stays running for 30+ iterations, then needs force kill
        mock_is_running.return_value = True

        result = stop_daemon("/tmp/test.pid")

        # Should have tried SIGTERM first, then SIGKILL
        assert mock_kill.call_count >= 2
        assert result is True
        mock_remove.assert_called_once()


class TestStateManagement:
    """Test cases for alert state management with thresholds."""

    @patch('monitor.time.sleep')  # Mock sleep to avoid delays
    @patch('monitor.URLMonitor.check_url')
    @patch('monitor.URLMonitor.send_discord_notification')
    def test_failure_only_alerts_after_threshold(self, mock_notify, mock_check, mock_sleep, config_file, state_file):
        """Test that alert is only sent after FAILURE_THRESHOLD (5) consecutive failures."""
        monitor = URLMonitor(config_file, state_file)

        # Simulate a failure
        mock_check.return_value = {
            "success": False,
            "status_code": 500,
            "error": "Internal Server Error",
            "ssl_error": None
        }

        monitor.monitor_once()

        # Should have sent firing alert for both URLs after 5 retries each
        assert mock_notify.call_count == 2
        # Check that status="firing" was used
        for call in mock_notify.call_args_list:
            assert call[1]['status'] == 'firing'

    @patch('monitor.time.sleep')  # Mock sleep to avoid delays
    @patch('monitor.URLMonitor.check_url')
    @patch('monitor.URLMonitor.send_discord_notification')
    def test_continued_failure_no_additional_alert(self, mock_notify, mock_check, mock_sleep, config_file, state_file):
        """Test that continued failures after alert don't send additional alerts."""
        monitor = URLMonitor(config_file, state_file)

        # First check - fails 5 times, triggers alert
        mock_check.return_value = {
            "success": False,
            "status_code": 500,
            "error": "Internal Server Error",
            "ssl_error": None
        }

        monitor.monitor_once()
        assert mock_notify.call_count == 2  # Both URLs fail, both send alerts

        # Second check - still failing (no additional alerts)
        mock_notify.reset_mock()
        monitor.monitor_once()
        assert mock_notify.call_count == 0  # No additional alerts sent

    @patch('monitor.time.sleep')  # Mock sleep to avoid delays
    @patch('monitor.URLMonitor.check_url')
    @patch('monitor.URLMonitor.send_discord_notification')
    def test_recovery_requires_threshold(self, mock_notify, mock_check, mock_sleep, config_file, state_file):
        """Test that recovery requires RECOVERY_THRESHOLD (2) consecutive successes."""
        monitor = URLMonitor(config_file, state_file)

        # First check - fails and triggers alert
        mock_check.return_value = {
            "success": False,
            "status_code": 500,
            "error": "Internal Server Error",
            "ssl_error": None
        }

        monitor.monitor_once()
        assert mock_notify.call_count == 2  # Firing alerts

        # First success - not enough for recovery
        mock_notify.reset_mock()
        mock_check.return_value = {
            "success": True,
            "status_code": 200,
            "error": None,
            "ssl_error": None
        }

        monitor.monitor_once()
        assert mock_notify.call_count == 0  # No resolved alerts yet (need 2 successes)

        # Second success - triggers resolved alert
        monitor.monitor_once()
        assert mock_notify.call_count == 2  # Resolved alerts sent
        # Check that status="resolved" was used
        for call in mock_notify.call_args_list:
            assert call[1]['status'] == 'resolved'

    @patch('monitor.time.sleep')  # Mock sleep to avoid delays
    @patch('monitor.URLMonitor.check_url')
    @patch('monitor.URLMonitor.send_discord_notification')
    def test_state_persists_between_checks(self, mock_notify, mock_check, mock_sleep, config_file, state_file):
        """Test that state persists to file and can be reloaded."""
        # First monitor instance - create failing state
        monitor1 = URLMonitor(config_file, state_file)
        mock_check.return_value = {
            "success": False,
            "status_code": 503,
            "error": "Service Unavailable",
            "ssl_error": None
        }

        monitor1.monitor_once()
        assert mock_notify.call_count == 2  # Firing alerts

        # Create new monitor instance - should load state
        mock_notify.reset_mock()
        monitor2 = URLMonitor(config_file, state_file)

        # URL still failing - should not send alert (already alerted)
        monitor2.monitor_once()
        assert mock_notify.call_count == 0  # No new alerts

    @patch('requests.post')
    def test_resolved_alert_uses_previous_severity(self, mock_post, config_file, state_file):
        """Test that resolved alerts use the severity from the original failure."""
        monitor = URLMonitor(config_file, state_file)

        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        # Set up state with a critical failure (new structure)
        monitor.state["https://example.com"] = {
            "alerted": True,
            "consecutive_failures": 5,
            "consecutive_successes": 0,
            "severity": "critical",
            "first_failure": "2025-10-28T10:00:00"
        }

        # Send resolved alert
        monitor.send_discord_notification("https://example.com", {}, status="resolved")

        # Check that the resolved alert uses "critical" severity
        payload = mock_post.call_args[1]['json']
        alert = payload['alerts'][0]
        assert alert['status'] == 'resolved'
        assert alert['labels']['severity'] == 'critical'
        assert 'now accessible' in alert['annotations']['summary']

    @patch('requests.post')
    def test_resolved_alert_format(self, mock_post, config_file, state_file):
        """Test the format of resolved alerts."""
        monitor = URLMonitor(config_file, state_file)

        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        # Set up state (new structure)
        monitor.state["https://example.com"] = {
            "alerted": True,
            "consecutive_failures": 5,
            "consecutive_successes": 0,
            "severity": "warning",
            "first_failure": "2025-10-28T10:00:00"
        }

        # Send resolved alert
        monitor.send_discord_notification("https://example.com", {}, status="resolved")

        # Verify resolved alert structure
        payload = mock_post.call_args[1]['json']
        alert = payload['alerts'][0]

        assert alert['status'] == 'resolved'
        assert 'endsAt' in alert
        assert 'startsAt' not in alert
        assert alert['labels']['url'] == 'https://example.com'
        assert alert['labels']['environment'] == 'prod'
        assert 'recovered' in alert['annotations']['description'].lower()

    def test_state_file_load_with_invalid_json(self, config_file, state_file):
        """Test that invalid state file is handled gracefully."""
        # Write invalid JSON to state file
        with open(state_file, 'w') as f:
            f.write("{ invalid json }")

        # Should not raise an exception, should start with empty state
        monitor = URLMonitor(config_file, state_file)
        assert monitor.state == {}

    def test_state_file_load_missing_file(self, config_file, state_file):
        """Test that missing state file is handled gracefully."""
        # Delete state file
        os.unlink(state_file)

        # Should not raise an exception, should start with empty state
        monitor = URLMonitor(config_file, state_file)
        assert monitor.state == {}

    @patch('json.load', side_effect=IOError("Disk read error"))
    def test_state_file_load_generic_exception(self, mock_load, config_file, state_file):
        """Test that generic exceptions during state load are handled gracefully."""
        # Write something to state file so open() succeeds but json.load() fails
        with open(state_file, 'w') as f:
            f.write('{"test": "data"}')

        # Should not raise an exception, should start with empty state
        monitor = URLMonitor(config_file, state_file)
        assert monitor.state == {}

    @patch('json.dump', side_effect=IOError("Disk full"))
    def test_state_file_save_exception(self, mock_dump, config_file, state_file):
        """Test that exceptions during state save are handled gracefully."""
        # Create monitor with state (new structure)
        monitor = URLMonitor(config_file, state_file)
        monitor.state = {
            "https://example.com": {
                "alerted": True,
                "consecutive_failures": 5,
                "consecutive_successes": 0
            }
        }

        # Should not raise an exception
        monitor._save_state()

    @patch('monitor.time.sleep')  # Mock sleep to avoid delays
    @patch('monitor.URLMonitor.check_url')
    @patch('monitor.URLMonitor.send_discord_notification')
    def test_failure_with_ssl_error_sets_critical(self, mock_notify, mock_check, mock_sleep, config_file, state_file):
        """Test failure with SSL error sets critical severity."""
        monitor = URLMonitor(config_file, state_file)

        # Simulate an SSL error
        mock_check.return_value = {
            "success": False,
            "status_code": None,
            "error": None,
            "ssl_error": "SSL certificate expired"
        }

        monitor.monitor_once()

        # Should have sent firing alert after 5 failures
        assert mock_notify.call_count == 2
        # Check that state has critical severity
        for url in monitor.urls:
            assert monitor.state[url]["severity"] == "critical"
            assert monitor.state[url]["alerted"] is True

    @patch('monitor.time.sleep')  # Mock sleep to avoid delays
    @patch('monitor.URLMonitor.check_url')
    @patch('monitor.URLMonitor.send_discord_notification')
    def test_failure_with_4xx_error_sets_warning(self, mock_notify, mock_check, mock_sleep, config_file, state_file):
        """Test failure with 4xx error sets warning severity."""
        monitor = URLMonitor(config_file, state_file)

        # Simulate a 404 error
        mock_check.return_value = {
            "success": False,
            "status_code": 404,
            "error": "Not Found",
            "ssl_error": None
        }

        monitor.monitor_once()

        # Should have sent firing alert after 5 failures
        assert mock_notify.call_count == 2
        # Check that state has warning severity
        for url in monitor.urls:
            assert monitor.state[url]["severity"] == "warning"
            assert monitor.state[url]["alerted"] is True

    @patch('monitor.time.sleep')  # Mock sleep to avoid delays
    @patch('monitor.URLMonitor.check_url')
    @patch('monitor.URLMonitor.send_discord_notification')
    def test_failure_with_3xx_error_sets_critical(self, mock_notify, mock_check, mock_sleep, config_file, state_file):
        """Test failure with 3xx error sets critical severity (default)."""
        monitor = URLMonitor(config_file, state_file)

        # Simulate a 301 redirect error
        mock_check.return_value = {
            "success": False,
            "status_code": 301,
            "error": "Moved Permanently",
            "ssl_error": None
        }

        monitor.monitor_once()

        # Should have sent firing alert after 5 failures
        assert mock_notify.call_count == 2
        # Check that state has critical severity (default when not 4xx or 5xx)
        for url in monitor.urls:
            assert monitor.state[url]["severity"] == "critical"
            assert monitor.state[url]["alerted"] is True


class TestRedirectHandling:
    """Test cases for HTTP redirect handling."""

    @patch('requests.get')
    def test_check_url_follows_redirects(self, mock_get, config_file):
        """Test that check_url follows redirects."""
        monitor = URLMonitor(config_file)

        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        result = monitor.check_url("https://example.com")

        # Verify allow_redirects=True was passed
        mock_get.assert_called_once()
        call_kwargs = mock_get.call_args[1]
        assert call_kwargs['allow_redirects'] is True
        assert result['success'] is True
        assert result['status_code'] == 200

    @patch('requests.get')
    def test_check_url_redirect_to_success(self, mock_get, config_file):
        """Test URL that redirects to a successful page."""
        monitor = URLMonitor(config_file)

        # Simulate a redirect chain that ends in 200
        mock_response = Mock()
        mock_response.status_code = 200  # Final status after following redirects
        mock_get.return_value = mock_response

        result = monitor.check_url("https://example.com/old-page")

        assert result['success'] is True
        assert result['status_code'] == 200

class TestPagerDutyIntegration:
    """Test PagerDuty backup notification functionality."""

    @patch('requests.post')
    def test_pagerduty_alert_firing(self, mock_post, config_file):
        """Test sending a firing alert to PagerDuty."""
        # Create config with PagerDuty key
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
        config['pagerduty_integration_key'] = 'test_key_12345'
        with open(config_file, 'w') as f:
            yaml.dump(config, f)

        monitor = URLMonitor(config_file)

        # Mock successful PagerDuty response
        mock_response = Mock()
        mock_response.status_code = 202
        mock_post.return_value = mock_response

        error_details = {
            "error": "Internal Server Error",
            "status_code": 500,
            "ssl_error": None
        }

        result = monitor.send_pagerduty_alert(
            "https://example.com",
            error_details,
            "critical",
            "firing"
        )

        assert result is True
        assert mock_post.called
        call_args = mock_post.call_args
        assert call_args[0][0] == "https://events.pagerduty.com/v2/enqueue"

        payload = call_args[1]['json']
        assert payload['routing_key'] == 'test_key_12345'
        assert payload['event_action'] == 'trigger'
        assert payload['dedup_key'] == 'external-monitor-https://example.com'
        assert payload['payload']['severity'] == 'critical'
        assert payload['payload']['source'] == monitor.hostname

    @patch('requests.post')
    def test_pagerduty_alert_resolved(self, mock_post, config_file):
        """Test sending a resolved alert to PagerDuty."""
        # Create config with PagerDuty key
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
        config['pagerduty_integration_key'] = 'test_key_12345'
        with open(config_file, 'w') as f:
            yaml.dump(config, f)

        monitor = URLMonitor(config_file)

        # Mock successful PagerDuty response
        mock_response = Mock()
        mock_response.status_code = 202
        mock_post.return_value = mock_response

        result = monitor.send_pagerduty_alert(
            "https://example.com",
            {},
            "critical",
            "resolved"
        )

        assert result is True
        payload = mock_post.call_args[1]['json']
        assert payload['event_action'] == 'resolve'

    def test_pagerduty_without_key(self, config_file):
        """Test PagerDuty alert when no key is configured."""
        monitor = URLMonitor(config_file)

        result = monitor.send_pagerduty_alert(
            "https://example.com",
            {"error": "Test"},
            "critical",
            "firing"
        )

        assert result is False

    @patch('requests.post')
    def test_pagerduty_api_error(self, mock_post, config_file):
        """Test PagerDuty API returning error status."""
        # Create config with PagerDuty key
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
        config['pagerduty_integration_key'] = 'test_key_12345'
        with open(config_file, 'w') as f:
            yaml.dump(config, f)

        monitor = URLMonitor(config_file)

        # Mock error response
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.text = "Invalid request"
        mock_post.return_value = mock_response

        result = monitor.send_pagerduty_alert(
            "https://example.com",
            {"error": "Test"},
            "critical",
            "firing"
        )

        assert result is False

    @patch('requests.post')
    def test_pagerduty_connection_error(self, mock_post, config_file):
        """Test PagerDuty API connection exception."""
        # Create config with PagerDuty key
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
        config['pagerduty_integration_key'] = 'test_key_12345'
        with open(config_file, 'w') as f:
            yaml.dump(config, f)

        monitor = URLMonitor(config_file)

        # Mock connection error
        mock_post.side_effect = requests.exceptions.ConnectionError("Connection refused")

        result = monitor.send_pagerduty_alert(
            "https://example.com",
            {"error": "Test"},
            "critical",
            "firing"
        )

        assert result is False

    @patch('requests.post')
    def test_alertmanager_failure_triggers_pagerduty(self, mock_post, config_file):
        """Test that Alertmanager failure triggers PagerDuty backup."""
        # Create config with PagerDuty key
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
        config['pagerduty_integration_key'] = 'test_key_12345'
        with open(config_file, 'w') as f:
            yaml.dump(config, f)

        monitor = URLMonitor(config_file)

        # First call to Alertmanager fails, second call to PagerDuty succeeds
        alertmanager_response = Mock()
        alertmanager_response.status_code = 500
        alertmanager_response.text = "Internal Server Error"

        pagerduty_response = Mock()
        pagerduty_response.status_code = 202

        mock_post.side_effect = [alertmanager_response, pagerduty_response]

        error_details = {
            "error": "Connection timeout",
            "status_code": None,
            "ssl_error": None
        }

        monitor.send_discord_notification("https://example.com", error_details, "firing")

        # Should have called both Alertmanager and PagerDuty
        assert mock_post.call_count == 2

        # First call to Alertmanager (webhook URL ends with /critical)
        first_call = mock_post.call_args_list[0]
        assert first_call[0][0].endswith('/critical')

        # Second call to PagerDuty
        second_call = mock_post.call_args_list[1]
        assert second_call[0][0] == "https://events.pagerduty.com/v2/enqueue"

    @patch('requests.post')
    def test_alertmanager_exception_triggers_pagerduty(self, mock_post, config_file):
        """Test that Alertmanager exception triggers PagerDuty backup."""
        # Create config with PagerDuty key
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
        config['pagerduty_integration_key'] = 'test_key_12345'
        with open(config_file, 'w') as f:
            yaml.dump(config, f)

        monitor = URLMonitor(config_file)

        # First call to Alertmanager raises exception, second call to PagerDuty succeeds
        pagerduty_response = Mock()
        pagerduty_response.status_code = 202

        mock_post.side_effect = [
            requests.exceptions.ConnectionError("Cannot reach Alertmanager"),
            pagerduty_response
        ]

        error_details = {
            "error": "Connection timeout",
            "status_code": None,
            "ssl_error": None
        }

        monitor.send_discord_notification("https://example.com", error_details, "firing")

        # Should have called both Alertmanager and PagerDuty
        assert mock_post.call_count == 2

        # Second call should be to PagerDuty
        second_call = mock_post.call_args_list[1]
        assert second_call[0][0] == "https://events.pagerduty.com/v2/enqueue"

    @patch('requests.post')
    def test_alertmanager_success_skips_pagerduty(self, mock_post, config_file):
        """Test that successful Alertmanager call does not trigger PagerDuty."""
        # Create config with PagerDuty key
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
        config['pagerduty_integration_key'] = 'test_key_12345'
        with open(config_file, 'w') as f:
            yaml.dump(config, f)

        monitor = URLMonitor(config_file)

        # Alertmanager succeeds
        alertmanager_response = Mock()
        alertmanager_response.status_code = 200
        mock_post.return_value = alertmanager_response

        error_details = {
            "error": "Connection timeout",
            "status_code": None,
            "ssl_error": None
        }

        monitor.send_discord_notification("https://example.com", error_details, "firing")

        # Should only call Alertmanager, not PagerDuty
        assert mock_post.call_count == 1
        assert mock_post.call_args[0][0].endswith('/critical')

    @patch('requests.post')
    def test_pagerduty_alert_with_ssl_error(self, mock_post, config_file):
        """Test PagerDuty alert with SSL error details."""
        # Create config with PagerDuty key
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
        config['pagerduty_integration_key'] = 'test_key_12345'
        with open(config_file, 'w') as f:
            yaml.dump(config, f)

        monitor = URLMonitor(config_file)

        # Mock successful PagerDuty response
        mock_response = Mock()
        mock_response.status_code = 202
        mock_post.return_value = mock_response

        error_details = {
            "error": "Connection failed",
            "status_code": None,
            "ssl_error": "Certificate has expired"
        }

        result = monitor.send_pagerduty_alert(
            "https://example.com",
            error_details,
            "critical",
            "firing"
        )

        assert result is True
        payload = mock_post.call_args[1]['json']
        assert payload['payload']['custom_details']['ssl_error'] == "Certificate has expired"


class TestPrometheusMetrics:
    """Test Prometheus textfile exporter functionality."""

    def test_prometheus_metrics_written_successfully(self, config_file):
        """Test that Prometheus metrics are written successfully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Update config with prometheus directory
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
            config['prometheus_textfile_dir'] = tmpdir
            with open(config_file, 'w') as f:
                yaml.dump(config, f)

            monitor = URLMonitor(config_file)

            # Set some state
            monitor.state = {
                "https://example.com": {
                    "alerted": False,
                    "consecutive_failures": 0,
                    "consecutive_successes": 5
                },
                "https://test.com": {
                    "alerted": True,
                    "consecutive_failures": 3,
                    "consecutive_successes": 0
                }
            }

            # Write metrics
            monitor._write_prometheus_metrics()

            # Verify file was created
            metrics_file = os.path.join(tmpdir, "url_monitor.prom")
            assert os.path.exists(metrics_file)

            # Read and verify content
            with open(metrics_file, 'r') as f:
                content = f.read()

            # Check for metric headers
            assert "# HELP url_monitor_up" in content
            assert "# TYPE url_monitor_up gauge" in content
            assert "# HELP url_monitor_consecutive_failures" in content
            assert "# TYPE url_monitor_consecutive_failures gauge" in content

            # Check for metrics
            assert 'url_monitor_up{url="https://example.com"' in content
            assert 'url_monitor_up{url="https://test.com"' in content

            # Check values - example.com is up (not alerted)
            assert f'url_monitor_up{{url="https://example.com",instance="{monitor.hostname}"}} 1' in content
            # test.com is down (alerted)
            assert f'url_monitor_up{{url="https://test.com",instance="{monitor.hostname}"}} 0' in content

            # Check consecutive failures
            assert f'url_monitor_consecutive_failures{{url="https://example.com",instance="{monitor.hostname}"}} 0' in content
            assert f'url_monitor_consecutive_failures{{url="https://test.com",instance="{monitor.hostname}"}} 3' in content

    def test_prometheus_metrics_not_configured(self, config_file):
        """Test that metrics are not written when prometheus_textfile_dir is not configured."""
        monitor = URLMonitor(config_file)

        # Should not raise an error, just return early
        monitor._write_prometheus_metrics()

        # No metrics file should be created (can't test directly, but shouldn't crash)
        assert monitor.prometheus_textfile_dir is None

    def test_prometheus_metrics_directory_created(self, config_file):
        """Test that Prometheus metrics directory is created if it doesn't exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Use a subdirectory that doesn't exist yet
            metrics_dir = os.path.join(tmpdir, "prometheus", "textfiles")

            # Update config
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
            config['prometheus_textfile_dir'] = metrics_dir
            with open(config_file, 'w') as f:
                yaml.dump(config, f)

            monitor = URLMonitor(config_file)
            monitor.state = {}

            # Write metrics
            monitor._write_prometheus_metrics()

            # Directory should be created
            assert os.path.exists(metrics_dir)
            assert os.path.isdir(metrics_dir)

            # Metrics file should exist
            metrics_file = os.path.join(metrics_dir, "url_monitor.prom")
            assert os.path.exists(metrics_file)

    def test_prometheus_metrics_write_error_handling(self, config_file):
        """Test error handling when writing Prometheus metrics fails."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Update config
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
            config['prometheus_textfile_dir'] = tmpdir
            with open(config_file, 'w') as f:
                yaml.dump(config, f)

            monitor = URLMonitor(config_file)
            monitor.state = {}

            # Make the directory read-only to cause write failure
            os.chmod(tmpdir, 0o444)

            try:
                # Should not raise exception, just log error
                monitor._write_prometheus_metrics()
            finally:
                # Restore permissions for cleanup
                os.chmod(tmpdir, 0o755)

    def test_prometheus_metrics_url_label_escaping(self, config_file):
        """Test that URL labels with quotes are properly escaped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Update config with URL containing quotes (edge case)
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
            config['prometheus_textfile_dir'] = tmpdir
            # Not a realistic URL, but tests the escaping logic
            config['urls'] = ['https://example.com/path?param="value"']
            with open(config_file, 'w') as f:
                yaml.dump(config, f)

            monitor = URLMonitor(config_file)
            monitor.state = {
                'https://example.com/path?param="value"': {
                    "alerted": False,
                    "consecutive_failures": 0
                }
            }

            # Write metrics
            monitor._write_prometheus_metrics()

            # Read and verify content
            metrics_file = os.path.join(tmpdir, "url_monitor.prom")
            with open(metrics_file, 'r') as f:
                content = f.read()

            # Quote should be escaped
            assert 'url="https://example.com/path?param=\\"value\\""' in content

    def test_prometheus_metrics_logged_on_init(self, config_file, caplog):
        """Test that Prometheus configuration is logged on initialization."""
        import logging
        with tempfile.TemporaryDirectory() as tmpdir:
            # Update config
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
            config['prometheus_textfile_dir'] = tmpdir
            with open(config_file, 'w') as f:
                yaml.dump(config, f)

            with caplog.at_level(logging.INFO):
                monitor = URLMonitor(config_file)

            # Check that prometheus is mentioned in logs
            assert any("Prometheus textfile exporter enabled" in record.message for record in caplog.records)

    def test_prometheus_metrics_move_fails_cleanup(self, config_file):
        """Test that temp file is cleaned up when move fails."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Update config
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
            config['prometheus_textfile_dir'] = tmpdir
            with open(config_file, 'w') as f:
                yaml.dump(config, f)

            monitor = URLMonitor(config_file)
            monitor.state = {}

            # Make the target file immutable to cause move to fail
            textfile_path = os.path.join(tmpdir, "url_monitor.prom")

            # Create an existing file and make directory read-only after
            with open(textfile_path, 'w') as f:
                f.write("test")
            os.chmod(textfile_path, 0o444)
            os.chmod(tmpdir, 0o555)

            try:
                # This should fail but not crash
                monitor._write_prometheus_metrics()

                # Verify temp file in /tmp was cleaned up
                import glob
                temp_files = glob.glob(f"/tmp/url_monitor_{os.getpid()}.prom.tmp")
                assert len(temp_files) == 0, "Temp file should be cleaned up after failed move"
            finally:
                # Restore permissions for cleanup
                os.chmod(tmpdir, 0o755)
                os.chmod(textfile_path, 0o644)
