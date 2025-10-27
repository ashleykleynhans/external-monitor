"""
Unit tests for URL Monitor
"""

import pytest
import tempfile
import os
import signal
import time
from unittest.mock import Mock, patch, MagicMock, mock_open
from monitor import (
    URLMonitor,
    signal_handler,
    write_pid_file,
    remove_pid_file,
    read_pid_file,
    is_process_running,
    stop_daemon,
    status_daemon
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
        """Test Discord notification sending."""
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
        assert monitor.webhook_url in call_args[0]

        # Verify payload structure
        payload = call_args[1]['json']
        assert 'embeds' in payload
        assert len(payload['embeds']) > 0

    @patch('monitor.socket.gethostname')
    def test_hostname_included(self, mock_hostname, config_file):
        """Test that hostname is captured."""
        mock_hostname.return_value = "test-server-123"
        monitor = URLMonitor(config_file)

        assert monitor.hostname == "test-server-123"

    @patch('monitor.requests.get')
    @patch('monitor.URLMonitor.check_ssl_certificate')
    def test_check_url_https_ssl_check(self, mock_ssl_check, mock_get, config_file):
        """Test that SSL check is performed for HTTPS URLs."""
        monitor = URLMonitor(config_file)

        # Mock SSL check returns no error
        mock_ssl_check.return_value = None

        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        result = monitor.check_url("https://example.com")

        # Verify SSL check was called
        assert mock_ssl_check.called
        assert result["success"] is True

    @patch('monitor.requests.get')
    @patch('monitor.URLMonitor.check_ssl_certificate')
    def test_check_url_https_ssl_error(self, mock_ssl_check, mock_get, config_file):
        """Test SSL error detection."""
        monitor = URLMonitor(config_file)

        # Mock SSL check returns error
        mock_ssl_check.return_value = "SSL certificate expired"

        # Mock successful HTTP response (but SSL failed)
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        result = monitor.check_url("https://example.com")

        assert result["success"] is False
        assert result["ssl_error"] == "SSL certificate expired"


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

    @patch('monitor.read_pid_file')
    @patch('monitor.is_process_running')
    def test_stop_daemon_not_running(self, mock_is_running, mock_read_pid):
        """Test stopping daemon that's not running."""
        mock_read_pid.return_value = None

        result = stop_daemon("/tmp/test.pid")
        assert result is False
