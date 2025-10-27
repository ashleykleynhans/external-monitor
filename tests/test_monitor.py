"""
Unit tests for URL Monitor
"""

import pytest
import tempfile
import os
from unittest.mock import Mock, patch, MagicMock
from monitor import URLMonitor


class TestURLMonitor:
    """Test cases for URLMonitor class."""

    @pytest.fixture
    def config_file(self):
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
