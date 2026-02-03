"""
Unit tests for Audit Middleware.

These tests verify:
- Health check exclusion (paths with/without "/health")
- Static asset exclusion
- Request/response capture
"""

import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from registry.audit import AuditLogger, AuditMiddleware


class MockRequest:
    """Mock FastAPI Request object for testing."""
    
    def __init__(
        self,
        path: str = "/api/test",
        method: str = "GET",
        query_params: dict = None,
        headers: dict = None,
        cookies: dict = None,
        client_host: str = "127.0.0.1",
    ):
        self.url = MagicMock()
        self.url.path = path
        self.method = method
        self.query_params = query_params or {}
        self._headers = headers or {}
        self._cookies = cookies or {}
        self.client = MagicMock()
        self.client.host = client_host
        self.state = MagicMock()
        
        # Set up default state attributes
        self.state.user_context = None
        self.state.audit_action = None
        self.state.audit_authorization = None
    
    @property
    def headers(self):
        return self._headers
    
    @property
    def cookies(self):
        return self._cookies


class MockResponse:
    """Mock FastAPI Response object for testing."""
    
    def __init__(self, status_code: int = 200, headers: dict = None):
        self.status_code = status_code
        self.headers = headers or {}


class TestAuditMiddlewareShouldLog:
    """Tests for _should_log method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.tmpdir = tempfile.mkdtemp()
        self.audit_logger = AuditLogger(log_dir=self.tmpdir)
        self.mock_app = MagicMock()

    def test_should_log_regular_api_path(self):
        """Regular API paths should be logged."""
        middleware = AuditMiddleware(self.mock_app, self.audit_logger)
        assert middleware._should_log("/api/servers") is True
        assert middleware._should_log("/api/agents") is True
        assert middleware._should_log("/api/auth/login") is True

    def test_should_not_log_health_check_by_default(self):
        """Health check paths should NOT be logged by default."""
        middleware = AuditMiddleware(self.mock_app, self.audit_logger)
        assert middleware._should_log("/health") is False
        assert middleware._should_log("/api/health") is False
        assert middleware._should_log("/api/health/ready") is False
        assert middleware._should_log("/healthcheck") is False

    def test_should_log_health_check_when_enabled(self):
        """Health check paths should be logged when log_health_checks=True."""
        middleware = AuditMiddleware(
            self.mock_app, 
            self.audit_logger, 
            log_health_checks=True
        )
        assert middleware._should_log("/health") is True
        assert middleware._should_log("/api/health") is True

    def test_should_not_log_static_assets_by_default(self):
        """Static asset paths should NOT be logged by default."""
        middleware = AuditMiddleware(self.mock_app, self.audit_logger)
        assert middleware._should_log("/static/app.js") is False
        assert middleware._should_log("/static/styles.css") is False
        assert middleware._should_log("/favicon.ico") is False

    def test_should_log_static_assets_when_enabled(self):
        """Static asset paths should be logged when log_static_assets=True."""
        middleware = AuditMiddleware(
            self.mock_app, 
            self.audit_logger, 
            log_static_assets=True
        )
        assert middleware._should_log("/static/app.js") is True
        assert middleware._should_log("/favicon.ico") is True

    def test_should_not_log_excluded_paths(self):
        """Explicitly excluded paths should NOT be logged."""
        middleware = AuditMiddleware(
            self.mock_app, 
            self.audit_logger, 
            exclude_paths=["/api/internal", "/metrics"]
        )
        assert middleware._should_log("/api/internal") is False
        assert middleware._should_log("/metrics") is False
        # Other paths should still be logged
        assert middleware._should_log("/api/servers") is True

    def test_should_not_log_static_file_extensions(self):
        """Files with static extensions should NOT be logged by default."""
        middleware = AuditMiddleware(self.mock_app, self.audit_logger)
        assert middleware._should_log("/assets/logo.png") is False
        assert middleware._should_log("/fonts/roboto.woff2") is False
        assert middleware._should_log("/images/banner.jpg") is False
        assert middleware._should_log("/scripts/bundle.js") is False
        assert middleware._should_log("/styles/main.css") is False


class TestAuditMiddlewareCredentialType:
    """Tests for _get_credential_type method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.tmpdir = tempfile.mkdtemp()
        self.audit_logger = AuditLogger(log_dir=self.tmpdir)
        self.mock_app = MagicMock()
        self.middleware = AuditMiddleware(self.mock_app, self.audit_logger)

    def test_credential_type_session_cookie(self):
        """Session cookie should be detected."""
        request = MockRequest(cookies={"session": "abc123"})
        assert self.middleware._get_credential_type(request) == "session_cookie"

    def test_credential_type_bearer_token(self):
        """Bearer token should be detected."""
        request = MockRequest(headers={"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9..."})
        assert self.middleware._get_credential_type(request) == "bearer_token"

    def test_credential_type_none(self):
        """No credential should return 'none'."""
        request = MockRequest()
        assert self.middleware._get_credential_type(request) == "none"

    def test_credential_type_session_takes_precedence(self):
        """Session cookie takes precedence over bearer token."""
        request = MockRequest(
            cookies={"session": "abc123"},
            headers={"Authorization": "Bearer token"}
        )
        assert self.middleware._get_credential_type(request) == "session_cookie"


class TestAuditMiddlewareCredentialHint:
    """Tests for _get_credential_hint method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.tmpdir = tempfile.mkdtemp()
        self.audit_logger = AuditLogger(log_dir=self.tmpdir)
        self.mock_app = MagicMock()
        self.middleware = AuditMiddleware(self.mock_app, self.audit_logger)

    def test_credential_hint_from_session(self):
        """Session cookie value should be returned as hint."""
        request = MockRequest(cookies={"session": "session_value_123"})
        assert self.middleware._get_credential_hint(request) == "session_value_123"

    def test_credential_hint_from_bearer_token(self):
        """Bearer token should be extracted (without 'Bearer ' prefix)."""
        request = MockRequest(headers={"Authorization": "Bearer my_jwt_token_here"})
        assert self.middleware._get_credential_hint(request) == "my_jwt_token_here"

    def test_credential_hint_none(self):
        """No credential should return None."""
        request = MockRequest()
        assert self.middleware._get_credential_hint(request) is None


class TestAuditMiddlewareIdentityExtraction:
    """Tests for _extract_identity method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.tmpdir = tempfile.mkdtemp()
        self.audit_logger = AuditLogger(log_dir=self.tmpdir)
        self.mock_app = MagicMock()
        self.middleware = AuditMiddleware(self.mock_app, self.audit_logger)

    def test_extract_identity_from_user_context(self):
        """Identity should be extracted from request.state.user_context."""
        request = MockRequest()
        request.state.user_context = {
            "username": "testuser",
            "auth_method": "oauth2",
            "provider": "cognito",
            "groups": ["admin", "users"],
            "scopes": ["read", "write"],
            "is_admin": True,
        }
        
        identity = self.middleware._extract_identity(request)
        
        assert identity.username == "testuser"
        assert identity.auth_method == "oauth2"
        assert identity.provider == "cognito"
        assert identity.groups == ["admin", "users"]
        assert identity.scopes == ["read", "write"]
        assert identity.is_admin is True

    def test_extract_identity_anonymous_fallback(self):
        """Anonymous identity should be returned when no user context."""
        request = MockRequest()
        request.state.user_context = None
        
        identity = self.middleware._extract_identity(request)
        
        assert identity.username == "anonymous"
        assert identity.auth_method == "anonymous"

    def test_extract_identity_with_credential_type(self):
        """Credential type should be detected from request."""
        request = MockRequest(cookies={"session": "abc123"})
        request.state.user_context = {"username": "testuser", "auth_method": "traditional"}
        
        identity = self.middleware._extract_identity(request)
        
        assert identity.credential_type == "session_cookie"


class TestAuditMiddlewareActionExtraction:
    """Tests for _extract_action method."""

    def setup_method(self):
        """Set up test fixtures."""
        self.tmpdir = tempfile.mkdtemp()
        self.audit_logger = AuditLogger(log_dir=self.tmpdir)
        self.mock_app = MagicMock()
        self.middleware = AuditMiddleware(self.mock_app, self.audit_logger)

    def test_extract_action_from_state(self):
        """Action should be extracted from request.state.audit_action."""
        request = MockRequest()
        request.state.audit_action = {
            "operation": "create",
            "resource_type": "server",
            "resource_id": "my-server",
            "description": "Created new MCP server",
        }
        
        action = self.middleware._extract_action(request)
        
        assert action is not None
        assert action.operation == "create"
        assert action.resource_type == "server"
        assert action.resource_id == "my-server"
        assert action.description == "Created new MCP server"

    def test_extract_action_none_when_not_set(self):
        """None should be returned when audit_action is not set."""
        request = MockRequest()
        request.state.audit_action = None
        
        action = self.middleware._extract_action(request)
        
        assert action is None


class TestAuditMiddlewareDispatch:
    """Tests for dispatch method (request/response capture)."""

    def setup_method(self):
        """Set up test fixtures."""
        self.tmpdir = tempfile.mkdtemp()
        self.audit_logger = AuditLogger(log_dir=self.tmpdir)
        self.mock_app = MagicMock()
        self.middleware = AuditMiddleware(self.mock_app, self.audit_logger)

    @pytest.mark.asyncio
    async def test_dispatch_captures_request_response(self):
        """Dispatch should capture request and response details."""
        request = MockRequest(
            path="/api/servers",
            method="POST",
            query_params={"name": "test"},
            headers={"User-Agent": "TestClient/1.0", "Content-Length": "100"},
            client_host="192.168.1.1",
        )
        request.state.user_context = {"username": "testuser", "auth_method": "oauth2"}
        
        response = MockResponse(status_code=201, headers={"Content-Length": "50"})
        
        async def mock_call_next(req):
            return response
        
        # Patch the audit logger to capture the logged event
        logged_events = []
        original_log_event = self.audit_logger.log_event
        
        async def capture_log_event(record):
            logged_events.append(record)
            await original_log_event(record)
        
        self.audit_logger.log_event = capture_log_event
        
        result = await self.middleware.dispatch(request, mock_call_next)
        
        assert result == response
        assert len(logged_events) == 1
        
        record = logged_events[0]
        assert record.request.method == "POST"
        assert record.request.path == "/api/servers"
        assert record.request.client_ip == "192.168.1.1"
        assert record.response.status_code == 201
        assert record.identity.username == "testuser"

    @pytest.mark.asyncio
    async def test_dispatch_skips_excluded_paths(self):
        """Dispatch should skip logging for excluded paths."""
        request = MockRequest(path="/health")
        response = MockResponse(status_code=200)
        
        async def mock_call_next(req):
            return response
        
        # Patch the audit logger to track calls
        log_event_called = []
        
        async def track_log_event(record):
            log_event_called.append(record)
        
        self.audit_logger.log_event = track_log_event
        
        result = await self.middleware.dispatch(request, mock_call_next)
        
        assert result == response
        assert len(log_event_called) == 0  # Should not have logged

    @pytest.mark.asyncio
    async def test_dispatch_generates_request_id(self):
        """Dispatch should generate request_id if not provided."""
        request = MockRequest(path="/api/test", headers={})
        response = MockResponse(status_code=200)
        
        async def mock_call_next(req):
            return response
        
        logged_events = []
        
        async def capture_log_event(record):
            logged_events.append(record)
        
        self.audit_logger.log_event = capture_log_event
        
        await self.middleware.dispatch(request, mock_call_next)
        
        assert len(logged_events) == 1
        assert logged_events[0].request_id is not None
        assert len(logged_events[0].request_id) > 0

    @pytest.mark.asyncio
    async def test_dispatch_uses_provided_request_id(self):
        """Dispatch should use X-Request-ID header if provided."""
        request = MockRequest(
            path="/api/test", 
            headers={"X-Request-ID": "custom-request-id-123"}
        )
        response = MockResponse(status_code=200)
        
        async def mock_call_next(req):
            return response
        
        logged_events = []
        
        async def capture_log_event(record):
            logged_events.append(record)
        
        self.audit_logger.log_event = capture_log_event
        
        await self.middleware.dispatch(request, mock_call_next)
        
        assert len(logged_events) == 1
        assert logged_events[0].request_id == "custom-request-id-123"

    @pytest.mark.asyncio
    async def test_dispatch_captures_correlation_id(self):
        """Dispatch should capture X-Correlation-ID header."""
        request = MockRequest(
            path="/api/test",
            headers={"X-Correlation-ID": "corr-456"}
        )
        response = MockResponse(status_code=200)
        
        async def mock_call_next(req):
            return response
        
        logged_events = []
        
        async def capture_log_event(record):
            logged_events.append(record)
        
        self.audit_logger.log_event = capture_log_event
        
        await self.middleware.dispatch(request, mock_call_next)
        
        assert len(logged_events) == 1
        assert logged_events[0].correlation_id == "corr-456"
