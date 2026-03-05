"""Unit tests for cli.agentcore.registration — RegistrationBuilder & SyncOrchestrator.

Tests registration model building, idempotency checks, overwrite behavior,
and error handling (registry 4xx/5xx, retry logic).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SAMPLE_GATEWAY = {
    "gatewayId": "gw-123",
    "gatewayArn": "arn:aws:bedrock:us-east-1:111122223333:gateway/gw-123",
    "gatewayUrl": "https://gw.example.com/mcp",
    "name": "Customer Support Gateway",
    "description": "Customer support MCP gateway",
    "status": "READY",
    "authorizerType": "CUSTOM_JWT",
}

SAMPLE_MCP_RUNTIME = {
    "agentRuntimeId": "rt-mcp-1",
    "agentRuntimeArn": "arn:aws:bedrock:us-east-1:111122223333:runtime/rt-mcp-1",
    "agentRuntimeName": "MCP Runtime",
    "description": "An MCP runtime",
    "status": "READY",
    "protocolConfiguration": {"serverProtocol": "MCP"},
}

SAMPLE_HTTP_RUNTIME = {
    "agentRuntimeId": "rt-http-1",
    "agentRuntimeArn": "arn:aws:bedrock:us-east-1:111122223333:runtime/rt-http-1",
    "agentRuntimeName": "HTTP Agent",
    "description": "An HTTP agent",
    "status": "READY",
    "protocolConfiguration": {"serverProtocol": "HTTP"},
}

SAMPLE_A2A_RUNTIME = {
    "agentRuntimeId": "rt-a2a-1",
    "agentRuntimeArn": "arn:aws:bedrock:us-east-1:111122223333:runtime/rt-a2a-1",
    "agentRuntimeName": "A2A Agent",
    "description": "An A2A agent",
    "status": "READY",
    "protocolConfiguration": {"serverProtocol": "A2A"},
}

SAMPLE_MCP_TARGET = {
    "targetId": "t-mcp-1",
    "name": "MCP Target",
    "description": "An MCP server target",
    "status": "READY",
    "targetConfiguration": {
        "mcp": {
            "mcpServer": {
                "endpoint": "https://mcp-target.example.com/mcp",
            }
        }
    },
}

SAMPLE_LAMBDA_TARGET = {
    "targetId": "t-lambda-1",
    "name": "Lambda Target",
    "status": "READY",
    "targetConfiguration": {
        "lambda": {"functionArn": "arn:aws:lambda:us-east-1:111:function:foo"}
    },
}


def _make_builder(region: str = "us-east-1"):
    """Create a RegistrationBuilder with mocked STS."""
    with patch("cli.agentcore.registration.boto3") as mock_boto3:
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {"Account": "111122223333"}
        mock_boto3.client.return_value = mock_sts
        from cli.agentcore.registration import RegistrationBuilder

        return RegistrationBuilder(region=region)


# ---------------------------------------------------------------------------
# Task 4.2 — Registration model building
# ---------------------------------------------------------------------------


class TestGatewayRegistration:
    """Tests for build_gateway_registration()."""

    def test_gateway_produces_mcp_server_registration(self):
        builder = _make_builder()
        reg = builder.build_gateway_registration(SAMPLE_GATEWAY)

        assert reg.service_path == "/customer-support-gateway"
        assert reg.name == "Customer Support Gateway"
        assert reg.mcp_endpoint == "https://gw.example.com/mcp"
        assert reg.auth_provider == "bedrock-agentcore"
        assert reg.auth_scheme == "bearer"
        assert reg.supported_transports == ["streamable-http"]
        assert "agentcore" in reg.tags
        assert "gateway" in reg.tags
        assert "auto-registered" in reg.tags
        assert reg.metadata["gateway_arn"] == SAMPLE_GATEWAY["gatewayArn"]
        assert reg.metadata["source"] == "agentcore-sync"
        assert reg.metadata["region"] == "us-east-1"
        assert reg.metadata["account_id"] == "111122223333"

    def test_gateway_iam_auth_scheme(self):
        builder = _make_builder()
        gw = {**SAMPLE_GATEWAY, "authorizerType": "AWS_IAM"}
        reg = builder.build_gateway_registration(gw)
        assert reg.auth_scheme == "bearer"

    def test_gateway_none_auth_scheme(self):
        builder = _make_builder()
        gw = {**SAMPLE_GATEWAY, "authorizerType": "NONE"}
        reg = builder.build_gateway_registration(gw)
        assert reg.auth_scheme == "none"


class TestRuntimeMCPRegistration:
    """Tests for build_runtime_mcp_registration()."""

    def test_mcp_runtime_produces_mcp_server_registration(self):
        builder = _make_builder()
        reg = builder.build_runtime_mcp_registration(SAMPLE_MCP_RUNTIME)

        assert reg.service_path == "/mcp-runtime"
        assert reg.name == "MCP Runtime"
        assert "https://bedrock-agentcore.us-east-1.amazonaws.com/runtimes/" in reg.mcp_endpoint
        assert reg.mcp_endpoint.endswith("/invocations")
        assert reg.auth_provider == "bedrock-agentcore"
        assert reg.auth_scheme == "bearer"
        assert "mcp-server" in reg.tags
        assert "runtime" in reg.tags
        assert reg.metadata["server_protocol"] == "MCP"
        assert reg.metadata["runtime_arn"] == SAMPLE_MCP_RUNTIME["agentRuntimeArn"]


class TestRuntimeAgentRegistration:
    """Tests for build_runtime_agent_registration()."""

    def test_http_runtime_produces_agent_registration(self):
        builder = _make_builder()
        reg = builder.build_runtime_agent_registration(SAMPLE_HTTP_RUNTIME)

        assert reg.name == "HTTP Agent"
        assert reg.version == "1.0.0"
        assert "https://bedrock-agentcore.us-east-1.amazonaws.com/runtimes/" in reg.url
        assert reg.url.endswith("/invocations")
        assert "agent" in reg.tags
        assert "runtime" in reg.tags
        assert reg.metadata["server_protocol"] == "HTTP"

    def test_a2a_runtime_produces_agent_registration(self):
        builder = _make_builder()
        reg = builder.build_runtime_agent_registration(SAMPLE_A2A_RUNTIME)

        assert reg.name == "A2A Agent"
        assert reg.version == "1.0.0"
        assert reg.metadata["server_protocol"] == "A2A"


class TestTargetRegistration:
    """Tests for build_target_registration()."""

    def test_mcp_target_produces_registration(self):
        builder = _make_builder()
        reg = builder.build_target_registration(SAMPLE_GATEWAY, SAMPLE_MCP_TARGET)

        assert reg is not None
        assert reg.service_path == "/customer-support-gateway-mcp-target"
        assert reg.mcp_endpoint == "https://mcp-target.example.com/mcp"
        assert "gateway-target" in reg.tags
        assert "mcp-server" in reg.tags

    def test_lambda_target_returns_none(self):
        builder = _make_builder()
        reg = builder.build_target_registration(SAMPLE_GATEWAY, SAMPLE_LAMBDA_TARGET)
        assert reg is None

    def test_target_no_endpoint_returns_none(self):
        builder = _make_builder()
        target = {
            "targetId": "t-1",
            "name": "No Endpoint",
            "targetConfiguration": {"mcp": {"mcpServer": {}}},
        }
        reg = builder.build_target_registration(SAMPLE_GATEWAY, target)
        assert reg is None


# ---------------------------------------------------------------------------
# Task 4.3 — Idempotency check tests
# ---------------------------------------------------------------------------


def _make_orchestrator(dry_run=False, overwrite=False, include_mcp_targets=False):
    """Create a SyncOrchestrator with all dependencies mocked."""
    with patch("cli.agentcore.registration.boto3") as mock_boto3:
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {"Account": "111122223333"}
        mock_boto3.client.return_value = mock_sts

        from cli.agentcore.registration import (
            RegistrationBuilder,
            SyncOrchestrator,
        )

        scanner = MagicMock()
        builder = RegistrationBuilder(region="us-east-1")
        registry = MagicMock()
        cred_helper = MagicMock()
        token_manager = MagicMock()

        orch = SyncOrchestrator(
            scanner=scanner,
            builder=builder,
            registry_client=registry,
            credential_helper=cred_helper,
            token_manager=token_manager,
            dry_run=dry_run,
            overwrite=overwrite,
            include_mcp_targets=include_mcp_targets,
        )
        return orch, registry, scanner, cred_helper


class TestIdempotency:
    """Tests for idempotent registration — skip existing, overwrite flag."""

    def test_already_exists_without_overwrite_skips(self):
        orch, registry, scanner, _ = _make_orchestrator(overwrite=False)
        registry.register_service.side_effect = Exception("already exists")
        scanner.scan_gateways.return_value = [SAMPLE_GATEWAY]

        orch.sync_gateways()

        assert len(orch.results) == 1
        assert orch.results[0]["status"] == "skipped"
        assert "already registered" in orch.results[0]["message"].lower()

    def test_overwrite_sets_flag_on_registration(self):
        orch, registry, scanner, _ = _make_orchestrator(overwrite=True)
        scanner.scan_gateways.return_value = [SAMPLE_GATEWAY]

        orch.sync_gateways()

        # The registration should have been called (not skipped)
        assert registry.register_service.called
        assert len(orch.results) == 1
        assert orch.results[0]["status"] == "registered"

    def test_dry_run_does_not_call_registry(self):
        orch, registry, scanner, _ = _make_orchestrator(dry_run=True)
        scanner.scan_gateways.return_value = [SAMPLE_GATEWAY]

        orch.sync_gateways()

        registry.register_service.assert_not_called()
        assert len(orch.results) == 1
        assert orch.results[0]["status"] == "dry_run"


# ---------------------------------------------------------------------------
# Task 4.4 — Error handling tests (registration portion)
# ---------------------------------------------------------------------------


class TestRegistrationErrorHandling:
    """Tests for registry error handling and retry logic."""

    def test_registry_error_records_failed_and_continues(self):
        orch, registry, scanner, _ = _make_orchestrator()
        # First gateway fails, second succeeds
        gw1 = {**SAMPLE_GATEWAY, "gatewayId": "gw-fail", "name": "Fail GW",
                "gatewayArn": "arn:fail", "authorizerType": "NONE"}
        gw2 = {**SAMPLE_GATEWAY, "gatewayId": "gw-ok", "name": "OK GW",
                "gatewayArn": "arn:ok", "authorizerType": "NONE"}
        scanner.scan_gateways.return_value = [gw1, gw2]
        registry.register_service.side_effect = [
            Exception("Internal Server Error"),
            None,
        ]

        orch.sync_gateways()

        assert len(orch.results) == 2
        assert orch.results[0]["status"] == "failed"
        assert orch.results[1]["status"] == "registered"

    def test_invalid_url_skips_registration(self):
        orch, registry, scanner, _ = _make_orchestrator()
        gw = {**SAMPLE_GATEWAY, "gatewayUrl": "http://insecure.example.com"}
        scanner.scan_gateways.return_value = [gw]

        orch.sync_gateways()

        registry.register_service.assert_not_called()
        assert len(orch.results) == 1
        assert orch.results[0]["status"] == "skipped"
        assert "HTTPS" in orch.results[0]["message"]

    def test_empty_url_skips_registration(self):
        orch, registry, scanner, _ = _make_orchestrator()
        gw = {**SAMPLE_GATEWAY, "gatewayUrl": ""}
        scanner.scan_gateways.return_value = [gw]

        orch.sync_gateways()

        registry.register_service.assert_not_called()
        assert orch.results[0]["status"] == "skipped"

    def test_runtime_mcp_registration_error_records_failed(self):
        orch, registry, scanner, _ = _make_orchestrator()
        scanner.scan_runtimes.return_value = [SAMPLE_MCP_RUNTIME]
        registry.register_service.side_effect = Exception("500 Server Error")

        orch.sync_runtimes()

        assert len(orch.results) == 1
        assert orch.results[0]["status"] == "failed"

    def test_runtime_agent_registration_error_records_failed(self):
        orch, registry, scanner, _ = _make_orchestrator()
        scanner.scan_runtimes.return_value = [SAMPLE_HTTP_RUNTIME]
        registry.register_agent.side_effect = Exception("Connection refused")

        orch.sync_runtimes()

        assert len(orch.results) == 1
        assert orch.results[0]["status"] == "failed"

    def test_include_mcp_targets_registers_targets(self):
        orch, registry, scanner, _ = _make_orchestrator(include_mcp_targets=True)
        gw = {**SAMPLE_GATEWAY, "targets": [SAMPLE_MCP_TARGET], "authorizerType": "NONE"}
        scanner.scan_gateways.return_value = [gw]

        orch.sync_gateways()

        # Gateway + target = 2 results
        assert len(orch.results) == 2
        assert registry.register_service.call_count == 2
