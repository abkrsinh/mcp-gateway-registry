#!/usr/bin/env python3
"""
AgentCore Auto-Registration Script.

Scans AWS AgentCore Gateways and Agent Runtimes, then registers them
with the MCP Gateway Registry.

Usage:
    # Dry-run to preview what would be registered
    python scripts/agentcore_sync.py sync --dry-run

    # Full sync with overwrite
    python scripts/agentcore_sync.py sync --overwrite --visibility internal

    # JSON output for automation
    python scripts/agentcore_sync.py sync --dry-run --output json

    # List discovered resources
    python scripts/agentcore_sync.py list
"""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import re
import sys
from typing import Any
from urllib.parse import quote

import boto3
import requests
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError
from pydantic import BaseModel, Field
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.registry_client import (
    AgentRegistration,
    InternalServiceRegistration,
    RegistryClient,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s,p%(process)s,{%(filename)s:%(lineno)d},%(levelname)s,%(message)s",
)
logger = logging.getLogger(__name__)

# Constants
DEFAULT_REGISTRY_URL = "http://localhost"
DEFAULT_TOKEN_FILE = ".oauth-tokens/ingress.json"
DEFAULT_REGION = "us-east-1"
DEFAULT_TIMEOUT = 30
READY_STATUS = "READY"


class GatewayInfo(BaseModel):
    """Discovered AgentCore Gateway information."""

    gateway_id: str = Field(..., description="Gateway ID")
    gateway_arn: str = Field(..., description="Gateway ARN")
    gateway_url: str = Field(..., description="Gateway MCP endpoint URL")
    name: str = Field(..., description="Gateway name")
    description: str | None = Field(None, description="Gateway description")
    status: str = Field(..., description="Gateway status")
    authorizer_type: str = Field(..., description="CUSTOM_JWT, AWS_IAM, or NONE")
    authorizer_config: dict[str, Any] | None = Field(
        None, description="Authorizer configuration"
    )
    targets: list[TargetInfo] = Field(
        default_factory=list, description="Gateway targets"
    )


class TargetInfo(BaseModel):
    """Discovered Gateway Target information."""

    target_id: str = Field(..., description="Target ID")
    name: str = Field(..., description="Target name")
    description: str | None = Field(None, description="Target description")
    status: str = Field(..., description="Target status")
    target_type: str = Field(
        ..., description="mcpServer, lambda, apiGateway, etc."
    )
    endpoint: str | None = Field(
        None, description="MCP server endpoint (for mcpServer type)"
    )


class RuntimeInfo(BaseModel):
    """Discovered AgentCore Runtime information."""

    runtime_id: str = Field(..., description="Runtime ID")
    runtime_arn: str = Field(..., description="Runtime ARN")
    runtime_name: str = Field(..., description="Runtime name")
    description: str | None = Field(None, description="Runtime description")
    status: str = Field(..., description="Runtime status")
    server_protocol: str = Field(..., description="MCP, HTTP, or A2A")
    authorizer_config: dict[str, Any] | None = Field(
        None, description="Authorizer configuration"
    )
    invocation_url: str = Field(..., description="Constructed invocation URL")


class SyncResult(BaseModel):
    """Result of a sync operation."""

    resource_type: str = Field(..., description="gateway, runtime, or target")
    resource_name: str = Field(..., description="Resource name")
    resource_arn: str = Field(..., description="Resource ARN")
    registration_type: str = Field(..., description="mcp_server or agent")
    path: str = Field(..., description="Registry path")
    status: str = Field(..., description="registered, skipped, failed, dry_run")
    message: str | None = Field(None, description="Status message or error")


class SyncSummary(BaseModel):
    """Summary of sync operation."""

    total_gateways: int = Field(0, description="Total gateways found")
    total_runtimes: int = Field(0, description="Total runtimes found")
    total_targets: int = Field(0, description="Total mcpServer targets found")
    registered: int = Field(0, description="Successfully registered")
    skipped: int = Field(0, description="Skipped (already exists)")
    failed: int = Field(0, description="Failed to register")
    dry_run: bool = Field(False, description="Whether this was a dry run")
    results: list[SyncResult] = Field(
        default_factory=list, description="Individual results"
    )


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _slugify(name: str) -> str:
    """Convert name to URL-safe slug."""
    slug = name.lower().replace(" ", "-").replace("_", "-")
    slug = re.sub(r"[^a-z0-9-]", "", slug)
    slug = re.sub(r"-+", "-", slug)
    slug = slug.strip("-")
    return slug


def _validate_https_url(url: str, resource_name: str) -> bool:
    """Validate that URL uses HTTPS protocol.

    Args:
        url: URL to validate
        resource_name: Name of resource for error message

    Returns:
        True if valid HTTPS URL, False otherwise
    """
    if not url:
        logger.warning(f"Empty URL for resource: {resource_name}")
        return False

    if not url.startswith("https://"):
        logger.warning(
            f"Insecure URL for {resource_name}: {url} - "
            f"Expected HTTPS, skipping registration"
        )
        return False

    return True


def _retry_registry_call(func):
    """Decorator to add retry logic to registry calls."""
    return retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=4),
        retry=retry_if_exception_type(requests.exceptions.RequestException),
        before_sleep=lambda retry_state: logger.warning(
            f"Registry call failed, retrying in {retry_state.next_action.sleep}s..."
        ),
    )(func)


def _build_invocation_url(region: str, runtime_arn: str) -> str:
    """Build the invocation URL for an AgentCore Runtime."""
    encoded_arn = quote(runtime_arn, safe="")
    return f"https://bedrock-agentcore.{region}.amazonaws.com/runtimes/{encoded_arn}/invocations"


def _get_auth_scheme(authorizer_type: str) -> str:
    """Map AgentCore authorizer type to registry auth scheme."""
    mapping = {
        "CUSTOM_JWT": "bearer",
        "AWS_IAM": "bearer",
        "NONE": "none",
    }
    return mapping.get(authorizer_type, "none")


def _load_token(token_file: str) -> str:
    """Load JWT token from file."""
    abs_path = os.path.abspath(token_file)
    try:
        with open(abs_path) as f:
            data = json.load(f)
            token = data.get("access_token") or data.get("token")
            if not token:
                raise ValueError("No access_token found in token file")
            return token
    except FileNotFoundError:
        raise FileNotFoundError(f"Token file not found: {abs_path}")
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in token file: {abs_path}: {e}")

# ---------------------------------------------------------------------------
# AgentCore Scanner
# ---------------------------------------------------------------------------


class AgentCoreScanner:
    """Scans AWS AgentCore resources using boto3."""

    def __init__(
        self,
        region: str,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        """Initialize scanner with AWS region and timeout."""
        self.region = region
        self.timeout = timeout

        # Configure boto3 with timeout and standard retry
        boto_config = BotoConfig(
            connect_timeout=timeout,
            read_timeout=timeout,
            retries={"max_attempts": 3, "mode": "standard"},
        )
        self.client = boto3.client(
            "bedrock-agentcore-control",
            region_name=region,
            config=boto_config,
        )
        logger.info(
            f"Initialized AgentCore scanner for region: {region} (timeout: {timeout}s)"
        )

    def scan_gateways(self) -> list[dict[str, Any]]:
        """Scan all AgentCore Gateways in the region.

        Paginates through list_gateways(), filters to READY status,
        fetches full details via get_gateway(), and collects targets.
        """
        gateways = []
        paginator_params: dict[str, Any] = {}

        while True:
            response = self.client.list_gateways(**paginator_params)

            for item in response.get("items", []):
                if item.get("status") == READY_STATUS:
                    gateway = self.client.get_gateway(
                        gatewayIdentifier=item["gatewayId"]
                    )
                    gateway["targets"] = self._get_gateway_targets(item["gatewayId"])
                    gateways.append(gateway)
                else:
                    logger.debug(
                        f"Skipping gateway {item['gatewayId']} "
                        f"with status {item['status']}"
                    )

            if "nextToken" in response:
                paginator_params["nextToken"] = response["nextToken"]
            else:
                break

        logger.info(f"Found {len(gateways)} READY gateways")
        return gateways

    def _get_gateway_targets(
        self,
        gateway_id: str,
    ) -> list[dict[str, Any]]:
        """Get all targets for a gateway.

        Paginates through list_gateway_targets() and filters to READY targets.
        """
        targets = []
        paginator_params: dict[str, Any] = {"gatewayIdentifier": gateway_id}

        while True:
            response = self.client.list_gateway_targets(**paginator_params)

            for item in response.get("items", []):
                if item.get("status") == READY_STATUS:
                    target = self.client.get_gateway_target(
                        gatewayIdentifier=gateway_id,
                        targetId=item["targetId"],
                    )
                    targets.append(target)

            if "nextToken" in response:
                paginator_params["nextToken"] = response["nextToken"]
            else:
                break

        return targets

    def scan_runtimes(self) -> list[dict[str, Any]]:
        """Scan all AgentCore Runtimes in the region.

        Paginates through list_agent_runtimes(), filters to READY status,
        fetches full details via get_agent_runtime(), and collects endpoints.
        """
        runtimes = []
        paginator_params: dict[str, Any] = {}

        while True:
            response = self.client.list_agent_runtimes(**paginator_params)

            for item in response.get("agentRuntimes", []):
                if item.get("status") == READY_STATUS:
                    runtime = self.client.get_agent_runtime(
                        agentRuntimeId=item["agentRuntimeId"]
                    )
                    runtime["endpoints"] = self._get_runtime_endpoints(
                        item["agentRuntimeId"]
                    )
                    runtimes.append(runtime)
                else:
                    logger.debug(
                        f"Skipping runtime {item['agentRuntimeId']} "
                        f"with status {item['status']}"
                    )

            if "nextToken" in response:
                paginator_params["nextToken"] = response["nextToken"]
            else:
                break

        logger.info(f"Found {len(runtimes)} READY runtimes")
        return runtimes

    def _get_runtime_endpoints(
        self,
        runtime_id: str,
    ) -> list[dict[str, Any]]:
        """Get all endpoints for a runtime.

        Paginates through list_agent_runtime_endpoints() and filters to READY.
        """
        endpoints = []
        paginator_params: dict[str, Any] = {"agentRuntimeId": runtime_id}

        while True:
            response = self.client.list_agent_runtime_endpoints(**paginator_params)

            for item in response.get("runtimeEndpoints", []):
                if item.get("status") == READY_STATUS:
                    endpoints.append(item)

            if "nextToken" in response:
                paginator_params["nextToken"] = response["nextToken"]
            else:
                break

        return endpoints


    # ---------------------------------------------------------------------------
    # Registration Builder
    # ---------------------------------------------------------------------------


    class RegistrationBuilder:
        """Builds registration models from discovered resources."""

        def __init__(
            self,
            region: str,
            visibility: str = "internal",
        ) -> None:
            """Initialize builder with region and visibility."""
            self.region = region
            self.visibility = visibility
            self.account_id = self._get_account_id()

        def _get_account_id(self) -> str:
            """Get AWS account ID via STS."""
            sts = boto3.client("sts")
            return sts.get_caller_identity()["Account"]

        def build_gateway_registration(
            self,
            gateway: dict[str, Any],
        ) -> InternalServiceRegistration:
            """Build MCP Server registration from a gateway."""
            name = gateway.get("name", gateway["gatewayId"])
            path = f"/{_slugify(name)}"
            gateway_url = gateway.get("gatewayUrl", "")
            authorizer_type = gateway.get("authorizerType", "NONE")

            return InternalServiceRegistration(
                path=path,
                name=name,
                description=gateway.get("description", f"AgentCore Gateway: {name}"),
                proxy_pass_url=gateway_url,
                mcp_endpoint=gateway_url,
                auth_provider="bedrock-agentcore",
                auth_scheme=_get_auth_scheme(authorizer_type),
                supported_transports=["streamable-http"],
                tags=["agentcore", "gateway", "auto-registered"],
                overwrite=False,
                metadata={
                    "source": "agentcore-sync",
                    "gateway_arn": gateway.get("gatewayArn"),
                    "gateway_id": gateway.get("gatewayId"),
                    "authorizer_type": authorizer_type,
                    "region": self.region,
                    "account_id": self.account_id,
                },
            )

        def build_target_registration(
            self,
            gateway: dict[str, Any],
            target: dict[str, Any],
        ) -> InternalServiceRegistration | None:
            """Build MCP Server registration from an mcpServer target.

            Returns None for non-mcpServer targets (lambda, apiGateway,
            openApiSchema, smithyModel).
            """
            target_config = target.get("targetConfiguration", {})
            mcp_config = target_config.get("mcp", {})

            if "mcpServer" not in mcp_config:
                return None

            mcp_server = mcp_config["mcpServer"]
            endpoint = mcp_server.get("endpoint")
            if not endpoint:
                return None

            target_name = target.get("name", target["targetId"])
            gateway_name = gateway.get("name", gateway["gatewayId"])
            path = f"/{_slugify(gateway_name)}-{_slugify(target_name)}"

            return InternalServiceRegistration(
                path=path,
                name=f"{gateway_name} - {target_name}",
                description=target.get("description", f"MCP Server target: {target_name}"),
                proxy_pass_url=endpoint,
                mcp_endpoint=endpoint,
                auth_provider="bedrock-agentcore",
                auth_scheme="bearer",
                supported_transports=["streamable-http"],
                tags=["agentcore", "gateway-target", "mcp-server", "auto-registered"],
                overwrite=False,
                metadata={
                    "source": "agentcore-sync",
                    "gateway_arn": gateway.get("gatewayArn"),
                    "target_id": target.get("targetId"),
                    "region": self.region,
                    "account_id": self.account_id,
                },
            )

        def build_runtime_mcp_registration(
            self,
            runtime: dict[str, Any],
        ) -> InternalServiceRegistration:
            """Build MCP Server registration from a runtime with MCP protocol."""
            name = runtime.get("agentRuntimeName", runtime["agentRuntimeId"])
            path = f"/{_slugify(name)}"
            invocation_url = _build_invocation_url(
                self.region, runtime.get("agentRuntimeArn", "")
            )

            return InternalServiceRegistration(
                path=path,
                name=name,
                description=runtime.get("description", f"AgentCore MCP Server: {name}"),
                proxy_pass_url=invocation_url,
                mcp_endpoint=invocation_url,
                auth_provider="bedrock-agentcore",
                auth_scheme="bearer",
                supported_transports=["streamable-http"],
                tags=["agentcore", "runtime", "mcp-server", "auto-registered"],
                overwrite=False,
                metadata={
                    "source": "agentcore-sync",
                    "runtime_arn": runtime.get("agentRuntimeArn"),
                    "runtime_id": runtime.get("agentRuntimeId"),
                    "server_protocol": "MCP",
                    "region": self.region,
                    "account_id": self.account_id,
                },
            )

        def build_runtime_agent_registration(
            self,
            runtime: dict[str, Any],
        ) -> AgentRegistration:
            """Build A2A Agent registration from a runtime with HTTP/A2A protocol."""
            name = runtime.get("agentRuntimeName", runtime["agentRuntimeId"])
            path = f"/{_slugify(name)}"
            invocation_url = _build_invocation_url(
                self.region, runtime.get("agentRuntimeArn", "")
            )
            protocol = runtime.get("protocolConfiguration", {}).get(
                "serverProtocol", "HTTP"
            )

            return AgentRegistration(
                name=name,
                description=runtime.get("description", f"AgentCore Agent: {name}"),
                url=invocation_url,
                path=path,
                version="1.0.0",
                tags=["agentcore", "runtime", "agent", "auto-registered"],
                visibility=self.visibility,
                metadata={
                    "source": "agentcore-sync",
                    "runtime_arn": runtime.get("agentRuntimeArn"),
                    "runtime_id": runtime.get("agentRuntimeId"),
                    "server_protocol": protocol,
                    "region": self.region,
                    "account_id": self.account_id,
                },
            )


