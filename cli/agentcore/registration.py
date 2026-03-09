"""Registry integration — build registrations and orchestrate sync.

Contains ``RegistrationBuilder`` (maps discovered AWS resources to
registry models) and ``SyncOrchestrator`` (coordinates scanning,
registration, credential persistence, and token generation).
"""

from __future__ import annotations

import json
import logging
import os
import sys
from typing import TYPE_CHECKING, Any

import boto3
import requests
from tenacity import (
    retry,
    retry_if_exception,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from .models import (
    _build_invocation_url,
    _get_auth_scheme,
    _slugify,
    _validate_https_url,
)

if TYPE_CHECKING:
    from .credentials import CredentialHelper
    from .discovery import AgentCoreScanner
    from .token_manager import TokenManager

# Add parent directory to path for api imports
sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)
from api.registry_client import (
    AgentRegistration,
    InternalServiceRegistration,
    RegistryClient,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Retry decorator for registry calls
# ---------------------------------------------------------------------------


def _retry_registry_call(func):
    """Decorator: retry on ``requests.exceptions.RequestException``.

    3 attempts, exponential backoff 1-4 s.
    Does NOT retry on 409 Conflict (idempotency — resource already exists).
    """

    def _should_retry(exc: BaseException) -> bool:
        if isinstance(exc, requests.exceptions.HTTPError):
            # Don't retry 409 Conflict — it means the resource already exists
            if exc.response is not None and exc.response.status_code == 409:
                return False
        return isinstance(exc, requests.exceptions.RequestException)

    return retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=4),
        retry=retry_if_exception(_should_retry),
        before_sleep=lambda retry_state: logger.warning(
            f"Registry call failed, retrying in "
            f"{retry_state.next_action.sleep}s..."
        ),
    )(func)


def _is_conflict_error(exc: Exception) -> bool:
    """Check if an exception indicates a 409 Conflict (resource already exists).

    Handles:
    - Direct HTTPError with 409 status code
    - Error message containing "already exists" or "already registered"
    - Tenacity RetryError wrapping any of the above
    """
    # Check direct HTTPError response
    if hasattr(exc, "response") and getattr(exc.response, "status_code", None) == 409:
        return True

    # Check error message
    err_str = str(exc).lower()
    if "already exists" in err_str or "already registered" in err_str:
        return True

    # Unwrap tenacity RetryError
    if hasattr(exc, "last_attempt"):
        inner = exc.last_attempt.exception()
        if inner:
            if hasattr(inner, "response") and getattr(inner.response, "status_code", None) == 409:
                return True
            inner_str = str(inner).lower()
            if "already exists" in inner_str or "already registered" in inner_str:
                return True

    return False


# ---------------------------------------------------------------------------
# Registration Builder
# ---------------------------------------------------------------------------


class RegistrationBuilder:
    """Builds registration models from discovered AWS resources."""

    def __init__(
        self,
        region: str,
        visibility: str = "internal",
        session: boto3.Session | None = None,
    ) -> None:
        self.region = region
        self.visibility = visibility
        self._session = session
        self.account_id = self._get_account_id()

    def _get_account_id(self) -> str:
        if self._session:
            sts = self._session.client("sts")
        else:
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

        Returns ``None`` for non-mcpServer targets.
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
            description=target.get(
                "description", f"MCP Server target: {target_name}"
            ),
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
            description=runtime.get(
                "description", f"AgentCore MCP Server: {name}"
            ),
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
            description=runtime.get(
                "description", f"AgentCore Agent: {name}"
            ),
            url=invocation_url,
            path=path,
            version="1.0.0",
            tags=["agentcore", "runtime", "agent", "auto-registered"],
            # Agent validator accepts: public, private, group-restricted (not "internal").
            # MCP Servers use "internal" but A2A Agents use "public" as the default,
            # so we map "internal" -> "public" for Agent registrations.
            visibility="public" if self.visibility == "internal" else self.visibility,
            metadata={
                "source": "agentcore-sync",
                "runtime_arn": runtime.get("agentRuntimeArn"),
                "runtime_id": runtime.get("agentRuntimeId"),
                "server_protocol": protocol,
                "region": self.region,
                "account_id": self.account_id,
            },
        )


# ---------------------------------------------------------------------------
# Sync Orchestrator
# ---------------------------------------------------------------------------


class SyncOrchestrator:
    """Orchestrates discovery, registration, credentials, and tokens.

    Coordinates the full sync lifecycle:
    1. Scan gateways / runtimes via ``AgentCoreScanner``
    2. Build registrations via ``RegistrationBuilder``
    3. Register with the registry via ``RegistryClient``
    4. Persist credentials via ``CredentialHelper`` (CUSTOM_JWT only)
    5. Generate initial tokens via ``TokenManager`` (CUSTOM_JWT only)

    Supports dry-run, overwrite, scope filtering, and JSON output.
    """

    def __init__(
        self,
        scanner: AgentCoreScanner,
        builder: RegistrationBuilder,
        registry_client: RegistryClient,
        credential_helper: CredentialHelper,
        token_manager: TokenManager | None = None,
        dry_run: bool = False,
        overwrite: bool = False,
        include_mcp_targets: bool = False,
        skip_token_generation: bool = False,
        output_format: str = "text",
    ) -> None:
        self.scanner = scanner
        self.builder = builder
        self.registry = registry_client
        self.credentials = credential_helper
        self.token_manager = token_manager
        self.dry_run = dry_run
        self.overwrite = overwrite
        self.include_mcp_targets = include_mcp_targets
        self.skip_token_generation = skip_token_generation
        self.output_format = output_format
        self.results: list[dict[str, Any]] = []
        self._credentials_saved = 0
        self._tokens_generated = 0
        # Track ARN→index for token generation
        self._arn_to_index: dict[str, int] = {}
        # Track gateway configs for token generation
        self._gateway_configs: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def sync_gateways(self) -> None:
        """Scan and register all gateways."""
        logger.info("Scanning AgentCore Gateways...")
        gateways = self.scanner.scan_gateways()

        for gateway in gateways:
            self._register_gateway(gateway)

            if self.include_mcp_targets:
                for target in gateway.get("targets", []):
                    self._register_target(gateway, target)

    def sync_runtimes(self) -> None:
        """Scan and register all runtimes."""
        logger.info("Scanning AgentCore Runtimes...")
        runtimes = self.scanner.scan_runtimes()

        for runtime in runtimes:
            self._register_runtime(runtime)

    def generate_tokens(self) -> None:
        """Generate initial egress tokens for CUSTOM_JWT gateways.

        Called after all registrations are complete. Skipped in
        dry-run mode or when ``--skip-token-generation`` is set.
        """
        if self.dry_run or self.skip_token_generation or not self.token_manager:
            return
        if not self._gateway_configs:
            return

        try:
            token_paths = self.token_manager.generate_tokens_for_gateways(
                self._gateway_configs, self._arn_to_index
            )
            self._tokens_generated = len(token_paths)
            if token_paths:
                logger.info(
                    f"Generated {len(token_paths)} initial egress tokens"
                )
        except Exception as e:
            logger.error(f"Token generation failed: {e}")

    def print_summary(self) -> None:
        """Print sync summary in text or JSON format."""
        registered = sum(
            1 for r in self.results if r["status"] == "registered"
        )
        skipped = sum(1 for r in self.results if r["status"] == "skipped")
        failed = sum(1 for r in self.results if r["status"] == "failed")
        dry_run_count = sum(
            1 for r in self.results if r["status"] == "dry_run"
        )

        summary = {
            "dry_run": self.dry_run,
            "registered": registered,
            "skipped": skipped,
            "failed": failed,
            "credentials_saved": self._credentials_saved,
            "tokens_generated": self._tokens_generated,
            "would_register": dry_run_count if self.dry_run else 0,
            "total": len(self.results),
            "results": self.results,
        }

        if self.output_format == "json":
            print(json.dumps(summary, indent=2, default=str))
            return

        print("\n" + "=" * 80)
        print("AGENTCORE SYNC SUMMARY")
        print("=" * 80)

        if self.dry_run:
            print("MODE: DRY-RUN (no changes made)")
            print(f"Would register: {dry_run_count}")
        else:
            print(f"Registered:        {registered}")
            print(f"Skipped:           {skipped}")
            print(f"Failed:            {failed}")
            print(f"Credentials saved: {self._credentials_saved}")
            print(f"Tokens generated:  {self._tokens_generated}")

        print("\nDETAILS:")
        print("-" * 80)
        print(f"{'Type':<10} {'Name':<30} {'Path':<25} {'Status':<10}")
        print("-" * 80)

        for r in self.results:
            print(
                f"{r['resource_type']:<10} "
                f"{r['resource_name'][:30]:<30} "
                f"{r['path'][:25]:<25} "
                f"{r['status']:<10}"
            )

        print("=" * 80)

    # ------------------------------------------------------------------
    # Internal — gateway registration
    # ------------------------------------------------------------------

    def _register_gateway(self, gateway: dict[str, Any]) -> None:
        gateway_name = gateway.get("name", gateway["gatewayId"])
        gateway_url = gateway.get("gatewayUrl", "")
        gateway_arn = gateway.get("gatewayArn", "")
        authorizer_type = gateway.get("authorizerType", "NONE")

        if not _validate_https_url(gateway_url, gateway_name):
            self.results.append({
                "resource_type": "gateway",
                "resource_name": gateway_name,
                "resource_arn": gateway_arn,
                "registration_type": "mcp_server",
                "path": f"/{_slugify(gateway_name)}",
                "status": "skipped",
                "message": "Invalid URL (must be HTTPS)",
            })
            return

        registration = self.builder.build_gateway_registration(gateway)
        registration.overwrite = self.overwrite

        result: dict[str, Any] = {
            "resource_type": "gateway",
            "resource_name": gateway_name,
            "resource_arn": gateway_arn,
            "registration_type": "mcp_server",
            "path": registration.service_path,
        }

        if self.dry_run:
            result["status"] = "dry_run"
            result["message"] = "Would register as MCP Server"
            logger.info(f"[DRY-RUN] Would register gateway: {gateway_name}")
            self.results.append(result)
            return

        try:
            self._register_service_with_retry(registration)
            result["status"] = "registered"
            result["message"] = "Successfully registered"
            logger.info(f"Registered gateway: {gateway_name}")
        except Exception as e:
            if _is_conflict_error(e) and not self.overwrite:
                result["status"] = "skipped"
                result["message"] = "Already registered - skipping (use --overwrite)"
                logger.warning(
                    f"Already registered - skipping: {gateway_name} "
                    f"(use --overwrite)"
                )
            else:
                result["status"] = "failed"
                result["message"] = str(e)
                logger.error(f"Failed to register gateway: {e}")
            self.results.append(result)
            return

        self.results.append(result)

        # Post-registration: credential persistence + token setup
        if authorizer_type == "CUSTOM_JWT":
            self._handle_gateway_credentials(gateway, gateway_name)

    def _handle_gateway_credentials(
        self,
        gateway: dict[str, Any],
        gateway_name: str,
    ) -> None:
        """Persist credentials and queue token generation for a CUSTOM_JWT gateway."""
        gateway_arn = gateway.get("gatewayArn", "")
        creds = self.credentials.get_credentials(
            gateway_arn, authorizer_type="CUSTOM_JWT"
        )
        if not creds or creds.get("type") in ("iam", "none"):
            return

        # Already has an index → credentials were loaded from env, no need to persist
        if creds.get("index"):
            self._arn_to_index[gateway_arn] = int(creds["index"])
            self._gateway_configs.append({
                "gateway_arn": gateway_arn,
                "server_name": creds.get("server_name", gateway_name),
            })
            return

        # Validate before persisting
        oauth_domain = os.environ.get("OAUTH_DOMAIN", "")
        if oauth_domain and hasattr(self.credentials, "validate_credentials"):
            if not self.credentials.validate_credentials(creds, oauth_domain):
                logger.warning(
                    f"Credential validation failed for {gateway_arn} — "
                    f"skipping persistence"
                )
                return

        # Persist new credentials
        server_name = creds.get("server_name", gateway_name)
        try:
            idx = self.credentials.persist_credentials(
                gateway_arn, creds, server_name
            )
            self._credentials_saved += 1
            self._arn_to_index[gateway_arn] = idx
            self._gateway_configs.append({
                "gateway_arn": gateway_arn,
                "server_name": server_name,
            })
        except Exception as e:
            # Rollback: registration succeeded but credential save failed
            logger.error(
                f"Failed to persist credentials for {gateway_arn}: {e}. "
                f"Remediation: manually add credentials to .env and run "
                f"generate_access_token.py"
            )
            # Update the last result to reflect the failure
            for r in reversed(self.results):
                if r.get("resource_arn") == gateway_arn:
                    r["status"] = "failed"
                    r["message"] = (
                        f"Registered but credential save failed: {e}"
                    )
                    break

    # ------------------------------------------------------------------
    # Internal — target registration
    # ------------------------------------------------------------------

    def _register_target(
        self, gateway: dict[str, Any], target: dict[str, Any]
    ) -> None:
        registration = self.builder.build_target_registration(gateway, target)
        if not registration:
            return

        registration.overwrite = self.overwrite
        target_name = target.get("name", target["targetId"])

        result: dict[str, Any] = {
            "resource_type": "target",
            "resource_name": target_name,
            "resource_arn": (
                f"{gateway.get('gatewayArn', '')}:target:{target['targetId']}"
            ),
            "registration_type": "mcp_server",
            "path": registration.service_path,
        }

        if self.dry_run:
            result["status"] = "dry_run"
            result["message"] = "Would register as MCP Server"
            logger.info(f"[DRY-RUN] Would register target: {target_name}")
        else:
            try:
                self._register_service_with_retry(registration)
                result["status"] = "registered"
                result["message"] = "Successfully registered"
                logger.info(f"Registered target: {target_name}")
            except Exception as e:
                if "already exists" in str(e).lower() and not self.overwrite:
                    result["status"] = "skipped"
                    result["message"] = "Already exists"
                else:
                    result["status"] = "failed"
                    result["message"] = str(e)
                    logger.error(f"Failed to register target: {e}")

        self.results.append(result)

    # ------------------------------------------------------------------
    # Internal — runtime registration
    # ------------------------------------------------------------------

    def _register_runtime(self, runtime: dict[str, Any]) -> None:
        protocol_config = runtime.get("protocolConfiguration", {})
        server_protocol = protocol_config.get("serverProtocol", "HTTP")

        if server_protocol == "MCP":
            self._register_runtime_as_server(runtime)
        else:
            self._register_runtime_as_agent(runtime)

    def _register_runtime_as_server(self, runtime: dict[str, Any]) -> None:
        registration = self.builder.build_runtime_mcp_registration(runtime)
        registration.overwrite = self.overwrite
        runtime_name = runtime.get(
            "agentRuntimeName", runtime["agentRuntimeId"]
        )

        result: dict[str, Any] = {
            "resource_type": "runtime",
            "resource_name": runtime_name,
            "resource_arn": runtime.get("agentRuntimeArn", ""),
            "registration_type": "mcp_server",
            "path": registration.service_path,
        }

        if self.dry_run:
            result["status"] = "dry_run"
            result["message"] = "Would register as MCP Server"
            logger.info(
                f"[DRY-RUN] Would register runtime as MCP Server: "
                f"{runtime_name}"
            )
        else:
            try:
                self._register_service_with_retry(registration)
                result["status"] = "registered"
                logger.info(
                    f"Registered runtime as MCP Server: {runtime_name}"
                )
            except Exception as e:
                if "already exists" in str(e).lower() and not self.overwrite:
                    result["status"] = "skipped"
                    result["message"] = "Already exists"
                else:
                    result["status"] = "failed"
                    result["message"] = str(e)
                    logger.error(f"Failed to register runtime: {e}")

        self.results.append(result)

    def _register_runtime_as_agent(self, runtime: dict[str, Any]) -> None:
        registration = self.builder.build_runtime_agent_registration(runtime)
        runtime_name = runtime.get(
            "agentRuntimeName", runtime["agentRuntimeId"]
        )

        result: dict[str, Any] = {
            "resource_type": "runtime",
            "resource_name": runtime_name,
            "resource_arn": runtime.get("agentRuntimeArn", ""),
            "registration_type": "agent",
            "path": registration.path,
        }

        if self.dry_run:
            result["status"] = "dry_run"
            result["message"] = "Would register as A2A Agent"
            logger.info(
                f"[DRY-RUN] Would register runtime as Agent: {runtime_name}"
            )
        else:
            try:
                self._register_agent_with_retry(registration)
                result["status"] = "registered"
                logger.info(
                    f"Registered runtime as Agent: {runtime_name}"
                )
            except Exception as e:
                if _is_conflict_error(e):
                    result["status"] = "skipped"
                    result["message"] = "Already registered - use --overwrite to update"
                else:
                    result["status"] = "failed"
                    result["message"] = str(e)
                    logger.error(f"Failed to register runtime as agent: {e}")

        self.results.append(result)

    # ------------------------------------------------------------------
    # Retry-wrapped registry calls
    # ------------------------------------------------------------------

    @_retry_registry_call
    def _register_service_with_retry(
        self, registration: InternalServiceRegistration
    ) -> None:
        self.registry.register_service(registration)

    @_retry_registry_call
    def _register_agent_with_retry(
        self, registration: AgentRegistration
    ) -> None:
        self.registry.register_agent(registration)
