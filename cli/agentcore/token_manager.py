"""Token generation and verification for AgentCore auto-registration.

Generates initial egress tokens after registration by calling
``generate_access_token.py`` programmatically, verifies token files
exist, and checks that ``token_refresher.py`` can read persisted
credentials from ``.env``.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Ensure credentials-provider/agentcore-auth is importable
_repo_root = Path(__file__).resolve().parent.parent.parent
_agentcore_auth = _repo_root / "credentials-provider" / "agentcore-auth"
if str(_agentcore_auth) not in sys.path:
    sys.path.insert(0, str(_agentcore_auth))


class TokenManager:
    """Generates initial egress tokens and verifies refresh setup.

    After registration, calls ``generate_access_token.py`` for each
    CUSTOM_JWT gateway to produce egress tokens at
    ``.oauth-tokens/bedrock-agentcore-{name}-egress.json``.
    """

    def __init__(
        self,
        oauth_domain: str | None = None,
        timeout: int = 30,
    ) -> None:
        self.oauth_domain = oauth_domain or os.environ.get("OAUTH_DOMAIN", "")
        self.timeout = int(
            os.environ.get("TOKEN_GENERATION_TIMEOUT", str(timeout))
        )

    def generate_tokens_for_gateways(
        self,
        gateway_configs: list[dict[str, Any]],
        arn_to_index: dict[str, int],
    ) -> dict[str, str]:
        """Generate initial egress tokens for registered CUSTOM_JWT gateways.

        Calls ``generate_access_token.generate_access_token()`` for each
        gateway config that has a credential index mapping.

        Returns ``{gateway_arn: token_file_path}`` for successful generations.
        """
        token_paths: dict[str, str] = {}

        # Bridge OAUTH_DOMAIN → COGNITO_DOMAIN so generate_access_token
        # can find the OAuth domain even when .env has a placeholder value
        if self.oauth_domain:
            os.environ.setdefault("COGNITO_DOMAIN", self.oauth_domain)
            os.environ.setdefault("OAUTH_DOMAIN", self.oauth_domain)

        for config in gateway_configs:
            gateway_arn = config["gateway_arn"]
            server_name = config.get("server_name", "")
            index = arn_to_index.get(gateway_arn)

            if not index:
                logger.warning(
                    f"No credential index for {gateway_arn} — "
                    f"skipping token generation"
                )
                continue

            try:
                from generate_access_token import (
                    generate_access_token,
                )

                generate_access_token(
                    gateway_index=index,
                    oauth_tokens_dir=".oauth-tokens",
                )

                expected_path = (
                    f".oauth-tokens/bedrock-agentcore-"
                    f"{server_name}-egress.json"
                )
                token_paths[gateway_arn] = expected_path
                logger.info(f"Token generated for {server_name} ({gateway_arn})")

            except Exception as e:
                logger.error(
                    f"Failed to generate token for {gateway_arn}: {e}. "
                    f"Remediation: run "
                    f"'python generate_access_token.py --index {index}' "
                    f"manually"
                )

        return token_paths

    def verify_token_files(
        self,
        expected_names: list[str],
        tokens_dir: str = ".oauth-tokens",
    ) -> list[str]:
        """Verify that egress token files exist for the given server names.

        Returns list of missing file paths.
        """
        missing: list[str] = []
        for name in expected_names:
            path = Path(tokens_dir) / f"bedrock-agentcore-{name}-egress.json"
            if not path.exists():
                missing.append(str(path))
                logger.warning(f"Token file missing: {path}")
        return missing

    def verify_refresh_setup(self, env_file: str = ".env") -> bool:
        """Verify that ``token_refresher.py`` can read credentials from ``.env``.

        Checks that the env file exists and contains at least one
        ``AGENTCORE_CLIENT_ID_`` entry.
        """
        env_path = Path(env_file)
        if not env_path.exists():
            logger.warning(f"Env file not found: {env_file}")
            return False

        content = env_path.read_text()
        has_creds = "AGENTCORE_CLIENT_ID_" in content

        if has_creds:
            logger.info("Token refresh setup verified — credentials in .env")
            return True

        logger.warning(
            f"No credential entries found in {env_file} — "
            f"token_refresher.py will not be able to refresh tokens"
        )
        return False
