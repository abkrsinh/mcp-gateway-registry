"""Multi-provider credential management for AgentCore auto-registration.

Handles credentials for all authorizer types:
- CUSTOM_JWT (OAuth2): Cognito, Auth0, Okta, custom providers
- AWS_IAM: Standard AWS credential chain via STS
- NONE: No credentials needed

Loads from environment variables (``AGENTCORE_CLIENT_ID_{N}`` /
``AGENTCORE_CLIENT_SECRET_{N}``), prompts interactively, validates
by test-generating a token, and persists to ``.env`` with 0600 permissions.
"""

from __future__ import annotations

import getpass
import logging
import os
from typing import Any

import boto3
import requests

logger = logging.getLogger(__name__)


class CredentialHelper:
    """Manages credentials for all authorizer types.

    On init, loads existing credentials from environment variables
    using ``AGENTCORE_CLIENT_ID_{N}`` / ``AGENTCORE_CLIENT_SECRET_{N}``
    naming conventions.
    """

    def __init__(self) -> None:
        self.credentials: dict[str, dict[str, str]] = {}
        self._load_from_env()

    # ------------------------------------------------------------------
    # Environment loading
    # ------------------------------------------------------------------

    def _load_from_env(self) -> None:
        """Load credentials from environment variables for N=1..100.

        Reads ``AGENTCORE_CLIENT_ID_{N}`` / ``AGENTCORE_CLIENT_SECRET_{N}``.
        Only stores complete triplets (client_id + client_secret + gateway_arn).
        """
        for i in range(1, 101):
            client_id = os.environ.get(f"AGENTCORE_CLIENT_ID_{i}")
            client_secret = os.environ.get(f"AGENTCORE_CLIENT_SECRET_{i}")

            gateway_arn = os.environ.get(f"AGENTCORE_GATEWAY_ARN_{i}")

            if client_id and client_secret and gateway_arn:
                self.credentials[gateway_arn] = {
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "server_name": os.environ.get(
                        f"AGENTCORE_SERVER_NAME_{i}", ""
                    ),
                    "authorizer_type": os.environ.get(
                        f"AGENTCORE_AUTHORIZER_TYPE_{i}", "CUSTOM_JWT"
                    ),
                    "index": str(i),
                }
                logger.debug(f"Loaded credentials for gateway: {gateway_arn}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_credentials(
        self,
        gateway_arn: str,
        authorizer_type: str = "CUSTOM_JWT",
        interactive: bool = True,
    ) -> dict[str, str] | None:
        """Get credentials for a gateway based on authorizer type.

        Routes by authorizer type:
        - ``CUSTOM_JWT``: OAuth2 client credentials (env or prompt)
        - ``AWS_IAM``: Verifies AWS creds via STS, returns marker dict
        - ``NONE``: Returns marker dict immediately
        """
        logger.info(
            f"Credential handling for {gateway_arn} "
            f"(authorizer: {authorizer_type})"
        )

        if authorizer_type == "NONE":
            return {"type": "none", "authorizer_type": "NONE"}

        if authorizer_type == "AWS_IAM":
            return self._handle_iam_authorizer()

        # CUSTOM_JWT path
        if gateway_arn in self.credentials:
            return self.credentials[gateway_arn]

        if interactive:
            return self._prompt_credentials(gateway_arn)

        logger.warning(
            f"No OAuth2 M2M client created for {gateway_arn} — "
            f"see prerequisites documentation"
        )
        return None

    def validate_credentials(
        self,
        creds: dict[str, str],
        oauth_domain: str,
    ) -> bool:
        """Validate OAuth2 credentials by test-generating a token.

        Returns True if token generation succeeds, False otherwise.
        Credentials that fail validation should NOT be persisted.
        """
        if not oauth_domain:
            logger.warning("No OAUTH_DOMAIN set — skipping credential validation")
            return True  # Can't validate without domain, allow persistence

        try:
            # Determine token endpoint based on provider
            if "auth0.com" in oauth_domain:
                url = f"{oauth_domain}/oauth/token"
            elif "okta.com" in oauth_domain:
                url = f"{oauth_domain}/oauth2/default/v1/token"
            else:
                # Cognito and other providers
                url = f"{oauth_domain}/oauth2/token"

            # Bandit B113: timeout IS set below (line ~149) - not a missing timeout
            response = requests.post(  # nosec B113
                url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": creds["client_id"],
                    "client_secret": creds["client_secret"],
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=int(os.environ.get("TOKEN_GENERATION_TIMEOUT", "30")),
            )

            if response.status_code == 200:
                logger.info("Credential validation succeeded (test token generated)")
                return True

            logger.warning(
                f"Credentials validation failed — check client ID/secret "
                f"(HTTP {response.status_code})"
            )
            return False

        except Exception as e:
            logger.warning(f"Credential validation error: {e}")
            return False

    def persist_credentials(
        self,
        gateway_arn: str,
        creds: dict[str, str],
        server_name: str,
        env_file: str = ".env",
    ) -> int:
        """Persist new credentials to ``.env`` file for token refresh.

        Writes ``AGENTCORE_CLIENT_ID_{N}``, ``AGENTCORE_CLIENT_SECRET_{N}``,
        ``AGENTCORE_GATEWAY_ARN_{N}``, and ``AGENTCORE_SERVER_NAME_{N}``
        entries. If credentials for this gateway ARN already exist,
        updates them in-place. Otherwise appends with the next available
        index. Sets file permissions to 0600.

        Returns the assigned index.
        """
        env_path = os.path.abspath(env_file)

        # Check if this gateway ARN already has credentials in the file
        existing_idx = self._find_existing_env_index(gateway_arn, env_path)

        if existing_idx:
            idx = existing_idx
            self._update_env_block(idx, creds, gateway_arn, server_name, env_path)
        else:
            idx = self.get_next_env_index()
            self._append_env_block(idx, creds, gateway_arn, server_name, env_path)

        # Secure file permissions
        try:
            os.chmod(env_path, 0o600)
        except OSError:
            logger.warning(f"Could not set permissions on {env_path}")

        # Update in-memory cache
        creds["server_name"] = server_name
        creds["index"] = str(idx)
        self.credentials[gateway_arn] = creds

        logger.info(
            f"Persisted credentials for {server_name} as index {idx} "
            f"in {env_file}"
        )
        return idx

    def get_next_env_index(self) -> int:
        """Find the next available credential index.

        Scans both in-memory cache and environment variables to
        determine the highest used index, then returns index + 1.
        """
        max_index = 0
        for cred in self.credentials.values():
            idx = int(cred.get("index", "0"))
            if idx > max_index:
                max_index = idx
        # Also check env vars directly
        for i in range(1, 101):
            if os.environ.get(f"AGENTCORE_CLIENT_ID_{i}"):
                max_index = max(max_index, i)
        return max_index + 1

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _handle_iam_authorizer(self) -> dict[str, str] | None:
        """Verify AWS credentials via ``sts:GetCallerIdentity``.

        Returns a marker dict ``{type: iam}`` on success, ``None`` on failure.
        """
        try:
            sts = boto3.client("sts")
            identity = sts.get_caller_identity()
            logger.debug(
                f"AWS IAM credentials verified "
                f"(account: {identity['Account']})"
            )
            return {"type": "iam", "authorizer_type": "AWS_IAM"}
        except Exception as e:
            logger.warning(f"AWS credentials not available for IAM auth: {e}")
            return None
    def _find_existing_env_index(
        self,
        gateway_arn: str,
        env_path: str,
    ) -> int | None:
        """Find the index of an existing credential block for a gateway ARN.

        Scans the ``.env`` file for ``AGENTCORE_GATEWAY_ARN_{N}={arn}``
        and returns N if found, else None.
        """
        if not os.path.exists(env_path):
            return None
        try:
            with open(env_path) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("AGENTCORE_GATEWAY_ARN_") and f"={gateway_arn}" in line:
                        # Extract index from AGENTCORE_GATEWAY_ARN_{N}=...
                        key = line.split("=", 1)[0]
                        idx_str = key.replace("AGENTCORE_GATEWAY_ARN_", "")
                        try:
                            return int(idx_str)
                        except ValueError:
                            continue
        except OSError:
            pass
        return None

    def _update_env_block(
        self,
        idx: int,
        creds: dict[str, str],
        gateway_arn: str,
        server_name: str,
        env_path: str,
    ) -> None:
        """Update an existing credential block in-place in the ``.env`` file."""
        with open(env_path) as f:
            content = f.read()

        replacements = {
            f"AGENTCORE_CLIENT_ID_{idx}": creds["client_id"],
            f"AGENTCORE_CLIENT_SECRET_{idx}": creds["client_secret"],
            f"AGENTCORE_GATEWAY_ARN_{idx}": gateway_arn,
            f"AGENTCORE_SERVER_NAME_{idx}": server_name,
        }

        lines = content.splitlines(keepends=True)
        new_lines = []
        for line in lines:
            replaced = False
            for key, value in replacements.items():
                if line.startswith(f"{key}="):
                    new_lines.append(f"{key}={value}\n")
                    replaced = True
                    break
            if not replaced:
                new_lines.append(line)

        with open(env_path, "w") as f:
            f.writelines(new_lines)

        logger.debug(f"Updated existing credential block at index {idx}")

    def _append_env_block(
        self,
        idx: int,
        creds: dict[str, str],
        gateway_arn: str,
        server_name: str,
        env_path: str,
    ) -> None:
        """Append a new credential block to the ``.env`` file."""
        lines = [
            f"\n# AgentCore Gateway: {server_name} ({gateway_arn})\n",
            f"AGENTCORE_CLIENT_ID_{idx}={creds['client_id']}\n",
            f"AGENTCORE_CLIENT_SECRET_{idx}={creds['client_secret']}\n",
            f"AGENTCORE_GATEWAY_ARN_{idx}={gateway_arn}\n",
            f"AGENTCORE_SERVER_NAME_{idx}={server_name}\n",
        ]
        with open(env_path, "a") as f:
            f.writelines(lines)



    def _prompt_credentials(
        self,
        gateway_arn: str,
    ) -> dict[str, str] | None:
        """Prompt user for OAuth2 credentials securely.

        Uses ``input()`` for Client ID and ``getpass.getpass()`` for
        Client Secret. Returns ``None`` if user presses Enter without input.
        """
        print(f"\nOAuth2 credentials needed for gateway: {gateway_arn}")
        print("(Press Enter to skip)")

        client_id = input("  Client ID: ").strip()
        if not client_id:
            return None

        client_secret = getpass.getpass("  Client Secret: ").strip()
        if not client_secret:
            return None

        creds = {"client_id": client_id, "client_secret": client_secret}
        self.credentials[gateway_arn] = creds
        return creds
