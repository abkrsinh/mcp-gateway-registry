"""CLI entry point for AgentCore auto-registration.

Provides ``sync`` and ``list`` subcommands via argparse.

Usage::

    python -m cli.agentcore.sync sync [options]
    python -m cli.agentcore.sync list [options]
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys

from .models import (
    DEFAULT_REGION,
    DEFAULT_REGISTRY_URL,
    DEFAULT_TIMEOUT,
    DEFAULT_TOKEN_FILE,
    _load_token,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Argparse setup
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser with sync and list subcommands."""
    parser = argparse.ArgumentParser(
        prog="agentcore-sync",
        description=(
            "Discover and register AWS Bedrock AgentCore Gateways and "
            "Agent Runtimes with the MCP Gateway Registry."
        ),
        epilog=(
            "Environment variables:\n"
            "  AWS_REGION              AWS region (default: us-east-1)\n"
            "  REGISTRY_URL            Registry base URL\n"
            "  REGISTRY_TOKEN_FILE     Path to registry auth token file\n"
            "  OAUTH_DOMAIN            OAuth2 provider domain URL\n"
            "  OAUTH_CLIENT_ID_{N}     OAuth2 client ID for gateway N\n"
            "  OAUTH_CLIENT_SECRET_{N} OAuth2 client secret for gateway N\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest="command")

    # -- shared arguments --------------------------------------------------
    def add_common_args(sub: argparse.ArgumentParser) -> None:
        sub.add_argument(
            "--region",
            default=os.environ.get("AWS_REGION", DEFAULT_REGION),
            help="AWS region (default: AWS_REGION env or us-east-1)",
        )
        sub.add_argument(
            "--registry-url",
            default=os.environ.get("REGISTRY_URL", DEFAULT_REGISTRY_URL),
            help="Registry base URL (default: REGISTRY_URL env or http://localhost)",
        )
        sub.add_argument(
            "--token-file",
            default=os.environ.get("REGISTRY_TOKEN_FILE", DEFAULT_TOKEN_FILE),
            help="Path to registry auth token file",
        )
        sub.add_argument(
            "--timeout",
            type=int,
            default=DEFAULT_TIMEOUT,
            help="AWS API call timeout in seconds (default: 30)",
        )
        sub.add_argument(
            "--gateways-only",
            action="store_true",
            help="Only process gateways",
        )
        sub.add_argument(
            "--runtimes-only",
            action="store_true",
            help="Only process runtimes",
        )
        sub.add_argument(
            "--output",
            choices=["text", "json"],
            default="text",
            help="Output format (default: text)",
        )
        sub.add_argument(
            "--debug",
            action="store_true",
            help="Enable DEBUG logging",
        )

    # -- sync subcommand ---------------------------------------------------
    sync_parser = subparsers.add_parser(
        "sync",
        help="Discover and register AgentCore resources",
    )
    add_common_args(sync_parser)
    sync_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview without registering or persisting credentials",
    )
    sync_parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing registrations",
    )
    sync_parser.add_argument(
        "--visibility",
        choices=["public", "internal", "group-restricted"],
        default="internal",
        help="Registration visibility (default: internal)",
    )
    sync_parser.add_argument(
        "--include-mcp-targets",
        action="store_true",
        help="Register mcpServer gateway targets as separate MCP Servers",
    )
    sync_parser.add_argument(
        "--skip-token-generation",
        action="store_true",
        help="Skip initial egress token generation after registration",
    )

    # -- list subcommand ---------------------------------------------------
    list_parser = subparsers.add_parser(
        "list",
        help="Discover and display AgentCore resources without registering",
    )
    add_common_args(list_parser)

    return parser


# ---------------------------------------------------------------------------
# cmd_sync
# ---------------------------------------------------------------------------


def cmd_sync(args: argparse.Namespace) -> int:
    """Execute the sync subcommand: discover, register, persist creds, gen tokens."""
    # Load registry token
    try:
        token = _load_token(args.token_file)
    except (FileNotFoundError, ValueError) as e:
        logger.error(str(e))
        return 1

    # Late imports to keep argparse fast
    from .credentials import CredentialHelper
    from .discovery import AgentCoreScanner
    from .registration import RegistrationBuilder, SyncOrchestrator
    from .token_manager import TokenManager

    # Add project root so api.registry_client is importable
    sys.path.insert(
        0,
        os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        ),
    )
    from api.registry_client import RegistryClient

    scanner = AgentCoreScanner(region=args.region, timeout=args.timeout)
    builder = RegistrationBuilder(region=args.region, visibility=args.visibility)
    registry = RegistryClient(registry_url=args.registry_url, token=token)
    cred_helper = CredentialHelper()

    token_manager = None
    if not args.skip_token_generation:
        token_manager = TokenManager()

    orchestrator = SyncOrchestrator(
        scanner=scanner,
        builder=builder,
        registry_client=registry,
        credential_helper=cred_helper,
        token_manager=token_manager,
        dry_run=args.dry_run,
        overwrite=args.overwrite,
        include_mcp_targets=args.include_mcp_targets,
        skip_token_generation=args.skip_token_generation,
        output_format=args.output,
    )

    # Scope filtering
    if not args.runtimes_only:
        orchestrator.sync_gateways()
    if not args.gateways_only:
        orchestrator.sync_runtimes()

    # Post-registration token generation
    orchestrator.generate_tokens()

    # Summary
    orchestrator.print_summary()
    return 0


# ---------------------------------------------------------------------------
# cmd_list
# ---------------------------------------------------------------------------


def cmd_list(args: argparse.Namespace) -> int:
    """Execute the list subcommand: discover and display resources."""
    from .discovery import AgentCoreScanner

    scanner = AgentCoreScanner(region=args.region, timeout=args.timeout)

    gateways: list = []
    runtimes: list = []
    errors: list[str] = []

    if not args.runtimes_only:
        try:
            gateways = scanner.scan_gateways()
        except Exception as e:
            errors.append(f"Gateway scan error: {e}")
            logger.error(f"Failed to scan gateways: {e}")

    if not args.gateways_only:
        try:
            runtimes = scanner.scan_runtimes()
        except Exception as e:
            errors.append(f"Runtime scan error: {e}")
            logger.error(f"Failed to scan runtimes: {e}")

    if args.output == "json":
        print(
            json.dumps(
                {
                    "region": args.region,
                    "gateways": gateways,
                    "runtimes": runtimes,
                    "errors": errors,
                },
                indent=2,
                default=str,
            )
        )
    else:
        _print_list_text(gateways, runtimes, args.region, errors)

    return 0


def _print_list_text(
    gateways: list,
    runtimes: list,
    region: str,
    errors: list[str],
) -> None:
    """Print discovered resources in text format."""
    print(f"\nAgentCore Resources in {region}")
    print("=" * 70)

    if gateways:
        print(f"\nGateways ({len(gateways)}):")
        print("-" * 70)
        for gw in gateways:
            name = gw.get("name", gw.get("gatewayId", "unknown"))
            auth = gw.get("authorizerType", "unknown")
            status = gw.get("status", "unknown")
            targets = len(gw.get("targets", []))
            print(f"  {name:<30} auth={auth:<12} targets={targets}  [{status}]")
    else:
        print("\nNo gateways found.")

    if runtimes:
        print(f"\nRuntimes ({len(runtimes)}):")
        print("-" * 70)
        for rt in runtimes:
            name = rt.get("agentRuntimeName", rt.get("agentRuntimeId", "unknown"))
            protocol = rt.get("protocolConfiguration", {}).get(
                "serverProtocol", "unknown"
            )
            status = rt.get("status", "unknown")
            print(f"  {name:<30} protocol={protocol:<8} [{status}]")
    else:
        print("\nNo runtimes found.")

    if errors:
        print(f"\nErrors ({len(errors)}):")
        for err in errors:
            print(f"  - {err}")

    print("=" * 70)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    """Entry point: parse args, configure logging, dispatch subcommand."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 1

    # Logging
    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )

    logger.debug(f"CLI args: {args}")

    if args.command == "sync":
        return cmd_sync(args)
    elif args.command == "list":
        return cmd_list(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
