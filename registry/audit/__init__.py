"""
Audit and Compliance Logging Package.

This package provides audit logging capabilities for the MCP Gateway Registry,
capturing API access and MCP server access events for compliance and security review.

Components:
- models: Pydantic models for audit log records
- service: AuditLogger class for async writing and rotation
- middleware: FastAPI middleware for request/response capture
"""

from .models import (
    Action,
    Authorization,
    Identity,
    RegistryApiAccessRecord,
    Request,
    Response,
    SENSITIVE_QUERY_PARAMS,
    mask_credential,
)
from .service import AuditLogger
from .middleware import AuditMiddleware, add_audit_middleware
from .context import set_audit_action, set_audit_authorization

__all__ = [
    # Models
    "RegistryApiAccessRecord",
    "Identity",
    "Request",
    "Response",
    "Action",
    "Authorization",
    "mask_credential",
    "SENSITIVE_QUERY_PARAMS",
    # Service
    "AuditLogger",
    # Middleware
    "AuditMiddleware",
    "add_audit_middleware",
    # Context utilities
    "set_audit_action",
    "set_audit_authorization",
]
