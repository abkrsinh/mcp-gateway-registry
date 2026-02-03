"""
Pydantic models for audit log records.

This module defines the structured data models for audit events,
including credential masking validators to ensure sensitive data
is never logged in plain text.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


def mask_credential(value: str) -> str:
    """
    Mask credential to show only last 6 characters.
    
    Args:
        value: The credential string to mask
        
    Returns:
        Masked string in format "***" + last 6 chars, or "***" if too short
    """
    if not value or len(value) <= 6:
        return "***"
    return "***" + value[-6:]


# Set of sensitive query parameter keys that should be masked
SENSITIVE_QUERY_PARAMS = frozenset({
    "token",
    "password",
    "key",
    "secret",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "auth",
    "authorization",
    "credential",
    "credentials",
})


class Identity(BaseModel):
    """
    Identity information for the user making the request.
    
    Captures authentication context including username, auth method,
    provider, groups, scopes, and credential hints (masked).
    """
    
    username: str = Field(description="Username or identifier of the requester")
    auth_method: str = Field(
        description="Authentication method: oauth2, traditional, jwt_bearer, anonymous"
    )
    provider: Optional[str] = Field(
        default=None,
        description="Identity provider: cognito, entra_id, keycloak"
    )
    groups: List[str] = Field(
        default_factory=list,
        description="Groups the user belongs to"
    )
    scopes: List[str] = Field(
        default_factory=list,
        description="OAuth scopes granted to the user"
    )
    is_admin: bool = Field(
        default=False,
        description="Whether the user has admin privileges"
    )
    credential_type: str = Field(
        description="Type of credential: session_cookie, bearer_token, none"
    )
    credential_hint: Optional[str] = Field(
        default=None,
        description="Masked hint of the credential (last 6 chars)"
    )
    
    @field_validator("credential_hint", mode="before")
    @classmethod
    def mask_credential_hint(cls, v: Optional[str]) -> Optional[str]:
        """Mask the credential hint to protect sensitive data."""
        if v:
            return mask_credential(v)
        return v


class Request(BaseModel):
    """
    HTTP request information captured for audit logging.
    
    Includes method, path, query parameters (with sensitive values masked),
    client IP, and other request metadata.
    """
    
    method: str = Field(description="HTTP method: GET, POST, PUT, DELETE, etc.")
    path: str = Field(description="Request path")
    query_params: Dict[str, Any] = Field(
        default_factory=dict,
        description="Query parameters (sensitive values masked)"
    )
    client_ip: str = Field(description="Client IP address")
    forwarded_for: Optional[str] = Field(
        default=None,
        description="X-Forwarded-For header value"
    )
    user_agent: Optional[str] = Field(
        default=None,
        description="User-Agent header value"
    )
    content_length: Optional[int] = Field(
        default=None,
        description="Content-Length of the request body"
    )
    
    @field_validator("query_params", mode="before")
    @classmethod
    def mask_sensitive_params(cls, v: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Mask sensitive query parameter values."""
        if not v:
            return {}
        return {
            k: mask_credential(str(val)) if k.lower() in SENSITIVE_QUERY_PARAMS else val
            for k, val in v.items()
        }


class Response(BaseModel):
    """
    HTTP response information captured for audit logging.
    """
    
    status_code: int = Field(description="HTTP status code")
    duration_ms: float = Field(description="Request duration in milliseconds")
    content_length: Optional[int] = Field(
        default=None,
        description="Content-Length of the response body"
    )


class Action(BaseModel):
    """
    Business-level action information set by route handlers.
    
    Provides semantic context about what operation was performed
    on what resource.
    """
    
    operation: str = Field(
        description="Operation type: create, read, update, delete, list, toggle, rate, login, logout, search"
    )
    resource_type: str = Field(
        description="Resource type: server, agent, auth, federation, health, search"
    )
    resource_id: Optional[str] = Field(
        default=None,
        description="Identifier of the resource being acted upon"
    )
    description: Optional[str] = Field(
        default=None,
        description="Human-readable description of the action"
    )


class Authorization(BaseModel):
    """
    Authorization decision information for the request.
    """
    
    decision: str = Field(
        description="Authorization decision: ALLOW, DENY, NOT_REQUIRED"
    )
    required_permission: Optional[str] = Field(
        default=None,
        description="Permission required for the action"
    )
    evaluated_scopes: List[str] = Field(
        default_factory=list,
        description="Scopes that were evaluated for authorization"
    )


class RegistryApiAccessRecord(BaseModel):
    """
    Complete audit record for a Registry API access event.
    
    This is the primary audit log record type for Phase 1,
    capturing all relevant information about an API request
    for compliance and security review.
    """
    
    timestamp: datetime = Field(description="When the event occurred (UTC)")
    log_type: str = Field(
        default="registry_api_access",
        description="Type of audit log record"
    )
    version: str = Field(
        default="1.0",
        description="Schema version for this record type"
    )
    request_id: str = Field(description="Unique identifier for this request")
    correlation_id: Optional[str] = Field(
        default=None,
        description="Correlation ID for tracing across services"
    )
    identity: Identity = Field(description="Identity of the requester")
    request: Request = Field(description="HTTP request details")
    response: Response = Field(description="HTTP response details")
    action: Optional[Action] = Field(
        default=None,
        description="Business-level action context"
    )
    authorization: Optional[Authorization] = Field(
        default=None,
        description="Authorization decision details"
    )
