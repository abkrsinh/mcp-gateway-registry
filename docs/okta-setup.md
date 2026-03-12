# Okta Identity Provider Setup Guide

This guide walks through configuring Okta as the identity provider for the MCP Gateway Registry.

## Prerequisites

- An Okta developer account ([sign up free](https://developer.okta.com/signup/))
- Your Okta domain (e.g., `dev-123456.okta.com`)

## Step 1: Create an OAuth2 Web Application

1. In the Okta Admin Console, go to **Applications** → **Applications** → **Create App Integration**
2. Select **OIDC - OpenID Connect** and **Web Application**, then click **Next**
3. Configure the application:
   - **Name**: `MCP Gateway Registry`
   - **Grant types**: Authorization Code, Refresh Token, Client Credentials
   - **Sign-in redirect URIs**: `http://localhost:8888/oauth2/callback/okta` (dev) or `https://your-auth-server-domain/oauth2/callback/okta` (production)
   - **Sign-out redirect URIs**: `http://localhost` (dev) or your production URL
   - **Controlled access**: Allow everyone in your organization
4. Click **Save** and copy the **Client ID** and **Client Secret** immediately

## Step 2: Configure Groups Claim in Tokens

1. Go to **Security** → **API** → **Authorization Servers** → select **default**
2. Go to the **Claims** tab → **Add Claim**
3. Configure:
   - **Name**: `groups`
   - **Include in token type**: ID Token (Always) and Access Token (Always)
   - **Value type**: Groups
   - **Filter**: Matches regex `.*`
4. Click **Create**

## Step 3: Create Groups for Access Control

1. Go to **Directory** → **Groups** → **Add Group**
2. Create groups as needed (e.g., `mcp-admin`, `mcp-user`)
3. Assign users to groups via each group's **Assign people** tab

## Step 4: Create API Token (Optional)

Only required if you need IAM operations (user/group management through the registry).

1. Go to **Security** → **API** → **Tokens** → **Create Token**
2. Name it `MCP Gateway IAM` and copy the token value immediately
3. For least-privilege access, create a custom admin role with only the permissions you need:

| Operation | Required Permission |
|-----------|-------------------|
| List users | `okta.users.read` |
| List groups | `okta.groups.read` |
| Create/delete users | `okta.users.manage` |
| Create/delete groups | `okta.groups.manage` |
| Create service accounts | `okta.apps.manage` |

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `AUTH_PROVIDER` | Yes | Set to `okta` |
| `OKTA_DOMAIN` | Yes | Your Okta org domain (e.g., `dev-123456.okta.com`) |
| `OKTA_CLIENT_ID` | Yes | OAuth2 client ID from Step 1 |
| `OKTA_CLIENT_SECRET` | Yes | OAuth2 client secret from Step 1 |
| `OKTA_M2M_CLIENT_ID` | No | Separate M2M client ID (defaults to `OKTA_CLIENT_ID`) |
| `OKTA_M2M_CLIENT_SECRET` | No | Separate M2M client secret (defaults to `OKTA_CLIENT_SECRET`) |
| `OKTA_API_TOKEN` | For IAM | Admin API token from Step 4 |

## Example .env Configuration

```bash
AUTH_PROVIDER=okta
OKTA_DOMAIN=dev-123456.okta.com
OKTA_CLIENT_ID=0oa1234567890abcdef
OKTA_CLIENT_SECRET=your-client-secret-here

# Optional: Admin API token for IAM operations
# OKTA_API_TOKEN=your-api-token-here

# Optional: Separate M2M credentials
# OKTA_M2M_CLIENT_ID=0oa0987654321fedcba
# OKTA_M2M_CLIENT_SECRET=your-m2m-secret-here
```

## Okta Endpoints (Auto-Derived)

All endpoints are derived from `OKTA_DOMAIN`:

| Endpoint | URL |
|----------|-----|
| Authorization | `https://{OKTA_DOMAIN}/oauth2/v1/authorize` |
| Token | `https://{OKTA_DOMAIN}/oauth2/v1/token` |
| UserInfo | `https://{OKTA_DOMAIN}/oauth2/v1/userinfo` |
| JWKS | `https://{OKTA_DOMAIN}/oauth2/v1/keys` |
| Logout | `https://{OKTA_DOMAIN}/oauth2/v1/logout` |
| Issuer | `https://{OKTA_DOMAIN}` |

## Verifying Your Setup

Test the JWKS endpoint:

```bash
curl https://dev-123456.okta.com/oauth2/v1/keys
```

Test client credentials token generation:

```bash
curl -X POST https://dev-123456.okta.com/oauth2/v1/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&scope=openid" \
  -u "CLIENT_ID:CLIENT_SECRET"
```

## Troubleshooting

**Can't find Client Secret after app creation**
Regenerate it: App → General tab → Client Credentials → Edit → Regenerate Secret.

**Groups not appearing in tokens**
Verify the groups claim is configured in the Authorization Server (Step 2). Ensure the filter regex is `.*`.

**API token permission errors**
Check **Security** → **Administrators** for the role assigned to the token. Create a custom admin role with the specific scopes needed.

**Non-standard domain warning in logs**
The provider validates domains against `*.okta.com`, `*.oktapreview.com`, and `*.okta-emea.com`. Custom domains will log a warning but still work.
