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
   - **Sign-out redirect URIs**: `http://localhost:7860/logout` (dev) or `https://your-registry-domain/logout` (production)
   - **Controlled access**: Allow everyone in your organization
4. Click **Save** and copy the **Client ID** and **Client Secret** immediately

## Step 2: Configure Groups Claim in ID Tokens

The groups claim is configured on the application's Sign On tab using the legacy configuration. This uses the Okta Org Authorization Server (`/oauth2/v1/*`), which has a built-in `groups` scope.

1. Go to **Applications** → your app → **Sign On** tab
2. Scroll to the **Token claims (OIDC)** section and expand **Show legacy configuration**
3. Under **Group Claims**, click **Edit**
4. Set **Groups claim type** to **Filter**
5. Set the name to `groups`, select **Matches regex**, and enter `.*`
6. Click **Save**

> **Note:** The Org Authorization Server and the "default" custom authorization server are different. This integration uses the Org Authorization Server, which natively supports the `groups` scope. Custom claims configured under Security → API → Authorization Servers → default will not apply to the Org Authorization Server.

## Step 3: Create Groups for Access Control

Okta group names must match the group names in your registry's `scopes.yml`. The default configuration expects groups like `registry-admins` and `public-mcp-users`.

1. Go to **Directory** → **Groups** → **Add Group**
2. Create groups that match your `scopes.yml` group mappings:
   - `registry-admins` — full admin access to the registry
   - `public-mcp-users` — read-only access to public MCP servers
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

All endpoints use the Org Authorization Server and are derived from `OKTA_DOMAIN`:

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

**"Permission Required" error after login**
Your Okta groups don't match the group names in `scopes.yml`. Create groups in Okta that match (e.g., `registry-admins`) and assign your user to them. See Step 3.

**Groups not appearing in tokens**
The groups claim must be configured on the app's Sign On tab under "Show legacy configuration", not on the Authorization Server's Claims tab. See Step 2. Also verify your user is assigned to at least one group.

**"One or more scopes are not configured" error**
This happens when using the default custom authorization server (`/oauth2/default/v1/*`) instead of the Org Authorization Server (`/oauth2/v1/*`). The Org Authorization Server has a built-in `groups` scope. Verify your endpoints use `/oauth2/v1/*`.

**Can't find Client Secret after app creation**
Regenerate it: App → General tab → Client Credentials → Edit → Regenerate Secret.

**API token permission errors**
Check **Security** → **Administrators** for the role assigned to the token. Create a custom admin role with the specific scopes needed.

**Non-standard domain warning in logs**
The provider validates domains against `*.okta.com`, `*.oktapreview.com`, and `*.okta-emea.com`. Custom domains will log a warning but still work.
