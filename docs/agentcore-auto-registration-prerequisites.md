# AgentCore Auto-Registration Prerequisites

This guide covers the setup required before using the AgentCore auto-registration CLI (`python -m cli.agentcore sync`). The prerequisites depend on the **authorizer type** configured on each AgentCore Gateway.

| Authorizer Type | What You Need |
|-----------------|---------------|
| `CUSTOM_JWT` | OAuth2 M2M client credentials from your identity provider (Cognito, Auth0, Okta, etc.) |
| `AWS_IAM` | AWS credentials with appropriate IAM permissions |
| `NONE` | No setup required |

> The auto-registration CLI discovers the authorizer type from each gateway automatically. You only need to prepare credentials for the authorizer types your gateways use.

---

## IAM Permissions for Discovery

Regardless of gateway authorizer type, the CLI needs AWS credentials with permissions to call the Bedrock AgentCore control-plane APIs for resource discovery.

### Required IAM Policy

Attach the following policy to the IAM user or role running the CLI:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AgentCoreDiscovery",
      "Effect": "Allow",
      "Action": [
        "bedrock-agent:ListAgentGateways",
        "bedrock-agent:GetAgentGateway",
        "bedrock-agent:ListAgentRuntimes",
        "bedrock-agent:GetAgentRuntime",
        "bedrock-agent:ListTargets",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

- `bedrock-agent:ListAgentGateways` / `GetAgentGateway` — discover gateways and their details
- `bedrock-agent:ListAgentRuntimes` / `GetAgentRuntime` — discover runtimes and their protocol configuration
- `bedrock-agent:ListTargets` — enumerate targets behind each gateway
- `sts:GetCallerIdentity` — verify AWS credentials are valid (also used for `AWS_IAM` authorizer verification)

### AWS Credential Setup

The CLI uses the standard boto3 credential chain. Configure credentials using any of these methods:

**Option A: Environment variables**

```bash
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_REGION=us-east-1
```

**Option B: AWS CLI profile**

```bash
aws configure --profile agentcore-sync
export AWS_PROFILE=agentcore-sync
export AWS_REGION=us-east-1
```

**Option C: IAM role (EC2 / ECS / Lambda)**

If running on an AWS compute resource, attach the IAM policy above to the instance role or task role. No explicit credential configuration is needed.

---

## CUSTOM_JWT Authorizer — OAuth2 M2M Client Setup

Gateways with `CUSTOM_JWT` authorizer require OAuth2 machine-to-machine (M2M) client credentials. The CLI uses these credentials to generate egress tokens for authenticating with the gateway.

You need to create an M2M client in your OAuth2 provider and note the **Client ID**, **Client Secret**, and **OAuth2 domain URL**.

### Amazon Cognito

1. Open the [Amazon Cognito console](https://console.aws.amazon.com/cognito/) and select the User Pool associated with your AgentCore Gateway.

2. Navigate to **App integration** → **App clients** and create a new app client:
   - App type: **Confidential client**
   - App client name: e.g., `agentcore-sync-m2m`
   - Generate a client secret: **Yes**
   - Authentication flows: **Client credentials** (`ALLOW_CUSTOM_AUTH` is not needed)

3. Under **Hosted UI**, configure the allowed OAuth scopes for the client. Use the scope defined by your AgentCore Gateway's resource server (e.g., `default-m2m-resource-server-XXXXXXXX/read`).

4. Note the following values:
   - **Client ID**: shown on the app client page
   - **Client Secret**: click "Show client secret"
   - **OAuth2 domain**: `https://<your-domain>.auth.<region>.amazoncognito.com`

5. Set the environment variable:
   ```bash
   export OAUTH_DOMAIN="https://<your-domain>.auth.<region>.amazoncognito.com"
   ```

### Auth0

1. Log in to the [Auth0 Dashboard](https://manage.auth0.com/) and navigate to **Applications** → **Applications**.

2. Click **Create Application**:
   - Name: e.g., `agentcore-sync-m2m`
   - Application type: **Machine to Machine**

3. Authorize the application for the API (audience) that your AgentCore Gateway uses. Select the required scopes.

4. Note the following values from the **Settings** tab:
   - **Client ID**
   - **Client Secret**
   - **Domain**: e.g., `your-tenant.auth0.com`

5. Set the environment variable:
   ```bash
   export OAUTH_DOMAIN="https://your-tenant.auth0.com"
   ```

### Okta

1. Log in to the [Okta Admin Console](https://developer.okta.com/) and navigate to **Applications** → **Applications**.

2. Click **Create App Integration**:
   - Sign-in method: **API Services** (client credentials)
   - App integration name: e.g., `agentcore-sync-m2m`

3. On the app's **General** tab, note:
   - **Client ID**
   - **Client Secret**

4. Under **Okta API Scopes**, grant the scopes required by your AgentCore Gateway.

5. Set the environment variable using your Okta domain:
   ```bash
   export OAUTH_DOMAIN="https://your-org.okta.com"
   ```

### Providing Credentials to the CLI

You can provide OAuth2 credentials in two ways:

**Option A: Environment variables (recommended for CI/CD)**

```bash
# For gateway 1
export OAUTH_CLIENT_ID_1="your-client-id"
export OAUTH_CLIENT_SECRET_1="your-client-secret"
export AGENTCORE_GATEWAY_ARN_1="arn:aws:bedrock:us-east-1:123456789012:gateway/gw-abc123"
export AGENTCORE_SERVER_NAME_1="my-gateway"
export AGENTCORE_AUTHORIZER_TYPE_1="CUSTOM_JWT"

# For gateway 2
export OAUTH_CLIENT_ID_2="another-client-id"
export OAUTH_CLIENT_SECRET_2="another-client-secret"
export AGENTCORE_GATEWAY_ARN_2="arn:aws:bedrock:us-east-1:123456789012:gateway/gw-def456"
export AGENTCORE_SERVER_NAME_2="another-gateway"
export AGENTCORE_AUTHORIZER_TYPE_2="CUSTOM_JWT"
```

> Legacy env var names `AGENTCORE_CLIENT_ID_{N}` and `AGENTCORE_CLIENT_SECRET_{N}` are also supported for backward compatibility.

**Option B: Interactive prompt**

If no environment variables are set, the CLI will prompt for credentials during `sync`:

```
OAuth2 credentials needed for gateway: arn:aws:bedrock:us-east-1:123456789012:gateway/gw-abc123
(Press Enter to skip)
  Client ID: <your-client-id>
  Client Secret: <hidden input>
```

The Client Secret is entered securely (not echoed to the terminal).

---

## AWS_IAM Authorizer

Gateways with `AWS_IAM` authorizer use the standard AWS credential chain for authentication (SigV4 signing). No OAuth2 client setup is needed.

### What You Need

1. AWS credentials configured (see [AWS Credential Setup](#aws-credential-setup) above).
2. The `sts:GetCallerIdentity` permission (included in the discovery policy above).

The CLI verifies your AWS credentials by calling `sts:GetCallerIdentity` during the sync process. If verification succeeds, the gateway is registered without any OAuth2 credential collection or token generation.

---

## NONE Authorizer

Gateways with `NONE` authorizer require **no setup**. The CLI registers these gateways without collecting credentials or generating tokens.

---

## Verification Checklist

Before running `python -m cli.agentcore sync`, verify:

- [ ] AWS credentials are configured and can call `sts:GetCallerIdentity`
- [ ] The IAM policy includes all required `bedrock-agent:*` permissions
- [ ] For `CUSTOM_JWT` gateways: OAuth2 M2M client is created and `OAUTH_DOMAIN` is set
- [ ] For `AWS_IAM` gateways: AWS credentials are available in the environment
- [ ] The MCP Gateway Registry is running and accessible at the configured `REGISTRY_URL`
- [ ] A valid registry auth token exists at the configured `--token-file` path

## Next Steps

- [Auto-Registration CLI Usage](agentcore.md#auto-registration) — CLI commands, environment variables, and troubleshooting
- [AgentCore Gateway Integration Guide](agentcore.md) — Manual gateway registration walkthrough
