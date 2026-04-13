# OpenID SSO Configuration Quick Start

## 1-Minute Setup Checklist

- [ ] Identity provider account created (Auth0, Okta, etc.)
- [ ] OAuth application configured in provider
- [ ] Encryption key claim created in provider
- [ ] Redirect URI added to provider: `https://YOUR_DOMAIN/agent/openid_callback.php`
- [ ] Database migration applied: `add_sso_support.sql`
- [ ] OpenID enabled in N45-PSA settings
- [ ] Provider Discovery URL configured
- [ ] Client ID and Secret entered
- [ ] Decryption key claim name correct
- [ ] First technician test login successful

## Provider-Specific Quick Setup

### Auth0

```
1. Create Application (Regular Web Application)
2. Add Allowed Callback URLs: https://YOUR_DOMAIN/agent/openid_callback.php
3. Go to Rules → Create new rule (add encryption key to token)
4. Get Discovery URL: https://YOUR_TENANT.auth0.com/.well-known/openid-configuration
```

### Okta

```
1. Create OIDC App (Web)
2. Add Redirect URIs: https://YOUR_DOMAIN/agent/openid_callback.php
3. Add custom user attribute: encryption_key
4. Get Discovery URL: https://YOUR_DOMAIN/oauth2/v1/.well-known/openid-configuration
```

### Azure AD / Entra ID

```
1. Register new application
2. Add web redirect URI: https://YOUR_DOMAIN/agent/openid_callback.php
3. Create client secret
4. Get Discovery URL: https://login.microsoftonline.com/[TENANT_ID]/v2.0/.well-known/openid-configuration
5. Configure token claims to include encryption key
```

### Keycloak

```
1. Create new Client (OIDC)
2. Valid Redirect URIs: https://YOUR_DOMAIN/agent/openid_callback.php
3. Create Client Scope Mappers for encryption_key
4. Get Discovery URL: https://YOUR_KEYCLOAK/auth/realms/[REALM]/.well-known/openid-configuration
```

## Testing

### Test OpenID Configuration

```bash
# Verify Discovery URL works
curl https://YOUR_PROVIDER/.well-known/openid-configuration

# Generate test encryption key
openssl rand -base64 16
```

### Verify Database Migration

```sql
-- Check new columns exist
DESCRIBE users;  -- Should show: user_sso_decryption_key
DESCRIBE settings;  -- Should show: config_openid_*

-- Check new table exists
DESCRIBE sso_auth_log;
```

### First Login Test

1. Go to login page
2. Should see "Sign in with SSO" button
3. Click button
4. Authenticate with provider
5. Should redirect to technician dashboard
6. Verify technician can access credentials

## Troubleshooting Checklist

| Issue | Solution |
|-------|----------|
| No SSO button on login | Check `config_openid_enabled = 1` in database |
| "Provider metadata error" | Verify Discovery URL is correct and HTTPS |
| "Missing encryption key claim" | Verify claim name matches provider config |
| Login loops | Check refresh token handling in callback |
| Can't decrypt credentials | Verify encryption key in OIDC token matches DB |

## Environment Variables (Optional)

For enhanced security, store sensitive config in environment:

```php
// In config.php
$config_openid_client_secret = $_ENV['OPENID_CLIENT_SECRET'] ?? 'fallback_if_needed';
```

Then set in `.env` or environment:
```
OPENID_CLIENT_SECRET=your_secret_here
```

## Security Best Practices

✅ **DO**:
- Use HTTPS everywhere
- Store client secret securely (environment variable or encrypted)
- Rotate encryption keys periodically
- Log all SSO authentications
- Use strong encryption keys (openssl rand -base64 16)
- Enable MFA on provider account

❌ **DON'T**:
- Store secrets in version control
- Disable HTTPS in production
- Share encryption keys between users
- Use same encryption key for multiple users
- Disable token validation

## Common Claim Examples

```json
// Full OIDC Token
{
  "sub": "user123",
  "email": "tech@example.com",
  "name": "John Technician",
  "encryption_key": "Hs7j2KQp4L8nM9xR5vW2dF+3aB6cE0gJ1kL=",
  "iss": "https://provider.com",
  "aud": "your_client_id",
  "exp": 1234567890
}
```

## Commands Reference

```bash
# Generate new encryption key for technician
openssl rand -base64 16

# Check if provider endpoint is accessible
curl -s https://YOUR_PROVIDER/.well-known/openid-configuration | jq '.authorization_endpoint'

# View SSO authentication log (from MySQL CLI)
SELECT * FROM sso_auth_log ORDER BY sso_log_created_at DESC LIMIT 20;

# Update technician encryption key (if needed)
mysql -u user -p dbname -e "UPDATE users SET user_sso_decryption_key='NEW_KEY_BASE64' WHERE user_email='tech@example.com';"
```

## Support Resources

- [OpenID Connect Debugger](https://openidconnect.net/) - Test your configuration
- Provider's OIDC documentation
- GitHub Issues in this repository
- [OpenID Connect Spec](https://openid.net/connect/)

## Next Steps

1. ✅ Set up OpenID provider
2. ✅ Configure N45-PSA settings
3. ✅ Test first login
4. ✅ Create additional technician accounts
5. ✅ Monitor sso_auth_log for issues
6. ✅ Consider group/role mapping enhancements
7. ✅ Plan encryption key rotation strategy
