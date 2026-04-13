# OpenID Connect SSO for Technicians - Implementation Guide

## Overview

This implementation adds OpenID Connect (OIDC) Single Sign-On support for technician authentication in the N45-PSA application. Technicians can now authenticate using any OIDC-compliant identity provider (Auth0, Okta, Azure AD, Keycloak, etc.) without compromising the existing encryption system.

## Architecture

### Key Challenge & Solution

**Challenge**: The application's password manager encrypts credentials using each user's password as part of the encryption key derivation (PBKDF2-SHA256). With SSO, there's no password available after authentication.

**Solution**: The OpenID provider supplies a pre-generated 16-byte encryption key as a custom claim. This key is used directly for decryption, bypassing password-based key derivation while maintaining compatibility with the existing encryption model.

```
Traditional Login Flow:
Email + Password → PBKDF2(password) → Decrypt Master Key → Decrypt Credentials

SSO Login Flow:
OIDC Credentials → Provider Issues Token → Extract Encryption Key Claim → Decrypt Master Key → Decrypt Credentials
```

### Components

#### 1. Database Schema (`database/migrations/add_sso_support.sql`)
- **New columns**:
  - `users.user_sso_decryption_key` - Base64-encoded 16-byte encryption key from OIDC provider
  - `settings.config_openid_*` - OpenID Connect provider configuration
  - `sso_auth_log` table - Audit log for SSO authentication attempts

#### 2. Helper Functions (in `functions.php`)
- `getOpenIDConfig()` - Fetch OpenID configuration from database
- `fetchOpenIDMetadata()` - Retrieve provider metadata from discovery endpoint
- `generateOpenIDAuthorizationURL()` - Create authorization request URL
- `exchangeOpenIDAuthorizationCode()` - Exchange auth code for access token
- `getOpenIDUserInfo()` - Retrieve user information and claims from provider
- `decodeOpenIDToken()` - Decode JWT tokens without signature verification
- `decryptUserSpecificKeyWithSSO()` - Decrypt master key using SSO key
- `generateSSODecryptionKey()` - Generate new SSO keys for new technicians
- `decryptUserMasterKey()` - Universal decryption (intelligently handles both password and SSO)
- `logSSOAuth()` - Log SSO authentication attempts for audit trail

#### 3. OpenID Endpoints
- `agent/openid_login.php` - Initiates OpenID authorization request
- `agent/openid_callback.php` - Handles authorization callback and completes login
  - Creates technician account on first login (auto-provisioning)
  - Updates SSO decryption key on subsequent logins
  - Sets up encryption session with SSO key

#### 4. Admin Configuration UI
- Enhanced `admin/identity_provider.php` with OpenID Connect settings:
  - Enable/disable toggle
  - Discovery URL
  - Client ID and Secret
  - Custom claim name for encryption key
  - OAuth scopes
  - Response type (code vs id_token)
  - Configuration validation and feedback

#### 5. Login Flow Integration
- Updated `login.php` with:
  - SSO-aware decryption using `decryptUserMasterKey()`
  - "Sign in with SSO" button when OpenID is configured
  - Support for both local and OpenID authentication methods

## Setup Instructions

### Prerequisites

1. **OpenID Connect Provider**
   - Account with an OIDC-compliant provider (Auth0, Okta, Azure AD, Keycloak, etc.)
   - OAuth application/client created

2. **Custom Claims Support**
   - Provider must support custom claims/attributes
   - Ability to add a custom claim containing the encryption key

3. **HTTPS Enabled**
   - OIDC over HTTP is insecure and not recommended
   - Application should use HTTPS

### Step 1: Configure Identity Provider

#### Generate Encryption Keys for Technicians

Each technician needs a unique 16-byte encryption key. Generate these using:

```bash
# Generate a base64-encoded 16-byte key
openssl rand -base64 16

# Example output: Hs7j2KQp4L8nM9xR5vW2dF+3aB6cE0gJ1kL=
```

#### Add Custom Claim to OIDC Provider

Configure your identity provider to include the encryption key in the OIDC token:

**For Auth0**:
1. Go to Applications → Your App → Rules
2. Create a new rule:
```javascript
function addEncryptionKeyToToken(user, context, callback) {
  context.idToken['encryption_key'] = user.user_metadata?.encryption_key || '';
  callback(null, user, context);
}
```
3. Store the encryption key in user metadata

**For Okta**:
1. Go to API → Authorization Servers → default → Claims
2. Add a custom claim: `encryption_key`
3. Map it to `user.profile.encryption_key`

**For Azure AD**:
1. Go to App registrations → Your App → Token configuration
2. Add optional claim: `encryption_key`
3. Use manifest to map to custom extension property

**For Keycloak**:
1. Go to Clients → Your Client → Mappers
2. Add a mapper of type "User Attribute"
3. Map `encryption_key` attribute

### Step 2: Configure N45-PSA

1. **Access Admin Panel**
   - Navigate to Settings → Identity Providers (Admin → identity_provider.php)

2. **Enable OpenID Connect**
   - Check "Enable OpenID Connect for Technicians"

3. **Enter Provider Details**
   - **Discovery URL**: The OpenID Connect discovery endpoint
     - Auth0: `https://YOUR_DOMAIN/.well-known/openid-configuration`
     - Okta: `https://YOUR_DOMAIN/oauth2/v1/.well-known/openid-configuration`
     - Azure: `https://login.microsoftonline.com/YOUR_TENANT_ID/v2.0/.well-known/openid-configuration`
     - Keycloak: `https://YOUR_KEYCLOAK/.well-known/openid-configuration`
   
   - **Client ID**: Your OAuth application ID
   - **Client Secret**: Your OAuth application secret
   - **Decryption Key Claim**: The custom claim containing the encryption key (default: `encryption_key`)
   - **OAuth Scopes**: Space-separated scopes (default: `openid profile email`)
   - **Response Type**: `code` (recommended for security)

4. **Configure Redirect URI**
   - Add the callback URL to your identity provider:
     ```
     https://YOUR_DOMAIN/agent/openid_callback.php
     ```

5. **Save Configuration**
   - Click Save

### Step 3: Add Technician Accounts

#### Option A: Auto-Provisioning (Recommended)

Technicians can create accounts on first login:

1. Technician clicks "Sign in with SSO" on login page
2. Authenticates with identity provider
3. Account is automatically created if they don't exist
4. Encryption key from OIDC claim is stored
5. Technician can access credentials immediately

#### Option B: Pre-provisioned Accounts

For more control, pre-create technician accounts:

1. Admin navigates to Settings → Users
2. Creates technician account manually
3. Sets `user_auth_method = 'openid'`
4. Updates with `user_sso_decryption_key` from the OIDC provider
5. Technician uses SSO to login

```php
// Direct database example (if needed)
UPDATE users 
SET user_auth_method = 'openid',
    user_sso_decryption_key = 'Hs7j2KQp4L8nM9xR5vW2dF+3aB6cE0gJ1kL='
WHERE user_email = 'technician@example.com';
```

## Technical Details

### Encryption Key Format

- **Size**: Exactly 16 bytes (128-bit)
- **Encoding**: Base64
- **Content**: Random bytes, cryptographically generated
- **Location**: Must be returned in OIDC token/userinfo as custom claim

### Encryption Process

```
New SSO User Registration:
1. New OIDC token received with encryption_key claim
2. generateSSODecryptionKey() creates ciphertext using that key
3. Encrypted master key stored as: IV (16 bytes) + Ciphertext (encrypted master key)
4. No salt is used (unlike password-based encryption)
5. Key stored base64-encoded for easy transmission

At SSO Login:
1. OIDC token provides encryption_key claim
2. decryptUserSpecificKeyWithSSO() decrypts the stored ciphertext
3. Master key is recovered and session is established
4. All credential decryption uses this recovered master key
```

### Session Management

```
1. User authenticates via OIDC
2. Master key is decrypted using SSO key
3. generateUserSessionKey() creates ephemeral session key
4. Master key encrypted with session key
5. Session key split: ciphertext in session, key in HttpOnly cookie
6. Credentials decrypted on-demand using session key
```

## Audit Trail

All SSO authentication attempts are logged in `sso_auth_log` table:

```sql
SELECT * FROM sso_auth_log 
ORDER BY sso_log_created_at DESC 
LIMIT 50;
```

Logged events:
- Authorization initiation
- Token exchange
- User info retrieval
- Session setup
- Login success/failure
- IP address and user agent

## Security Considerations

### 1. Encryption Key Security
- Keys should be generated from CSPRNG (cryptographically secure random number generator)
- Keys must be securely transmitted in OIDC tokens (HTTPS only)
- Keys should be rotated periodically
- Consider using encryption for the `user_sso_decryption_key` column in production

### 2. HTTPS Enforcement
- Production deployments **must** use HTTPS
- Set `config_https_only = 1` in `config.php`
- Ensure browser sends secure cookies only

### 3. Token Validation (Future Enhancement)
Current implementation:
- ✅ Validates state parameter (CSRF protection)
- ✅ Validates nonce
- ✅ Verifies email claim exists
- ✅ Checks decryption key format

Recommended additions:
- Verify JWT signature using provider's public key (JWKS endpoint)
- Validate token expiration
- Validate token issuer (`iss` claim)

### 4. Authority & Permissions
- Auto-provisioned accounts need role assignment
- Consider restricting auto-provisioning to specific email domains
- Implement approval workflow for new SSO technicians

## Troubleshooting

### "OpenID Connect is not configured"
- Verify settings saved in database
- Check `config_openid_enabled = 1` via: `SELECT * FROM settings LIMIT 1;`

### "Failed to fetch OpenID Connect provider metadata"
- Verify Discovery URL is correct and accessible
- Check HTTPS certificate validity
- Ensure firewall allows outbound HTTPS

### "OpenID provider did not supply required encryption key claim"
- Verify custom claim name matches configuration (default: `encryption_key`)
- Ensure OIDC provider is configured to return the claim
- Check claim scope (may need to add custom scope)

### "Invalid decryption key format or length"
- Decryption key must be base64-encoded 16 bytes
- Generate valid key: `openssl rand -base64 16`
- Verify provider returns proper base64

### "Failed to decrypt encryption key"
- Encryption key in OIDC token may not match `user_sso_decryption_key` in database
- Key may have been rotated in provider but not updated in application
- Check `sso_auth_log` for detailed error messages

### Technician can't access credentials after SSO login
- Verify master key was properly decrypted (check debug logs)
- Confirm `user_sso_decryption_key` is not NULL in `users` table
- Try password reset to generate new encryption ciphertext

## API Integration

If technicians use API keys, these also support SSO-style decryption:

```php
// API key decryption with SSO support
$api_key = decryptUserMasterKey(
    $api_key_decrypt_hash,
    null,  // No password
    'openid',  // Auth method
    $api_key_sso_decryption_key  // SSO key
);
```

## Future Enhancements

- [ ] JWT signature verification using JWKS endpoint
- [ ] Token introspection endpoint usage
- [ ] Refresh token handling
- [ ] Multi-provider support (Federation)
- [ ] Group/role mapping from OIDC provider
- [ ] Encryption key rotation policies
- [ ] Admin approval for new SSO users
- [ ] SSO-only technician accounts (password authentication disabled)
- [ ] Just-In-Time (JIT) user provisioning with custom attributes

## References

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OAuth 2.0 Authorization Code Flow](https://tools.ietf.org/html/rfc6749#section-1.3.1)
- [OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html)

## Support

For issues or questions regarding SSO implementation:

1. Check `sso_auth_log` table for detailed error messages
2. Review PHP error logs
3. Verify database schema was updated (run migration)
4. Confirm OpenID provider endpoint is accessible
5. Test manually with curl:
   ```bash
   curl "https://YOUR_PROVIDER/.well-known/openid-configuration"
   ```

## Files Modified

- `functions.php` - Added OpenID helper functions
- `login.php` - Updated to support SSO decryption
- `admin/identity_provider.php` - Added OpenID configuration UI
- `admin/post/identity_provider.php` - Handle form submission
- `database/migrations/add_sso_support.sql` - Schema updates

## Files Created

- `agent/openid_login.php` - Authorization initiator
- `agent/openid_callback.php` - Authorization callback handler
