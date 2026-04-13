<?php
require_once "includes/inc_all_admin.php";
 ?>

<div class="card card-dark">
    <div class="card-header py-3">
        <h3 class="card-title"><i class="fas fa-fw fa-fingerprint mr-2"></i>Identity Providers</h3>
    </div>
    <div class="card-body">
        <form action="post.php" method="post" autocomplete="off">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token'] ?>">

            <h4>Client Portal SSO via Microsoft Entra</h4>

            <div class="form-group">
                <label>Identity Provider <small class='text-secondary'>(Currently only works with Microsoft Entra ID/AAD)</small></label>
                <div class="input-group">
                    <div class="input-group-prepend">
                        <span class="input-group-text"><i class="fa fa-fw fa-fingerprint"></i></span>
                    </div>
                    <select class="form-control select2" readonly>
                        <option <?php if (empty($config_azure_client_id)) { echo "selected"; } ?>>Disabled</option>
                        <option <?php if ($config_azure_client_id) { echo "selected"; } ?>>Microsoft Entra</option>
                        <option>Google (WIP)</option>
                        <option>Custom SSO (WIP)</option>
                    </select>
                </div>
            </div>

            <div class="form-group">
                <label>MS Entra OAuth App (Client) ID</label>
                <div class="input-group">
                    <div class="input-group-prepend">
                        <span class="input-group-text"><i class="fa fa-fw fa-user"></i></span>
                    </div>
                    <input type="text" class="form-control" name="azure_client_id" placeholder="e721e3b6-01d6-50e8-7f22-c84d951a52e7" value="<?php echo nullable_htmlentities($config_azure_client_id); ?>">
                </div>
            </div>

            <div class="form-group">
                <label>MS Entra OAuth Secret</label>
                <div class="input-group">
                    <div class="input-group-prepend">
                        <span class="input-group-text"><i class="fa fa-fw fa-key"></i></span>
                    </div>
                    <input type="password" class="form-control" name="azure_client_secret" placeholder="Auto-generated from App Registration" value="<?php echo nullable_htmlentities($config_azure_client_secret); ?>" autocomplete="new-password">
                </div>
            </div>

            <hr class="my-4">

            <h4>Agent/Technician Portal SSO via OpenID Connect</h4>
            <p class="text-muted mb-3"><small>Enable Single Sign-On for technicians using any OpenID Connect compatible provider (Auth0, Okta, Azure AD, Keycloak, etc.)</small></p>

            <div class="form-group">
                <div class="custom-control custom-switch">
                    <input type="checkbox" class="custom-control-input" id="openid_enabled" name="openid_enabled" value="1" <?php if ($config_openid_enabled) { echo "checked"; } ?>>
                    <label class="custom-control-label" for="openid_enabled">Enable OpenID Connect for Technicians</label>
                </div>
            </div>

            <div class="form-group">
                <label>OpenID Discovery URL <small class="text-secondary">(e.g., https://auth.example.com/.well-known/openid-configuration)</small></label>
                <div class="input-group">
                    <div class="input-group-prepend">
                        <span class="input-group-text"><i class="fa fa-fw fa-link"></i></span>
                    </div>
                    <input type="url" class="form-control" name="openid_discovery_url" placeholder="https://auth.example.com/.well-known/openid-configuration" value="<?php echo nullable_htmlentities($config_openid_discovery_url); ?>">
                </div>
                <small class="form-text text-muted">The OpenID Connect Discovery endpoint from your identity provider</small>
            </div>

            <div class="form-group">
                <label>OpenID Client ID</label>
                <div class="input-group">
                    <div class="input-group-prepend">
                        <span class="input-group-text"><i class="fa fa-fw fa-user"></i></span>
                    </div>
                    <input type="text" class="form-control" name="openid_client_id" placeholder="your-client-id" value="<?php echo nullable_htmlentities($config_openid_client_id); ?>">
                </div>
            </div>

            <div class="form-group">
                <label>OpenID Client Secret</label>
                <div class="input-group">
                    <div class="input-group-prepend">
                        <span class="input-group-text"><i class="fa fa-fw fa-key"></i></span>
                    </div>
                    <input type="password" class="form-control" name="openid_client_secret" placeholder="your-client-secret" value="<?php echo nullable_htmlentities($config_openid_client_secret); ?>" autocomplete="new-password">
                </div>
            </div>

            <div class="form-group">
                <label>Decryption Key Claim Name <small class="text-secondary">(Custom claim containing 16-byte base64-encoded encryption key)</small></label>
                <div class="input-group">
                    <div class="input-group-prepend">
                        <span class="input-group-text"><i class="fa fa-fw fa-lock"></i></span>
                    </div>
                    <input type="text" class="form-control" name="openid_decryption_key_claim" placeholder="encryption_key" value="<?php echo nullable_htmlentities($config_openid_decryption_key_claim); ?>">
                </div>
                <small class="form-text text-muted">
                    The OpenID Connect claim that contains the encryption key. Must contain a 16-byte random key base64-encoded.
                    <a href="#" data-toggle="popover" data-trigger="hover" data-content="Each technician must have a unique 16-byte encryption key provided by your identity provider. This key is used to decrypt stored credentials. Generate with: openssl rand -base64 16">
                        <i class="fas fa-fw fa-question-circle"></i>
                    </a>
                </small>
            </div>

            <div class="form-group">
                <label>OAuth Scopes <small class="text-secondary">(Space-separated)</small></label>
                <div class="input-group">
                    <div class="input-group-prepend">
                        <span class="input-group-text"><i class="fa fa-fw fa-tag"></i></span>
                    </div>
                    <input type="text" class="form-control" name="openid_scopes" placeholder="openid profile email" value="<?php echo nullable_htmlentities($config_openid_scopes); ?>">
                </div>
            </div>

            <div class="form-group">
                <label>Response Type</label>
                <div class="input-group">
                    <div class="input-group-prepend">
                        <span class="input-group-text"><i class="fa fa-fw fa-exchange-alt"></i></span>
                    </div>
                    <select class="form-control" name="openid_response_type">
                        <option value="code" <?php if ($config_openid_response_type === 'code') { echo "selected"; } ?>>code (Authorization Code Flow)</option>
                        <option value="id_token" <?php if ($config_openid_response_type === 'id_token') { echo "selected"; } ?>>id_token (Implicit Flow)</option>
                    </select>
                </div>
                <small class="form-text text-muted">Use 'code' for most providers (recommended for security)</small>
            </div>

            <div class="alert alert-info" role="alert">
                <h6 class="alert-heading"><i class="fa fa-fw fa-info-circle mr-2"></i>Configuration Requirements</h6>
                <ul class="mb-0 ml-3">
                    <li>Your OpenID provider must return <strong>email</strong> claim for user identification</li>
                    <li>Add a custom claim to your OpenID provider containing the 16-byte encryption key</li>
                    <li>Configure the callback URL in your provider: <strong><?php echo (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https://' : 'http://') . $_SERVER['HTTP_HOST']; ?>/agent/openid_callback.php</strong></li>
                    <li>New technician accounts are created automatically on first login</li>
                </ul>
            </div>

            <hr class="my-4">

            <button type="submit" name="edit_identity_provider" class="btn btn-primary text-bold"><i class="fa fa-check mr-2"></i>Save</button>

        </form>
    </div>
</div>

<?php require_once "../includes/footer.php";
