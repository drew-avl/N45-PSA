-- Add SSO support for technicians
-- Date: 2026-04-13

-- Add column to store OpenID decryption key (16-byte base64 encoded)
ALTER TABLE `users` ADD COLUMN `user_sso_decryption_key` VARCHAR(32) DEFAULT NULL AFTER `user_specific_encryption_ciphertext`;

-- Add OpenID Connect configuration settings
ALTER TABLE `settings` ADD COLUMN `config_openid_enabled` TINYINT(1) DEFAULT 0 AFTER `config_azure_client_id`;
ALTER TABLE `settings` ADD COLUMN `config_openid_client_id` VARCHAR(500) DEFAULT NULL AFTER `config_openid_enabled`;
ALTER TABLE `settings` ADD COLUMN `config_openid_client_secret` VARCHAR(500) DEFAULT NULL AFTER `config_openid_client_id`;
ALTER TABLE `settings` ADD COLUMN `config_openid_discovery_url` VARCHAR(500) DEFAULT NULL AFTER `config_openid_client_secret`;
ALTER TABLE `settings` ADD COLUMN `config_openid_decryption_key_claim` VARCHAR(255) DEFAULT 'encryption_key' AFTER `config_openid_discovery_url`;
ALTER TABLE `settings` ADD COLUMN `config_openid_scopes` VARCHAR(500) DEFAULT 'openid profile email' AFTER `config_openid_decryption_key_claim`;
ALTER TABLE `settings` ADD COLUMN `config_openid_response_type` VARCHAR(50) DEFAULT 'code' AFTER `config_openid_scopes`;
ALTER TABLE `settings` ADD COLUMN `config_site_encryption_master_key` VARCHAR(255) DEFAULT NULL AFTER `config_openid_response_type`;

-- Add index for faster lookups by auth method
ALTER TABLE `users` ADD INDEX `idx_user_auth_method` (`user_auth_method`);

-- Log table for SSO authentication attempts
CREATE TABLE IF NOT EXISTS `sso_auth_log` (
  `sso_log_id` INT(11) NOT NULL AUTO_INCREMENT,
  `sso_log_type` VARCHAR(50) NOT NULL,
  `sso_log_provider` VARCHAR(50) NOT NULL,
  `sso_log_user_email` VARCHAR(200),
  `sso_log_user_id` INT(11),
  `sso_log_status` VARCHAR(50) NOT NULL,
  `sso_log_message` TEXT,
  `sso_log_ip` VARCHAR(50),
  `sso_log_user_agent` VARCHAR(500),
  `sso_log_created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`sso_log_id`),
  KEY `idx_sso_user_id` (`sso_log_user_id`),
  KEY `idx_sso_provider` (`sso_log_provider`),
  KEY `idx_sso_created_at` (`sso_log_created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
