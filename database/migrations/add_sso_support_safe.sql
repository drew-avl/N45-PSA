-- Safe migration for existing databases - Add SSO support for technicians
-- Date: 2026-04-13
-- This version checks for existing columns before adding them

-- Add column to store OpenID decryption key (16-byte base64 encoded)
SET @sql = (SELECT IF(
    (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'user_sso_decryption_key') = 0,
    'ALTER TABLE `users` ADD COLUMN `user_sso_decryption_key` VARCHAR(32) DEFAULT NULL AFTER `user_specific_encryption_ciphertext`;',
    'SELECT "Column user_sso_decryption_key already exists";'
));
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Add OpenID Connect configuration settings (check each one)
SET @sql = (SELECT IF(
    (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'settings' AND COLUMN_NAME = 'config_openid_enabled') = 0,
    'ALTER TABLE `settings` ADD COLUMN `config_openid_enabled` TINYINT(1) DEFAULT 0 AFTER `config_azure_client_id`;',
    'SELECT "Column config_openid_enabled already exists";'
));
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(
    (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'settings' AND COLUMN_NAME = 'config_openid_client_id') = 0,
    'ALTER TABLE `settings` ADD COLUMN `config_openid_client_id` VARCHAR(500) DEFAULT NULL AFTER `config_openid_enabled`;',
    'SELECT "Column config_openid_client_id already exists";'
));
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(
    (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'settings' AND COLUMN_NAME = 'config_openid_client_secret') = 0,
    'ALTER TABLE `settings` ADD COLUMN `config_openid_client_secret` VARCHAR(500) DEFAULT NULL AFTER `config_openid_client_id`;',
    'SELECT "Column config_openid_client_secret already exists";'
));
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(
    (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'settings' AND COLUMN_NAME = 'config_openid_discovery_url') = 0,
    'ALTER TABLE `settings` ADD COLUMN `config_openid_discovery_url` VARCHAR(500) DEFAULT NULL AFTER `config_openid_client_secret`;',
    'SELECT "Column config_openid_discovery_url already exists";'
));
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(
    (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'settings' AND COLUMN_NAME = 'config_openid_decryption_key_claim') = 0,
    'ALTER TABLE `settings` ADD COLUMN `config_openid_decryption_key_claim` VARCHAR(255) DEFAULT \'encryption_key\' AFTER `config_openid_discovery_url`;',
    'SELECT "Column config_openid_decryption_key_claim already exists";'
));
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(
    (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'settings' AND COLUMN_NAME = 'config_openid_scopes') = 0,
    'ALTER TABLE `settings` ADD COLUMN `config_openid_scopes` VARCHAR(500) DEFAULT \'openid profile email\' AFTER `config_openid_decryption_key_claim`;',
    'SELECT "Column config_openid_scopes already exists";'
));
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(
    (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'settings' AND COLUMN_NAME = 'config_openid_response_type') = 0,
    'ALTER TABLE `settings` ADD COLUMN `config_openid_response_type` VARCHAR(50) DEFAULT \'code\' AFTER `config_openid_scopes`;',
    'SELECT "Column config_openid_response_type already exists";'
));
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(
    (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'settings' AND COLUMN_NAME = 'config_site_encryption_master_key') = 0,
    'ALTER TABLE `settings` ADD COLUMN `config_site_encryption_master_key` VARCHAR(255) DEFAULT NULL AFTER `config_openid_response_type`;',
    'SELECT "Column config_site_encryption_master_key already exists";'
));
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Add index for faster lookups by auth method (check if exists first)
SET @sql = (SELECT IF(
    (SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND INDEX_NAME = 'idx_user_auth_method') = 0,
    'ALTER TABLE `users` ADD INDEX `idx_user_auth_method` (`user_auth_method`);',
    'SELECT "Index idx_user_auth_method already exists";'
));
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

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