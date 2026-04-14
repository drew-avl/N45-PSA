-- Complete SSO migration for existing databases
-- This script safely adds all required columns and populates missing values
-- Date: 2026-04-13

-- ===========================================
-- PART 1: Safe column additions
-- ===========================================

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

-- ===========================================
-- PART 2: Populate missing encryption key
-- ===========================================

DELIMITER //

-- Function to generate a random string (similar to PHP's randomString)
CREATE FUNCTION generate_random_string(length INT) RETURNS VARCHAR(255)
BEGIN
    DECLARE chars VARCHAR(62) DEFAULT 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    DECLARE result VARCHAR(255) DEFAULT '';
    DECLARE i INT DEFAULT 1;

    WHILE i <= length DO
        SET result = CONCAT(result, SUBSTRING(chars, FLOOR(RAND() * LENGTH(chars)) + 1, 1));
        SET i = i + 1;
    END WHILE;

    RETURN result;
END //

DELIMITER ;

-- Generate and set the master key if it's NULL or empty
UPDATE settings
SET config_site_encryption_master_key = generate_random_string(32)
WHERE company_id = 1
  AND (config_site_encryption_master_key IS NULL OR config_site_encryption_master_key = '');

-- Clean up the function
DROP FUNCTION IF EXISTS generate_random_string;

-- ===========================================
-- PART 3: Verification
-- ===========================================

-- Show what was added/changed
SELECT 'Migration completed successfully!' as status;
SELECT
    'Columns added to users table' as table_name,
    COUNT(*) as columns_added
FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = DATABASE()
  AND TABLE_NAME = 'users'
  AND COLUMN_NAME IN ('user_sso_decryption_key');

SELECT
    'Columns added to settings table' as table_name,
    COUNT(*) as columns_added
FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = DATABASE()
  AND TABLE_NAME = 'settings'
  AND COLUMN_NAME IN (
    'config_openid_enabled',
    'config_openid_client_id',
    'config_openid_client_secret',
    'config_openid_discovery_url',
    'config_openid_decryption_key_claim',
    'config_openid_scopes',
    'config_openid_response_type',
    'config_site_encryption_master_key'
  );

SELECT
    'SSO auth log table created' as table_name,
    COUNT(*) as tables_created
FROM INFORMATION_SCHEMA.TABLES
WHERE TABLE_SCHEMA = DATABASE()
  AND TABLE_NAME = 'sso_auth_log';

SELECT
    'Master key populated' as status,
    config_site_encryption_master_key IS NOT NULL AND config_site_encryption_master_key != '' as key_exists
FROM settings
WHERE company_id = 1;