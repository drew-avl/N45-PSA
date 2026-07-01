-- Prepare legacy production databases for the managed SSO migration.
-- Some live databases predate these columns even though current db.sql has them.

SET @sql = (SELECT IF(
    (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'settings' AND COLUMN_NAME = 'config_azure_client_id') = 0,
    'ALTER TABLE `settings` ADD COLUMN `config_azure_client_id` VARCHAR(200) DEFAULT NULL;',
    'SELECT "Column config_azure_client_id already exists";'
));
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(
    (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'settings' AND COLUMN_NAME = 'config_azure_client_secret') = 0,
    'ALTER TABLE `settings` ADD COLUMN `config_azure_client_secret` VARCHAR(200) DEFAULT NULL;',
    'SELECT "Column config_azure_client_secret already exists";'
));
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(
    (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'user_auth_method') = 0,
    'ALTER TABLE `users` ADD COLUMN `user_auth_method` VARCHAR(200) NOT NULL DEFAULT ''local'';',
    'SELECT "Column user_auth_method already exists";'
));
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @sql = (SELECT IF(
    (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'user_specific_encryption_ciphertext') = 0,
    'ALTER TABLE `users` ADD COLUMN `user_specific_encryption_ciphertext` VARCHAR(200) DEFAULT NULL;',
    'SELECT "Column user_specific_encryption_ciphertext already exists";'
));
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
