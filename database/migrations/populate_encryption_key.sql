-- Populate missing site encryption master key for existing databases
-- This script generates and sets the config_site_encryption_master_key if it's empty

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