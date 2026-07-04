-- Add shared N45 integration framework tables.
-- These tables are provider-neutral so Level.io, CIPP, SentinelOne, and future
-- integrations can share credential health, mappings, sync state, actions, and audit.

CREATE TABLE IF NOT EXISTS `integrations` (
  `integration_id` INT(11) NOT NULL AUTO_INCREMENT,
  `integration_provider` VARCHAR(100) NOT NULL,
  `integration_name` VARCHAR(200) NOT NULL,
  `integration_status` VARCHAR(50) NOT NULL DEFAULT 'disabled',
  `integration_api_version` VARCHAR(100) DEFAULT NULL,
  `integration_credential_ref` VARCHAR(255) DEFAULT NULL,
  `integration_health_status` VARCHAR(50) NOT NULL DEFAULT 'unknown',
  `integration_last_health_check_at` DATETIME DEFAULT NULL,
  `integration_last_success_at` DATETIME DEFAULT NULL,
  `integration_last_error_at` DATETIME DEFAULT NULL,
  `integration_last_error` TEXT DEFAULT NULL,
  `integration_config` LONGTEXT DEFAULT NULL,
  `integration_created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `integration_updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`integration_id`),
  UNIQUE KEY `idx_integrations_provider` (`integration_provider`),
  KEY `idx_integrations_status` (`integration_status`),
  KEY `idx_integrations_health` (`integration_health_status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `integration_tenants` (
  `integration_tenant_id` INT(11) NOT NULL AUTO_INCREMENT,
  `integration_id` INT(11) NOT NULL,
  `integration_tenant_external_id` VARCHAR(255) NOT NULL,
  `integration_tenant_name` VARCHAR(255) NOT NULL,
  `integration_tenant_status` VARCHAR(50) NOT NULL DEFAULT 'active',
  `integration_tenant_last_sync_at` DATETIME DEFAULT NULL,
  `integration_tenant_sync_state` VARCHAR(50) NOT NULL DEFAULT 'pending',
  `integration_tenant_error` TEXT DEFAULT NULL,
  `integration_tenant_metadata` LONGTEXT DEFAULT NULL,
  `integration_tenant_created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `integration_tenant_updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`integration_tenant_id`),
  UNIQUE KEY `idx_integration_tenant_external` (`integration_id`, `integration_tenant_external_id`),
  KEY `idx_integration_tenant_status` (`integration_tenant_status`),
  CONSTRAINT `fk_integration_tenants_integration`
    FOREIGN KEY (`integration_id`) REFERENCES `integrations` (`integration_id`)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `integration_client_mappings` (
  `integration_client_mapping_id` INT(11) NOT NULL AUTO_INCREMENT,
  `integration_id` INT(11) NOT NULL,
  `integration_tenant_id` INT(11) DEFAULT NULL,
  `client_id` INT(11) NOT NULL,
  `integration_external_client_id` VARCHAR(255) NOT NULL,
  `integration_external_client_name` VARCHAR(255) DEFAULT NULL,
  `integration_mapping_status` VARCHAR(50) NOT NULL DEFAULT 'active',
  `integration_mapping_confidence` VARCHAR(50) NOT NULL DEFAULT 'manual',
  `integration_mapping_metadata` LONGTEXT DEFAULT NULL,
  `integration_mapping_created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `integration_mapping_updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`integration_client_mapping_id`),
  UNIQUE KEY `idx_integration_client_external` (`integration_id`, `integration_external_client_id`),
  UNIQUE KEY `idx_integration_client_local` (`integration_id`, `client_id`),
  KEY `idx_integration_client_tenant` (`integration_tenant_id`),
  KEY `idx_integration_client_status` (`integration_mapping_status`),
  CONSTRAINT `fk_integration_client_mappings_integration`
    FOREIGN KEY (`integration_id`) REFERENCES `integrations` (`integration_id`)
    ON DELETE CASCADE,
  CONSTRAINT `fk_integration_client_mappings_tenant`
    FOREIGN KEY (`integration_tenant_id`) REFERENCES `integration_tenants` (`integration_tenant_id`)
    ON DELETE SET NULL,
  CONSTRAINT `fk_integration_client_mappings_client`
    FOREIGN KEY (`client_id`) REFERENCES `clients` (`client_id`)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `integration_asset_mappings` (
  `integration_asset_mapping_id` INT(11) NOT NULL AUTO_INCREMENT,
  `integration_id` INT(11) NOT NULL,
  `integration_tenant_id` INT(11) DEFAULT NULL,
  `client_id` INT(11) DEFAULT NULL,
  `asset_id` INT(11) DEFAULT NULL,
  `integration_external_asset_id` VARCHAR(255) NOT NULL,
  `integration_external_asset_name` VARCHAR(255) DEFAULT NULL,
  `integration_external_asset_type` VARCHAR(100) DEFAULT NULL,
  `integration_mapping_status` VARCHAR(50) NOT NULL DEFAULT 'active',
  `integration_mapping_confidence` VARCHAR(50) NOT NULL DEFAULT 'manual',
  `integration_last_seen_at` DATETIME DEFAULT NULL,
  `integration_mapping_metadata` LONGTEXT DEFAULT NULL,
  `integration_mapping_created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `integration_mapping_updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`integration_asset_mapping_id`),
  UNIQUE KEY `idx_integration_asset_external` (`integration_id`, `integration_external_asset_id`),
  KEY `idx_integration_asset_local` (`asset_id`),
  KEY `idx_integration_asset_client` (`client_id`),
  KEY `idx_integration_asset_tenant` (`integration_tenant_id`),
  KEY `idx_integration_asset_status` (`integration_mapping_status`),
  CONSTRAINT `fk_integration_asset_mappings_integration`
    FOREIGN KEY (`integration_id`) REFERENCES `integrations` (`integration_id`)
    ON DELETE CASCADE,
  CONSTRAINT `fk_integration_asset_mappings_tenant`
    FOREIGN KEY (`integration_tenant_id`) REFERENCES `integration_tenants` (`integration_tenant_id`)
    ON DELETE SET NULL,
  CONSTRAINT `fk_integration_asset_mappings_client`
    FOREIGN KEY (`client_id`) REFERENCES `clients` (`client_id`)
    ON DELETE SET NULL,
  CONSTRAINT `fk_integration_asset_mappings_asset`
    FOREIGN KEY (`asset_id`) REFERENCES `assets` (`asset_id`)
    ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `integration_events` (
  `integration_event_id` BIGINT(20) NOT NULL AUTO_INCREMENT,
  `integration_id` INT(11) NOT NULL,
  `integration_tenant_id` INT(11) DEFAULT NULL,
  `client_id` INT(11) DEFAULT NULL,
  `asset_id` INT(11) DEFAULT NULL,
  `ticket_id` INT(11) DEFAULT NULL,
  `integration_event_external_id` VARCHAR(255) DEFAULT NULL,
  `integration_event_idempotency_key` VARCHAR(255) NOT NULL,
  `integration_event_type` VARCHAR(100) NOT NULL,
  `integration_event_severity` VARCHAR(50) NOT NULL DEFAULT 'info',
  `integration_event_status` VARCHAR(50) NOT NULL DEFAULT 'new',
  `integration_event_title` VARCHAR(255) NOT NULL,
  `integration_event_message` TEXT DEFAULT NULL,
  `integration_event_source_payload` LONGTEXT DEFAULT NULL,
  `integration_event_occurred_at` DATETIME DEFAULT NULL,
  `integration_event_created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `integration_event_updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`integration_event_id`),
  UNIQUE KEY `idx_integration_event_idempotency` (`integration_id`, `integration_event_idempotency_key`),
  KEY `idx_integration_event_status` (`integration_event_status`),
  KEY `idx_integration_event_type` (`integration_event_type`),
  KEY `idx_integration_event_client` (`client_id`),
  KEY `idx_integration_event_asset` (`asset_id`),
  KEY `idx_integration_event_ticket` (`ticket_id`),
  CONSTRAINT `fk_integration_events_integration`
    FOREIGN KEY (`integration_id`) REFERENCES `integrations` (`integration_id`)
    ON DELETE CASCADE,
  CONSTRAINT `fk_integration_events_tenant`
    FOREIGN KEY (`integration_tenant_id`) REFERENCES `integration_tenants` (`integration_tenant_id`)
    ON DELETE SET NULL,
  CONSTRAINT `fk_integration_events_client`
    FOREIGN KEY (`client_id`) REFERENCES `clients` (`client_id`)
    ON DELETE SET NULL,
  CONSTRAINT `fk_integration_events_asset`
    FOREIGN KEY (`asset_id`) REFERENCES `assets` (`asset_id`)
    ON DELETE SET NULL,
  CONSTRAINT `fk_integration_events_ticket`
    FOREIGN KEY (`ticket_id`) REFERENCES `tickets` (`ticket_id`)
    ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `integration_jobs` (
  `integration_job_id` BIGINT(20) NOT NULL AUTO_INCREMENT,
  `integration_id` INT(11) NOT NULL,
  `integration_job_type` VARCHAR(100) NOT NULL,
  `integration_job_status` VARCHAR(50) NOT NULL DEFAULT 'queued',
  `integration_job_attempts` INT(11) NOT NULL DEFAULT 0,
  `integration_job_max_attempts` INT(11) NOT NULL DEFAULT 3,
  `integration_job_scheduled_at` DATETIME DEFAULT NULL,
  `integration_job_started_at` DATETIME DEFAULT NULL,
  `integration_job_finished_at` DATETIME DEFAULT NULL,
  `integration_job_last_error` TEXT DEFAULT NULL,
  `integration_job_payload` LONGTEXT DEFAULT NULL,
  `integration_job_created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `integration_job_updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`integration_job_id`),
  KEY `idx_integration_job_queue` (`integration_job_status`, `integration_job_scheduled_at`),
  KEY `idx_integration_job_type` (`integration_id`, `integration_job_type`),
  CONSTRAINT `fk_integration_jobs_integration`
    FOREIGN KEY (`integration_id`) REFERENCES `integrations` (`integration_id`)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `integration_actions` (
  `integration_action_id` BIGINT(20) NOT NULL AUTO_INCREMENT,
  `integration_id` INT(11) NOT NULL,
  `integration_tenant_id` INT(11) DEFAULT NULL,
  `user_id` INT(11) DEFAULT NULL,
  `client_id` INT(11) DEFAULT NULL,
  `asset_id` INT(11) DEFAULT NULL,
  `ticket_id` INT(11) DEFAULT NULL,
  `integration_action_type` VARCHAR(100) NOT NULL,
  `integration_action_status` VARCHAR(50) NOT NULL DEFAULT 'requested',
  `integration_action_external_id` VARCHAR(255) DEFAULT NULL,
  `integration_action_request` LONGTEXT DEFAULT NULL,
  `integration_action_response` LONGTEXT DEFAULT NULL,
  `integration_action_error` TEXT DEFAULT NULL,
  `integration_action_requested_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `integration_action_completed_at` DATETIME DEFAULT NULL,
  PRIMARY KEY (`integration_action_id`),
  KEY `idx_integration_action_status` (`integration_action_status`),
  KEY `idx_integration_action_type` (`integration_id`, `integration_action_type`),
  KEY `idx_integration_action_user` (`user_id`),
  KEY `idx_integration_action_ticket` (`ticket_id`),
  CONSTRAINT `fk_integration_actions_integration`
    FOREIGN KEY (`integration_id`) REFERENCES `integrations` (`integration_id`)
    ON DELETE CASCADE,
  CONSTRAINT `fk_integration_actions_tenant`
    FOREIGN KEY (`integration_tenant_id`) REFERENCES `integration_tenants` (`integration_tenant_id`)
    ON DELETE SET NULL,
  CONSTRAINT `fk_integration_actions_user`
    FOREIGN KEY (`user_id`) REFERENCES `users` (`user_id`)
    ON DELETE SET NULL,
  CONSTRAINT `fk_integration_actions_client`
    FOREIGN KEY (`client_id`) REFERENCES `clients` (`client_id`)
    ON DELETE SET NULL,
  CONSTRAINT `fk_integration_actions_asset`
    FOREIGN KEY (`asset_id`) REFERENCES `assets` (`asset_id`)
    ON DELETE SET NULL,
  CONSTRAINT `fk_integration_actions_ticket`
    FOREIGN KEY (`ticket_id`) REFERENCES `tickets` (`ticket_id`)
    ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `integration_audit` (
  `integration_audit_id` BIGINT(20) NOT NULL AUTO_INCREMENT,
  `integration_id` INT(11) DEFAULT NULL,
  `user_id` INT(11) DEFAULT NULL,
  `integration_audit_action` VARCHAR(100) NOT NULL,
  `integration_audit_object_type` VARCHAR(100) NOT NULL,
  `integration_audit_object_id` VARCHAR(255) DEFAULT NULL,
  `integration_audit_message` TEXT DEFAULT NULL,
  `integration_audit_payload` LONGTEXT DEFAULT NULL,
  `integration_audit_ip` VARCHAR(50) DEFAULT NULL,
  `integration_audit_user_agent` VARCHAR(500) DEFAULT NULL,
  `integration_audit_created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`integration_audit_id`),
  KEY `idx_integration_audit_integration` (`integration_id`),
  KEY `idx_integration_audit_user` (`user_id`),
  KEY `idx_integration_audit_action` (`integration_audit_action`),
  KEY `idx_integration_audit_created` (`integration_audit_created_at`),
  CONSTRAINT `fk_integration_audit_integration`
    FOREIGN KEY (`integration_id`) REFERENCES `integrations` (`integration_id`)
    ON DELETE SET NULL,
  CONSTRAINT `fk_integration_audit_user`
    FOREIGN KEY (`user_id`) REFERENCES `users` (`user_id`)
    ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
