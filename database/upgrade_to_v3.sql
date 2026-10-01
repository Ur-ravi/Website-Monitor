-- Upgrade an existing Website Monitor database to v3.
-- Does NOT delete existing websites or monitoring logs.
SET NAMES utf8mb4;

ALTER TABLE websites
 ADD COLUMN IF NOT EXISTS security_status VARCHAR(30) NOT NULL DEFAULT 'unknown',
 ADD COLUMN IF NOT EXISTS security_findings JSON NULL,
 ADD COLUMN IF NOT EXISTS security_checked_at TIMESTAMP NULL,
 ADD COLUMN IF NOT EXISTS consecutive_failures INT UNSIGNED NOT NULL DEFAULT 0,
 ADD COLUMN IF NOT EXISTS consecutive_successes INT UNSIGNED NOT NULL DEFAULT 0,
 ADD COLUMN IF NOT EXISTS first_failed_at TIMESTAMP NULL,
 ADD COLUMN IF NOT EXISTS last_recovered_at TIMESTAMP NULL,
 ADD COLUMN IF NOT EXISTS maintenance_mode TINYINT(1) NOT NULL DEFAULT 0,
 ADD COLUMN IF NOT EXISTS document_root VARCHAR(1024) NULL,
 ADD COLUMN IF NOT EXISTS ssl_expires_at TIMESTAMP NULL,
 ADD COLUMN IF NOT EXISTS last_dns_check_at TIMESTAMP NULL,
 ADD COLUMN IF NOT EXISTS last_ssl_check_at TIMESTAMP NULL;

ALTER TABLE monitoring_logs
 ADD COLUMN IF NOT EXISTS security_status VARCHAR(30) NOT NULL DEFAULT 'unknown',
 ADD COLUMN IF NOT EXISTS security_findings JSON NULL,
 ADD COLUMN IF NOT EXISTS dns_ok TINYINT(1) NULL,
 ADD COLUMN IF NOT EXISTS ssl_ok TINYINT(1) NULL,
 ADD COLUMN IF NOT EXISTS diagnostic JSON NULL;

CREATE TABLE IF NOT EXISTS sessions (
 id VARCHAR(255) NOT NULL, user_id BIGINT UNSIGNED NULL, ip_address VARCHAR(45) NULL, user_agent TEXT NULL,
 payload LONGTEXT NOT NULL, last_activity INT NOT NULL, PRIMARY KEY(id), KEY sessions_user_id_index(user_id), KEY sessions_last_activity_index(last_activity)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS cache (`key` VARCHAR(255) NOT NULL, value MEDIUMTEXT NOT NULL, expiration INT NOT NULL, PRIMARY KEY(`key`), KEY cache_expiration_index(expiration)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS cache_locks (`key` VARCHAR(255) NOT NULL, owner VARCHAR(255) NOT NULL, expiration INT NOT NULL, PRIMARY KEY(`key`)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS jobs (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT, queue VARCHAR(255) NOT NULL, payload LONGTEXT NOT NULL, attempts TINYINT UNSIGNED NOT NULL, reserved_at INT UNSIGNED NULL, available_at INT UNSIGNED NOT NULL, created_at INT UNSIGNED NOT NULL, PRIMARY KEY(id), KEY jobs_queue_index(queue)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS job_batches (id VARCHAR(255) NOT NULL, name VARCHAR(255) NOT NULL, total_jobs INT NOT NULL, pending_jobs INT NOT NULL, failed_jobs INT NOT NULL, failed_job_ids LONGTEXT NOT NULL, options MEDIUMTEXT NULL, cancelled_at INT NULL, created_at INT NOT NULL, finished_at INT NULL, PRIMARY KEY(id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS failed_jobs (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT, uuid VARCHAR(255) NOT NULL, connection TEXT NOT NULL, queue TEXT NOT NULL, payload LONGTEXT NOT NULL, exception LONGTEXT NOT NULL, failed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(id), UNIQUE KEY failed_jobs_uuid_unique(uuid)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO users(name,email,password,created_at,updated_at)
VALUES ('Administrator','admin@edutechy.in','$2y$12$6ZHuKFvJVKiQwZ.RItGNT.kx.Diw80GBWCI0p0brDryUIDOFtpcki',NOW(),NOW())
ON DUPLICATE KEY UPDATE name=VALUES(name), password=VALUES(password), updated_at=NOW();
