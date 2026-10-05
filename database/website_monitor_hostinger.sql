-- Website Monitor v5 - Laravel 13 / MySQL
-- SAFE FRESH IMPORT: drops/recreates application tables. BACK UP an existing DB first.
SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS=0;

DROP TABLE IF EXISTS monitoring_logs;
DROP TABLE IF EXISTS websites;
DROP TABLE IF EXISTS website_file_baselines;
DROP TABLE IF EXISTS failed_jobs;
DROP TABLE IF EXISTS job_batches;
DROP TABLE IF EXISTS jobs;
DROP TABLE IF EXISTS cache_locks;
DROP TABLE IF EXISTS cache;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
 name VARCHAR(255) NOT NULL,
 email VARCHAR(255) NOT NULL,
 email_verified_at TIMESTAMP NULL,
 password VARCHAR(255) NOT NULL,
 remember_token VARCHAR(100) NULL,
 created_at TIMESTAMP NULL, updated_at TIMESTAMP NULL,
 PRIMARY KEY(id), UNIQUE KEY users_email_unique(email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE websites (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
 name VARCHAR(255) NOT NULL,
 url TEXT NOT NULL,
 technology VARCHAR(255) NULL,
 is_active TINYINT(1) NOT NULL DEFAULT 1,
 status VARCHAR(30) NOT NULL DEFAULT 'unknown',
 http_code SMALLINT UNSIGNED NULL,
 response_time_ms INT UNSIGNED NULL,
 last_checked_at TIMESTAMP NULL,
 last_error TEXT NULL,
 security_status VARCHAR(30) NOT NULL DEFAULT 'unknown',
 security_findings JSON NULL,
 security_checked_at TIMESTAMP NULL,
 consecutive_failures INT UNSIGNED NOT NULL DEFAULT 0,
 consecutive_successes INT UNSIGNED NOT NULL DEFAULT 0,
 first_failed_at TIMESTAMP NULL,
 last_recovered_at TIMESTAMP NULL,
 maintenance_mode TINYINT(1) NOT NULL DEFAULT 0,
 document_root VARCHAR(1024) NULL,
 ssl_expires_at TIMESTAMP NULL,
 last_dns_check_at TIMESTAMP NULL,
 last_ssl_check_at TIMESTAMP NULL,
 security_score TINYINT UNSIGNED NULL,
 security_headers JSON NULL,
 expected_title VARCHAR(255) NULL,
 expected_keywords TEXT NULL,
 expected_http_code SMALLINT UNSIGNED NULL,
 content_check_enabled TINYINT(1) NOT NULL DEFAULT 1,
 file_integrity_enabled TINYINT(1) NOT NULL DEFAULT 0,
 homepage_baseline JSON NULL,
 integrity_status VARCHAR(30) NOT NULL DEFAULT 'unknown',
 last_content_ok TINYINT(1) NULL,
 status_reasons JSON NULL,
 first_suspicious_at TIMESTAMP NULL,
 last_suspicious_at TIMESTAMP NULL,
 created_at TIMESTAMP NULL, updated_at TIMESTAMP NULL,
 PRIMARY KEY(id), KEY websites_status_index(status,is_active), KEY websites_last_checked_index(last_checked_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE monitoring_logs (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
 website_id BIGINT UNSIGNED NOT NULL,
 status VARCHAR(30) NOT NULL,
 http_code SMALLINT UNSIGNED NULL,
 response_time_ms INT UNSIGNED NULL,
 error_message TEXT NULL,
 security_status VARCHAR(30) NOT NULL DEFAULT 'unknown',
 security_findings JSON NULL,
 dns_ok TINYINT(1) NULL,
 ssl_ok TINYINT(1) NULL,
 diagnostic JSON NULL,
 security_score TINYINT UNSIGNED NULL,
 security_headers JSON NULL,
 content_ok TINYINT(1) NULL,
 integrity_status VARCHAR(30) NOT NULL DEFAULT 'unknown',
 status_reasons JSON NULL,
 homepage_hash VARCHAR(64) NULL,
 checked_at TIMESTAMP NOT NULL,
 created_at TIMESTAMP NULL, updated_at TIMESTAMP NULL,
 PRIMARY KEY(id), KEY logs_website_checked(website_id,checked_at),
 CONSTRAINT monitoring_logs_website_id_foreign FOREIGN KEY(website_id) REFERENCES websites(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE website_file_baselines (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
 website_id BIGINT UNSIGNED NOT NULL,
 path VARCHAR(512) NOT NULL,
 sha256 VARCHAR(64) NOT NULL,
 size BIGINT UNSIGNED NULL,
 recorded_at TIMESTAMP NULL,
 created_at TIMESTAMP NULL, updated_at TIMESTAMP NULL,
 PRIMARY KEY(id), UNIQUE KEY website_file_baselines_website_id_path_unique(website_id,path),
 CONSTRAINT website_file_baselines_website_id_foreign FOREIGN KEY(website_id) REFERENCES websites(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE sessions (
 id VARCHAR(255) NOT NULL, user_id BIGINT UNSIGNED NULL, ip_address VARCHAR(45) NULL, user_agent TEXT NULL,
 payload LONGTEXT NOT NULL, last_activity INT NOT NULL, PRIMARY KEY(id), KEY sessions_user_id_index(user_id), KEY sessions_last_activity_index(last_activity)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE cache (`key` VARCHAR(255) NOT NULL, value MEDIUMTEXT NOT NULL, expiration INT NOT NULL, PRIMARY KEY(`key`), KEY cache_expiration_index(expiration)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE cache_locks (`key` VARCHAR(255) NOT NULL, owner VARCHAR(255) NOT NULL, expiration INT NOT NULL, PRIMARY KEY(`key`)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE jobs (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT, queue VARCHAR(255) NOT NULL, payload LONGTEXT NOT NULL, attempts TINYINT UNSIGNED NOT NULL, reserved_at INT UNSIGNED NULL, available_at INT UNSIGNED NOT NULL, created_at INT UNSIGNED NOT NULL, PRIMARY KEY(id), KEY jobs_queue_index(queue)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE job_batches (id VARCHAR(255) NOT NULL, name VARCHAR(255) NOT NULL, total_jobs INT NOT NULL, pending_jobs INT NOT NULL, failed_jobs INT NOT NULL, failed_job_ids LONGTEXT NOT NULL, options MEDIUMTEXT NULL, cancelled_at INT NULL, created_at INT NOT NULL, finished_at INT NULL, PRIMARY KEY(id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE failed_jobs (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT, uuid VARCHAR(255) NOT NULL, connection TEXT NOT NULL, queue TEXT NOT NULL, payload LONGTEXT NOT NULL, exception LONGTEXT NOT NULL, failed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(id), UNIQUE KEY failed_jobs_uuid_unique(uuid)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO users(name,email,password,created_at,updated_at) VALUES ('Administrator','admin@edutechy.in','$2y$12$6ZHuKFvJVKiQwZ.RItGNT.kx.Diw80GBWCI0p0brDryUIDOFtpcki',NOW(),NOW());

SET FOREIGN_KEY_CHECKS=1;
