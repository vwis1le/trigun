-- =====================================================================
--  Student Security Incident & Ticket Portal
--  Run as a MySQL admin:  sudo mysql < schema.sql
-- =====================================================================

CREATE DATABASE IF NOT EXISTS incident_portal
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_0900_ai_ci;

USE incident_portal;

-- ---------------------------------------------------------------------
-- 1. USERS  (students, security officers, admins)
--    Passwords: NEVER stored in plain text. PHP will call
--    password_hash($pw, PASSWORD_ARGON2ID) and store the result here.
--    VARCHAR(255) leaves room for future algorithm upgrades.
-- ---------------------------------------------------------------------
CREATE TABLE users (
  id                    INT UNSIGNED     NOT NULL AUTO_INCREMENT,
  student_number        VARCHAR(20)      NULL,
  full_name             VARCHAR(100)     NOT NULL,
  email                 VARCHAR(150)     NOT NULL,
  password_hash         VARCHAR(255)     NOT NULL,
  role                  ENUM('student','officer','admin') NOT NULL DEFAULT 'student',
  is_active             TINYINT(1)       NOT NULL DEFAULT 1,
  failed_login_attempts TINYINT UNSIGNED NOT NULL DEFAULT 0,
  locked_until          DATETIME         NULL,
  last_login_at         DATETIME         NULL,
  created_at            TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_users_email (email),
  UNIQUE KEY uq_users_student_number (student_number),
  CONSTRAINT chk_users_email CHECK (email LIKE '%_@_%._%')
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- 2. CATEGORIES  (what kind of incident)
-- ---------------------------------------------------------------------
CREATE TABLE categories (
  id               SMALLINT UNSIGNED NOT NULL AUTO_INCREMENT,
  name             VARCHAR(60)       NOT NULL,
  description      VARCHAR(255)      NULL,
  default_priority ENUM('low','medium','high','critical') NOT NULL DEFAULT 'medium',
  PRIMARY KEY (id),
  UNIQUE KEY uq_categories_name (name)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- 3. INCIDENTS (the tickets)
--    tracking_token_hash = SHA-256 / HMAC of the random token given to
--    the reporter. The raw token is shown ONCE and never stored, so a
--    database leak cannot be used to read anyone's ticket.
--    reporter_id is NULL for anonymous reports.
-- ---------------------------------------------------------------------
CREATE TABLE incidents (
  id                  INT UNSIGNED  NOT NULL AUTO_INCREMENT,
  tracking_token_hash BINARY(32)    NOT NULL,
  token_hint          CHAR(4)       NOT NULL COMMENT 'last 4 chars of token, helps staff verify a caller',
  reporter_id         INT UNSIGNED  NULL,
  is_anonymous        TINYINT(1)    NOT NULL DEFAULT 0,
  category_id         SMALLINT UNSIGNED NOT NULL,
  title               VARCHAR(150)  NOT NULL,
  description         TEXT          NOT NULL,
  location            VARCHAR(150)  NULL,
  occurred_at         DATETIME      NOT NULL,
  priority            ENUM('low','medium','high','critical') NOT NULL DEFAULT 'medium',
  status              ENUM('open','in_review','in_progress','resolved','closed') NOT NULL DEFAULT 'open',
  assigned_to         INT UNSIGNED  NULL,
  created_at          TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at          TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  closed_at           DATETIME      NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_incidents_token (tracking_token_hash),
  KEY idx_incidents_status_priority (status, priority),
  KEY idx_incidents_reporter (reporter_id),
  KEY idx_incidents_assigned (assigned_to),
  CONSTRAINT fk_incidents_reporter FOREIGN KEY (reporter_id)
    REFERENCES users (id) ON DELETE SET NULL,
  CONSTRAINT fk_incidents_assigned FOREIGN KEY (assigned_to)
    REFERENCES users (id) ON DELETE SET NULL,
  CONSTRAINT fk_incidents_category FOREIGN KEY (category_id)
    REFERENCES categories (id),
  CONSTRAINT chk_incidents_title CHECK (CHAR_LENGTH(TRIM(title)) >= 5),
  CONSTRAINT chk_incidents_anon CHECK (is_anonymous = 0 OR reporter_id IS NULL)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- 4. TICKET UPDATES  (comments + status history in one timeline)
--    is_public = 1  -> the reporter can see it when they enter their token
--    is_public = 0  -> internal staff note
-- ---------------------------------------------------------------------
CREATE TABLE ticket_updates (
  id          INT UNSIGNED NOT NULL AUTO_INCREMENT,
  incident_id INT UNSIGNED NOT NULL,
  author_id   INT UNSIGNED NULL COMMENT 'NULL = the anonymous reporter',
  message     TEXT         NOT NULL,
  is_public   TINYINT(1)   NOT NULL DEFAULT 1,
  old_status  ENUM('open','in_review','in_progress','resolved','closed') NULL,
  new_status  ENUM('open','in_review','in_progress','resolved','closed') NULL,
  created_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_updates_incident (incident_id, created_at),
  CONSTRAINT fk_updates_incident FOREIGN KEY (incident_id)
    REFERENCES incidents (id) ON DELETE CASCADE,
  CONSTRAINT fk_updates_author FOREIGN KEY (author_id)
    REFERENCES users (id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- 5. ATTACHMENTS (evidence: photos, screenshots)
--    Files live on disk OUTSIDE the web root; DB stores a random name
--    and a SHA-256 of the file for integrity checking.
-- ---------------------------------------------------------------------
CREATE TABLE attachments (
  id              INT UNSIGNED NOT NULL AUTO_INCREMENT,
  incident_id     INT UNSIGNED NOT NULL,
  stored_name     CHAR(36)     NOT NULL COMMENT 'random UUID filename on disk',
  original_name   VARCHAR(255) NOT NULL,
  mime_type       VARCHAR(100) NOT NULL,
  size_bytes      INT UNSIGNED NOT NULL,
  file_sha256     CHAR(64)     NOT NULL,
  uploaded_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_attach_stored (stored_name),
  KEY idx_attach_incident (incident_id),
  CONSTRAINT fk_attach_incident FOREIGN KEY (incident_id)
    REFERENCES incidents (id) ON DELETE CASCADE,
  CONSTRAINT chk_attach_size CHECK (size_bytes <= 5242880)  -- 5 MB
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- 6. TOKEN LOOKUP ATTEMPTS  (rate limiting / brute-force protection)
-- ---------------------------------------------------------------------
CREATE TABLE token_lookup_attempts (
  id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  ip_address   VARBINARY(16)   NOT NULL COMMENT 'INET6_ATON(ip)',
  success      TINYINT(1)      NOT NULL DEFAULT 0,
  attempted_at TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_attempts_ip_time (ip_address, attempted_at)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- 7. AUDIT LOG  (who did what, append-only)
-- ---------------------------------------------------------------------
CREATE TABLE audit_log (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id     INT UNSIGNED    NULL,
  action      VARCHAR(50)     NOT NULL,   -- e.g. LOGIN_OK, LOGIN_FAIL, STATUS_CHANGE
  incident_id INT UNSIGNED    NULL,
  ip_address  VARBINARY(16)   NULL,
  details     VARCHAR(255)    NULL,
  created_at  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_audit_user (user_id),
  KEY idx_audit_incident (incident_id),
  KEY idx_audit_time (created_at)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- 8. VIEW for the staff dashboard
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW v_incident_dashboard AS
SELECT i.id,
       CONCAT('INC-', LPAD(i.id, 6, '0')) AS ref_no,
       i.title, c.name AS category, i.priority, i.status,
       CASE WHEN i.is_anonymous = 1 THEN 'Anonymous' ELSE u.full_name END AS reporter,
       a.full_name AS assigned_officer,
       i.created_at, i.updated_at
FROM incidents i
JOIN categories c      ON c.id = i.category_id
LEFT JOIN users u      ON u.id = i.reporter_id
LEFT JOIN users a      ON a.id = i.assigned_to;

-- ---------------------------------------------------------------------
-- 9. SEED DATA: categories
-- ---------------------------------------------------------------------
INSERT INTO categories (name, description, default_priority) VALUES
 ('Theft / Lost Property',   'Stolen or missing personal items',            'medium'),
 ('Harassment / Bullying',   'Verbal, physical or online harassment',       'high'),
 ('Physical Safety Hazard',  'Broken lights, unsafe buildings, fire risks', 'high'),
 ('Cybersecurity Incident',  'Phishing, hacked accounts, data leaks',       'high'),
 ('Suspicious Person',       'Unknown or suspicious individuals on campus', 'medium'),
 ('Medical Emergency',       'Injury or sudden illness',                    'critical'),
 ('Vandalism',               'Damage to campus property',                   'low'),
 ('Other',                   'Anything not listed above',                   'low');

-- ---------------------------------------------------------------------
-- 10. LEAST-PRIVILEGE DATABASE USER FOR PHP
--     PHP must NOT connect as root. Change the password before running!
--     Note: no DELETE anywhere, and audit_log / attempts are insert-only.
-- ---------------------------------------------------------------------
CREATE USER IF NOT EXISTS 'portal_app'@'localhost' IDENTIFIED BY 'CHANGE_ME_TO_A_LONG_RANDOM_PASSWORD';

GRANT SELECT, INSERT, UPDATE ON incident_portal.users          TO 'portal_app'@'localhost';
GRANT SELECT                 ON incident_portal.categories     TO 'portal_app'@'localhost';
GRANT SELECT, INSERT, UPDATE ON incident_portal.incidents      TO 'portal_app'@'localhost';
GRANT SELECT, INSERT         ON incident_portal.ticket_updates TO 'portal_app'@'localhost';
GRANT SELECT, INSERT         ON incident_portal.attachments    TO 'portal_app'@'localhost';
GRANT SELECT, INSERT         ON incident_portal.token_lookup_attempts TO 'portal_app'@'localhost';
GRANT INSERT                 ON incident_portal.audit_log      TO 'portal_app'@'localhost';
GRANT SELECT                 ON incident_portal.v_incident_dashboard TO 'portal_app'@'localhost';

FLUSH PRIVILEGES;
