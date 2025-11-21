-- 001_gamification.sql  (MySQL 5.7+ safe, optimized for MySQL 8+)

-- ------------------------------------------------------------------
-- 0) SESSION SAFETY
-- ------------------------------------------------------------------
SET @prev_sql_require_pk := NULL;
/*!80000 SET @prev_sql_require_pk := @@SESSION.sql_require_primary_key */;
/*!80000 SET SESSION sql_require_primary_key = 0 */;

-- ------------------------------------------------------------------
-- 1) CORE TABLES (CREATE IF NOT EXISTS)
-- ------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS UserPointsLedger (
  id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  user_id BIGINT UNSIGNED NOT NULL,
  points INT NOT NULL,
  reason VARCHAR(80) NOT NULL,
  build_id BIGINT UNSIGNED NULL,
  uniq_key VARCHAR(120) NULL,
  occurred_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_user_event (user_id, uniq_key),
  INDEX idx_user_time (user_id, occurred_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS Badge (
  badge_id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  code VARCHAR(64) NOT NULL UNIQUE,
  name VARCHAR(120) NOT NULL,
  description VARCHAR(255) NULL,
  icon_url VARCHAR(300) NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS UserBadge (
  user_id BIGINT UNSIGNED NOT NULL,
  badge_id BIGINT UNSIGNED NOT NULL,
  build_id BIGINT UNSIGNED NULL,
  earned_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (user_id, badge_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS UserStreak (
  user_id BIGINT UNSIGNED PRIMARY KEY,
  current_length INT NOT NULL DEFAULT 0,
  best_length INT NOT NULL DEFAULT 0,
  last_day DATE NOT NULL
) ENGINE=InnoDB;

-- ------------------------------------------------------------------
-- 2) FAST SUMMARY + USER PREFS (NEW)
-- ------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS UserPointsSummary (
  user_id BIGINT UNSIGNED PRIMARY KEY,
  points_total BIGINT NOT NULL DEFAULT 0,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS UserGamificationPrefs (
  user_id BIGINT UNSIGNED PRIMARY KEY,
  show_points       TINYINT(1) NOT NULL DEFAULT 1,
  show_badges       TINYINT(1) NOT NULL DEFAULT 1,
  email_opt_in      TINYINT(1) NOT NULL DEFAULT 0,
  streak_grace_days INT        NOT NULL DEFAULT 1,
  timezone          VARCHAR(64) NOT NULL DEFAULT 'UTC',
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ------------------------------------------------------------------
-- 3) SCHEMA TIGHTENING (FKs + useful indexes)
-- ------------------------------------------------------------------
SET @schema := DATABASE();

-- Ensure UserPointsLedger unique key
SET @stmt := (
  SELECT CASE
    WHEN EXISTS (
      SELECT 1 FROM information_schema.statistics
      WHERE table_schema = @schema
        AND table_name = 'UserPointsLedger'
        AND index_name = 'uq_user_event'
    )
    THEN 'DO 0'
    ELSE 'ALTER TABLE UserPointsLedger ADD UNIQUE INDEX uq_user_event (user_id, uniq_key)'
  END
);
PREPARE stmt FROM @stmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Ensure UserPointsLedger idx_user_time
SET @stmt := (
  SELECT CASE
    WHEN EXISTS (
      SELECT 1 FROM information_schema.statistics
      WHERE table_schema = @schema
        AND table_name = 'UserPointsLedger'
        AND index_name = 'idx_user_time'
    )
    THEN 'DO 0'
    ELSE 'ALTER TABLE UserPointsLedger ADD INDEX idx_user_time (user_id, occurred_at)'
  END
);
PREPARE stmt FROM @stmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Helpful compound index for reason/time queries
SET @stmt := (
  SELECT CASE
    WHEN EXISTS (
      SELECT 1 FROM information_schema.statistics
      WHERE table_schema = @schema
        AND table_name = 'UserPointsLedger'
        AND index_name = 'idx_upl_user_reason_time'
    )
    THEN 'DO 0'
    ELSE 'CREATE INDEX idx_upl_user_reason_time ON UserPointsLedger (user_id, reason, occurred_at)'
  END
);
PREPARE stmt FROM @stmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Add FK fk_upl_user
SET @stmt := (
  SELECT CASE
    WHEN EXISTS (
      SELECT 1 FROM information_schema.referential_constraints
      WHERE constraint_schema = @schema
        AND table_name = 'UserPointsLedger'
        AND constraint_name = 'fk_upl_user'
    )
    THEN 'DO 0'
    ELSE 'ALTER TABLE UserPointsLedger ADD CONSTRAINT fk_upl_user FOREIGN KEY (user_id) REFERENCES UserAccount(user_id) ON DELETE CASCADE'
  END
);
PREPARE stmt FROM @stmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Add FK fk_upl_build
SET @stmt := (
  SELECT CASE
    WHEN EXISTS (
      SELECT 1 FROM information_schema.referential_constraints
      WHERE constraint_schema = @schema
        AND table_name = 'UserPointsLedger'
        AND constraint_name = 'fk_upl_build'
    )
    THEN 'DO 0'
    ELSE 'ALTER TABLE UserPointsLedger ADD CONSTRAINT fk_upl_build FOREIGN KEY (build_id) REFERENCES Build(build_id) ON DELETE SET NULL'
  END
);
PREPARE stmt FROM @stmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Ensure UserBadge.build_id column
SET @stmt := (
  SELECT CASE
    WHEN EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = @schema
        AND table_name = 'UserBadge'
        AND column_name = 'build_id'
    )
    THEN 'DO 0'
    ELSE 'ALTER TABLE UserBadge ADD COLUMN build_id BIGINT UNSIGNED NULL'
  END
);
PREPARE stmt FROM @stmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Speed up "my badges" lookups
SET @stmt := (
  SELECT CASE
    WHEN EXISTS (
      SELECT 1 FROM information_schema.statistics
      WHERE table_schema = @schema
        AND table_name = 'UserBadge'
        AND index_name = 'idx_userbadge_user_time'
    )
    THEN 'DO 0'
    ELSE 'CREATE INDEX idx_userbadge_user_time ON UserBadge (user_id, earned_at)'
  END
);
PREPARE stmt FROM @stmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Add FK fk_ub_build
SET @stmt := (
  SELECT CASE
    WHEN EXISTS (
      SELECT 1 FROM information_schema.referential_constraints
      WHERE constraint_schema = @schema
        AND table_name = 'UserBadge'
        AND constraint_name = 'fk_ub_build'
    )
    THEN 'DO 0'
    ELSE 'ALTER TABLE UserBadge ADD CONSTRAINT fk_ub_build FOREIGN KEY (build_id) REFERENCES Build(build_id) ON DELETE SET NULL'
  END
);
PREPARE stmt FROM @stmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Add FK fk_ub_badge
SET @stmt := (
  SELECT CASE
    WHEN EXISTS (
      SELECT 1 FROM information_schema.referential_constraints
      WHERE constraint_schema = @schema
        AND table_name = 'UserBadge'
        AND constraint_name = 'fk_ub_badge'
    )
    THEN 'DO 0'
    ELSE 'ALTER TABLE UserBadge ADD CONSTRAINT fk_ub_badge FOREIGN KEY (badge_id) REFERENCES Badge(badge_id) ON DELETE CASCADE'
  END
);
PREPARE stmt FROM @stmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Add FK fk_streak_user
SET @stmt := (
  SELECT CASE
    WHEN EXISTS (
      SELECT 1 FROM information_schema.referential_constraints
      WHERE constraint_schema = @schema
        AND table_name = 'UserStreak'
        AND constraint_name = 'fk_streak_user'
    )
    THEN 'DO 0'
    ELSE 'ALTER TABLE UserStreak ADD CONSTRAINT fk_streak_user FOREIGN KEY (user_id) REFERENCES UserAccount(user_id) ON DELETE CASCADE'
  END
);
PREPARE stmt FROM @stmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Add FK fk_ups_user
SET @stmt := (
  SELECT CASE
    WHEN EXISTS (
      SELECT 1 FROM information_schema.referential_constraints
      WHERE constraint_schema = @schema
        AND table_name = 'UserPointsSummary'
        AND constraint_name = 'fk_ups_user'
    )
    THEN 'DO 0'
    ELSE 'ALTER TABLE UserPointsSummary ADD CONSTRAINT fk_ups_user FOREIGN KEY (user_id) REFERENCES UserAccount(user_id) ON DELETE CASCADE'
  END
);
PREPARE stmt FROM @stmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Add FK fk_gprefs_user
SET @stmt := (
  SELECT CASE
    WHEN EXISTS (
      SELECT 1 FROM information_schema.referential_constraints
      WHERE constraint_schema = @schema
        AND table_name = 'UserGamificationPrefs'
        AND constraint_name = 'fk_gprefs_user'
    )
    THEN 'DO 0'
    ELSE 'ALTER TABLE UserGamificationPrefs ADD CONSTRAINT fk_gprefs_user FOREIGN KEY (user_id) REFERENCES UserAccount(user_id) ON DELETE CASCADE'
  END
);
PREPARE stmt FROM @stmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- ------------------------------------------------------------------
-- 4) SEED BADGES (idempotent)
-- ------------------------------------------------------------------
INSERT IGNORE INTO Badge (code, name, description, icon_url) VALUES
  ('FIRST_BUILD','First Build','Create your first build',NULL),
  ('FIRST_SELECTION','First Part Selected','Add your first part to a build',NULL),
  ('FIRST_CATEGORY','First System Complete','Complete any category',NULL),
  ('FIRST_START','First Start','All required categories complete',NULL);

-- ------------------------------------------------------------------
-- 5) DEFAULT PREFS FOR EXISTING USERS (idempotent)
-- ------------------------------------------------------------------
INSERT IGNORE INTO UserGamificationPrefs (user_id, show_points, show_badges, email_opt_in, streak_grace_days, timezone)
SELECT u.user_id, 1, 1, 0, 1, 'UTC'
FROM UserAccount u;

-- ------------------------------------------------------------------
-- 6) OPTIONAL: BACKFILL SUMMARY FROM EXISTING LEDGER (safe; no-op if empty)
-- ------------------------------------------------------------------
INSERT INTO UserPointsSummary (user_id, points_total)
SELECT user_id, COALESCE(SUM(points),0) AS pts
FROM UserPointsLedger
GROUP BY user_id
ON DUPLICATE KEY UPDATE points_total = VALUES(points_total);

-- ------------------------------------------------------------------
-- 7) RESTORE SESSION SETTING
-- ------------------------------------------------------------------
/*!80000 SET SESSION sql_require_primary_key = @prev_sql_require_pk */;
