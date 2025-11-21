-- ============================================================
-- MySQL Step 1 + 2: Slot scaffolding, gating, and candidates
-- ============================================================

-- Subsystems group slots under an engine family (optional metadata for 3D)
CREATE TABLE IF NOT EXISTS Subsystem (
  subsystem_id      BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  engine_family_id  BIGINT UNSIGNED NOT NULL,
  `key`             VARCHAR(100) NOT NULL,
  `name`            VARCHAR(200) NOT NULL,
  gltf_node_path    VARCHAR(300) NULL,
  sort_order        INT NOT NULL DEFAULT 0,
  UNIQUE KEY uq_subsystem_key (engine_family_id, `key`),
  CONSTRAINT fk_subsystem_engine_family
    FOREIGN KEY (engine_family_id) REFERENCES EngineFamily(engine_family_id)
    ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Slots represent attachment points on an engine family
CREATE TABLE IF NOT EXISTS Slot (
  slot_id           BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  engine_family_id  BIGINT UNSIGNED NOT NULL,
  subsystem_id      BIGINT UNSIGNED NULL,
  `key`             VARCHAR(100) NOT NULL,
  `name`            VARCHAR(200) NOT NULL,
  gltf_node_path    VARCHAR(300) NOT NULL,
  `transform`       JSON NULL,
  min_required      INT NOT NULL DEFAULT 1,
  capacity          INT NOT NULL DEFAULT 1,
  notes             TEXT NULL,
  UNIQUE KEY uq_slot_key (engine_family_id, `key`),
  INDEX idx_slot_engine (engine_family_id),
  INDEX idx_slot_subsystem (subsystem_id),
  CONSTRAINT fk_slot_engine_family
    FOREIGN KEY (engine_family_id) REFERENCES EngineFamily(engine_family_id)
    ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT fk_slot_subsystem
    FOREIGN KEY (subsystem_id) REFERENCES Subsystem(subsystem_id)
    ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS slot_socket_alias (
  slot_id BIGINT UNSIGNED NOT NULL,
  alias   VARCHAR(128) NOT NULL,
  PRIMARY KEY (slot_id, alias),
  KEY ix_alias (alias),
  CONSTRAINT fk_slot_alias_slot
    FOREIGN KEY (slot_id) REFERENCES Slot(slot_id)
    ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Rules/edges between slots (requirements, exclusions, attribute checks, gating)
CREATE TABLE IF NOT EXISTS SlotEdge (
  slot_edge_id      BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  engine_family_id  BIGINT UNSIGNED NOT NULL,
  from_slot_id      BIGINT UNSIGNED NOT NULL,
  to_slot_id        BIGINT UNSIGNED NOT NULL,
  edge              ENUM('REQUIRES','EXCLUDES','MATCH_ATTR','ENABLED_IF') NOT NULL,
  min_required      INT NOT NULL DEFAULT 1,
  description       VARCHAR(255) NULL,
  fix_hint          VARCHAR(255) NULL,
  rule              JSON NULL,
  UNIQUE KEY uq_slotedge (from_slot_id, to_slot_id, edge),
  INDEX idx_slotedge_from (from_slot_id),
  INDEX idx_slotedge_to (to_slot_id),
  CONSTRAINT fk_slotedge_engine_family
    FOREIGN KEY (engine_family_id) REFERENCES EngineFamily(engine_family_id)
    ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT fk_slotedge_from
    FOREIGN KEY (from_slot_id) REFERENCES Slot(slot_id)
    ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT fk_slotedge_to
    FOREIGN KEY (to_slot_id) REFERENCES Slot(slot_id)
    ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Slot → part or category allow list
CREATE TABLE IF NOT EXISTS PartSlot (
  part_slot_id  BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  slot_id       BIGINT UNSIGNED NOT NULL,
  category_id   BIGINT UNSIGNED NULL,
  part_id       BIGINT UNSIGNED NULL,
  allow         TINYINT(1) NOT NULL DEFAULT 1,
  UNIQUE KEY uq_partslot_category (slot_id, category_id),
  UNIQUE KEY uq_partslot_part (slot_id, part_id),
  INDEX idx_partslot_slot (slot_id),
  CONSTRAINT fk_partslot_slot
    FOREIGN KEY (slot_id) REFERENCES Slot(slot_id)
    ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT fk_partslot_category
    FOREIGN KEY (category_id) REFERENCES Category(category_id)
    ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT fk_partslot_part
    FOREIGN KEY (part_id) REFERENCES Part(part_id)
    ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE INDEX IF NOT EXISTS ix_part_category_part   ON PartCategory(part_id);
CREATE INDEX IF NOT EXISTS ix_part_category_cat    ON PartCategory(category_id);
CREATE INDEX IF NOT EXISTS ix_part_slot_slot       ON PartSlot(slot_id);
CREATE INDEX IF NOT EXISTS ix_part_slot_part       ON PartSlot(part_id);
CREATE INDEX IF NOT EXISTS ix_part_slot_category   ON PartSlot(category_id);

-- Attribute catalog (used for MATCH_ATTR / ENABLED_IF rules)
CREATE TABLE IF NOT EXISTS Attribute (
  attribute_id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  `key`        VARCHAR(100) NOT NULL,
  `name`       VARCHAR(200) NOT NULL,
  `type`       ENUM('NUMBER','TEXT','BOOL') NOT NULL,
  UNIQUE KEY uq_attribute_key (`key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS PartAttribute (
  part_id      BIGINT UNSIGNED NOT NULL,
  attribute_id BIGINT UNSIGNED NOT NULL,
  value_num    DECIMAL(18,6) NULL,
  value_text   VARCHAR(255)  NULL,
  value_bool   TINYINT(1)    NULL,
  PRIMARY KEY (part_id, attribute_id),
  INDEX idx_part_attribute_attr (attribute_id),
  CONSTRAINT fk_part_attribute_part
    FOREIGN KEY (part_id) REFERENCES Part(part_id)
    ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT fk_part_attribute_attribute
    FOREIGN KEY (attribute_id) REFERENCES Attribute(attribute_id)
    ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Build slot selections (one active part per slot per build)
CREATE TABLE IF NOT EXISTS BuildSlotSelection (
  build_slot_selection_id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  build_id                BIGINT UNSIGNED NOT NULL,
  slot_id                 BIGINT UNSIGNED NOT NULL,
  part_id                 BIGINT UNSIGNED NOT NULL,
  quantity                INT NOT NULL DEFAULT 1,
  added_at                TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_build_slot (build_id, slot_id),
  INDEX idx_build_slot_build (build_id),
  INDEX idx_build_slot_slot (slot_id),
  CONSTRAINT fk_build_slot_selection_build
    FOREIGN KEY (build_id) REFERENCES Build(build_id)
    ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT fk_build_slot_selection_slot
    FOREIGN KEY (slot_id) REFERENCES Slot(slot_id)
    ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT fk_build_slot_selection_part
    FOREIGN KEY (part_id) REFERENCES Part(part_id)
    ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- View: slot enablement per build (gating)
-- ============================================================
DROP VIEW IF EXISTS v_build_slot_enabled;
CREATE VIEW v_build_slot_enabled AS
WITH
  sel AS (
    SELECT build_id, slot_id, part_id
    FROM BuildSlotSelection
  ),
  en_rules AS (
    SELECT slot_edge_id, from_slot_id, to_slot_id, rule
    FROM SlotEdge
    WHERE edge = 'ENABLED_IF'
  ),
  needs AS (
    SELECT b.build_id, s.slot_id, COUNT(er.slot_edge_id) AS needed
    FROM Build b
    JOIN Slot s ON s.engine_family_id = b.engine_family_id
    LEFT JOIN en_rules er ON er.to_slot_id = s.slot_id
    GROUP BY b.build_id, s.slot_id
  ),
  satisfied AS (
    SELECT
      n.build_id,
      n.slot_id,
      SUM(
        EXISTS (
          SELECT 1
          FROM sel sf
          WHERE sf.build_id = n.build_id
            AND sf.slot_id = er.from_slot_id
        )
        AND (
          (JSON_EXTRACT(er.rule, '$.part_id') IS NOT NULL AND
           (SELECT sf.part_id FROM sel sf WHERE sf.build_id = n.build_id AND sf.slot_id = er.from_slot_id LIMIT 1)
             = JSON_EXTRACT(er.rule, '$.part_id'))
          OR
          (JSON_EXTRACT(er.rule, '$.category_id') IS NOT NULL AND EXISTS (
             SELECT 1
             FROM PartCategory pc
             WHERE pc.part_id = (SELECT sf.part_id FROM sel sf WHERE sf.build_id = n.build_id AND sf.slot_id = er.from_slot_id LIMIT 1)
               AND pc.category_id = CAST(JSON_UNQUOTE(JSON_EXTRACT(er.rule, '$.category_id')) AS UNSIGNED)
          ))
          OR
          (JSON_EXTRACT(er.rule, '$.attribute_key') IS NOT NULL AND EXISTS (
             SELECT 1
             FROM Attribute a
             JOIN PartAttribute pa ON pa.attribute_id = a.attribute_id
             WHERE a.`key` = JSON_UNQUOTE(JSON_EXTRACT(er.rule, '$.attribute_key'))
               AND pa.part_id = (SELECT sf.part_id FROM sel sf WHERE sf.build_id = n.build_id AND sf.slot_id = er.from_slot_id LIMIT 1)
               AND (
                 (a.`type` = 'TEXT'   AND JSON_EXTRACT(er.rule,'$.value_text') IS NOT NULL AND pa.value_text = JSON_UNQUOTE(JSON_EXTRACT(er.rule,'$.value_text')))
                 OR (a.`type` = 'BOOL'   AND JSON_EXTRACT(er.rule,'$.value_bool') IS NOT NULL AND pa.value_bool = JSON_EXTRACT(er.rule,'$.value_bool'))
                 OR (a.`type` = 'NUMBER' AND JSON_EXTRACT(er.rule,'$.value_num')  IS NOT NULL AND (
                       (JSON_UNQUOTE(JSON_EXTRACT(er.rule,'$.op')) = 'eq'  AND pa.value_num =  JSON_EXTRACT(er.rule,'$.value_num')) OR
                       (JSON_UNQUOTE(JSON_EXTRACT(er.rule,'$.op')) = 'gte' AND pa.value_num >= JSON_EXTRACT(er.rule,'$.value_num')) OR
                       (JSON_UNQUOTE(JSON_EXTRACT(er.rule,'$.op')) = 'lte' AND pa.value_num <= JSON_EXTRACT(er.rule,'$.value_num'))
                 ))
               )
          ))
        )
      ) AS ok
    FROM needs n
    LEFT JOIN en_rules er ON er.to_slot_id = n.slot_id
    GROUP BY n.build_id, n.slot_id
  )
SELECT
  n.build_id,
  n.slot_id,
  (n.needed = 0 OR COALESCE(s.ok, 0) = n.needed) AS enabled
FROM needs n
LEFT JOIN satisfied s ON s.build_id = n.build_id AND s.slot_id = n.slot_id;

-- ============================================================
-- Stored procedures: slot candidates & validation
-- ============================================================
DELIMITER $$

DROP PROCEDURE IF EXISTS sp_compatible_parts $$
CREATE PROCEDURE sp_compatible_parts(IN p_build_id BIGINT, IN p_slot_id BIGINT)
BEGIN
  WITH enabled AS (
    SELECT COALESCE(e.enabled, TRUE) AS enabled
    FROM v_build_slot_enabled e
    WHERE e.build_id = p_build_id AND e.slot_id = p_slot_id
  ),
  candidates AS (
    SELECT p.part_id, p.name AS part_name, ps.category_id
    FROM PartSlot ps
    JOIN Part p ON p.part_id = ps.part_id
    WHERE ps.slot_id = p_slot_id AND ps.allow = 1 AND ps.part_id IS NOT NULL

    UNION

    SELECT p.part_id, p.name AS part_name, ps.category_id
    FROM PartSlot ps
    JOIN PartCategory pc ON pc.category_id = ps.category_id
    JOIN Part p ON p.part_id = pc.part_id
    WHERE ps.slot_id = p_slot_id AND ps.allow = 1 AND ps.category_id IS NOT NULL
  ),
  selected AS (
    SELECT slot_id, part_id
    FROM BuildSlotSelection
    WHERE build_id = p_build_id
  ),
  others AS (
    SELECT *
    FROM SlotEdge
    WHERE (from_slot_id = p_slot_id OR to_slot_id = p_slot_id)
      AND edge IN ('MATCH_ATTR','EXCLUDES')
  ),
  paired AS (
    SELECT
      slot_edge_id,
      CASE WHEN from_slot_id = p_slot_id THEN to_slot_id ELSE from_slot_id END AS other_slot_id,
      edge AS kind,
      rule
    FROM others
  ),
  excl_hits AS (
    SELECT 1
    FROM paired pr
    JOIN selected s ON s.slot_id = pr.other_slot_id
    WHERE pr.kind = 'EXCLUDES'
    LIMIT 1
  ),
  attr_mismatch AS (
    SELECT c.part_id
    FROM candidates c
    JOIN paired pr ON pr.kind = 'MATCH_ATTR'
    JOIN selected s_to ON s_to.slot_id = pr.other_slot_id
    JOIN Attribute a ON a.`key` = JSON_UNQUOTE(JSON_EXTRACT(pr.rule, '$.attribute_key'))
    JOIN PartAttribute pa_cand ON pa_cand.part_id = c.part_id AND pa_cand.attribute_id = a.attribute_id
    JOIN PartAttribute pa_sel  ON pa_sel.part_id  = s_to.part_id AND pa_sel.attribute_id  = a.attribute_id
    WHERE
      (a.`type`='TEXT'   AND (pa_cand.value_text <> pa_sel.value_text OR pa_cand.value_text IS NULL OR pa_sel.value_text IS NULL)) OR
      (a.`type`='NUMBER' AND (pa_cand.value_num  <> pa_sel.value_num  OR pa_cand.value_num  IS NULL OR pa_sel.value_num  IS NULL)) OR
      (a.`type`='BOOL'   AND (pa_cand.value_bool <> pa_sel.value_bool OR pa_cand.value_bool IS NULL OR pa_sel.value_bool IS NULL))
  )
  SELECT
    c.part_id,
    c.part_name,
    c.category_id,
    CASE
      WHEN NOT (SELECT enabled FROM enabled) THEN 0
      WHEN EXISTS (SELECT 1 FROM excl_hits) THEN 0
      WHEN EXISTS (SELECT 1 FROM attr_mismatch am WHERE am.part_id = c.part_id) THEN 0
      ELSE 1
    END AS allowed,
    CASE
      WHEN NOT (SELECT enabled FROM enabled) THEN 'socket_disabled'
      WHEN EXISTS (SELECT 1 FROM excl_hits) THEN 'excluded_by_rule'
      WHEN EXISTS (SELECT 1 FROM attr_mismatch am WHERE am.part_id = c.part_id) THEN 'attr_mismatch'
      ELSE 'ok'
    END AS reason
  FROM candidates c
  ORDER BY c.part_name;
END $$

DROP PROCEDURE IF EXISTS sp_check_part_allowed $$
CREATE PROCEDURE sp_check_part_allowed(
  IN  p_build_id BIGINT,
  IN  p_slot_id  BIGINT,
  IN  p_part_id  BIGINT,
  OUT p_allowed  TINYINT,
  OUT p_reason   VARCHAR(32)
)
BEGIN
  SET p_allowed = 0;
  SET p_reason  = 'not_candidate';

  WITH enabled AS (
    SELECT COALESCE(e.enabled, TRUE) AS enabled
    FROM v_build_slot_enabled e
    WHERE e.build_id = p_build_id AND e.slot_id = p_slot_id
  ),
  candidates AS (
    SELECT ps.part_id
    FROM PartSlot ps
    WHERE ps.slot_id = p_slot_id AND ps.allow = 1 AND ps.part_id = p_part_id

    UNION

    SELECT pc.part_id
    FROM PartSlot ps
    JOIN PartCategory pc ON pc.category_id = ps.category_id
    WHERE ps.slot_id = p_slot_id AND ps.allow = 1 AND ps.category_id IS NOT NULL AND pc.part_id = p_part_id
  ),
  selected AS (
    SELECT slot_id, part_id
    FROM BuildSlotSelection
    WHERE build_id = p_build_id
  ),
  others AS (
    SELECT *
    FROM SlotEdge
    WHERE (from_slot_id = p_slot_id OR to_slot_id = p_slot_id)
      AND edge IN ('MATCH_ATTR','EXCLUDES')
  ),
  paired AS (
    SELECT
      slot_edge_id,
      CASE WHEN from_slot_id = p_slot_id THEN to_slot_id ELSE from_slot_id END AS other_slot_id,
      edge AS kind,
      rule
    FROM others
  ),
  excl_block AS (
    SELECT 1
    FROM paired pr
    JOIN selected s ON s.slot_id = pr.other_slot_id
    WHERE pr.kind = 'EXCLUDES'
    LIMIT 1
  ),
  attr_block AS (
    SELECT 1
    FROM paired pr
    JOIN selected s_to ON s_to.slot_id = pr.other_slot_id
    JOIN Attribute a ON a.`key` = JSON_UNQUOTE(JSON_EXTRACT(pr.rule, '$.attribute_key'))
    JOIN PartAttribute pa_cand ON pa_cand.part_id = p_part_id AND pa_cand.attribute_id = a.attribute_id
    JOIN PartAttribute pa_sel  ON pa_sel.part_id  = s_to.part_id AND pa_sel.attribute_id  = a.attribute_id
    WHERE pr.kind = 'MATCH_ATTR'
      AND (
        (a.`type`='TEXT'   AND (pa_cand.value_text <> pa_sel.value_text OR pa_cand.value_text IS NULL OR pa_sel.value_text IS NULL)) OR
        (a.`type`='NUMBER' AND (pa_cand.value_num  <> pa_sel.value_num  OR pa_cand.value_num  IS NULL OR pa_sel.value_num  IS NULL)) OR
        (a.`type`='BOOL'   AND (pa_cand.value_bool <> pa_sel.value_bool OR pa_cand.value_bool IS NULL OR pa_sel.value_bool IS NULL))
      )
    LIMIT 1
  ),
  decision AS (
    SELECT
      CASE
        WHEN NOT EXISTS (SELECT 1 FROM candidates) THEN 0
        WHEN NOT (SELECT enabled FROM enabled) THEN 0
        WHEN EXISTS (SELECT 1 FROM excl_block) THEN 0
        WHEN EXISTS (SELECT 1 FROM attr_block) THEN 0
        ELSE 1
      END AS allowed,
      CASE
        WHEN NOT EXISTS (SELECT 1 FROM candidates) THEN 'not_candidate'
        WHEN NOT (SELECT enabled FROM enabled) THEN 'socket_disabled'
        WHEN EXISTS (SELECT 1 FROM excl_block) THEN 'excluded_by_rule'
        WHEN EXISTS (SELECT 1 FROM attr_block) THEN 'attr_mismatch'
        ELSE 'ok'
      END AS reason
  )
  SELECT allowed, reason
  INTO p_allowed, p_reason
  FROM decision;
END $$

DELIMITER ;
