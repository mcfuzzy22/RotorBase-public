-- ============================================================
-- MySQL Step 3: Presets (save/apply/validate)
-- ============================================================

CREATE TABLE IF NOT EXISTS Preset (
  preset_id         BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  engine_family_id  BIGINT UNSIGNED NOT NULL,
  name              VARCHAR(160) NOT NULL,
  owner_user        BIGINT UNSIGNED NULL,
  is_public         TINYINT(1) NOT NULL DEFAULT 0,
  created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uq_preset_engine_name (engine_family_id, name),
  INDEX idx_preset_engine (engine_family_id),
  CONSTRAINT fk_preset_engine_family FOREIGN KEY (engine_family_id)
    REFERENCES EngineFamily(engine_family_id) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT fk_preset_owner FOREIGN KEY (owner_user)
    REFERENCES UserAccount(user_id) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS PresetSelection (
  preset_id BIGINT UNSIGNED NOT NULL,
  slot_id   BIGINT UNSIGNED NOT NULL,
  part_id   BIGINT UNSIGNED NOT NULL,
  quantity  INT NOT NULL DEFAULT 1,
  PRIMARY KEY (preset_id, slot_id),
  CONSTRAINT fk_psel_preset FOREIGN KEY (preset_id)
    REFERENCES Preset(preset_id) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT fk_psel_slot FOREIGN KEY (slot_id)
    REFERENCES Slot(slot_id) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT fk_psel_part FOREIGN KEY (part_id)
    REFERENCES Part(part_id) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

DROP VIEW IF EXISTS v_preset_slot_validation;
CREATE VIEW v_preset_slot_validation AS
WITH
  presets AS (
    SELECT preset_id, engine_family_id
    FROM Preset
  ),
  needs AS (
    SELECT
      pr.preset_id,
      pr.engine_family_id,
      s.slot_id,
      COUNT(se.slot_edge_id) AS needed
    FROM presets pr
    JOIN Slot s ON s.engine_family_id = pr.engine_family_id
    LEFT JOIN SlotEdge se
      ON se.engine_family_id = pr.engine_family_id
     AND se.to_slot_id = s.slot_id
     AND se.edge = 'ENABLED_IF'
    GROUP BY pr.preset_id, pr.engine_family_id, s.slot_id
  ),
  en_ok AS (
    SELECT
      n.preset_id,
      n.slot_id,
      SUM(
        EXISTS (
          SELECT 1
          FROM PresetSelection psf
          WHERE psf.preset_id = n.preset_id
            AND psf.slot_id = se.from_slot_id
        )
        AND (
          (JSON_EXTRACT(se.rule, '$.part_id') IS NOT NULL AND
           (SELECT psf.part_id
            FROM PresetSelection psf
            WHERE psf.preset_id = n.preset_id
              AND psf.slot_id = se.from_slot_id
            LIMIT 1) = JSON_EXTRACT(se.rule, '$.part_id'))
          OR
          (JSON_EXTRACT(se.rule, '$.category_id') IS NOT NULL AND EXISTS (
             SELECT 1
             FROM PresetSelection psf2
             JOIN PartCategory pc ON pc.part_id = psf2.part_id
             WHERE psf2.preset_id = n.preset_id
               AND psf2.slot_id = se.from_slot_id
               AND pc.category_id = CAST(JSON_UNQUOTE(JSON_EXTRACT(se.rule, '$.category_id')) AS UNSIGNED)
          ))
          OR
          (JSON_EXTRACT(se.rule, '$.attribute_key') IS NOT NULL AND EXISTS (
             SELECT 1
             FROM PresetSelection psf3
             JOIN Attribute a ON a.`key` = JSON_UNQUOTE(JSON_EXTRACT(se.rule, '$.attribute_key'))
             JOIN PartAttribute pa ON pa.part_id = psf3.part_id AND pa.attribute_id = a.attribute_id
             WHERE psf3.preset_id = n.preset_id
               AND psf3.slot_id = se.from_slot_id
               AND (
                 (JSON_EXTRACT(se.rule,'$.value_text') IS NOT NULL AND pa.value_text = JSON_UNQUOTE(JSON_EXTRACT(se.rule,'$.value_text')))
                 OR (JSON_EXTRACT(se.rule,'$.value_bool') IS NOT NULL AND pa.value_bool = JSON_EXTRACT(se.rule,'$.value_bool'))
                 OR (JSON_EXTRACT(se.rule,'$.value_num')  IS NOT NULL AND (
                       (JSON_UNQUOTE(JSON_EXTRACT(se.rule,'$.op')) = 'eq'  AND pa.value_num =  JSON_EXTRACT(se.rule,'$.value_num')) OR
                       (JSON_UNQUOTE(JSON_EXTRACT(se.rule,'$.op')) = 'gte' AND pa.value_num >= JSON_EXTRACT(se.rule,'$.value_num')) OR
                       (JSON_UNQUOTE(JSON_EXTRACT(se.rule,'$.op')) = 'lte' AND pa.value_num <= JSON_EXTRACT(se.rule,'$.value_num'))
                 ))
               )
          ))
        )
      ) AS ok
    FROM needs n
    LEFT JOIN SlotEdge se
      ON se.engine_family_id = n.engine_family_id
     AND se.to_slot_id = n.slot_id
     AND se.edge = 'ENABLED_IF'
    GROUP BY n.preset_id, n.slot_id
  ),
  enabled AS (
    SELECT
      n.preset_id,
      n.slot_id,
      (n.needed = 0 OR COALESCE(o.ok, 0) = n.needed) AS socket_enabled
    FROM needs n
    LEFT JOIN en_ok o
      ON o.preset_id = n.preset_id
     AND o.slot_id = n.slot_id
  ),
  others AS (
    SELECT
      pr.preset_id,
      se.from_slot_id,
      se.to_slot_id,
      se.edge,
      se.rule
    FROM presets pr
    JOIN SlotEdge se
      ON se.engine_family_id = pr.engine_family_id
    WHERE se.edge IN ('MATCH_ATTR','EXCLUDES')
  ),
  attr_mismatch AS (
    SELECT
      o.preset_id,
      o.from_slot_id AS slot_id
    FROM others o
    JOIN PresetSelection ps_from
      ON ps_from.preset_id = o.preset_id
     AND ps_from.slot_id = o.from_slot_id
    JOIN PresetSelection ps_to
      ON ps_to.preset_id = o.preset_id
     AND ps_to.slot_id = o.to_slot_id
    JOIN Attribute a
      ON a.`key` = JSON_UNQUOTE(JSON_EXTRACT(o.rule,'$.attribute_key'))
    JOIN PartAttribute pa_from
      ON pa_from.part_id = ps_from.part_id
     AND pa_from.attribute_id = a.attribute_id
    JOIN PartAttribute pa_to
      ON pa_to.part_id = ps_to.part_id
     AND pa_to.attribute_id = a.attribute_id
    WHERE o.edge = 'MATCH_ATTR'
      AND (
        (a.`type`='TEXT'   AND (pa_from.value_text <> pa_to.value_text OR pa_from.value_text IS NULL OR pa_to.value_text IS NULL)) OR
        (a.`type`='NUMBER' AND (pa_from.value_num  <> pa_to.value_num  OR pa_from.value_num  IS NULL OR pa_to.value_num  IS NULL)) OR
        (a.`type`='BOOL'   AND (pa_from.value_bool <> pa_to.value_bool OR pa_from.value_bool IS NULL OR pa_to.value_bool IS NULL))
      )
  ),
  excludes_hit AS (
    SELECT
      o.preset_id,
      o.from_slot_id AS slot_id
    FROM others o
    JOIN PresetSelection ps_from
      ON ps_from.preset_id = o.preset_id
     AND ps_from.slot_id = o.from_slot_id
    JOIN PresetSelection ps_to
      ON ps_to.preset_id = o.preset_id
     AND ps_to.slot_id = o.to_slot_id
    WHERE o.edge = 'EXCLUDES'
  )
SELECT
  pr.preset_id,
  s.slot_id,
  s.`key` AS slot_key,
  s.`name` AS slot_name,
  ps.part_id,
  p.name AS part_name,
  COALESCE(en.socket_enabled, TRUE) AS socket_enabled,
  CASE
    WHEN COALESCE(en.socket_enabled, TRUE) = FALSE THEN 'socket_disabled'
    WHEN EXISTS (
           SELECT 1 FROM excludes_hit eh
           WHERE eh.preset_id = pr.preset_id
             AND eh.slot_id = s.slot_id
         ) THEN 'excluded_by_rule'
    WHEN EXISTS (
           SELECT 1 FROM attr_mismatch am
           WHERE am.preset_id = pr.preset_id
             AND am.slot_id = s.slot_id
         ) THEN 'attr_mismatch'
    WHEN ps.part_id IS NULL THEN 'incomplete'
    ELSE 'ok'
  END AS status_code
FROM presets pr
JOIN Slot s
  ON s.engine_family_id = pr.engine_family_id
LEFT JOIN PresetSelection ps
  ON ps.preset_id = pr.preset_id
 AND ps.slot_id = s.slot_id
LEFT JOIN Part p
  ON p.part_id = ps.part_id
LEFT JOIN enabled en
  ON en.preset_id = pr.preset_id
 AND en.slot_id = s.slot_id;
