-- ============================================================
-- MySQL Step 4: Combined slot status summaries
-- ============================================================

DROP VIEW IF EXISTS v_build_slot_summary;
CREATE VIEW v_build_slot_summary AS
WITH
  sel AS (
    SELECT build_id, slot_id, part_id
    FROM BuildSlotSelection
  ),
  cnt AS (
    SELECT build_id, slot_id, COUNT(*) AS selected_count
    FROM BuildSlotSelection
    GROUP BY build_id, slot_id
  ),
  en AS (
    SELECT * FROM v_build_slot_enabled
  ),
  req_edges AS (
    SELECT slot_edge_id, engine_family_id, from_slot_id, to_slot_id, min_required
    FROM SlotEdge
    WHERE edge = 'REQUIRES'
  ),
  req_bad AS (
    SELECT s.build_id, r.from_slot_id AS slot_id
    FROM sel s
    JOIN req_edges r ON r.from_slot_id = s.slot_id
    LEFT JOIN cnt c_to ON c_to.build_id = s.build_id AND c_to.slot_id = r.to_slot_id
    WHERE COALESCE(c_to.selected_count, 0) < r.min_required
    GROUP BY s.build_id, r.from_slot_id
  ),
  ma_edges AS (
    SELECT slot_edge_id, from_slot_id, to_slot_id, rule
    FROM SlotEdge
    WHERE edge = 'MATCH_ATTR'
  ),
  ma_bad AS (
    SELECT s_from.build_id, e.from_slot_id AS slot_id
    FROM ma_edges e
    JOIN sel s_from ON s_from.slot_id = e.from_slot_id
    JOIN sel s_to   ON s_to.slot_id   = e.to_slot_id AND s_to.build_id = s_from.build_id
    JOIN Attribute a ON a.`key` = JSON_UNQUOTE(JSON_EXTRACT(e.rule,'$.attribute_key'))
    JOIN PartAttribute pa_f ON pa_f.part_id = s_from.part_id AND pa_f.attribute_id = a.attribute_id
    JOIN PartAttribute pa_t ON pa_t.part_id = s_to.part_id   AND pa_t.attribute_id = a.attribute_id
    WHERE
      (a.`type`='TEXT'   AND (pa_f.value_text <> pa_t.value_text OR pa_f.value_text IS NULL OR pa_t.value_text IS NULL)) OR
      (a.`type`='NUMBER' AND (pa_f.value_num  <> pa_t.value_num  OR pa_f.value_num  IS NULL OR pa_t.value_num  IS NULL)) OR
      (a.`type`='BOOL'   AND (pa_f.value_bool <> pa_t.value_bool OR pa_f.value_bool IS NULL OR pa_t.value_bool IS NULL))
    GROUP BY s_from.build_id, e.from_slot_id
  ),
  base AS (
    SELECT
      b.build_id,
      s.slot_id,
      s.`key` AS slot_key,
      s.`name` AS slot_name,
      s.subsystem_id,
      COALESCE(c.selected_count, 0) AS selected_count,
      s.min_required,
      s.capacity
    FROM Build b
    JOIN Slot s ON s.engine_family_id = b.engine_family_id
    LEFT JOIN cnt c ON c.build_id = b.build_id AND c.slot_id = s.slot_id
  )
SELECT
  x.build_id,
  x.slot_id,
  x.slot_key,
  x.slot_name,
  x.subsystem_id,
  bs.part_id,
  p.name AS part_name,
  COALESCE(e.enabled, TRUE) AS enabled,
  (x.selected_count BETWEEN x.min_required AND x.capacity) AS local_complete,
  (rb.slot_id IS NULL AND mb.slot_id IS NULL) AS rules_ok,
  CASE
    WHEN COALESCE(e.enabled, TRUE) = 0 THEN 'socket_disabled'
    WHEN NOT (x.selected_count BETWEEN x.min_required AND x.capacity) THEN 'incomplete'
    WHEN rb.slot_id IS NOT NULL THEN 'requires_failed'
    WHEN mb.slot_id IS NOT NULL THEN 'attr_mismatch'
    ELSE 'ok'
  END AS status_code,
  CASE
    WHEN COALESCE(e.enabled, TRUE) = 1
     AND (x.selected_count BETWEEN x.min_required AND x.capacity)
     AND rb.slot_id IS NULL AND mb.slot_id IS NULL
    THEN '✅'
    ELSE '🔴'
  END AS badge
FROM base x
LEFT JOIN en e ON e.build_id = x.build_id AND e.slot_id = x.slot_id
LEFT JOIN BuildSlotSelection bs ON bs.build_id = x.build_id AND bs.slot_id = x.slot_id
LEFT JOIN Part p ON p.part_id = bs.part_id
LEFT JOIN req_bad rb ON rb.build_id = x.build_id AND rb.slot_id = x.slot_id
LEFT JOIN ma_bad  mb ON mb.build_id = x.build_id AND mb.slot_id = x.slot_id;

DROP VIEW IF EXISTS v_build_slot_status;
CREATE VIEW v_build_slot_status AS
SELECT *
FROM v_build_slot_summary;

DROP VIEW IF EXISTS v_build_subsystem_summary;
CREATE VIEW v_build_subsystem_summary AS
SELECT
  v.build_id,
  sub.subsystem_id,
  sub.`name` AS subsystem_name,
  SUM(CASE WHEN v.badge = '✅' THEN 1 ELSE 0 END) AS ok_slots,
  COUNT(*) AS total_slots,
  CASE
    WHEN SUM(CASE WHEN v.badge = '✅' THEN 1 ELSE 0 END) = COUNT(*) THEN '✅'
    ELSE '🔴'
  END AS badge
FROM v_build_slot_summary v
JOIN Subsystem sub ON sub.subsystem_id = v.subsystem_id
GROUP BY v.build_id, sub.subsystem_id, sub.`name`;
