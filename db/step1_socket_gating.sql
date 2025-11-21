-- Step 1: add socket gating edge type and enablement view
ALTER TYPE edge_type ADD VALUE IF NOT EXISTS 'ENABLED_IF';

CREATE OR REPLACE VIEW v_build_slot_enabled AS
WITH sel AS (
  SELECT build_id, slot_id, part_id FROM build_selection
),
en_rules AS (
  SELECT e.id, e.from_slot_id, e.to_slot_id, e.rule
  FROM slot_edge e
  WHERE e.edge = 'ENABLED_IF'
),
needs AS (
  SELECT b.id AS build_id, s.id AS slot_id, COUNT(er.id) AS needed
  FROM build b
  JOIN slot s ON s.engine_id = b.engine_id
  LEFT JOIN en_rules er ON er.to_slot_id = s.id
  GROUP BY b.id, s.id
),
satisfied AS (
  SELECT n.build_id, n.slot_id,
         COUNT(*) FILTER (WHERE EXISTS (
           SELECT 1
           FROM sel sf
           WHERE sf.build_id=n.build_id
             AND sf.slot_id = er.from_slot_id
         )
         AND (
           -- attribute/part/category checks (all optional)
           (er.rule ? 'part_id' AND (SELECT part_id FROM sel WHERE build_id=n.build_id AND slot_id=er.from_slot_id) = (er.rule->>'part_id')::bigint)
           OR
           (er.rule ? 'category_id' AND EXISTS (
              SELECT 1 FROM part p
              WHERE p.id = (SELECT part_id FROM sel WHERE build_id=n.build_id AND slot_id=er.from_slot_id)
                AND p.category_id = (er.rule->>'category_id')::bigint
           ))
           OR
           (er.rule ? 'attribute_key' AND EXISTS (
              SELECT 1
              FROM attribute a
              JOIN part_attribute pa ON pa.attribute_id=a.id
              WHERE a.key = er.rule->>'attribute_key'
                AND pa.part_id = (SELECT part_id FROM sel WHERE build_id=n.build_id AND slot_id=er.from_slot_id)
                AND (
                  (er.rule ? 'value_text' AND pa.value_text = er.rule->>'value_text')
                  OR (er.rule ? 'value_bool' AND pa.value_text::boolean = (er.rule->>'value_bool')::boolean)
                  OR (er.rule ? 'value_num'  AND pa.value_num IS NOT NULL
                       AND (
                         (er.rule->>'op') = 'eq'  AND pa.value_num =  (er.rule->>'value_num')::numeric OR
                         (er.rule->>'op') = 'gte' AND pa.value_num >= (er.rule->>'value_num')::numeric OR
                         (er.rule->>'op') = 'lte' AND pa.value_num <= (er.rule->>'value_num')::numeric
                       )
                     )
                )
           ))
         )) AS ok
  FROM needs n
  LEFT JOIN en_rules er ON er.to_slot_id=n.slot_id
  GROUP BY n.build_id, n.slot_id
)
SELECT n.build_id, n.slot_id,
       (n.needed = 0 OR s.ok = n.needed) AS enabled
FROM needs n
LEFT JOIN satisfied s ON s.build_id=n.build_id AND s.slot_id=n.slot_id;
