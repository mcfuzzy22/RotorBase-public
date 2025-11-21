DROP VIEW IF EXISTS v_admin_socket_map;
CREATE VIEW v_admin_socket_map AS
SELECT
  ef.engine_family_id,
  ef.code                            AS engine_code,

  sub.subsystem_id,
  sub.`key`                          AS subsystem_key,
  sub.`name`                         AS subsystem_name,

  s.slot_id,
  s.`key`                            AS slot_key,
  s.`name`                           AS slot_name,
  s.gltf_node_path,
  s.mate_tx,
  s.mate_ty,
  s.mate_tz,
  s.mate_rx,
  s.mate_ry,
  s.mate_rz,
  s.mate_scale,

  ps.part_slot_id,
  c.category_id,
  c.slug                             AS category_slug,
  c.name                             AS category_name,

  p.part_id,
  p.sku,
  p.name                             AS part_name,
  p.gltf_uri,
  p.gltf_attach_node
FROM EngineFamily ef
JOIN Subsystem sub       ON sub.engine_family_id = ef.engine_family_id
JOIN Slot s              ON s.subsystem_id       = sub.subsystem_id
LEFT JOIN PartSlot ps    ON ps.slot_id           = s.slot_id
LEFT JOIN Category c     ON c.category_id        = ps.category_id
LEFT JOIN Part p         ON p.part_id            = ps.part_id
ORDER BY ef.code, sub.sort_order, s.slot_id, ps.part_slot_id;
