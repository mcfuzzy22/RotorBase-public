/* 13B-REW first target slice
   Adds a street-turbo planning skeleton to the existing default 13B-REW tree.
   This intentionally seeds categories/slots/rules before exact part coverage is complete.
*/

SET @engine_id := (SELECT engine_family_id FROM EngineFamily WHERE code = '13B-REW' LIMIT 1);
SET @tree_id := (
  SELECT tree_id
    FROM EngineFamilyTree
   WHERE engine_family_id = @engine_id
     AND is_default = 1
   ORDER BY tree_id
   LIMIT 1
);

INSERT INTO Category (name, slug, description, is_selectable)
VALUES
  ('Air & Exhaust', 'air-exhaust', 'Turbo, intake, charge air, and exhaust planning group.', FALSE),
  ('Fuel System', 'fuel-system', 'Fuel delivery planning group.', FALSE),
  ('Engine Management', 'engine-management', 'ECU, sensors, boost control, ignition, and instrumentation planning group.', FALSE),
  ('Cooling', 'cooling', 'Coolant and oil temperature control planning group.', FALSE),
  ('Drivetrain', 'drivetrain', 'Power transfer and mounting planning group.', FALSE),
  ('Turbocharger', 'turbocharger', 'Primary turbocharger selection.', TRUE),
  ('Exhaust Manifold', 'exhaust-manifold', 'Turbo manifold or exhaust manifold selection.', TRUE),
  ('Wastegate', 'wastegate', 'External or internal wastegate planning slot.', TRUE),
  ('Downpipe', 'downpipe', 'Turbo outlet and downpipe planning slot.', TRUE),
  ('Intercooler', 'intercooler', 'Charge-air cooler planning slot.', TRUE),
  ('Intercooler Piping', 'intercooler-piping', 'Charge piping planning slot.', TRUE),
  ('Blow-Off Valve', 'blow-off-valve', 'Compressor bypass or blow-off valve planning slot.', TRUE),
  ('Intake Filter', 'intake-filter', 'Turbo inlet filter or intake filter planning slot.', TRUE),
  ('Primary Injectors', 'primary-injectors', 'Primary injector set planning slot.', TRUE),
  ('Secondary Injectors', 'secondary-injectors', 'Secondary injector set planning slot.', TRUE),
  ('Fuel Pump', 'fuel-pump', 'Fuel pump planning slot.', TRUE),
  ('Fuel Pressure Regulator', 'fuel-pressure-regulator', 'Fuel pressure regulator planning slot.', TRUE),
  ('Fuel Rails', 'fuel-rails', 'Fuel rail planning slot.', TRUE),
  ('ECU', 'ecu', 'Engine management controller planning slot.', TRUE),
  ('MAP Sensor', 'map-sensor', 'Manifold pressure sensor planning slot.', TRUE),
  ('Boost Control', 'boost-control', 'Boost control solenoid or controller planning slot.', TRUE),
  ('Ignition Coils', 'ignition-coils', 'Ignition coil planning slot.', TRUE),
  ('Spark Plug Set', 'spark-plug-set', 'Spark plug set planning slot.', TRUE),
  ('Plug Wires', 'plug-wires', 'Ignition wire or lead planning slot.', TRUE),
  ('Wideband O2 Sensor', 'wideband-o2-sensor', 'Wideband oxygen sensor and controller planning slot.', TRUE),
  ('Radiator', 'radiator', 'Radiator planning slot.', TRUE),
  ('Oil Cooler', 'oil-cooler', 'Oil cooler planning slot.', TRUE),
  ('Thermostat', 'thermostat', 'Thermostat planning slot.', TRUE),
  ('Cooling Fans', 'cooling-fans', 'Cooling fan planning slot.', TRUE),
  ('Clutch', 'clutch', 'Clutch planning slot.', TRUE),
  ('Flywheel', 'flywheel', 'Flywheel planning slot.', TRUE),
  ('Engine Mounts', 'engine-mounts', 'Engine mount planning slot.', TRUE)
ON DUPLICATE KEY UPDATE
  name = VALUES(name),
  description = VALUES(description),
  is_selectable = VALUES(is_selectable);

DROP TEMPORARY TABLE IF EXISTS seed_13brew_edges;
CREATE TEMPORARY TABLE seed_13brew_edges (
  parent_slug VARCHAR(200) COLLATE utf8mb4_general_ci NOT NULL,
  child_slug VARCHAR(200) COLLATE utf8mb4_general_ci NOT NULL,
  position INT NOT NULL,
  PRIMARY KEY (parent_slug, child_slug)
);

INSERT INTO seed_13brew_edges (parent_slug, child_slug, position)
VALUES
  ('air-exhaust', 'turbocharger', 10),
  ('air-exhaust', 'exhaust-manifold', 20),
  ('air-exhaust', 'wastegate', 30),
  ('air-exhaust', 'downpipe', 40),
  ('air-exhaust', 'intercooler', 50),
  ('air-exhaust', 'intercooler-piping', 60),
  ('air-exhaust', 'blow-off-valve', 70),
  ('air-exhaust', 'intake-filter', 80),
  ('fuel-system', 'primary-injectors', 10),
  ('fuel-system', 'secondary-injectors', 20),
  ('fuel-system', 'fuel-pump', 30),
  ('fuel-system', 'fuel-pressure-regulator', 40),
  ('fuel-system', 'fuel-rails', 50),
  ('engine-management', 'ecu', 10),
  ('engine-management', 'map-sensor', 20),
  ('engine-management', 'boost-control', 30),
  ('engine-management', 'ignition-coils', 40),
  ('engine-management', 'spark-plug-set', 50),
  ('engine-management', 'plug-wires', 60),
  ('engine-management', 'wideband-o2-sensor', 70),
  ('cooling', 'radiator', 10),
  ('cooling', 'oil-cooler', 20),
  ('cooling', 'thermostat', 30),
  ('cooling', 'cooling-fans', 40),
  ('drivetrain', 'clutch', 10),
  ('drivetrain', 'flywheel', 20),
  ('drivetrain', 'engine-mounts', 30);

INSERT INTO CategoryEdge (tree_id, parent_category_id, child_category_id, position)
SELECT @tree_id, parent.category_id, child.category_id, e.position
  FROM seed_13brew_edges e
  JOIN Category parent ON parent.slug = e.parent_slug
  JOIN Category child ON child.slug = e.child_slug
 WHERE @engine_id IS NOT NULL
   AND @tree_id IS NOT NULL
ON DUPLICATE KEY UPDATE position = VALUES(position);

DROP TEMPORARY TABLE IF EXISTS seed_13brew_subsystems;
CREATE TEMPORARY TABLE seed_13brew_subsystems (
  subsystem_key VARCHAR(100) COLLATE utf8mb4_general_ci PRIMARY KEY,
  subsystem_name VARCHAR(200) COLLATE utf8mb4_general_ci NOT NULL,
  sort_order INT NOT NULL
);

INSERT INTO seed_13brew_subsystems (subsystem_key, subsystem_name, sort_order)
VALUES
  ('air_exhaust', 'Air & Exhaust', 20),
  ('fuel', 'Fuel System', 30),
  ('management', 'Engine Management', 40),
  ('cooling', 'Cooling', 50),
  ('drivetrain', 'Drivetrain', 60);

INSERT INTO Subsystem (engine_family_id, `key`, `name`, gltf_node_path, sort_order)
SELECT @engine_id, subsystem_key, subsystem_name, NULL, sort_order
  FROM seed_13brew_subsystems
 WHERE @engine_id IS NOT NULL
ON DUPLICATE KEY UPDATE
  `name` = VALUES(`name`),
  sort_order = VALUES(sort_order);

DROP TEMPORARY TABLE IF EXISTS seed_13brew_slots;
CREATE TEMPORARY TABLE seed_13brew_slots (
  subsystem_key VARCHAR(100) COLLATE utf8mb4_general_ci NOT NULL,
  slot_key VARCHAR(100) COLLATE utf8mb4_general_ci PRIMARY KEY,
  slot_name VARCHAR(200) COLLATE utf8mb4_general_ci NOT NULL,
  category_slug VARCHAR(200) COLLATE utf8mb4_general_ci NOT NULL,
  min_required INT NOT NULL DEFAULT 1,
  capacity INT NOT NULL DEFAULT 1
);

INSERT INTO seed_13brew_slots (subsystem_key, slot_key, slot_name, category_slug)
VALUES
  ('air_exhaust', '13b_rew_turbocharger', 'Turbocharger', 'turbocharger'),
  ('air_exhaust', '13b_rew_exhaust_manifold', 'Exhaust Manifold', 'exhaust-manifold'),
  ('air_exhaust', '13b_rew_wastegate', 'Wastegate', 'wastegate'),
  ('air_exhaust', '13b_rew_downpipe', 'Downpipe', 'downpipe'),
  ('air_exhaust', '13b_rew_intercooler', 'Intercooler', 'intercooler'),
  ('air_exhaust', '13b_rew_intercooler_piping', 'Intercooler Piping', 'intercooler-piping'),
  ('air_exhaust', '13b_rew_blow_off_valve', 'Blow-Off Valve', 'blow-off-valve'),
  ('air_exhaust', '13b_rew_intake_filter', 'Intake Filter', 'intake-filter'),
  ('fuel', '13b_rew_primary_injectors', 'Primary Injectors', 'primary-injectors'),
  ('fuel', '13b_rew_secondary_injectors', 'Secondary Injectors', 'secondary-injectors'),
  ('fuel', '13b_rew_fuel_pump', 'Fuel Pump', 'fuel-pump'),
  ('fuel', '13b_rew_fuel_pressure_regulator', 'Fuel Pressure Regulator', 'fuel-pressure-regulator'),
  ('fuel', '13b_rew_fuel_rails', 'Fuel Rails', 'fuel-rails'),
  ('management', '13b_rew_ecu', 'ECU', 'ecu'),
  ('management', '13b_rew_map_sensor', 'MAP Sensor', 'map-sensor'),
  ('management', '13b_rew_boost_control', 'Boost Control', 'boost-control'),
  ('management', '13b_rew_ignition_coils', 'Ignition Coils', 'ignition-coils'),
  ('management', '13b_rew_spark_plug_set', 'Spark Plug Set', 'spark-plug-set'),
  ('management', '13b_rew_plug_wires', 'Plug Wires', 'plug-wires'),
  ('management', '13b_rew_wideband_o2_sensor', 'Wideband O2 Sensor', 'wideband-o2-sensor'),
  ('cooling', '13b_rew_radiator', 'Radiator', 'radiator'),
  ('cooling', '13b_rew_oil_cooler', 'Oil Cooler', 'oil-cooler'),
  ('cooling', '13b_rew_thermostat', 'Thermostat', 'thermostat'),
  ('cooling', '13b_rew_cooling_fans', 'Cooling Fans', 'cooling-fans'),
  ('drivetrain', '13b_rew_clutch', 'Clutch', 'clutch'),
  ('drivetrain', '13b_rew_flywheel', 'Flywheel', 'flywheel'),
  ('drivetrain', '13b_rew_engine_mounts', 'Engine Mounts', 'engine-mounts');

INSERT INTO Slot (engine_family_id, subsystem_id, `key`, `name`, gltf_node_path, min_required, capacity, notes)
SELECT @engine_id,
       ss.subsystem_id,
       s.slot_key,
       s.slot_name,
       CONCAT('Socket_', s.slot_key),
       s.min_required,
       s.capacity,
       '13B-REW street-turbo planning placeholder; exact GLB optional.'
  FROM seed_13brew_slots s
  JOIN Subsystem ss ON ss.engine_family_id = @engine_id AND ss.`key` = s.subsystem_key
 WHERE @engine_id IS NOT NULL
ON DUPLICATE KEY UPDATE
  subsystem_id = VALUES(subsystem_id),
  `name` = VALUES(`name`),
  gltf_node_path = VALUES(gltf_node_path),
  min_required = VALUES(min_required),
  capacity = VALUES(capacity),
  notes = VALUES(notes);

INSERT INTO PartSlot (slot_id, category_id, allow)
SELECT sl.slot_id, c.category_id, TRUE
  FROM seed_13brew_slots s
  JOIN Slot sl ON sl.engine_family_id = @engine_id AND sl.`key` = s.slot_key
  JOIN Category c ON c.slug = s.category_slug
 WHERE @engine_id IS NOT NULL
ON DUPLICATE KEY UPDATE allow = VALUES(allow);

INSERT INTO CategoryRequirement (
  engine_family_id,
  category_id,
  tree_id,
  tree_scope,
  requirement_type,
  req_mode,
  required_qty,
  notes
)
SELECT @engine_id,
       c.category_id,
       @tree_id,
       @tree_id,
       'exact_count',
       'exact_count',
       1.000,
       '13B-REW target planning slot; verify specific part compatibility before purchase.'
  FROM seed_13brew_slots s
  JOIN Category c ON c.slug = s.category_slug
 WHERE @engine_id IS NOT NULL
   AND @tree_id IS NOT NULL
ON DUPLICATE KEY UPDATE
  tree_id = VALUES(tree_id),
  tree_scope = VALUES(tree_scope),
  requirement_type = VALUES(requirement_type),
  req_mode = VALUES(req_mode),
  required_qty = VALUES(required_qty),
  notes = VALUES(notes);

INSERT INTO Attribute (`key`, `name`, `type`)
VALUES
  ('turbo_flange', 'Turbo Flange', 'TEXT'),
  ('wastegate_type', 'Wastegate Type', 'TEXT'),
  ('injector_feed', 'Injector Feed Style', 'TEXT'),
  ('injector_impedance', 'Injector Impedance', 'TEXT'),
  ('map_sensor_bar', 'MAP Sensor Range', 'NUMBER'),
  ('clutch_spline', 'Clutch Spline', 'TEXT')
ON DUPLICATE KEY UPDATE
  `name` = VALUES(`name`),
  `type` = VALUES(`type`);

INSERT INTO SlotEdge (engine_family_id, from_slot_id, to_slot_id, edge, min_required, rule)
SELECT @engine_id, from_slot.slot_id, to_slot.slot_id, 'REQUIRES', 1, JSON_OBJECT('reason', '13B-REW turbo support system')
  FROM (
    SELECT '13b_rew_turbocharger' from_key, '13b_rew_exhaust_manifold' to_key UNION ALL
    SELECT '13b_rew_turbocharger', '13b_rew_downpipe' UNION ALL
    SELECT '13b_rew_turbocharger', '13b_rew_intercooler' UNION ALL
    SELECT '13b_rew_turbocharger', '13b_rew_intercooler_piping' UNION ALL
    SELECT '13b_rew_turbocharger', '13b_rew_fuel_pump' UNION ALL
    SELECT '13b_rew_turbocharger', '13b_rew_ecu' UNION ALL
    SELECT '13b_rew_turbocharger', '13b_rew_boost_control' UNION ALL
    SELECT '13b_rew_ecu', '13b_rew_map_sensor' UNION ALL
    SELECT '13b_rew_ecu', '13b_rew_wideband_o2_sensor' UNION ALL
    SELECT '13b_rew_fuel_pump', '13b_rew_fuel_pressure_regulator'
  ) r
  JOIN Slot from_slot ON from_slot.engine_family_id = @engine_id AND from_slot.`key` = r.from_key
  JOIN Slot to_slot ON to_slot.engine_family_id = @engine_id AND to_slot.`key` = r.to_key
 WHERE @engine_id IS NOT NULL
ON DUPLICATE KEY UPDATE
  min_required = VALUES(min_required),
  rule = VALUES(rule);

SELECT
  @engine_id AS engine_family_id,
  @tree_id AS tree_id,
  (SELECT COUNT(*) FROM Slot WHERE engine_family_id = @engine_id) AS total_slots_for_engine,
  (SELECT COUNT(*)
     FROM Slot s
    WHERE s.engine_family_id = @engine_id
      AND s.`key` LIKE '13b_rew_%') AS target_slots_for_engine;
