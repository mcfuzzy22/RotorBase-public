-- Demo seed: eccentric shaft + bearings for socket picker (MySQL)

-- 1) Engine family
INSERT INTO EngineFamily (code, notes)
VALUES ('ENGINE_DEMO', 'Socket picker demo engine')
ON DUPLICATE KEY UPDATE notes = VALUES(notes);

SET @engine_family_id := (SELECT engine_family_id FROM EngineFamily WHERE code = 'ENGINE_DEMO');

-- 2) Subsystem
INSERT INTO Subsystem (engine_family_id, `key`, `name`, gltf_node_path, sort_order)
VALUES (@engine_family_id, 'eccentric', 'Eccentric shaft & bearings', '/Root/Subsystems/Eccentric', 10)
ON DUPLICATE KEY UPDATE `name` = VALUES(`name`), gltf_node_path = VALUES(gltf_node_path);

SET @subsystem_id := (SELECT subsystem_id FROM Subsystem WHERE engine_family_id = @engine_family_id AND `key` = 'eccentric');

-- 3) Slots
INSERT INTO Slot (engine_family_id, subsystem_id, `key`, `name`, gltf_node_path, min_required, capacity)
VALUES
(@engine_family_id, @subsystem_id, 'shaft', 'Eccentric Shaft', '/Sockets/Shaft', 1, 1),
(@engine_family_id, @subsystem_id, 'brg_l', 'Bearing – Left', '/Sockets/Bearing_L', 1, 1),
(@engine_family_id, @subsystem_id, 'brg_r', 'Bearing – Right', '/Sockets/Bearing_R', 1, 1)
ON DUPLICATE KEY UPDATE `name` = VALUES(`name`), gltf_node_path = VALUES(gltf_node_path);

SET @slot_shaft := (SELECT slot_id FROM Slot WHERE engine_family_id = @engine_family_id AND `key` = 'shaft');
SET @slot_bl := (SELECT slot_id FROM Slot WHERE engine_family_id = @engine_family_id AND `key` = 'brg_l');
SET @slot_br := (SELECT slot_id FROM Slot WHERE engine_family_id = @engine_family_id AND `key` = 'brg_r');

-- 4) Attribute
INSERT INTO Attribute (`key`, `name`, `type`)
VALUES ('size_code', 'Size code', 'TEXT')
ON DUPLICATE KEY UPDATE `name` = VALUES(`name`);

SET @attr_size := (SELECT attribute_id FROM Attribute WHERE `key` = 'size_code');

-- 5) Categories (create if missing – adjust IDs as needed)
INSERT INTO Category (category_id, name, slug, is_selectable)
SELECT 90001, 'Shaft', 'shaft', TRUE FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM Category WHERE slug = 'shaft');

INSERT INTO Category (category_id, name, slug, is_selectable)
SELECT 90002, 'Ball Bearing', 'bearing', TRUE FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM Category WHERE slug = 'bearing');

SET @cat_shaft := (SELECT category_id FROM Category WHERE slug = 'shaft');
SET @cat_bearing := (SELECT category_id FROM Category WHERE slug = 'bearing');

-- 6) Parts (basic metadata only)
INSERT INTO Part (part_id, sku, name, is_kit, uom, pieces_per_unit, status)
SELECT 91001, 'SHAFT-25', 'Eccentric Shaft 25mm', FALSE, 'piece', 1, 'active' FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM Part WHERE sku = 'SHAFT-25');

INSERT INTO Part (part_id, sku, name, is_kit, uom, pieces_per_unit, status)
SELECT 91002, '6205-25', 'Bearing 6205 (25mm bore)', FALSE, 'piece', 1, 'active' FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM Part WHERE sku = '6205-25');

INSERT INTO Part (part_id, sku, name, is_kit, uom, pieces_per_unit, status)
SELECT 91003, '6206-30', 'Bearing 6206 (30mm bore)', FALSE, 'piece', 1, 'active' FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM Part WHERE sku = '6206-30');

SET @p_shaft_25 := (SELECT part_id FROM Part WHERE sku = 'SHAFT-25');
SET @p_brg_25 := (SELECT part_id FROM Part WHERE sku = '6205-25');
SET @p_brg_30 := (SELECT part_id FROM Part WHERE sku = '6206-30');

-- 7) Part ↔ Category links
INSERT IGNORE INTO PartCategory (part_id, category_id, is_primary, coverage_weight, display_order)
VALUES
(@p_shaft_25, @cat_shaft, TRUE, 1, 0),
(@p_brg_25, @cat_bearing, TRUE, 1, 0),
(@p_brg_30, @cat_bearing, TRUE, 1, 0);

-- 8) Part attributes
INSERT INTO PartAttribute (part_id, attribute_id, value_text)
VALUES
(@p_shaft_25, @attr_size, '25mm'),
(@p_brg_25, @attr_size, '25mm'),
(@p_brg_30, @attr_size, '30mm')
ON DUPLICATE KEY UPDATE value_text = VALUES(value_text);

-- 9) Slot permissions
INSERT INTO PartSlot (slot_id, part_id, allow)
VALUES (@slot_shaft, @p_shaft_25, 1)
ON DUPLICATE KEY UPDATE allow = VALUES(allow);

INSERT INTO PartSlot (slot_id, category_id, allow)
VALUES
(@slot_bl, @cat_bearing, 1),
(@slot_br, @cat_bearing, 1)
ON DUPLICATE KEY UPDATE allow = VALUES(allow);

-- 10) Slot rules (shaft requires bearings, bearings must match attribute)
INSERT INTO SlotEdge (engine_family_id, from_slot_id, to_slot_id, edge, min_required, rule)
VALUES
(@engine_family_id, @slot_shaft, @slot_bl, 'REQUIRES', 1, NULL),
(@engine_family_id, @slot_shaft, @slot_br, 'REQUIRES', 1, NULL)
ON DUPLICATE KEY UPDATE min_required = VALUES(min_required);

INSERT INTO SlotEdge (engine_family_id, from_slot_id, to_slot_id, edge, min_required, rule)
VALUES
(@engine_family_id, @slot_bl, @slot_shaft, 'MATCH_ATTR', 1, JSON_OBJECT('attribute_key', 'size_code')),
(@engine_family_id, @slot_br, @slot_shaft, 'MATCH_ATTR', 1, JSON_OBJECT('attribute_key', 'size_code'))
ON DUPLICATE KEY UPDATE rule = VALUES(rule);

-- (Optional) Manually associate an existing Build with engine_family_id = @engine_family_id for UI testing.
