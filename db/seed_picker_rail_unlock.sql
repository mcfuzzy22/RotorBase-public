-- Demo seed: handguard gating a top rail with adapter unlock (MySQL)

-- Resolve engine family and subsystem
SET @engine_family_id := (SELECT engine_family_id FROM EngineFamily WHERE code = 'ENGINE_DEMO');
SET @subsystem_id := (
    SELECT subsystem_id
    FROM Subsystem
    WHERE engine_family_id = @engine_family_id
      AND `key` = 'eccentric'
    LIMIT 1
);

-- Attributes required for gating and MATCH_ATTR
INSERT INTO Attribute (`key`, `name`, `type`)
VALUES
('has_top_rail', 'Has Top Rail', 'BOOL'),
('rail_interface', 'Rail Interface', 'TEXT')
ON DUPLICATE KEY UPDATE `name` = VALUES(`name`);

SET @attr_has_rail := (SELECT attribute_id FROM Attribute WHERE `key` = 'has_top_rail');
SET @attr_interface := (SELECT attribute_id FROM Attribute WHERE `key` = 'rail_interface');

-- Categories for handguards and foregrips (create if absent)
INSERT INTO Category (category_id, name, slug, is_selectable)
SELECT 90010, 'Handguard', 'handguard', TRUE FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM Category WHERE slug = 'handguard');

INSERT INTO Category (category_id, name, slug, is_selectable)
SELECT 90011, 'Foregrip', 'foregrip', TRUE FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM Category WHERE slug = 'foregrip');

SET @cat_handguard := (SELECT category_id FROM Category WHERE slug = 'handguard');
SET @cat_foregrip  := (SELECT category_id FROM Category WHERE slug = 'foregrip');

-- Slots for handguard and top rail
INSERT INTO Slot (engine_family_id, subsystem_id, `key`, `name`, gltf_node_path, min_required, capacity)
VALUES
(@engine_family_id, @subsystem_id, 'handguard', 'Handguard', '/Sockets/Handguard', 1, 1),
(@engine_family_id, @subsystem_id, 'top_rail', 'Top Rail', '/Sockets/TopRail', 1, 1)
ON DUPLICATE KEY UPDATE `name` = VALUES(`name`), gltf_node_path = VALUES(gltf_node_path);

SET @slot_handguard := (
    SELECT slot_id FROM Slot
    WHERE engine_family_id = @engine_family_id AND `key` = 'handguard'
);
SET @slot_toprail := (
    SELECT slot_id FROM Slot
    WHERE engine_family_id = @engine_family_id AND `key` = 'top_rail'
);

-- Slot allow lists (handguard accepts handguard parts, top rail accepts foregrips)
INSERT INTO PartSlot (slot_id, category_id, allow)
VALUES
(@slot_handguard, @cat_handguard, 1),
(@slot_toprail, @cat_foregrip, 1)
ON DUPLICATE KEY UPDATE allow = VALUES(allow);

-- Parts
INSERT INTO Part (sku, name, is_kit, uom, pieces_per_unit, status)
VALUES
('HG-A', 'Handguard A', FALSE, 'piece', 1, 'active'),
('HG-B', 'Handguard B (Top Rail)', FALSE, 'piece', 1, 'active'),
('VG-PIC', 'Vertical Grip (Picatinny)', FALSE, 'piece', 1, 'active')
ON DUPLICATE KEY UPDATE name = VALUES(name);

SET @part_hg_a  := (SELECT part_id FROM Part WHERE sku = 'HG-A');
SET @part_hg_b  := (SELECT part_id FROM Part WHERE sku = 'HG-B');
SET @part_vg_pic := (SELECT part_id FROM Part WHERE sku = 'VG-PIC');

-- Part-category associations
INSERT IGNORE INTO PartCategory (part_id, category_id, is_primary, coverage_weight, display_order)
VALUES
(@part_hg_a, @cat_handguard, TRUE, 1, 0),
(@part_hg_b, @cat_handguard, TRUE, 1, 0),
(@part_vg_pic, @cat_foregrip, TRUE, 1, 0);

-- Part attributes
INSERT INTO PartAttribute (part_id, attribute_id, value_bool, value_text, value_num)
VALUES (@part_hg_a, @attr_has_rail, 0, NULL, NULL)
ON DUPLICATE KEY UPDATE value_bool = VALUES(value_bool), value_text = NULL, value_num = NULL;

INSERT INTO PartAttribute (part_id, attribute_id, value_bool, value_text, value_num)
VALUES (@part_hg_b, @attr_has_rail, 1, NULL, NULL)
ON DUPLICATE KEY UPDATE value_bool = VALUES(value_bool), value_text = NULL, value_num = NULL;

INSERT INTO PartAttribute (part_id, attribute_id, value_bool, value_text, value_num)
VALUES (@part_hg_b, @attr_interface, NULL, 'picatinny', NULL)
ON DUPLICATE KEY UPDATE value_text = VALUES(value_text), value_bool = NULL, value_num = NULL;

INSERT INTO PartAttribute (part_id, attribute_id, value_bool, value_text, value_num)
VALUES (@part_vg_pic, @attr_interface, NULL, 'picatinny', NULL)
ON DUPLICATE KEY UPDATE value_text = VALUES(value_text), value_bool = NULL, value_num = NULL;

-- Slot rules: enable top rail only when handguard has a rail, and match rail interface
INSERT INTO SlotEdge (engine_family_id, from_slot_id, to_slot_id, edge, min_required, rule)
VALUES (@engine_family_id, @slot_handguard, @slot_toprail, 'ENABLED_IF', 1,
        JSON_OBJECT('attribute_key', 'has_top_rail', 'op', 'eq', 'value_bool', true))
ON DUPLICATE KEY UPDATE rule = VALUES(rule);

INSERT INTO SlotEdge (engine_family_id, from_slot_id, to_slot_id, edge, min_required, rule)
VALUES (@engine_family_id, @slot_toprail, @slot_handguard, 'MATCH_ATTR', 1,
        JSON_OBJECT('attribute_key', 'rail_interface'))
ON DUPLICATE KEY UPDATE rule = VALUES(rule);
