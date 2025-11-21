-- Beta engine family (create if missing)
SET @fam_code := 'engine_beta';
INSERT IGNORE INTO EngineFamily(code, notes) VALUES (@fam_code, 'Beta GLB subset');
SET @fam_id := (SELECT engine_family_id FROM EngineFamily WHERE code=@fam_code);

-- Subsystem for beta sockets (create/find)
INSERT IGNORE INTO Subsystem(engine_family_id, `key`, `name`, gltf_node_path, sort_order)
VALUES (@fam_id,'core','Core Assembly','/Root/Subsystems/Core',10);
UPDATE Subsystem SET `name`='Core Assembly', gltf_node_path='/Root/Subsystems/Core', sort_order=10
WHERE engine_family_id=@fam_id AND `key`='core';
SET @sub_id := (SELECT subsystem_id FROM Subsystem WHERE engine_family_id=@fam_id AND `key`='core');

-- If your Part table doesn’t yet have these columns, run once (then comment out):
-- ALTER TABLE Part ADD COLUMN gltf_uri VARCHAR(500) NULL;
-- ALTER TABLE Part ADD COLUMN gltf_attach_node VARCHAR(100) NULL;

-- ========= SKU → GLB mapping (hyphen SKUs) =========
SET @cat_engine := (SELECT category_id FROM Category WHERE slug='engine-internals');
INSERT INTO Part (sku, name, status, description, gltf_uri, gltf_attach_node)
VALUES
('eccentric-shaft',       'Eccentric Shaft',       'active', 'Beta GLB: eccentric shaft',       '/assets/glb/parts/13b/Socket_Eccentricshaft3-6.glb', 'Attach_Main'),
('front-side-plate',      'Front Side Plate',      'active', 'Beta GLB: front side plate',      '/assets/glb/parts/13b/Socket_frontplate3-1.glb',    'Attach_Main'),
('rear-side-plate',       'Rear Side Plate',       'active', 'Beta GLB: rear side plate',       '/assets/glb/parts/13b/Socket_rearplate4-1.glb',     'Attach_Main'),
('centre-plate',          'Centre Plate',          'active', 'Beta GLB: centre plate',          '/assets/glb/parts/13b/Socket_midplate4-1.glb',      'Attach_Main'),
('front-stationary-gear', 'Front Stationary Gear', 'active', 'Beta GLB: front stationary gear', '/assets/glb/parts/13b/Socket_frontstatgear1-1.glb', 'Attach_Main'),
('rear-stationary-gear',  'Rear Stationary Gear',  'active', 'Beta GLB: rear stationary gear',  '/assets/glb/parts/13b/Socket_rearstatgear1-1.glb',  'Attach_Main'),
('rotor-housing-front',   'Rotor Housing (Front)', 'active', 'Beta GLB: rotor housing front',   '/assets/glb/parts/13b/Socket_Housing5_13b-1.glb',   'Attach_Main'),
('rotor-housing-rear',    'Rotor Housing (Rear)',  'active', 'Beta GLB: rotor housing rear',    '/assets/glb/parts/13b/Socket_Housing5_13b-2.glb',   'Attach_Main'),
('front-rotor',           'Front Rotor',           'active', 'Beta GLB: front rotor',           '/assets/glb/parts/13b/Socket_Rotang3_13b-1.glb',    'Attach_Main'),
('rear-rotor',            'Rear Rotor',            'active', 'Beta GLB: rear rotor',            '/assets/glb/parts/13b/Socket_Rotang3_13b-2.glb',    'Attach_Main')
ON DUPLICATE KEY UPDATE name=VALUES(name), description=VALUES(description), status=VALUES(status), gltf_uri=VALUES(gltf_uri), gltf_attach_node=VALUES(gltf_attach_node);

INSERT INTO PartCategory (part_id, category_id, is_primary, coverage_weight, display_order)
SELECT p.part_id, @cat_engine, 1, 1, 0
FROM Part p
WHERE p.sku IN ('eccentric-shaft','front-side-plate','rear-side-plate','centre-plate','front-stationary-gear','rear-stationary-gear','rotor-housing-front','rotor-housing-rear','front-rotor','rear-rotor')
ON DUPLICATE KEY UPDATE is_primary=VALUES(is_primary), coverage_weight=VALUES(coverage_weight), display_order=VALUES(display_order);

-- Resolve part_ids (assumes these SKUs already exist)
SET @p_shaft  := (SELECT part_id FROM Part WHERE sku='eccentric-shaft');
SET @p_fsp    := (SELECT part_id FROM Part WHERE sku='front-side-plate');
SET @p_rsp    := (SELECT part_id FROM Part WHERE sku='rear-side-plate');
SET @p_center := (SELECT part_id FROM Part WHERE sku='centre-plate');
SET @p_fgear  := (SELECT part_id FROM Part WHERE sku='front-stationary-gear');
SET @p_rgear  := (SELECT part_id FROM Part WHERE sku='rear-stationary-gear');
SET @p_hf     := (SELECT part_id FROM Part WHERE sku='rotor-housing-front');
SET @p_hr     := (SELECT part_id FROM Part WHERE sku='rotor-housing-rear');
SET @p_rf     := (SELECT part_id FROM Part WHERE sku='front-rotor');
SET @p_rr     := (SELECT part_id FROM Part WHERE sku='rear-rotor');

-- ========= Sockets (keys must match nodes you add in the engine GLB) =========
-- Add these empty nodes to your 13bAssembly.glb (root-level empties)
INSERT INTO Slot(engine_family_id, subsystem_id, `key`, `name`, gltf_node_path, min_required, capacity, notes) VALUES
(@fam_id,@sub_id,'eccentric_shaft','Eccentric Shaft','/Sockets/EccentricShaft',1,1,'beta'),
(@fam_id,@sub_id,'front_side_plate','Front Side Plate','/Sockets/FrontSidePlate',1,1,'beta'),
(@fam_id,@sub_id,'rear_side_plate','Rear Side Plate','/Sockets/RearSidePlate',1,1,'beta'),
(@fam_id,@sub_id,'centre_plate','Centre Plate','/Sockets/CentrePlate',1,1,'beta'),
(@fam_id,@sub_id,'front_stationary','Front Stationary Gear','/Sockets/FrontStationary',1,1,'beta'),
(@fam_id,@sub_id,'rear_stationary','Rear Stationary Gear','/Sockets/RearStationary',1,1,'beta'),
(@fam_id,@sub_id,'housing_front','Rotor Housing (Front)','/Sockets/HousingFront',1,1,'beta'),
(@fam_id,@sub_id,'housing_rear','Rotor Housing (Rear)','/Sockets/HousingRear',1,1,'beta'),
(@fam_id,@sub_id,'rotor_front','Front Rotor','/Sockets/RotorFront',1,1,'beta'),
(@fam_id,@sub_id,'rotor_rear','Rear Rotor','/Sockets/RotorRear',1,1,'beta')
ON DUPLICATE KEY UPDATE gltf_node_path=VALUES(gltf_node_path);

-- Resolve slot_ids
SET @s_shaft  := (SELECT slot_id FROM Slot WHERE engine_family_id=@fam_id AND `key`='eccentric_shaft');
SET @s_fsp    := (SELECT slot_id FROM Slot WHERE engine_family_id=@fam_id AND `key`='front_side_plate');
SET @s_rsp    := (SELECT slot_id FROM Slot WHERE engine_family_id=@fam_id AND `key`='rear_side_plate');
SET @s_center := (SELECT slot_id FROM Slot WHERE engine_family_id=@fam_id AND `key`='centre_plate');
SET @s_fgear  := (SELECT slot_id FROM Slot WHERE engine_family_id=@fam_id AND `key`='front_stationary');
SET @s_rgear  := (SELECT slot_id FROM Slot WHERE engine_family_id=@fam_id AND `key`='rear_stationary');
SET @s_hf     := (SELECT slot_id FROM Slot WHERE engine_family_id=@fam_id AND `key`='housing_front');
SET @s_hr     := (SELECT slot_id FROM Slot WHERE engine_family_id=@fam_id AND `key`='housing_rear');
SET @s_rf     := (SELECT slot_id FROM Slot WHERE engine_family_id=@fam_id AND `key`='rotor_front');
SET @s_rr     := (SELECT slot_id FROM Slot WHERE engine_family_id=@fam_id AND `key`='rotor_rear');

-- ========= Whitelists (tight subset: one part per socket) =========
INSERT INTO PartSlot(slot_id, part_id, allow) VALUES
(@s_shaft,@p_shaft,1), (@s_fsp,@p_fsp,1), (@s_rsp,@p_rsp,1), (@s_center,@p_center,1),
(@s_fgear,@p_fgear,1), (@s_rgear,@p_rgear,1), (@s_hf,@p_hf,1), (@s_hr,@p_hr,1),
(@s_rf,@p_rf,1), (@s_rr,@p_rr,1)
ON DUPLICATE KEY UPDATE allow=VALUES(allow);

-- ========= Light rules for UX guidance (expand later as needed) =========
-- Example: shaft requires both stationary gears
INSERT INTO SlotEdge(engine_family_id, from_slot_id, to_slot_id, edge, min_required)
VALUES
(@fam_id, @s_shaft, @s_fgear, 'REQUIRES', 1),
(@fam_id, @s_shaft, @s_rgear, 'REQUIRES', 1)
ON DUPLICATE KEY UPDATE min_required=VALUES(min_required);

-- You can add rotors → housings REQUIRES if desired:
-- INSERT INTO SlotEdge(engine_family_id, from_slot_id, to_slot_id, edge, min_required)
-- VALUES (@fam_id, @s_rf, @s_hf, 'REQUIRES', 1), (@fam_id, @s_rr, @s_hr, 'REQUIRES', 1)
-- ON DUPLICATE KEY UPDATE min_required=VALUES(min_required);
