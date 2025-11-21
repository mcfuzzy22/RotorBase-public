SET @base_uri := '/assets/glb/parts/13b/';

UPDATE Part
SET gltf_uri = CONCAT(@base_uri, 'Socket_midplate4-1.glb'),
    gltf_attach_node = 'Attach_Main'
WHERE sku = 'beta-centre-plate';

UPDATE Part
SET gltf_uri = CONCAT(@base_uri, 'Socket_Eccentricshaft3-6.glb'),
    gltf_attach_node = 'Attach_Main'
WHERE sku = 'beta-eccentric-shaft';

UPDATE Part
SET gltf_uri = CONCAT(@base_uri, 'Socket_frontplate3-1.glb'),
    gltf_attach_node = 'Attach_Main'
WHERE sku = 'beta-front-side-plate';

UPDATE Part
SET gltf_uri = CONCAT(@base_uri, 'Socket_frontstatgear1-1.glb'),
    gltf_attach_node = 'Attach_Main'
WHERE sku = 'beta-front-stationary-gear';

UPDATE Part
SET gltf_uri = CONCAT(@base_uri, 'Socket_Housing5_13b-1.glb'),
    gltf_attach_node = 'Attach_Main'
WHERE sku = 'beta-rotor-housing-front';

UPDATE Part
SET gltf_uri = CONCAT(@base_uri, 'Socket_Housing5_13b-2.glb'),
    gltf_attach_node = 'Attach_Main'
WHERE sku = 'beta-rotor-housing-rear';

UPDATE Part
SET gltf_uri = CONCAT(@base_uri, 'Socket_rearplate4-1.glb'),
    gltf_attach_node = 'Attach_Main'
WHERE sku = 'beta-rear-side-plate';

UPDATE Part
SET gltf_uri = CONCAT(@base_uri, 'Socket_rearstatgear1-1.glb'),
    gltf_attach_node = 'Attach_Main'
WHERE sku = 'beta-rear-stationary-gear';

UPDATE Part
SET gltf_uri = CONCAT(@base_uri, 'Socket_Rotang3_13b-1.glb'),
    gltf_attach_node = 'Attach_Main'
WHERE sku = 'beta-front-rotor';

UPDATE Part
SET gltf_uri = CONCAT(@base_uri, 'Socket_Rotang3_13b-2.glb'),
    gltf_attach_node = 'Attach_Main'
WHERE sku = 'beta-rear-rotor';

-- Optional verification
SELECT part_id, sku, gltf_uri, gltf_attach_node
FROM Part
WHERE gltf_uri LIKE CONCAT(@base_uri, '%')
ORDER BY part_id;
