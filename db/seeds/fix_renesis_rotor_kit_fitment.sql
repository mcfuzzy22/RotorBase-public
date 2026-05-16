-- Correct Renesis Rotor Kit fitment so it no longer appears as a 13B-REW part.
-- The catalog currently models Renesis/13B-MSP variants as RENESIS-4P and RENESIS-6P.

DELETE pf
  FROM PartFitment pf
  JOIN Part p ON p.part_id = pf.part_id
  JOIN EngineFamily ef ON ef.engine_family_id = pf.engine_family_id
 WHERE p.sku = 'RENESIS-ROTOR-KIT'
   AND ef.code = '13B-REW';

INSERT IGNORE INTO PartFitment (part_id, engine_family_id)
SELECT p.part_id, ef.engine_family_id
  FROM Part p
  JOIN EngineFamily ef ON ef.code IN ('RENESIS-4P', 'RENESIS-6P')
 WHERE p.sku = 'RENESIS-ROTOR-KIT';
