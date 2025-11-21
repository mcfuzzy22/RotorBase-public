-- Rebase builds that reference engine families without slots to the beta engine (584)
-- and align their tree_id to that engine's default tree.

SET @target_engine_family := 584;
SET @target_tree := (
    SELECT tree_id
    FROM EngineFamilyTree
    WHERE engine_family_id = @target_engine_family
      AND is_default = TRUE
    LIMIT 1
);

UPDATE Build b
LEFT JOIN (
    SELECT engine_family_id, COUNT(*) AS slot_count
    FROM Slot
    GROUP BY engine_family_id
) sc ON sc.engine_family_id = b.engine_family_id
SET b.engine_family_id = @target_engine_family,
    b.tree_id = @target_tree
WHERE @target_tree IS NOT NULL
  AND COALESCE(sc.slot_count, 0) = 0;

-- Review the current assignments for verification
SELECT build_id, engine_family_id, tree_id
FROM Build
ORDER BY build_id DESC
LIMIT 20;
