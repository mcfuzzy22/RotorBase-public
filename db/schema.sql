/* ====================================================================
   ENGINE BUILD CATALOG + CONFIGURATOR + MONETIZATION SCHEMA (MySQL 8)
   ==================================================================== */

SET NAMES utf8mb4;
SET time_zone = '+00:00';
-- START TRANSACTION;

/* =========================
   0) ENUM helper tables
   ========================= */

-- (Optional) If you prefer ENUMs as lookup tables, you can create them here.


/* =========================
   1) TAXONOMY: Categories & Trees
   ========================= */

CREATE TABLE IF NOT EXISTS Category (
  category_id       BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  name              VARCHAR(200) NOT NULL,
  slug              VARCHAR(200) NULL,
  description       TEXT NULL,
  is_selectable     BOOLEAN NOT NULL DEFAULT TRUE,  -- FALSE = grouping-only node
  created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT uq_category_slug UNIQUE (slug)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS CategoryTree (
  tree_id           BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  name              VARCHAR(200) NOT NULL,
  description       TEXT NULL,
  created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Reusable categories under multiple parents per tree
CREATE TABLE IF NOT EXISTS CategoryEdge (
  tree_id               BIGINT UNSIGNED NOT NULL,
  parent_category_id    BIGINT UNSIGNED NOT NULL,
  child_category_id     BIGINT UNSIGNED NOT NULL,
  position              INT NOT NULL DEFAULT 0, -- order under the same parent
  PRIMARY KEY (tree_id, parent_category_id, child_category_id),
  CONSTRAINT fk_cat_edge_tree   FOREIGN KEY (tree_id)            REFERENCES CategoryTree(tree_id) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT fk_cat_edge_parent FOREIGN KEY (parent_category_id) REFERENCES Category(category_id) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT fk_cat_edge_child  FOREIGN KEY (child_category_id)  REFERENCES Category(category_id) ON DELETE CASCADE ON UPDATE CASCADE,
  INDEX ix_edge_parent (tree_id, parent_category_id, position),
  INDEX ix_edge_child  (tree_id, child_category_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


/* =========================
   2) ENGINE FITMENT DOMAIN
   ========================= */

CREATE TABLE IF NOT EXISTS EngineFamily (
  engine_family_id  BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  code              VARCHAR(80) NOT NULL,    -- e.g., '13B-REW-S6'
  years_start       SMALLINT NULL,
  years_end         SMALLINT NULL,
  rotor_count       TINYINT  NULL,           -- used by formulas (e.g., 2 for 13B)
  hp_min            INT NULL,
  hp_max            INT NULL,
  notes             TEXT NULL,
  created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT uq_engine_code UNIQUE (code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS EngineFamilyVehicle (
  engine_family_vehicle_id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  engine_family_id         BIGINT UNSIGNED NOT NULL,
  model                    VARCHAR(120) NOT NULL,   -- e.g., RX-7 FD
  market                   VARCHAR(40) NULL,        -- JDM, USDM, etc.
  years_start              SMALLINT NULL,
  years_end                SMALLINT NULL,
  CONSTRAINT fk_ef_vehicle_family FOREIGN KEY (engine_family_id)
    REFERENCES EngineFamily(engine_family_id) ON DELETE CASCADE ON UPDATE CASCADE,
  INDEX ix_ef_vehicle_family (engine_family_id, model)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


/* ===========================================
   3) PER-ENGINE / PER-CATEGORY REQUIREMENTS
   =========================================== */

-- requirement_type:
--   exact_count: must equal required_qty
--   min_count:   must be >= required_qty
--   formula:     compute in app (e.g., "3 * rotor_count")
CREATE TABLE IF NOT EXISTS CategoryRequirement (
  engine_family_id  BIGINT UNSIGNED NOT NULL,
  category_id       BIGINT UNSIGNED NOT NULL,
  tree_id           BIGINT UNSIGNED NULL,   -- allow tree-specific overrides; NULL = global
  requirement_type  ENUM('exact_count','min_count','formula') NOT NULL DEFAULT 'exact_count',
  required_qty      DECIMAL(12,3) NULL,     -- used by exact/min
  formula           VARCHAR(255) NULL,      -- e.g., '3 * rotor_count' (app computes)
  notes             VARCHAR(255) NULL,
  PRIMARY KEY (engine_family_id, category_id, tree_id),
  CONSTRAINT fk_req_engine   FOREIGN KEY (engine_family_id) REFERENCES EngineFamily(engine_family_id) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT fk_req_category FOREIGN KEY (category_id)      REFERENCES Category(category_id)       ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT fk_req_tree     FOREIGN KEY (tree_id)          REFERENCES CategoryTree(tree_id)       ON DELETE CASCADE ON UPDATE CASCADE,
  INDEX ix_req_category (category_id),
  INDEX ix_req_tree (tree_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


/* =========================
   4) PARTS + KITS (BOM) + CATEGORY LINKS
   ========================= */

CREATE TABLE IF NOT EXISTS Brand (
  brand_id          BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  name              VARCHAR(160) NOT NULL,
  website           VARCHAR(300) NULL,
  created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT uq_brand_name UNIQUE (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS Part (
  part_id           BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  sku               VARCHAR(120) NULL,                 -- may be NULL for bundles/custom
  name              VARCHAR(255) NOT NULL,
  description       TEXT NULL,
  brand_id          BIGINT UNSIGNED NULL,
  is_kit            BOOLEAN NOT NULL DEFAULT FALSE,
  uom               VARCHAR(32) NOT NULL DEFAULT 'piece',   -- piece/set/kit/etc.
  pieces_per_unit   DECIMAL(12,3) NOT NULL DEFAULT 1.000,   -- leaf contribution
  status            ENUM('active','discontinued','draft') NOT NULL DEFAULT 'active',

  -- Retail metadata (optional, helpful for ecom/integrations)
  mpn               VARCHAR(120) NULL,  -- manufacturer part number
  upc               VARCHAR(24)  NULL,  -- GTIN/UPC
  gtin              VARCHAR(24)  NULL,
  core_charge       DECIMAL(12,2) NULL,  -- if applicable

  created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

  CONSTRAINT fk_part_brand FOREIGN KEY (brand_id) REFERENCES Brand(brand_id) ON DELETE SET NULL ON UPDATE CASCADE,
  CONSTRAINT uq_part_sku UNIQUE (sku),
  INDEX ix_part_name (name),
  INDEX ix_part_brand (brand_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Kit BOM: parent part composed of child parts with quantities
CREATE TABLE IF NOT EXISTS PartComponent (
  parent_part_id    BIGINT UNSIGNED NOT NULL,
  child_part_id     BIGINT UNSIGNED NOT NULL,
  qty_per_parent    DECIMAL(12,3) NOT NULL,
  PRIMARY KEY (parent_part_id, child_part_id),
  CONSTRAINT fk_pc_parent FOREIGN KEY (parent_part_id) REFERENCES Part(part_id) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT fk_pc_child  FOREIGN KEY (child_part_id)  REFERENCES Part(part_id) ON DELETE RESTRICT ON UPDATE CASCADE,
  INDEX ix_pc_child (child_part_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Many-to-many: which categories a part satisfies
CREATE TABLE IF NOT EXISTS PartCategory (
  part_id           BIGINT UNSIGNED NOT NULL,
  category_id       BIGINT UNSIGNED NOT NULL,
  is_primary        BOOLEAN NOT NULL DEFAULT TRUE,
  coverage_weight   DECIMAL(6,3) NOT NULL DEFAULT 1.000,  -- set <1.0 if you need to downweight coverage
  display_order     INT NOT NULL DEFAULT 0,
  PRIMARY KEY (part_id, category_id),
  CONSTRAINT fk_partcat_part     FOREIGN KEY (part_id)     REFERENCES Part(part_id)     ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT fk_partcat_category FOREIGN KEY (category_id) REFERENCES Category(category_id) ON DELETE CASCADE ON UPDATE CASCADE,
  INDEX ix_partcat_category (category_id, display_order),
  INDEX ix_partcat_part (part_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


/* =========================
   5) VENDORS, OFFERINGS (with affiliate support)
   ========================= */

CREATE TABLE IF NOT EXISTS Vendor (
  vendor_id         BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  name              VARCHAR(160) NOT NULL,
  website           VARCHAR(300) NULL,
  created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT uq_vendor_name UNIQUE (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Optional affiliate program metadata per vendor
CREATE TABLE IF NOT EXISTS AffiliateProgram (
  vendor_id           BIGINT UNSIGNED PRIMARY KEY,
  program_name        VARCHAR(120) NOT NULL,
  base_commission_pct DECIMAL(5,2) NULL,     -- e.g., 5.00 = 5%
  cookie_window_days  INT NULL,              -- attribution window
  tracking_notes      VARCHAR(255) NULL,
  FOREIGN KEY (vendor_id) REFERENCES Vendor(vendor_id) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Offerings: vendor x part x time (price/availability/affiliate URL)
CREATE TABLE IF NOT EXISTS PartOffering (
  offering_id       BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  part_id           BIGINT UNSIGNED NOT NULL,
  vendor_id         BIGINT UNSIGNED NOT NULL,

  -- Pricing
  price             DECIMAL(12,2) NULL,
  msrp              DECIMAL(12,2) NULL,
  map_price         DECIMAL(12,2) NULL,  -- Minimum Advertised Price (if applicable)
  currency          CHAR(3) NOT NULL DEFAULT 'USD',

  -- Availability & logistics
  availability      ENUM('in_stock','backorder','discontinued','unknown') NOT NULL DEFAULT 'in_stock',
  shipping_class    VARCHAR(60) NULL,

  -- Links
  url               VARCHAR(600) NULL,         -- product page
  affiliate_url     VARCHAR(800) NULL,         -- tagged link
  affiliate_notes   VARCHAR(255) NULL,

  -- Time validity
  effective_from    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  effective_to      DATETIME NULL,

  created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT fk_offering_part   FOREIGN KEY (part_id)   REFERENCES Part(part_id)   ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT fk_offering_vendor FOREIGN KEY (vendor_id) REFERENCES Vendor(vendor_id) ON DELETE CASCADE ON UPDATE CASCADE,

  INDEX ix_offering_part_time (part_id, effective_from),
  INDEX ix_offering_vendor (vendor_id),
  INDEX ix_offering_price (part_id, price)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


/* =========================
   6) FITMENT: Part ↔ Engine family
   ========================= */

CREATE TABLE IF NOT EXISTS PartFitment (
  part_fitment_id  BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  part_id          BIGINT UNSIGNED NOT NULL,
  engine_family_id BIGINT UNSIGNED NOT NULL,
  years_start      SMALLINT NULL,
  years_end        SMALLINT NULL,
  notes            VARCHAR(255) NULL,
  CONSTRAINT fk_fitment_part   FOREIGN KEY (part_id)          REFERENCES Part(part_id)         ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT fk_fitment_engine FOREIGN KEY (engine_family_id) REFERENCES EngineFamily(engine_family_id) ON DELETE CASCADE ON UPDATE CASCADE,
  UNIQUE KEY uq_fitment (part_id, engine_family_id, years_start, years_end),
  INDEX ix_fitment_engine (engine_family_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


/* =========================
   7) USER BUILDS & SELECTIONS
   ========================= */

CREATE TABLE IF NOT EXISTS Build (
  build_id          BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  user_id           BIGINT UNSIGNED NULL,     -- link to your auth system if desired
  engine_family_id  BIGINT UNSIGNED NOT NULL,
  tree_id           BIGINT UNSIGNED NULL,     -- which category tree this build uses
  name              VARCHAR(200) NOT NULL,
  created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT fk_build_engine FOREIGN KEY (engine_family_id) REFERENCES EngineFamily(engine_family_id) ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT fk_build_tree   FOREIGN KEY (tree_id)          REFERENCES CategoryTree(tree_id)       ON DELETE SET NULL ON UPDATE CASCADE,
  INDEX ix_build_user (user_id),
  INDEX ix_build_engine (engine_family_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Allow multiple parts per category (and multiple categories per part)
CREATE TABLE IF NOT EXISTS BuildSelection (
  build_id          BIGINT UNSIGNED NOT NULL,
  category_id       BIGINT UNSIGNED NOT NULL,
  part_id           BIGINT UNSIGNED NOT NULL,
  qty               DECIMAL(12,3) NOT NULL DEFAULT 1.000,
  notes             VARCHAR(255) NULL,
  PRIMARY KEY (build_id, category_id, part_id),
  CONSTRAINT fk_bs_build    FOREIGN KEY (build_id)    REFERENCES Build(build_id)       ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT fk_bs_category FOREIGN KEY (category_id) REFERENCES Category(category_id) ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT fk_bs_part     FOREIGN KEY (part_id)     REFERENCES Part(part_id)         ON DELETE RESTRICT ON UPDATE CASCADE,
  INDEX ix_bs_part (part_id),
  INDEX ix_bs_category (category_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Click tracking for attribution (after Build exists)
CREATE TABLE IF NOT EXISTS ClickAttribution (
  click_id         BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  build_id         BIGINT UNSIGNED NOT NULL,
  part_id          BIGINT UNSIGNED NOT NULL,
  vendor_id        BIGINT UNSIGNED NOT NULL,
  offering_id      BIGINT UNSIGNED NULL,
  user_id          BIGINT UNSIGNED NULL,
  clicked_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  referrer         VARCHAR(300) NULL,
  utm_source       VARCHAR(60) NULL,
  utm_medium       VARCHAR(60) NULL,
  utm_campaign     VARCHAR(120) NULL,
  FOREIGN KEY (build_id)    REFERENCES Build(build_id) ON DELETE CASCADE,
  FOREIGN KEY (part_id)     REFERENCES Part(part_id),
  FOREIGN KEY (vendor_id)   REFERENCES Vendor(vendor_id),
  FOREIGN KEY (offering_id) REFERENCES PartOffering(offering_id),
  INDEX ix_click_vendor_time (vendor_id, clicked_at),
  INDEX ix_click_build_time  (build_id, clicked_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


/* =========================
   8) DIRECT-SALE ECOM (Optional)
   ========================= */

CREATE TABLE IF NOT EXISTS Cart (
  cart_id          BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  user_id          BIGINT UNSIGNED NULL,
  created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX ix_cart_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS CartItem (
  cart_id          BIGINT UNSIGNED NOT NULL,
  part_id          BIGINT UNSIGNED NOT NULL,
  qty              DECIMAL(12,3) NOT NULL,
  PRIMARY KEY (cart_id, part_id),
  CONSTRAINT fk_ci_cart FOREIGN KEY (cart_id) REFERENCES Cart(cart_id) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT fk_ci_part FOREIGN KEY (part_id) REFERENCES Part(part_id),
  INDEX ix_ci_part (part_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `Order` (
  order_id         BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  user_id          BIGINT UNSIGNED NULL,
  subtotal         DECIMAL(12,2) NULL,
  shipping         DECIMAL(12,2) NULL,
  tax              DECIMAL(12,2) NULL,
  total            DECIMAL(12,2) NULL,
  currency         CHAR(3) NOT NULL DEFAULT 'USD',
  status           ENUM('pending','paid','shipped','cancelled','refunded') NOT NULL DEFAULT 'pending',
  created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX ix_order_user_status (user_id, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS OrderItem (
  order_item_id    BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  order_id         BIGINT UNSIGNED NOT NULL,
  part_id          BIGINT UNSIGNED NOT NULL,
  qty              DECIMAL(12,3) NOT NULL,
  unit_price       DECIMAL(12,2) NOT NULL,  -- your sell price at time of order
  currency         CHAR(3) NOT NULL DEFAULT 'USD',
  FOREIGN KEY (order_id) REFERENCES `Order`(order_id) ON DELETE CASCADE ON UPDATE CASCADE,
  FOREIGN KEY (part_id)  REFERENCES Part(part_id),
  INDEX ix_orderitem_order (order_id),
  INDEX ix_orderitem_part (part_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


/* =========================
   9) SUBSCRIPTIONS (Premium Features)
   ========================= */

CREATE TABLE IF NOT EXISTS Plan (
  plan_id          BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  code             VARCHAR(60) NOT NULL,       -- e.g., 'FREE','PRO','ENTERPRISE'
  name             VARCHAR(120) NOT NULL,
  monthly_price    DECIMAL(12,2) NOT NULL DEFAULT 0.00,
  currency         CHAR(3) NOT NULL DEFAULT 'USD',
  features_json    JSON NULL,                  -- feature flags/limits
  CONSTRAINT uq_plan_code UNIQUE (code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS UserPlan (
  user_plan_id     BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  user_id          BIGINT UNSIGNED NOT NULL,
  plan_id          BIGINT UNSIGNED NOT NULL,
  status           ENUM('active','past_due','canceled') NOT NULL DEFAULT 'active',
  current_period_start DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  current_period_end   DATETIME NULL,
  FOREIGN KEY (plan_id) REFERENCES Plan(plan_id),
  INDEX ix_userplan_user (user_id, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


/* ===========================================================
   10) VIEWS for real-time UX & monetization helpers
   =========================================================== */

-- Cheapest current offering per part (by price; ignores MAP/MSRP)
DROP VIEW IF EXISTS v_part_best_offering;
CREATE VIEW v_part_best_offering AS
SELECT po.part_id,
       MIN(po.price) AS best_price
FROM PartOffering po
WHERE (po.effective_to IS NULL OR po.effective_to > NOW())
  AND po.availability IN ('in_stock','backorder')  -- tweak as you like
GROUP BY po.part_id;

-- Real-time category completion for each build (expand kits, sum pieces, compare)
DROP VIEW IF EXISTS v_build_category_completion;
CREATE VIEW v_build_category_completion AS
WITH RECURSIVE
selected AS (
  SELECT
    b.build_id,
    b.engine_family_id,
    COALESCE(b.tree_id, 0) AS tree_id0,
    bs.category_id  AS selected_category_id,
    bs.part_id      AS selected_part_id,
    bs.qty          AS selected_qty
  FROM Build b
  JOIN BuildSelection bs ON bs.build_id = b.build_id
),
bom (build_id, engine_family_id, tree_id0, root_part_id, part_id, qty, depth, path) AS (
  SELECT
    s.build_id, s.engine_family_id, s.tree_id0,
    s.selected_part_id AS root_part_id,
    s.selected_part_id AS part_id,
    s.selected_qty     AS qty,
    0 AS depth,
    CAST(CONCAT('/', s.selected_part_id, '/') AS CHAR(2000)) AS path
  FROM selected s
  UNION ALL
  SELECT
    b.build_id, b.engine_family_id, b.tree_id0,
    b.root_part_id,
    pc.child_part_id,
    b.qty * pc.qty_per_parent,
    b.depth + 1,
    CONCAT(b.path, pc.child_part_id, '/')
  FROM bom b
  JOIN PartComponent pc ON pc.parent_part_id = b.part_id
  WHERE b.depth < 10
    AND b.path NOT LIKE CONCAT('%/', pc.child_part_id, '/%')
),
leaf_contrib AS (
  SELECT
    b.build_id,
    b.engine_family_id,
    b.tree_id0,
    b.part_id         AS leaf_part_id,
    SUM(b.qty)        AS leaf_units
  FROM bom b
  LEFT JOIN PartComponent pc ON pc.parent_part_id = b.part_id
  WHERE pc.parent_part_id IS NULL
  GROUP BY b.build_id, b.engine_family_id, b.tree_id0, b.part_id
),
category_supply AS (
  SELECT
    lc.build_id,
    lc.engine_family_id,
    lc.tree_id0,
    pc.category_id,
    SUM(lc.leaf_units * p.pieces_per_unit * pc.coverage_weight) AS pieces_supplied
  FROM leaf_contrib lc
  JOIN PartCategory pc ON pc.part_id = lc.leaf_part_id
  JOIN Part p         ON p.part_id    = lc.leaf_part_id
  GROUP BY lc.build_id, lc.engine_family_id, lc.tree_id0, pc.category_id
),
req_resolved AS (
  SELECT
    r.engine_family_id,
    COALESCE(r.tree_id, 0) AS tree_id0,
    r.category_id,
    r.requirement_type,
    r.required_qty,
    r.formula
  FROM CategoryRequirement r
),
required_per_category AS (
  SELECT
    b.build_id,
    b.engine_family_id,
    b.tree_id0,
    rr.category_id,
    CASE
      WHEN rr.requirement_type IN ('exact_count','min_count') THEN rr.required_qty
      ELSE NULL
    END AS required_qty,
    rr.requirement_type,
    rr.formula
  FROM (SELECT DISTINCT build_id, engine_family_id, tree_id0 FROM selected) b
  JOIN req_resolved rr
    ON rr.engine_family_id = b.engine_family_id
   AND (rr.tree_id0 = b.tree_id0 OR rr.tree_id0 = 0)
),
joined AS (
  SELECT
    rpc.build_id,
    rpc.engine_family_id,
    rpc.tree_id0,
    rpc.category_id,
    c.name AS category_name,
    rpc.requirement_type,
    rpc.formula,
    rpc.required_qty,
    COALESCE(cs.pieces_supplied, 0) AS pieces_supplied,
    CASE
      WHEN rpc.requirement_type = 'exact_count'
        THEN CASE WHEN COALESCE(cs.pieces_supplied,0) = rpc.required_qty THEN 1 ELSE 0 END
      WHEN rpc.requirement_type = 'min_count'
        THEN CASE WHEN COALESCE(cs.pieces_supplied,0) >= rpc.required_qty THEN 1 ELSE 0 END
      WHEN rpc.requirement_type = 'formula'
        THEN NULL
      ELSE 0
    END AS is_complete_exact_min
  FROM required_per_category rpc
  LEFT JOIN category_supply cs
    ON cs.build_id = rpc.build_id
   AND cs.category_id = rpc.category_id
  JOIN Category c ON c.category_id = rpc.category_id
)
SELECT
  j.build_id,
  j.engine_family_id,
  j.tree_id0 AS tree_id_or_global,
  j.category_id,
  j.category_name,
  j.requirement_type,
  j.formula,            -- if not NULL, compute required_qty in app using EngineFamily fields
  j.required_qty,
  j.pieces_supplied,
  (j.required_qty - j.pieces_supplied) AS pieces_missing_exact_min,
  CASE
    WHEN j.is_complete_exact_min = 1 THEN 'complete'
    WHEN j.is_complete_exact_min = 0 AND j.requirement_type IN ('exact_count','min_count') THEN 'incomplete'
    ELSE 'needs_formula_eval'
  END AS status
FROM joined j;

-- View: Build-level money summary (cheapest current offering for every selected part)
DROP VIEW IF EXISTS v_build_cost_summary;
CREATE VIEW v_build_cost_summary AS
SELECT
  bs.build_id,
  SUM(bs.qty * bo.best_price) AS estimated_cost_lowest
FROM BuildSelection bs
JOIN v_part_best_offering bo ON bo.part_id = bs.part_id
GROUP BY bs.build_id;


/* ===========================================================
   11) HANDY SAMPLE SEED (optional)
   =========================================================== */

-- Engine seed
INSERT IGNORE INTO EngineFamily (code, rotor_count) VALUES ('13B-REW-S6', 2);

-- Categories
INSERT IGNORE INTO Category (name, is_selectable) VALUES
  ('Apex Seals', TRUE),
  ('Oil Control Ring Springs', TRUE);

-- Requirements for 13B-REW-S6
INSERT IGNORE INTO CategoryRequirement (engine_family_id, category_id, tree_id, requirement_type, required_qty)
SELECT ef.engine_family_id, c.category_id, NULL, 'exact_count',
       CASE c.name WHEN 'Apex Seals' THEN 6 ELSE 3 END
FROM EngineFamily ef
JOIN Category c ON c.name IN ('Apex Seals','Oil Control Ring Springs')
WHERE ef.code='13B-REW-S6';

-- Parts
INSERT IGNORE INTO Brand (name) VALUES ('Mazda'), ('AftermarketCo');

INSERT IGNORE INTO Part (sku, name, brand_id, is_kit, pieces_per_unit, mpn)
VALUES
  ('APX-001', 'Apex Seal (single)',       (SELECT brand_id FROM Brand WHERE name='AftermarketCo'), FALSE, 1, 'APX001'),
  ('OCRS-001','Oil Control Ring Spring',  (SELECT brand_id FROM Brand WHERE name='AftermarketCo'), FALSE, 1, 'OCRS001'),
  ('SEAL-KIT-01','Seal Kit (4 apex + 3 oil springs)', (SELECT brand_id FROM Brand WHERE name='AftermarketCo'), TRUE, 1, 'KIT001');

-- BOM (kit composition)
INSERT IGNORE INTO PartComponent (parent_part_id, child_part_id, qty_per_parent)
SELECT parent.part_id, child.part_id, qty.q
FROM (SELECT part_id FROM Part WHERE sku='SEAL-KIT-01') parent
JOIN (SELECT 'APX-001' sku, 4 q UNION ALL SELECT 'OCRS-001', 3) qty ON 1=1
JOIN Part child ON child.sku = qty.sku;

-- Map leaf parts to categories
INSERT IGNORE INTO PartCategory (part_id, category_id)
SELECT p.part_id, c.category_id
FROM Part p JOIN Category c
WHERE (p.sku='APX-001'  AND c.name='Apex Seals')
   OR (p.sku='OCRS-001' AND c.name='Oil Control Ring Springs');

-- Vendor + Offering (with affiliate URL)
INSERT IGNORE INTO Vendor (name, website) VALUES ('SpeedyParts','https://speedyparts.example');
INSERT IGNORE INTO AffiliateProgram (vendor_id, program_name, base_commission_pct, cookie_window_days)
SELECT vendor_id, 'Speedy Affiliates', 6.5, 30 FROM Vendor WHERE name='SpeedyParts';

INSERT IGNORE INTO PartOffering
(part_id, vendor_id, price, msrp, currency, availability, url, affiliate_url)
SELECT p.part_id, v.vendor_id, x.price, x.msrp, 'USD', 'in_stock',
       CONCAT('https://speedyparts.example/p/', p.sku),
       CONCAT('https://speedyparts.example/p/', p.sku, '?aff=YOUR_TAG')
FROM Part p
JOIN Vendor v ON v.name='SpeedyParts'
JOIN (SELECT 'APX-001' sku, 49.99 price, 59.99 msrp
      UNION ALL SELECT 'OCRS-001', 19.99, 24.99
      UNION ALL SELECT 'SEAL-KIT-01', 199.00, 229.00) x
ON x.sku = p.sku;

-- A build selecting the kit
INSERT IGNORE INTO Build (user_id, engine_family_id, name)
SELECT 1, engine_family_id, 'My 13B-REW S6 Build' FROM EngineFamily WHERE code='13B-REW-S6';

INSERT IGNORE INTO BuildSelection (build_id, category_id, part_id, qty)
SELECT b.build_id, c.category_id, p.part_id, 1
FROM Build b
JOIN Category c ON c.name='Apex Seals'  -- placeholder to anchor the selection (supply counts via BOM)
JOIN Part p ON p.sku='SEAL-KIT-01'
WHERE b.name='My 13B-REW S6 Build'
LIMIT 1;

-- Test: real-time completion + cost
-- SELECT * FROM v_build_category_completion WHERE build_id = (SELECT build_id FROM Build WHERE name='My 13B-REW S6 Build');
-- SELECT * FROM v_build_cost_summary WHERE build_id = (SELECT build_id FROM Build WHERE name='My 13B-REW S6 Build');


/* ===========================================================
   12) NOTES FOR THE APP / AI AGENT
   =========================================================== */
--  a) Real-time completion:
--     Query v_build_category_completion after any BuildSelection change.
--     If requirement_type='formula', compute required_qty in app:
--       - fetch EngineFamily.rotor_count (or other fields you add)
--       - evaluate simple formula strings like "3 * rotor_count"
--       - then compare to pieces_supplied to decide status.

--  b) Avoid double-counting:
--     If you don’t want a part to fully count toward multiple categories,
--     set PartCategory.coverage_weight < 1.0 or adjust business rules in app.

--  c) “Finish Build” summary:
--     - Completion% = completed categories / total categories with requirements
--     - Missing list: rows from v_build_category_completion WHERE status='incomplete'
--     - Price: use v_part_best_offering joined to BuildSelection (or your own price rules)

--  d) Monetization:
--     - Affiliate: record a row in ClickAttribution, then redirect to PartOffering.affiliate_url (or url fallback)
--     - Direct sale: create Cart/Order from BuildSelection and decide your sell price policy
--       (e.g., MIN(vendor price) * (1 + margin), or brand/category price rules)

--  e) Fitment filtering:
--     - Use PartFitment to filter recommended parts for a given Build.engine_family_id
--     - Optionally tighten by year ranges

--  f) Indexes:
--     Already included on the hot paths (BuildSelection, PartComponent, PartCategory, PartOffering).
--     Add more if profiling suggests.


-- COMMIT; Quick “how to use” in your app

-- Show live completion:
-- SELECT * FROM v_build_category_completion WHERE build_id = :build_id ORDER BY category_name;

-- Show total low-price estimate:
-- SELECT * FROM v_build_cost_summary WHERE build_id = :build_id;

-- “Buy” button flow:
-- Insert into ClickAttribution(build_id, part_id, vendor_id, offering_id, user_id, …)
-- Redirect the user to PartOffering.affiliate_url (fallback to url)

-- Direct purchase flow:
-- Copy BuildSelection → CartItem (or straight to Order/OrderItem), pick sell prices from PartOffering or your own rules.
