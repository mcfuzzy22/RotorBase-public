using System.Text.Json.Serialization;

namespace RotorBase.Services;

public class IngestionPayload
{
    [JsonPropertyName("engine")] public EngineInfo? Engine { get; set; }
    [JsonPropertyName("tree")] public CategoryTreeDef? Tree { get; set; }
    [JsonPropertyName("engine_codes")] public List<string>? EngineCodes { get; set; }
    [JsonPropertyName("categories")] public List<CategoryDef> Categories { get; set; } = new();
    [JsonPropertyName("requirements")] public List<CategoryRequirementDef> Requirements { get; set; } = new();
    [JsonPropertyName("brands")] public List<BrandDef> Brands { get; set; } = new();
    [JsonPropertyName("parts")] public List<PartDef> Parts { get; set; } = new();
    [JsonPropertyName("components")] public List<PartComponentDef> Components { get; set; } = new();
    [JsonPropertyName("part_categories")] public List<PartCategoryDef> PartCategories { get; set; } = new();
    [JsonPropertyName("fitment")] public List<FitmentDef> Fitment { get; set; } = new();
    [JsonPropertyName("vendors")] public List<VendorDef> Vendors { get; set; } = new();
    [JsonPropertyName("offerings")] public List<OfferingDef> Offerings { get; set; } = new();
    [JsonPropertyName("plans")] public List<PlanDef> Plans { get; set; } = new();
}

public class EngineInfo
{
    [JsonPropertyName("code")] public string Code { get; set; } = string.Empty;
    [JsonPropertyName("rotor_count")] public int? RotorCount { get; set; }
    [JsonPropertyName("years_start")] public int? YearsStart { get; set; }
    [JsonPropertyName("years_end")] public int? YearsEnd { get; set; }
    [JsonPropertyName("hp_min")] public int? HpMin { get; set; }
    [JsonPropertyName("hp_max")] public int? HpMax { get; set; }
    [JsonPropertyName("notes")] public string? Notes { get; set; }
}

public class CategoryTreeDef
{
    [JsonPropertyName("name")] public string Name { get; set; } = "Default";
    // edges: parent_slug -> child_slug relationships
    [JsonPropertyName("edges")] public List<CategoryEdgeDef> Edges { get; set; } = new();
}

public class CategoryEdgeDef
{
    [JsonPropertyName("parent_slug")] public string ParentSlug { get; set; } = string.Empty;
    [JsonPropertyName("child_slug")] public string ChildSlug { get; set; } = string.Empty;
    [JsonPropertyName("position")] public int? Position { get; set; }
}

public class CategoryDef
{
    [JsonPropertyName("name")] public string Name { get; set; } = string.Empty;
    [JsonPropertyName("slug")] public string Slug { get; set; } = string.Empty;
    [JsonPropertyName("description")] public string? Description { get; set; }
    [JsonPropertyName("is_selectable")] public bool? IsSelectable { get; set; }
}

public class CategoryRequirementDef
{
    [JsonPropertyName("category_slug")] public string CategorySlug { get; set; } = string.Empty;
    [JsonPropertyName("requirement_type")] public string RequirementType { get; set; } = "exact_count";
    [JsonPropertyName("required_qty")] public decimal? RequiredQty { get; set; }
    [JsonPropertyName("formula")] public string? Formula { get; set; }
    [JsonPropertyName("req_mode")] public string? ReqMode { get; set; }
    [JsonPropertyName("multiplier")] public decimal? Multiplier { get; set; }
    [JsonPropertyName("operand_field")] public string? OperandField { get; set; }
    [JsonPropertyName("round_mode")] public string? RoundMode { get; set; }
    [JsonPropertyName("notes")] public string? Notes { get; set; }
    [JsonPropertyName("engine_codes")] public List<string>? EngineCodes { get; set; }
}

public class BrandDef { [JsonPropertyName("name")] public string Name { get; set; } = string.Empty; [JsonPropertyName("website")] public string? Website { get; set; } }

public class PartDef
{
    [JsonPropertyName("sku")] public string? Sku { get; set; }
    [JsonPropertyName("name")] public string Name { get; set; } = string.Empty;
    [JsonPropertyName("description")] public string? Description { get; set; }
    [JsonPropertyName("image_url")] public string? ImageUrl { get; set; }
    [JsonPropertyName("brand_name")] public string? BrandName { get; set; }
    [JsonPropertyName("is_kit")] public bool? IsKit { get; set; }
    [JsonPropertyName("uom")] public string? Uom { get; set; }
    [JsonPropertyName("pieces_per_unit")] public decimal? PiecesPerUnit { get; set; }
    [JsonPropertyName("status")] public string? Status { get; set; }
    [JsonPropertyName("mpn")] public string? Mpn { get; set; }
    [JsonPropertyName("upc")] public string? Upc { get; set; }
    [JsonPropertyName("gtin")] public string? Gtin { get; set; }
    [JsonPropertyName("core_charge")] public decimal? CoreCharge { get; set; }
}

public class PartComponentDef
{
    [JsonPropertyName("parent_sku")] public string ParentSku { get; set; } = string.Empty;
    [JsonPropertyName("child_sku")] public string ChildSku { get; set; } = string.Empty;
    [JsonPropertyName("qty_per_parent")] public decimal QtyPerParent { get; set; }
}

public class PartCategoryDef
{
    [JsonPropertyName("part_sku")] public string PartSku { get; set; } = string.Empty;
    [JsonPropertyName("category_slug")] public string CategorySlug { get; set; } = string.Empty;
    [JsonPropertyName("is_primary")] public bool? IsPrimary { get; set; }
    [JsonPropertyName("coverage_weight")] public decimal? CoverageWeight { get; set; }
    [JsonPropertyName("display_order")] public int? DisplayOrder { get; set; }
}

public class FitmentDef
{
    [JsonPropertyName("part_sku")] public string PartSku { get; set; } = string.Empty;
    [JsonPropertyName("engine_code")] public string EngineCode { get; set; } = string.Empty;
    [JsonPropertyName("years_start")] public int? YearsStart { get; set; }
    [JsonPropertyName("years_end")] public int? YearsEnd { get; set; }
    [JsonPropertyName("notes")] public string? Notes { get; set; }
}

public class VendorDef { [JsonPropertyName("name")] public string Name { get; set; } = string.Empty; [JsonPropertyName("website")] public string? Website { get; set; } }

public class OfferingDef
{
    [JsonPropertyName("part_sku")] public string PartSku { get; set; } = string.Empty;
    [JsonPropertyName("vendor_name")] public string VendorName { get; set; } = string.Empty;
    [JsonPropertyName("price")] public decimal? Price { get; set; }
    [JsonPropertyName("msrp")] public decimal? Msrp { get; set; }
    [JsonPropertyName("currency")] public string? Currency { get; set; }
    [JsonPropertyName("availability")] public string? Availability { get; set; }
    [JsonPropertyName("url")] public string? Url { get; set; }
    [JsonPropertyName("affiliate_url")] public string? AffiliateUrl { get; set; }
    [JsonPropertyName("effective_from")] public DateTimeOffset? EffectiveFrom { get; set; }
    [JsonPropertyName("effective_to")] public DateTimeOffset? EffectiveTo { get; set; }
}

public class PlanDef
{
    [JsonPropertyName("code")] public string Code { get; set; } = string.Empty;
    [JsonPropertyName("name")] public string Name { get; set; } = string.Empty;
    [JsonPropertyName("monthly_price")] public decimal MonthlyPrice { get; set; }
    [JsonPropertyName("currency")] public string Currency { get; set; } = "USD";
}
