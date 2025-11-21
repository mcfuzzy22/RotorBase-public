using System.Text.Json.Serialization;

namespace RotorBase;

public record ShopClickRequest(
    [property: JsonPropertyName("build_id")] long? BuildId,
    [property: JsonPropertyName("part_id")] long PartId,
    [property: JsonPropertyName("offering_id")] long? OfferingId,
    [property: JsonPropertyName("vendor_name")] string? VendorName);

public class BuildSelectionLine
{
    [JsonPropertyName("part_id")] public long PartId { get; set; }
    [JsonPropertyName("qty")] public decimal Qty { get; set; }
}

public class VendorCandidate
{
    [JsonPropertyName("vendor_id")] public long VendorId { get; set; }
    [JsonPropertyName("vendor")] public string Vendor { get; set; } = string.Empty;
}

public class SingleVendorPlanItem
{
    [JsonPropertyName("part_id")] public long PartId { get; set; }
    [JsonPropertyName("qty")] public decimal Qty { get; set; }
    [JsonPropertyName("unit_price")] public decimal UnitPrice { get; set; }
    [JsonPropertyName("offering_id")] public long OfferingId { get; set; }
}

public record ShopSearchRow(
    [property: JsonPropertyName("part_id")] long PartId,
    [property: JsonPropertyName("sku")] string Sku,
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("brand")] string Brand,
    [property: JsonPropertyName("image_url")] string? ImageUrl,
    [property: JsonPropertyName("is_kit")] bool IsKit,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("best_price")] decimal? BestPrice,
    [property: JsonPropertyName("fits_engine")] bool FitsEngine,
    [property: JsonPropertyName("category_slug")] string? CategorySlug,
    [property: JsonPropertyName("category_name")] string? CategoryName,
    [property: JsonPropertyName("pieces_per_unit")] decimal? PiecesPerUnit,
    [property: JsonPropertyName("updated_at")] DateTime? UpdatedAt);

public record ShopSearchResponse(
    [property: JsonPropertyName("items")] IReadOnlyList<ShopSearchRow> Items,
    [property: JsonPropertyName("total")] long Total,
    [property: JsonPropertyName("page")] int Page,
    [property: JsonPropertyName("page_size")] int PageSize,
    [property: JsonPropertyName("has_more")] bool HasMore);

public record ShopCardAddRequest(long PartId, string? Sku);

public record BuildSummaryDto(
    [property: JsonPropertyName("build_id")] long BuildId,
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("updated_at")] DateTime UpdatedAt,
    [property: JsonPropertyName("is_archived")] bool IsArchived);

public record CategorySummary(
    [property: JsonPropertyName("category_id")] long CategoryId,
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("is_primary")] bool IsPrimary);

public record PartMeta(
    [property: JsonPropertyName("part_id")] long PartId,
    [property: JsonPropertyName("name")] string? Name);

public record ShopPartMeta(
    [property: JsonPropertyName("part")] PartMeta? Part,
    [property: JsonPropertyName("categories")] List<CategorySummary> Categories);

public record BuildSelectionContext(long PartId, string PartName, List<CategorySummary> Categories);

public record PriceAlertRequest(
    [property: JsonPropertyName("part_id")] long? PartId,
    [property: JsonPropertyName("target_price")] decimal? TargetPrice,
    [property: JsonPropertyName("stock_only")] bool? StockOnly,
    [property: JsonPropertyName("email")] string? Email);

public sealed record SlotSelectDto(
    [property: JsonPropertyName("slot_id")] long SlotId,
    [property: JsonPropertyName("part_id")] long PartId,
    [property: JsonPropertyName("quantity")] int? Quantity);

public class OfferingLookup
{
    public ulong OfferingId { get; set; }
    public ulong PartId { get; set; }
    public ulong VendorId { get; set; }
    public string? AffiliateUrl { get; set; }
    public string? Url { get; set; }
}

public class PublicBuildListItem
{
    [JsonPropertyName("build_id")] public long BuildId { get; set; }
    [JsonPropertyName("public_slug")] public string PublicSlug { get; set; } = string.Empty;
    [JsonPropertyName("name")] public string Name { get; set; } = string.Empty;
    [JsonPropertyName("engine_code")] public string EngineCode { get; set; } = string.Empty;
    [JsonPropertyName("completion_pct")] public decimal? CompletionPct { get; set; }
    [JsonPropertyName("estimated_cost_lowest")] public decimal? EstimatedCostLowest { get; set; }
    [JsonPropertyName("updated_at")] public DateTime UpdatedAt { get; set; }
}

public class PublicBuildDetailDto
{
    [JsonPropertyName("build_id")] public long BuildId { get; set; }
    [JsonPropertyName("public_slug")] public string PublicSlug { get; set; } = string.Empty;
    [JsonPropertyName("name")] public string Name { get; set; } = string.Empty;
    [JsonPropertyName("engine_code")] public string EngineCode { get; set; } = string.Empty;
    [JsonPropertyName("updated_at")] public DateTime UpdatedAt { get; set; }
}

public class PublicBuildSummaryDto
{
    [JsonPropertyName("build_id")] public long BuildId { get; set; }
    [JsonPropertyName("categories_total")] public int? CategoriesTotal { get; set; }
    [JsonPropertyName("categories_complete")] public int? CategoriesComplete { get; set; }
    [JsonPropertyName("categories_incomplete")] public int? CategoriesIncomplete { get; set; }
    [JsonPropertyName("completion_pct")] public decimal? CompletionPct { get; set; }
    [JsonPropertyName("total_pieces_missing")] public decimal? TotalPiecesMissing { get; set; }
    [JsonPropertyName("estimated_cost_lowest")] public decimal? EstimatedCostLowest { get; set; }
}

public class PublicBuildCategoryDto
{
    [JsonPropertyName("category_name")] public string CategoryName { get; set; } = string.Empty;
    [JsonPropertyName("required_qty")] public decimal? RequiredQty { get; set; }
    [JsonPropertyName("pieces_supplied")] public decimal? PiecesSupplied { get; set; }
    [JsonPropertyName("pieces_missing")] public decimal? PiecesMissing { get; set; }
    [JsonPropertyName("status")] public string Status { get; set; } = string.Empty;
}

public class GuideSummaryDto
{
    [JsonPropertyName("guide_id")] public long GuideId { get; set; }
    [JsonPropertyName("slug")] public string Slug { get; set; } = string.Empty;
    [JsonPropertyName("title")] public string Title { get; set; } = string.Empty;
    [JsonPropertyName("published_at")] public DateTime? PublishedAt { get; set; }
    [JsonPropertyName("updated_at")] public DateTime UpdatedAt { get; set; }
}

public class GuideDetailDto
{
    [JsonPropertyName("guide_id")] public long GuideId { get; set; }
    [JsonPropertyName("slug")] public string Slug { get; set; } = string.Empty;
    [JsonPropertyName("title")] public string Title { get; set; } = string.Empty;
    [JsonPropertyName("content_md")] public string? ContentMarkdown { get; set; }
    [JsonPropertyName("published_at")] public DateTime? PublishedAt { get; set; }
    [JsonPropertyName("updated_at")] public DateTime UpdatedAt { get; set; }
}

public class GuidePartDto
{
    [JsonPropertyName("part_id")] public long PartId { get; set; }
    [JsonPropertyName("position")] public int Position { get; set; }
    [JsonPropertyName("name")] public string? Name { get; set; }
    [JsonPropertyName("sku")] public string? Sku { get; set; }
}
