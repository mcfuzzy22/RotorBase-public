using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RotorBase;

public class CreateBuildRequest
{
    [JsonPropertyName("engine_family_id")] public long EngineFamilyId { get; set; }
    [JsonPropertyName("name")] public string? Name { get; set; }
    [JsonPropertyName("tree_id")] public long? TreeId { get; set; }
    [JsonPropertyName("is_archived")] public bool? IsArchived { get; set; }
    [JsonPropertyName("is_shared")] public bool? IsShared { get; set; }
}

public class BuildPublishRequest
{
    [JsonPropertyName("is_public")] public bool? IsPublic { get; set; }
    [JsonPropertyName("slug")] public string? Slug { get; set; }
}

public class SelectionUpsertRequest
{
    [JsonPropertyName("category_id")] public long CategoryId { get; set; }
    [JsonPropertyName("part_id")] public long PartId { get; set; }
    [JsonPropertyName("qty")] public decimal? Qty { get; set; }
}

public class SelectionAdjustRequest
{
    [JsonPropertyName("category_id")] public long CategoryId { get; set; }
    [JsonPropertyName("part_id")] public long PartId { get; set; }
    [JsonPropertyName("delta")] public decimal? Delta { get; set; }
}

public class BuildAddPartRequest
{
    [JsonPropertyName("part_id")] public long PartId { get; set; }
    [JsonPropertyName("qty")] public decimal? Qty { get; set; }
    [JsonPropertyName("category_id")] public long? CategoryId { get; set; }
}

public class CreateUserRequest
{
    [JsonPropertyName("email")] public string Email { get; set; } = string.Empty;
    [JsonPropertyName("display_name")] public string? DisplayName { get; set; }
    [JsonPropertyName("password")] public string? Password { get; set; }
    [JsonPropertyName("email_opt_in")] public bool? EmailOptIn { get; set; }
}

public class UserProfileUpdateRequest
{
    [JsonPropertyName("display_name")] public string? DisplayName { get; set; }
    [JsonPropertyName("email_opt_in")] public bool? EmailOptIn { get; set; }
}

public class AssignPlanRequest
{
    [JsonPropertyName("plan_code")] public string PlanCode { get; set; } = string.Empty;
}

public class AdminUserPatchRequest
{
    [JsonPropertyName("is_admin")] public bool? IsAdmin { get; set; }
    [JsonPropertyName("display_name")] public string? DisplayName { get; set; }
    [JsonPropertyName("is_banned")] public bool? IsBanned { get; set; }
}

public class AdminAssignPlanRequest
{
    [JsonPropertyName("plan_code")] public string? PlanCode { get; set; }
}

public class UserPlanChangeRequest
{
    [JsonPropertyName("plan_code")] public string PlanCode { get; set; } = string.Empty;
}

public class CheckoutSessionRequest
{
    [JsonPropertyName("plan_code")] public string? PlanCode { get; set; }
}

public class AdminPlanUpdateRequest
{
    [JsonPropertyName("name")] public string? Name { get; set; }
    [JsonPropertyName("monthly_price")] public decimal? MonthlyPrice { get; set; }
    [JsonPropertyName("max_active_builds")] public int? MaxActiveBuilds { get; set; }
    [JsonPropertyName("max_total_builds")] public int? MaxTotalBuilds { get; set; }
}

public class AdminPlanCreateRequest
{
    [JsonPropertyName("code")] public string Code { get; set; } = string.Empty;
    [JsonPropertyName("name")] public string Name { get; set; } = string.Empty;
    [JsonPropertyName("monthly_price")] public decimal? MonthlyPrice { get; set; }
    [JsonPropertyName("currency")] public string? Currency { get; set; }
    [JsonPropertyName("max_active_builds")] public int? MaxActiveBuilds { get; set; }
    [JsonPropertyName("max_total_builds")] public int? MaxTotalBuilds { get; set; }
}

public class AdminRoleCreateRequest
{
    [JsonPropertyName("code")] public string Code { get; set; } = string.Empty;
    [JsonPropertyName("name")] public string Name { get; set; } = string.Empty;
    [JsonPropertyName("description")] public string? Description { get; set; }
}

public class AdminCategoryCreateRequest
{
    [JsonPropertyName("name")] public string Name { get; set; } = string.Empty;
    [JsonPropertyName("slug")] public string Slug { get; set; } = string.Empty;
    [JsonPropertyName("is_selectable")] public bool IsSelectable { get; set; } = true;
    [JsonPropertyName("description")] public string? Description { get; set; }
}

public class AdminCategoryUpdateRequest
{
    [JsonPropertyName("name")] public string? Name { get; set; }
    [JsonPropertyName("slug")] public string? Slug { get; set; }
    [JsonPropertyName("is_selectable")] public bool? IsSelectable { get; set; }
    [JsonPropertyName("description")] public string? Description { get; set; }
}

public class AdminPartUpdateRequest
{
    [JsonPropertyName("sku")] public string? Sku { get; set; }
    [JsonPropertyName("name")] public string? Name { get; set; }
    [JsonPropertyName("brand_name")] public string? BrandName { get; set; }
    [JsonPropertyName("status")] public string? Status { get; set; }
    [JsonPropertyName("is_kit")] public bool? IsKit { get; set; }
    [JsonPropertyName("uom")] public string? Uom { get; set; }
    [JsonPropertyName("pieces_per_unit")] public decimal? PiecesPerUnit { get; set; }
    [JsonPropertyName("description")] public string? Description { get; set; }
    [JsonPropertyName("image_url")] public string? ImageUrl { get; set; }
}

public class AdminPartCategoryRequest
{
    [JsonPropertyName("category_id")] public long CategoryId { get; set; }
    [JsonPropertyName("is_primary")] public bool? IsPrimary { get; set; }
    [JsonPropertyName("coverage_weight")] public decimal? CoverageWeight { get; set; }
    [JsonPropertyName("display_order")] public int? DisplayOrder { get; set; }
}

public class AdminPartFitmentRequest
{
    [JsonPropertyName("engine_code")] public string EngineCode { get; set; } = string.Empty;
    [JsonPropertyName("years_start")] public short? YearsStart { get; set; }
    [JsonPropertyName("years_end")] public short? YearsEnd { get; set; }
    [JsonPropertyName("notes")] public string? Notes { get; set; }
}

public class AdminPartOfferingRequest
{
    [JsonPropertyName("vendor_name")] public string VendorName { get; set; } = string.Empty;
    [JsonPropertyName("price")] public decimal Price { get; set; }
    [JsonPropertyName("currency")] public string? Currency { get; set; }
    [JsonPropertyName("url")] public string? Url { get; set; }
    [JsonPropertyName("affiliate_url")] public string? AffiliateUrl { get; set; }
    [JsonPropertyName("availability")] public string? Availability { get; set; }
}

public class UpdatePartUriRequest
{
    [JsonPropertyName("part_id")] public long PartId { get; set; }
    [JsonPropertyName("gltf_uri")] public string? GltfUri { get; set; }
    [JsonPropertyName("gltf_attach_node")] public string? GltfAttachNode { get; set; }
}

public sealed record BuildSlotSummaryDto(
    [property: JsonPropertyName("slot_id")] long SlotId,
    [property: JsonPropertyName("slot_key")] string SlotKey,
    [property: JsonPropertyName("slot_name")] string SlotName,
    [property: JsonPropertyName("subsystem_name")] string? SubsystemName,
    [property: JsonPropertyName("gltf_node_path")] string GltfNodePath,
    [property: JsonPropertyName("enabled")] bool Enabled,
    [property: JsonPropertyName("min_required")] int MinRequired,
    [property: JsonPropertyName("capacity")] int Capacity,
    [property: JsonPropertyName("selected_part_id")] long? SelectedPartId,
    [property: JsonPropertyName("selected_part_name")] string? SelectedPartName,
    [property: JsonPropertyName("quantity")] int? Quantity);

public sealed record SavePresetDto(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("is_public")] bool IsPublic);

public sealed record ApplyPresetResultDto(
    [property: JsonPropertyName("build_id")] long BuildId,
    [property: JsonPropertyName("preset_id")] long PresetId,
    [property: JsonPropertyName("slots_updated")] int SlotsUpdated);

public class AdminPartComponentRequest
{
    [JsonPropertyName("child_sku")] public string ChildSku { get; set; } = string.Empty;
    [JsonPropertyName("qty_per_parent")] public decimal QtyPerParent { get; set; }
}

public class AdminPartQuickOfferingRequest
{
    [JsonPropertyName("vendor_name")] public string? VendorName { get; set; }
    [JsonPropertyName("price")] public decimal? Price { get; set; }
    [JsonPropertyName("currency")] public string? Currency { get; set; }
    [JsonPropertyName("url")] public string? Url { get; set; }
}

public class AdminPartQuickCreateRequest
{
    [JsonPropertyName("sku")] public string Sku { get; set; } = string.Empty;
    [JsonPropertyName("name")] public string Name { get; set; } = string.Empty;
    [JsonPropertyName("brand_name")] public string? BrandName { get; set; }
    [JsonPropertyName("category_slug")] public string CategorySlug { get; set; } = string.Empty;
    [JsonPropertyName("pieces_per_unit")] public decimal? PiecesPerUnit { get; set; }
    [JsonPropertyName("status")] public string? Status { get; set; }
    [JsonPropertyName("uom")] public string? Uom { get; set; }
    [JsonPropertyName("offering")] public AdminPartQuickOfferingRequest? Offering { get; set; }
}

public class AdminKitAddOrCreateComponentRequest
{
    [JsonPropertyName("child_sku")] public string? ChildSku { get; set; }
    [JsonPropertyName("new_part")] public AdminPartQuickCreateRequest? NewPart { get; set; }
    [JsonPropertyName("qty")] public decimal? Qty { get; set; }
}

public class AdminKitComponentPatchRequest
{
    [JsonPropertyName("child_part_id")] public long ChildPartId { get; set; }
    [JsonPropertyName("qty_per_parent")] public decimal QtyPerParent { get; set; }
}

public class AdminKitComponentBulkRequest
{
    [JsonPropertyName("lines")] public List<AdminKitComponentBulkLine> Lines { get; set; } = new();
}

public class AdminKitComponentBulkLine
{
    [JsonPropertyName("child_sku")] public string ChildSku { get; set; } = string.Empty;
    [JsonPropertyName("qty")] public decimal Qty { get; set; }
}

public class AdminKitPriceSyncRequest
{
    [JsonPropertyName("vendor_name")] public string? VendorName { get; set; }
    [JsonPropertyName("margin_pct")] public decimal? MarginPct { get; set; }
    [JsonPropertyName("round")] public decimal? Round { get; set; }
}

public class AdminKitCreateRequest
{
    [JsonPropertyName("kit")] public AdminKitCreateDetails Kit { get; set; } = new();
    [JsonPropertyName("components")] public List<AdminKitCreateComponent> Components { get; set; } = new();
    [JsonPropertyName("price")] public AdminKitPriceRequest? Price { get; set; }
}

public class AdminKitCreateDetails
{
    [JsonPropertyName("sku")] public string Sku { get; set; } = string.Empty;
    [JsonPropertyName("name")] public string Name { get; set; } = string.Empty;
    [JsonPropertyName("brand_name")] public string? BrandName { get; set; }
    [JsonPropertyName("uom")] public string? Uom { get; set; }
    [JsonPropertyName("status")] public string? Status { get; set; }
    [JsonPropertyName("pieces_per_unit")] public decimal? PiecesPerUnit { get; set; }
    [JsonPropertyName("description")] public string? Description { get; set; }
    [JsonPropertyName("image_url")] public string? ImageUrl { get; set; }
    [JsonPropertyName("primary_category_slug")] public string? PrimaryCategorySlug { get; set; }
}

public class AdminKitCreateComponent
{
    [JsonPropertyName("child_sku")] public string ChildSku { get; set; } = string.Empty;
    [JsonPropertyName("qty")] public decimal Qty { get; set; }
}

public class AdminKitPriceRequest
{
    [JsonPropertyName("mode")] public string? Mode { get; set; }
    [JsonPropertyName("margin_pct")] public decimal? MarginPct { get; set; }
    [JsonPropertyName("round")] public decimal? Round { get; set; }
    [JsonPropertyName("vendor_name")] public string? VendorName { get; set; }
    [JsonPropertyName("manual_price")] public decimal? ManualPrice { get; set; }
    [JsonPropertyName("currency")] public string? Currency { get; set; }
    [JsonPropertyName("availability")] public string? Availability { get; set; }
}

public class AdminKitBuildFromRequest
{
    [JsonPropertyName("components")] public List<AdminKitCreateComponent> Components { get; set; } = new();
    [JsonPropertyName("set_is_kit")] public bool? SetIsKit { get; set; }
    [JsonPropertyName("replace_bom")] public bool? ReplaceBom { get; set; }
    [JsonPropertyName("primary_category_slug")] public string? PrimaryCategorySlug { get; set; }
    [JsonPropertyName("price")] public AdminKitPriceRequest? Price { get; set; }
}

public class AdminKitEditRequest
{
    [JsonPropertyName("components")] public List<AdminKitEditComponent>? Components { get; set; }
    [JsonPropertyName("kit_offering")] public AdminKitEditOffering? KitOffering { get; set; }
}

public class AdminKitEditComponent
{
    [JsonPropertyName("child_part_id")] public long ChildPartId { get; set; }
    [JsonPropertyName("qty")] public decimal Qty { get; set; }
    [JsonPropertyName("offering")] public AdminKitEditOffering? Offering { get; set; }
}

public class AdminKitEditOffering
{
    [JsonPropertyName("offering_id")] public long? OfferingId { get; set; }
    [JsonPropertyName("vendor_id")] public long? VendorId { get; set; }
    [JsonPropertyName("vendor_name")] public string? VendorName { get; set; }
    [JsonPropertyName("price")] public decimal Price { get; set; }
    [JsonPropertyName("currency")] public string? Currency { get; set; }
    [JsonPropertyName("url")] public string? Url { get; set; }
    [JsonPropertyName("availability")] public string? Availability { get; set; }
}

public class AdminKitEditComponentDto
{
    [JsonPropertyName("child_part_id")] public long ChildPartId { get; set; }
    [JsonPropertyName("sku")] public string? Sku { get; set; }
    [JsonPropertyName("name")] public string? Name { get; set; }
    [JsonPropertyName("qty")] public decimal Qty { get; set; }
    [JsonPropertyName("vendor_id")] public long? VendorId { get; set; }
    [JsonPropertyName("vendor_name")] public string? VendorName { get; set; }
    [JsonPropertyName("price")] public decimal? Price { get; set; }
    [JsonPropertyName("currency")] public string? Currency { get; set; }
    [JsonPropertyName("url")] public string? Url { get; set; }
    [JsonPropertyName("availability")] public string? Availability { get; set; }
}

public class AdminKitEditOfferingSummary
{
    [JsonPropertyName("vendor_id")] public long? VendorId { get; set; }
    [JsonPropertyName("vendor_name")] public string? VendorName { get; set; }
    [JsonPropertyName("price")] public decimal? Price { get; set; }
    [JsonPropertyName("currency")] public string? Currency { get; set; }
    [JsonPropertyName("url")] public string? Url { get; set; }
    [JsonPropertyName("availability")] public string? Availability { get; set; }
}

public class AdminVendorOption
{
    [JsonPropertyName("vendor_id")] public long VendorId { get; set; }
    [JsonPropertyName("name")] public string Name { get; set; } = string.Empty;
}

public class AdminKitEditSnapshot
{
    [JsonPropertyName("components")] public List<AdminKitEditComponentDto> Components { get; set; } = new();
    [JsonPropertyName("kit_offering")] public AdminKitEditOfferingSummary? KitOffering { get; set; }
    [JsonPropertyName("vendors")] public List<AdminVendorOption> Vendors { get; set; } = new();
}

public class AdminPartDeleteBlockers
{
    [JsonPropertyName("in_builds")] public int InBuilds { get; set; }
    [JsonPropertyName("used_as_child_in_kits")] public int UsedAsChildInKits { get; set; }
}

public class AdminPartDeleteInfo
{
    [JsonPropertyName("is_kit")] public bool IsKit { get; set; }
    [JsonPropertyName("bom_children")] public int BomChildren { get; set; }
    [JsonPropertyName("categories")] public int Categories { get; set; }
    [JsonPropertyName("fitment")] public int Fitment { get; set; }
    [JsonPropertyName("offerings")] public int Offerings { get; set; }
}

public class AdminPartDeleteProbeResponse
{
    [JsonPropertyName("deletable")] public bool Deletable { get; set; }
    [JsonPropertyName("blockers")] public AdminPartDeleteBlockers Blockers { get; set; } = new();
    [JsonPropertyName("info")] public AdminPartDeleteInfo Info { get; set; } = new();
}

public class AdminCategoryRequirementUpsertRequest
{
    [JsonPropertyName("engine_family_id")] public long EngineFamilyId { get; set; }
    [JsonPropertyName("tree_id")] public long? TreeId { get; set; }
    [JsonPropertyName("req_mode")] public string? ReqMode { get; set; }
    [JsonPropertyName("requirement_type")] public string? RequirementType { get; set; }
    [JsonPropertyName("required_qty")] public decimal? RequiredQty { get; set; }
    [JsonPropertyName("multiplier")] public decimal? Multiplier { get; set; }
    [JsonPropertyName("operand_field")] public string? OperandField { get; set; }
    [JsonPropertyName("round_mode")] public string? RoundMode { get; set; }
    [JsonPropertyName("notes")] public string? Notes { get; set; }
    [JsonPropertyName("formula")] public string? Formula { get; set; }
}

public class AdminCategoryRequirementCopyRequest
{
    [JsonPropertyName("source_engine_family_id")] public long? SourceEngineFamilyId { get; set; }
    [JsonPropertyName("source_engine_code")] public string? SourceEngineCode { get; set; }
    [JsonPropertyName("tree_id")] public long? TreeId { get; set; }
    [JsonPropertyName("target_engine_codes")] public List<string> TargetEngineCodes { get; set; } = new();
    [JsonPropertyName("overwrite")] public bool? Overwrite { get; set; }
}

public class AdminCategoryRequirementApplyRequest
{
    [JsonPropertyName("tree_id")] public long? TreeId { get; set; }
    [JsonPropertyName("target_engine_codes")] public List<string> TargetEngineCodes { get; set; } = new();
    [JsonPropertyName("overwrite")] public bool? Overwrite { get; set; }
    [JsonPropertyName("rule")] public AdminCategoryRequirementRule Rule { get; set; } = new();
}

public class AdminCategoryRequirementRule
{
    [JsonPropertyName("req_mode")] public string? ReqMode { get; set; }
    [JsonPropertyName("requirement_type")] public string? RequirementType { get; set; }
    [JsonPropertyName("required_qty")] public decimal? RequiredQty { get; set; }
    [JsonPropertyName("multiplier")] public decimal? Multiplier { get; set; }
    [JsonPropertyName("operand_field")] public string? OperandField { get; set; }
    [JsonPropertyName("round_mode")] public string? RoundMode { get; set; }
    [JsonPropertyName("notes")] public string? Notes { get; set; }
    [JsonPropertyName("formula")] public string? Formula { get; set; }
}

public class AdminTreeEdgeRequest
{
    [JsonPropertyName("parent_slug")] public string ParentSlug { get; set; } = string.Empty;
    [JsonPropertyName("child_slug")] public string ChildSlug { get; set; } = string.Empty;
    [JsonPropertyName("position")] public int? Position { get; set; }
}

public class AdminTreeCreateRequest
{
    [JsonPropertyName("name")] public string Name { get; set; } = string.Empty;
    [JsonPropertyName("description")] public string? Description { get; set; }
}

public class AdminTreeEngineToggleRequest
{
    [JsonPropertyName("engine_family_id")] public long EngineFamilyId { get; set; }
    [JsonPropertyName("attach")] public bool Attach { get; set; }
}

public class AdminTreeEngineDefaultRequest
{
    [JsonPropertyName("engine_family_id")] public long EngineFamilyId { get; set; }
}

public class AdminTreeEngineDefaultBatchRequest
{
    [JsonPropertyName("engine_family_ids")] public List<long> EngineFamilyIds { get; set; } = new();
}

public class AdminTreeAddCategoriesRequest
{
    [JsonPropertyName("parent_slug")] public string? ParentSlug { get; set; }
    [JsonPropertyName("child_slugs")] public List<string>? ChildSlugs { get; set; }
    [JsonPropertyName("start_position")] public int? StartPosition { get; set; }
    [JsonPropertyName("overwrite")] public bool? Overwrite { get; set; }
}

public class AdminTreeCopyFullRequest
{
    [JsonPropertyName("source_tree_name")] public string? SourceTreeName { get; set; }
    [JsonPropertyName("target_tree_name")] public string? TargetTreeName { get; set; }
    [JsonPropertyName("overwrite")] public bool? Overwrite { get; set; }
}

public class AdminTreeCopySubtreeRequest
{
    [JsonPropertyName("source_tree")] public string SourceTree { get; set; } = string.Empty;
    [JsonPropertyName("root_slug")] public string RootSlug { get; set; } = string.Empty;
    [JsonPropertyName("target_tree_names")] public List<string> TargetTreeNames { get; set; } = new();
    [JsonPropertyName("include_root")] public bool? IncludeRoot { get; set; }
    [JsonPropertyName("overwrite")] public bool? Overwrite { get; set; }
}

public class AdminTreeMoveRequest
{
    [JsonPropertyName("child_category_id")] public long ChildCategoryId { get; set; }
    [JsonPropertyName("current_parent_category_id")] public long CurrentParentCategoryId { get; set; }
    [JsonPropertyName("new_parent_category_id")] public long NewParentCategoryId { get; set; }
    [JsonPropertyName("position")] public int? Position { get; set; }
}

public class AdminTreeReorderRequest
{
    [JsonPropertyName("parent_category_id")] public long ParentCategoryId { get; set; }
    [JsonPropertyName("child_ids")] public List<long> ChildIds { get; set; } = new();
}

public class AdminIngestPartRequest
{
    [JsonPropertyName("sku")] public string Sku { get; set; } = string.Empty;
    [JsonPropertyName("name")] public string Name { get; set; } = string.Empty;
    [JsonPropertyName("brand_name")] public string BrandName { get; set; } = string.Empty;
    [JsonPropertyName("uom")] public string Uom { get; set; } = "each";
    [JsonPropertyName("pieces_per_unit")] public decimal PiecesPerUnit { get; set; } = 1m;
    [JsonPropertyName("is_kit")] public bool? IsKit { get; set; }
    [JsonPropertyName("status")] public string Status { get; set; } = "active";
}

public class AdminIngestOfferingRequest
{
    [JsonPropertyName("vendor_name")] public string VendorName { get; set; } = string.Empty;
    [JsonPropertyName("price")] public decimal Price { get; set; }
    [JsonPropertyName("currency")] public string? Currency { get; set; }
    [JsonPropertyName("url")] public string? Url { get; set; }
}

public class AdminIngestRequest
{
    [JsonPropertyName("part")] public AdminIngestPartRequest Part { get; set; } = new();
    [JsonPropertyName("category_id")] public long? CategoryId { get; set; }
    [JsonPropertyName("category_slugs")] public List<string>? CategorySlugs { get; set; }
    [JsonPropertyName("fitment_codes")] public List<string>? FitmentCodes { get; set; }
    [JsonPropertyName("offering")] public AdminIngestOfferingRequest Offering { get; set; } = new();
}

public class AdminIngestPartPayload
{
    [JsonPropertyName("sku")] public string? Sku { get; set; }
    [JsonPropertyName("name")] public string? Name { get; set; }
    [JsonPropertyName("brand_name")] public string? BrandName { get; set; }
    [JsonPropertyName("is_kit")] public bool? IsKit { get; set; }
    [JsonPropertyName("uom")] public string? Uom { get; set; }
    [JsonPropertyName("pieces_per_unit")] public decimal? PiecesPerUnit { get; set; }
    [JsonPropertyName("status")] public string? Status { get; set; }
    [JsonPropertyName("image_url")] public string? ImageUrl { get; set; }
}

public class AdminIngestOfferingPayload
{
    [JsonPropertyName("vendor_name")] public string? VendorName { get; set; }
    [JsonPropertyName("price")] public decimal? Price { get; set; }
    [JsonPropertyName("currency")] public string? Currency { get; set; }
    [JsonPropertyName("url")] public string? Url { get; set; }
    [JsonPropertyName("availability")] public string? Availability { get; set; }
}

public class AdminIngestPayloadEnvelope
{
    [JsonPropertyName("part")] public AdminIngestPartPayload Part { get; set; } = new();
    [JsonPropertyName("categories")] public List<string>? Categories { get; set; } = new();
    [JsonPropertyName("fitment")] public List<string>? Fitment { get; set; } = new();
    [JsonPropertyName("offerings")] public List<AdminIngestOfferingPayload>? Offerings { get; set; } = new();
}

public class AdminTransferBuildRequest
{
    [JsonPropertyName("user_id")] public long UserId { get; set; }
}

public class DuplicateBuildResponse
{
    [JsonPropertyName("build_id")] public long BuildId { get; set; }
}

public class RouteToSocketsRequest
{
    [JsonPropertyName("build_id")] public long? BuildId { get; set; }
    [JsonPropertyName("engine_family_id")] public long? EngineFamilyId { get; set; }
    [JsonPropertyName("tree_id")] public long? TreeId { get; set; }
    [JsonPropertyName("engine_key")] public string? EngineKey { get; set; }

    public RouteToSocketsRequest()
    {
    }

    public RouteToSocketsRequest(long? buildId, long? engineFamilyId, long? treeId = null, string? engineKey = null)
    {
        BuildId = buildId;
        EngineFamilyId = engineFamilyId;
        TreeId = treeId;
        EngineKey = engineKey;
    }
}

public class RouteToSocketsResult
{
    [JsonPropertyName("target_build_id")] public long TargetBuildId { get; set; }
    [JsonPropertyName("created")] public bool Created { get; set; }
    [JsonPropertyName("forked")] public bool Forked { get; set; }
    [JsonPropertyName("reason")] public string Reason { get; set; } = string.Empty;
}

public class UpdateBuildRequest
{
    [JsonPropertyName("is_archived")] public bool? IsArchived { get; set; }
    [JsonPropertyName("is_shared")] public bool? IsShared { get; set; }
    [JsonPropertyName("name")] public string? Name { get; set; }
}

public class ShareBuildRequest
{
    [JsonPropertyName("user_id")] public long? UserId { get; set; }
    [JsonPropertyName("email")] public string? Email { get; set; }
    [JsonPropertyName("role")] public string Role { get; set; } = "viewer";
}

public class ShareInviteRequest
{
    [JsonPropertyName("email")] public string Email { get; set; } = string.Empty;
    [JsonPropertyName("role")] public string Role { get; set; } = "viewer";
}

public class AcceptInviteRequest
{
    [JsonPropertyName("token")] public string Token { get; set; } = string.Empty;
}

public class LoginRequest
{
    [JsonPropertyName("email")] public string Email { get; set; } = string.Empty;
    [JsonPropertyName("password")] public string Password { get; set; } = string.Empty;
}

public class UserProfileDto
{
    [JsonPropertyName("user_id")] public long UserId { get; set; }
    [JsonPropertyName("email")] public string? Email { get; set; }
    [JsonPropertyName("display_name")] public string? DisplayName { get; set; }
    [JsonPropertyName("is_admin")] public bool IsAdmin { get; set; }
    [JsonPropertyName("is_banned")] public bool IsBanned { get; set; }
    [JsonPropertyName("email_opt_in")] public bool EmailOptIn { get; set; }
    [JsonPropertyName("email_verified")] public bool EmailVerified { get; set; }
    [JsonPropertyName("email_bounced")] public bool EmailBounced { get; set; }
    [JsonPropertyName("email_unsubscribed")] public bool EmailUnsubscribed { get; set; }
}

public class AdminUserSummary
{
    [JsonPropertyName("user_id")] public long UserId { get; set; }
    [JsonPropertyName("email")] public string Email { get; set; } = string.Empty;
    [JsonPropertyName("display_name")] public string? DisplayName { get; set; }
    [JsonPropertyName("is_admin")] public bool IsAdmin { get; set; }
    [JsonPropertyName("is_banned")] public bool IsBanned { get; set; }
    [JsonPropertyName("plan_code")] public string? PlanCode { get; set; }
    [JsonPropertyName("max_active_builds")] public int? MaxActiveBuilds { get; set; }
    [JsonPropertyName("max_total_builds")] public int? MaxTotalBuilds { get; set; }
    [JsonPropertyName("active_builds")] public int ActiveBuilds { get; set; }
    [JsonPropertyName("total_builds")] public int TotalBuilds { get; set; }
    [JsonPropertyName("created_at")] public DateTime CreatedAt { get; set; }
}

public sealed record AnalyticsDto(
    string EventName,
    string? EventUuid,
    DateTime? OccurredAtUtc,
    string? SessionId,
    long? UserId,
    long? BuildId,
    long? EngineFamilyId,
    long? CategoryId,
    long? PartId,
    long? RuleId,
    string? Severity,
    string? Source,
    decimal? NumericValue,
    JsonElement? Extra);
