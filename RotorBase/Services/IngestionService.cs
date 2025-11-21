using System.Data;
using System.Text.Json;
using System.Linq;
using System.Text.RegularExpressions;
using System.Collections.ObjectModel;
using Microsoft.Extensions.Options;
using MySqlConnector;
using RotorBase;

namespace RotorBase.Services;

public class IngestionService
{
    private readonly PerplexityClient _pplx;
    private readonly string _connString;

    private static readonly IReadOnlyDictionary<string, CanonicalCategory> CanonicalCategories =
        new ReadOnlyDictionary<string, CanonicalCategory>(new Dictionary<string, CanonicalCategory>(StringComparer.OrdinalIgnoreCase)
        {
            ["engine-internals"] = new("Engine Internals", false, null, 1, "Core rotary engine internals"),
            ["eccentric-shaft-and-bearings"] = new("Eccentric Shaft & Bearings", false, "engine-internals", 1, "Eccentric shaft components"),
            ["rotors-and-seals"] = new("Rotors & Seals", false, "engine-internals", 2, "Rotor assemblies and sealing components"),
            ["housings-and-irons"] = new("Housings & Irons", false, "engine-internals", 3, "Rotor housings and iron plates"),
            ["tension-bolts-and-studs"] = new("Tension Bolts & Studs", false, "engine-internals", 4, "Tension hardware"),

            ["eccentric-shaft"] = new("Eccentric Shaft", true, "eccentric-shaft-and-bearings", 1, "Core eccentric shaft"),
            ["eccentric-shaft-bearings"] = new("Eccentric Shaft Bearings", true, "eccentric-shaft-and-bearings", 2, "Eccentric shaft bearings"),
            ["endplay-spacer"] = new("Endplay Spacer", true, "eccentric-shaft-and-bearings", 3, "Endplay spacers"),
            ["front-cover-bearing-plate"] = new("Front Cover Bearing Plate", true, "eccentric-shaft-and-bearings", 4, "Front cover bearing plates"),
            ["counterweight"] = new("Counterweight", true, "eccentric-shaft-and-bearings", 5, "Counterweights"),
            ["eccentric-shaft-key"] = new("Eccentric Shaft Key", true, "eccentric-shaft-and-bearings", 6, "Eccentric shaft woodruff keys"),
            ["oil-pump-drive-gear"] = new("Oil Pump Drive Gear", true, "eccentric-shaft-and-bearings", 7, "Oil pump drive gears"),
            ["omp-drive-gear"] = new("OMP Drive Gear", true, "eccentric-shaft-and-bearings", 8, "Oil metering pump drive gears"),
            ["eccentric-pulley-hub"] = new("Eccentric Pulley & Hub", true, "eccentric-shaft-and-bearings", 9, "Pulley hubs"),
            ["e-shaft-thermostat"] = new("E-Shaft Thermostat", true, "eccentric-shaft-and-bearings", 10, "Thermostatic valves"),

            ["rotors"] = new("Rotors", true, "rotors-and-seals", 1, "Complete rotor assemblies"),
            ["apex-seals"] = new("Apex Seals", true, "rotors-and-seals", 2, "Apex seal sets"),
            ["corner-seals"] = new("Corner Seals", true, "rotors-and-seals", 3, "Corner seals"),
            ["side-seals"] = new("Side Seals", true, "rotors-and-seals", 4, "Side seal strips"),
            ["oil-control-ring-springs"] = new("Oil Control Ring Springs", true, "rotors-and-seals", 5, "Oil control ring springs"),
            ["seal-springs"] = new("Seal Springs", true, "rotors-and-seals", 6, "Miscellaneous seal springs"),
            ["side-oil-seals"] = new("Side Oil Seals", true, "rotors-and-seals", 7, "Side oil seals and springs"),

            ["rotor-housings"] = new("Rotor Housings", true, "housings-and-irons", 1, "Rotor housings"),
            ["end-irons"] = new("End Irons", true, "housings-and-irons", 2, "Front and rear irons"),
            ["center-iron"] = new("Center Iron", true, "housings-and-irons", 3, "Center iron plates"),
            ["water-seals-o-rings"] = new("Water Seals / O-Rings", true, "housings-and-irons", 4, "Water seals and O-rings"),

            ["tension-bolts"] = new("Tension Bolts", true, "tension-bolts-and-studs", 1, "Tension bolts"),
            ["tension-bolt-seals"] = new("Tension Bolt Seals", true, "tension-bolts-and-studs", 2, "Seals for tension bolts"),
            ["stud-kits"] = new("Stud Kits", true, "tension-bolts-and-studs", 3, "Stud kits"),
        });

    private static readonly IReadOnlyDictionary<string, string> CategoryAlias =
        new ReadOnlyDictionary<string, string>(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["side-oil-seal-springs"] = "side-oil-seals",
            ["side-oil-spring"] = "side-oil-seals",
            ["side-oil-seal"] = "side-oil-seals",
            ["side-oil-seals-springs"] = "side-oil-seals",
            ["side-seal-springs"] = "side-oil-seals",
            ["seal-spring"] = "seal-springs",
            ["seal-springs"] = "seal-springs",
            ["spring-seal"] = "seal-springs"
        });

    private static readonly IReadOnlyDictionary<string, string[]> EngineCodeExpansion =
        new ReadOnlyDictionary<string, string[]>(new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            ["13B-REW"] = new[] { "13B-REW", "13B-REW-S6", "13B-REW-S7", "13B-REW-S8" },
            ["13B-REW-S6"] = new[] { "13B-REW-S6", "13B-REW-S7", "13B-REW-S8" },
            ["13B-REW-S7"] = new[] { "13B-REW-S6", "13B-REW-S7", "13B-REW-S8" },
            ["13B-REW-S8"] = new[] { "13B-REW-S6", "13B-REW-S7", "13B-REW-S8" },
            ["13B-RE"] = new[] { "13B-RE", "13B-RE-NA", "13B-RE-Turbo" },
            ["13B-RE-NA"] = new[] { "13B-RE", "13B-RE-NA", "13B-RE-Turbo" },
            ["13B-RE-Turbo"] = new[] { "13B-RE", "13B-RE-NA", "13B-RE-Turbo" }
        });

    public IngestionService(PerplexityClient pplx, IOptions<PerplexityOptions> opts, IConfiguration cfg)
    {
        _pplx = pplx;
        _connString = cfg.GetConnectionString("Default")
                      ?? cfg.GetConnectionString("DefaultConnection")
                      ?? cfg["ConnectionStrings:Default"]
                      ?? cfg["ConnectionStrings:DefaultConnection"]
                      ?? throw new InvalidOperationException("Missing connection string");
    }

    public async Task<IngestionPayload> GenerateForEngineAsync(string engineCode, string? treeName, IReadOnlyCollection<string>? forcedEngineCodes, CancellationToken ct)
    {
        var system = "You are a domain expert for rotary engine parts and e-commerce. Output STRICT JSON matching the requested schema, no commentary. Do NOT use markdown or code fences. Start your response with '{' and end with '}'. For EVERY part you include, fill as many fields as possible: name, description, brand_name, is_kit, uom, pieces_per_unit, status, mpn, upc, gtin, core_charge, image_url (absolute URL).";
        var leafChoices = CanonicalCategories
            .Where(kvp => kvp.Value.IsSelectable)
            .Select(kvp => JsonSerializer.Serialize(new { slug = kvp.Key, name = kvp.Value.Name }))
            .ToList();
        var leafSection = string.Empty;
        if (leafChoices.Count > 0)
        {
            var leafJson = "[" + string.Join(",", leafChoices) + "]";
            leafSection = $"\\nAllowed leaf category slugs (JSON array of objects {{slug,name}}):\\n{leafJson}\\nEvery entry in part_categories MUST use one of these slugs. Do NOT invent new slugs.";
        }

        var user = $@"Task: Provide a complete dataset to populate a catalog and configurator for rotary engine builds.
Engine code: '{engineCode}'.
Canonical tree to use: 'rotary_build_v1'.

Return a single JSON object with these keys (arrays where noted):
engine: {{ code, rotor_count, years_start?, years_end?, hp_min?, hp_max?, notes? }}
tree: {{ name, edges: [ {{ parent_slug, child_slug, position? }} ] }}
categories: [ {{ name, slug, description?, is_selectable? }} ]
requirements: [ {{ category_slug, requirement_type ('exact_count'|'min_count'|'formula'), req_mode?, required_qty?, formula?, multiplier?, operand_field?, round_mode?, notes?, engine_codes? }} ]
brands: [ {{ name, website? }} ]
parts: [ {{ sku?, name, description?, brand_name?, is_kit?, uom?, pieces_per_unit?, status?, mpn?, upc?, gtin?, core_charge?, image_url? }} ]
components: [ {{ parent_sku, child_sku, qty_per_parent }} ]
part_categories: [ {{ part_sku, category_slug, is_primary?, coverage_weight?, display_order? }} ]
fitment: [ {{ part_sku, engine_code, years_start?, years_end?, notes? }} ]
vendors: [ {{ name, website? }} ]
offerings: [ {{ part_sku, vendor_name, price?, msrp?, currency?, availability?, url?, affiliate_url?, effective_from?, effective_to? }} ]
plans: [ {{ code, name, monthly_price, currency }} ]
{leafSection}

Canonical tree rules:
- Use only these category slugs: engine-internals; eccentric-shaft-and-bearings; rotors-and-seals; housings-and-irons; tension-bolts-and-studs; eccentric-shaft; eccentric-shaft-bearings; endplay-spacer; front-cover-bearing-plate; counterweight; eccentric-shaft-key; oil-pump-drive-gear; omp-drive-gear; eccentric-pulley-hub; e-shaft-thermostat; rotors; apex-seals; corner-seals; side-seals; side-oil-seals; oil-control-ring-springs; seal-springs; rotor-housings; end-irons; center-iron; water-seals-o-rings; tension-bolts; tension-bolt-seals; stud-kits.
- Tree edges must connect each child to its canonical parent inside 'rotary_build_v1'. Never invent new parents such as 'rotary-engine' or 'seals'.

Critical builder requirements:
- Provide at least one CategoryRequirement row per category. When counts scale with rotors, use `req_mode='structured'` with `multiplier` × `operand_field='rotor_count'`; otherwise use `exact_count`/`min_count` with `required_qty`.
- Every requirement must include `engine_codes` listing every engine family the requirement applies to (e.g., ['13B-REW-S6','13B-REW-S7','13B-REW-S8']).
- Every part must include `pieces_per_unit`, `status`, and be linked to at least one category from the canonical list.
- Use `fitment` to list every engine family the part fits (one row per engine_code).
- Use accurate `components` for kits so they explode to leaf parts.
- Focus on the exact products offered for the target engine build; avoid unrelated parts.

Rules:
- Prefer real brands/parts/vendors when confident; otherwise provide plausible placeholders clearly marked (e.g., 'ExampleCo').
- Ensure category slugs are unique, kebab-case, and referenced consistently (use canonical slugs when possible).
- Ensure every child_sku in components exists in parts.
- Ensure every part_sku in part_categories and fitment exists in parts.
- Provide at least a minimal set to exercise requirements and BOM logic (kits composed of leaf parts).";

        using var doc = await _pplx.ChatJsonAsync(system, user, ct);
        if (doc is null) throw new InvalidOperationException("Empty response from Perplexity");
        var payload = doc.Deserialize<IngestionPayload>(new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        });
        if (payload is null) throw new InvalidOperationException("Failed to parse Perplexity JSON");
        if (forcedEngineCodes is not null && forcedEngineCodes.Count > 0)
        {
            payload.EngineCodes ??= new List<string>();
            foreach (var code in forcedEngineCodes)
                if (!string.IsNullOrWhiteSpace(code))
                    payload.EngineCodes.Add(code);
        }
        
        return payload;
    }

    public async Task<IngestionPayload> GenerateFromUrlAsync(string url, string? engineCode, string? treeName, bool useDbEngineList, bool useDbCategoryList, bool useDbTreeEdges, IReadOnlyCollection<string>? forcedEngineCodes, CancellationToken ct)
    {
        var system = "You are a domain expert for rotary engine parts and e-commerce. Output STRICT JSON matching the requested schema, no commentary. Do NOT use markdown or code fences. Start your response with '{' and end with '}'. For EVERY part you include, fill as many fields as possible: name, description, brand_name, is_kit, uom, pieces_per_unit, status, mpn, upc, gtin, core_charge.";
        var engineHint = string.IsNullOrWhiteSpace(engineCode) ? string.Empty : $"\nHint engine code: '{engineCode}'.";
        string forcedEngineSection = string.Empty;
        if (forcedEngineCodes is not null && forcedEngineCodes.Count > 0)
        {
            var jsonCodes = System.Text.Json.JsonSerializer.Serialize(forcedEngineCodes);
            forcedEngineSection = $"\nMandatory engine codes (include in requirements.engine_codes and fitment):\n{jsonCodes}";
        }

        // If requested, include the current DB engine list and instruct the model to pick one.
        string engineListSection = string.Empty;
        if (useDbEngineList)
        {
            var engines = new List<string>();
            await using var conn = new MySqlConnection(_connString);
            await conn.OpenAsync(ct);
            await using var cmd = new MySqlCommand("SELECT code, rotor_count, years_start, years_end FROM EngineFamily ORDER BY code", conn);
            await using var r = await cmd.ExecuteReaderAsync(ct);
            while (await r.ReadAsync(ct))
            {
                var code = r.GetString(0);
                var rotors = r.IsDBNull(1) ? (int?)null : r.GetInt32(1);
                var ys = r.IsDBNull(2) ? (int?)null : r.GetInt32(2);
                var ye = r.IsDBNull(3) ? (int?)null : r.GetInt32(3);
                engines.Add(System.Text.Json.JsonSerializer.Serialize(new { code, rotor_count = rotors, years_start = ys, years_end = ye }));
            }
            var jsonArray = "[" + string.Join(",", engines) + "]";
            engineListSection = $"\nAvailable engine families (JSON array):\n{jsonArray}\nChoose the best matching 'engine.code' from this list when appropriate; otherwise propose a new code and include a note in engine.notes.";
        }

        // Optionally include current categories for reuse
        string categoryListSection = string.Empty;
        if (useDbCategoryList)
        {
            var cats = new List<string>();
            await using var conn2 = new MySqlConnection(_connString);
            await conn2.OpenAsync(ct);
            await using var cmd2 = new MySqlCommand("SELECT slug, name, is_selectable FROM Category ORDER BY name", conn2);
            await using var r2 = await cmd2.ExecuteReaderAsync(ct);
            while (await r2.ReadAsync(ct))
            {
                var slug = r2.IsDBNull(0) ? null : r2.GetString(0);
                var name = r2.IsDBNull(1) ? null : r2.GetString(1);
                var selectable = r2.IsDBNull(2) ? (bool?)null : r2.GetBoolean(2);
                if (!string.IsNullOrWhiteSpace(slug))
                {
                    cats.Add(System.Text.Json.JsonSerializer.Serialize(new { slug, name, is_selectable = selectable }));
                }
            }
            var jsonArray = "[" + string.Join(",", cats) + "]";
            categoryListSection = $"\nExisting categories (JSON array with slug, name, is_selectable):\n{jsonArray}\nWhen appropriate, reuse categories by slug. If creating new ones, ensure unique, kebab-case slugs.";
        }

        // Canonical leaf slugs (used to constrain model categorization)
        var leafChoices = CanonicalCategories
            .Where(kvp => kvp.Value.IsSelectable)
            .Select(kvp => JsonSerializer.Serialize(new { slug = kvp.Key, name = kvp.Value.Name }))
            .ToList();
        var leafSection = string.Empty;
        if (leafChoices.Count > 0)
        {
            var leafJson = "[" + string.Join(",", leafChoices) + "]";
            leafSection = $"\\nAllowed leaf category slugs (JSON array of objects {{slug,name}}):\\n{leafJson}\\nEvery entry in part_categories MUST use one of these slugs. Do NOT invent new slugs.";
        }

        // Optionally include current tree edges for a named tree
        string treeEdgeSection = string.Empty;
        if (useDbTreeEdges)
        {
            var tn = string.IsNullOrWhiteSpace(treeName) ? "Default" : treeName;
            await using var conn3 = new MySqlConnection(_connString);
            await conn3.OpenAsync(ct);
            long? tid = null;
            await using (var findTree = new MySqlCommand("SELECT tree_id FROM CategoryTree WHERE name=@n", conn3))
            {
                findTree.Parameters.AddWithValue("@n", tn!);
                var obj = await findTree.ExecuteScalarAsync(ct);
                if (obj != null && obj != DBNull.Value) tid = Convert.ToInt64(obj);
            }
            if (tid.HasValue)
            {
                var edges = new List<string>();
                var sql = @"SELECT p.slug AS parent_slug, c.slug AS child_slug, ce.position
                            FROM CategoryEdge ce
                            JOIN Category p ON p.category_id = ce.parent_category_id
                            JOIN Category c ON c.category_id = ce.child_category_id
                            WHERE ce.tree_id=@t ORDER BY ce.position";
                await using var cmd3 = new MySqlCommand(sql, conn3);
                cmd3.Parameters.AddWithValue("@t", tid.Value);
                await using var r3 = await cmd3.ExecuteReaderAsync(ct);
                while (await r3.ReadAsync(ct))
                {
                    var parentSlug = r3.IsDBNull(0) ? null : r3.GetString(0);
                    var childSlug = r3.IsDBNull(1) ? null : r3.GetString(1);
                    var pos = r3.IsDBNull(2) ? (int?)null : r3.GetInt32(2);
                    if (!string.IsNullOrWhiteSpace(parentSlug) && !string.IsNullOrWhiteSpace(childSlug))
                    {
                        edges.Add(System.Text.Json.JsonSerializer.Serialize(new { parent_slug = parentSlug, child_slug = childSlug, position = pos }));
                    }
                }
                var jsonEdges = "[" + string.Join(",", edges) + "]";
                treeEdgeSection = $"\nExisting tree edges for tree name '{tn}' (JSON array: parent_slug, child_slug, position):\n{jsonEdges}\nYou may reuse, refine, or extend this structure as needed.";
            }
        }

        var user = $@"Task: Analyze the content at the URL below and synthesize a dataset to populate a catalog and configurator for rotary engine builds.{engineHint}{forcedEngineSection}
URL: {url}
{engineListSection}
{categoryListSection}
{treeEdgeSection}

Return a single JSON object with these keys (arrays where noted):
engine: {{ code, rotor_count, years_start?, years_end?, hp_min?, hp_max?, notes? }}
tree: {{ name: 'rotary_build_v1', edges: [ {{ parent_slug, child_slug, position? }} ] }}
categories: [ {{ name, slug, description?, is_selectable? }} ]
requirements: [ {{ category_slug, requirement_type ('exact_count'|'min_count'|'formula'), req_mode?, required_qty?, formula?, multiplier?, operand_field?, round_mode?, notes?, engine_codes? }} ]
brands: [ {{ name, website? }} ]
parts: [ {{ sku?, name, description?, brand_name?, is_kit?, uom?, pieces_per_unit?, status?, mpn?, upc?, gtin?, core_charge?, image_url? }} ]
components: [ {{ parent_sku, child_sku, qty_per_parent }} ]
part_categories: [ {{ part_sku, category_slug, is_primary?, coverage_weight?, display_order? }} ]
fitment: [ {{ part_sku, engine_code, years_start?, years_end?, notes? }} ]
vendors: [ {{ name, website? }} ]
offerings: [ {{ part_sku, vendor_name, price?, msrp?, currency?, availability?, url?, affiliate_url?, effective_from?, effective_to? }} ]
plans: [ {{ code, name, monthly_price, currency }} ]

Canonical tree rules:
- Reuse the seeded rotary tree 'rotary_build_v1'. Valid slugs include engine-internals; eccentric-shaft-and-bearings; rotors-and-seals; housings-and-irons; tension-bolts-and-studs; and leaf slugs such as eccentric-shaft, apex-seals, corner-seals, side-seals, side-oil-seals, oil-control-ring-springs, seal-springs, etc. Do not invent new root nodes like 'rotary-engine' or 'seals'.
- Tree edges must connect each child to its canonical parent listed above.

Critical builder requirements:
- Every category must have a requirement row. Use `req_mode='structured'` with `multiplier` × `operand_field='rotor_count'` when counts scale with rotors; otherwise use `exact_count`/`min_count` with `required_qty`.
- Include `engine_codes` for each requirement covering every engine that applies (e.g., ['13B-REW-S6','13B-REW-S7','13B-REW-S8']).
- Every part must include `pieces_per_unit`, `status`, and map to at least one canonical category via `part_categories`.
- Provide `fitment` rows for each engine family the part supports.
- Provide kit `components` where applicable.
- Focus on parts actually described by the target URL; omit unrelated catalog items.

Rules:
- Prefer real brands/parts/vendors when confident; otherwise provide plausible placeholders clearly marked (e.g., 'ExampleCo').
- Ensure slugs are canonical or kebab-case aliases that map to the canonical list.
- Ensure every child_sku in components exists in parts.
- Ensure every part_sku in part_categories and fitment exists in parts.
- Provide at least a minimal set to exercise requirements and BOM logic (kits composed of leaf parts).";

        using var doc = await _pplx.ChatJsonAsync(system, user, ct);
        if (doc is null) throw new InvalidOperationException("Empty response from Perplexity");
        var payload = doc.Deserialize<IngestionPayload>(new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        });
        if (payload is null) throw new InvalidOperationException("Failed to parse Perplexity JSON");
        return payload;
    }

    public async Task<IngestionPayload> EnrichPartsAsync(IngestionPayload payload, CancellationToken ct)
    {
        if (payload.Parts == null || payload.Parts.Count == 0)
            return payload;

        var system = "You are a parts data enrichment assistant. Improve and complete part details. Output STRICT JSON with only a 'parts' array. No markdown.";
        var input = new
        {
            parts = payload.Parts.Select(p => new
            {
                p.Sku,
                p.Name,
                p.BrandName,
                p.IsKit,
                p.Uom,
                p.PiecesPerUnit,
                p.Status,
                p.Mpn,
                p.Upc,
                p.Gtin,
                p.CoreCharge,
                p.Description
            })
        };

        var user =
            "Given the following parts list with possibly missing fields, return JSON {\"parts\":[...]} where each part object fills as many fields as possible. " +
            "Match parts by SKU when present, or by name otherwise. " +
            "Fields to fill per part: name, description, brand_name, is_kit, uom, pieces_per_unit, status, mpn, upc, gtin, core_charge, image_url (absolute URL). " +
            "Use null (not empty strings) if unknown. Do not add or remove parts. Do not invent unrealistic MPN/UPC/GTIN; prefer authoritative sources from context or leave null." +
            "\n\nParts JSON:\n" + JsonSerializer.Serialize(input);

        using var doc = await _pplx.ChatJsonAsync(system, user, ct);
        if (doc is null) return payload;

        List<PartDef>? enrichedParts = null;
        try
        {
            if (doc.RootElement.TryGetProperty("parts", out var partsEl))
            {
                enrichedParts = JsonSerializer.Deserialize<List<PartDef>>(partsEl.GetRawText(), new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });
            }
            else
            {
                var temp = doc.Deserialize<IngestionPayload>(new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                enrichedParts = temp?.Parts;
            }
        }
        catch
        {
            // ignore enrich failure
        }

        if (enrichedParts == null || enrichedParts.Count == 0)
            return payload;

        // Merge: match by SKU first, then by Name (case-insensitive)
        foreach (var ep in enrichedParts)
        {
            PartDef? target = null;
            if (!string.IsNullOrWhiteSpace(ep.Sku))
                target = payload.Parts.FirstOrDefault(x => string.Equals(x.Sku, ep.Sku, StringComparison.OrdinalIgnoreCase));
            if (target == null && !string.IsNullOrWhiteSpace(ep.Name))
                target = payload.Parts.FirstOrDefault(x => string.Equals(x.Name, ep.Name, StringComparison.OrdinalIgnoreCase));
            if (target == null) continue;

            if (string.IsNullOrWhiteSpace(target.Description) && !string.IsNullOrWhiteSpace(ep.Description)) target.Description = ep.Description;
            if (string.IsNullOrWhiteSpace(target.BrandName) && !string.IsNullOrWhiteSpace(ep.BrandName)) target.BrandName = ep.BrandName;
            if (target.IsKit == null && ep.IsKit != null) target.IsKit = ep.IsKit;
            if (string.IsNullOrWhiteSpace(target.Uom) && !string.IsNullOrWhiteSpace(ep.Uom)) target.Uom = ep.Uom;
            if (target.PiecesPerUnit == null && ep.PiecesPerUnit != null) target.PiecesPerUnit = ep.PiecesPerUnit;
            if (string.IsNullOrWhiteSpace(target.Status) && !string.IsNullOrWhiteSpace(ep.Status)) target.Status = ep.Status;
            if (string.IsNullOrWhiteSpace(target.Mpn) && !string.IsNullOrWhiteSpace(ep.Mpn)) target.Mpn = ep.Mpn;
            if (string.IsNullOrWhiteSpace(target.Upc) && !string.IsNullOrWhiteSpace(ep.Upc)) target.Upc = ep.Upc;
            if (string.IsNullOrWhiteSpace(target.Gtin) && !string.IsNullOrWhiteSpace(ep.Gtin)) target.Gtin = ep.Gtin;
            if (target.CoreCharge == null && ep.CoreCharge != null) target.CoreCharge = ep.CoreCharge;
        }

        return payload;
    }

    public IngestionPayload NormalizePayload(IngestionPayload payload, IReadOnlyCollection<string>? forcedEngineCodes = null)
        => PrepareForBuilder(payload, forcedEngineCodes);

    private static IngestionPayload PrepareForBuilder(IngestionPayload payload, IReadOnlyCollection<string>? forcedEngineCodes = null)
    {
        if (payload.Engine is null)
            throw new InvalidOperationException("Engine data is required for ingestion.");

        payload.Brands ??= new();
        payload.Categories ??= new();
        payload.Requirements ??= new();
        payload.Parts ??= new();
        payload.Components ??= new();
        payload.PartCategories ??= new();
        payload.Fitment ??= new();
        payload.Vendors ??= new();
        payload.Offerings ??= new();
        payload.Plans ??= new();
        payload.Tree ??= new CategoryTreeDef { Name = "rotary_build_v1" };
        payload.Tree.Edges ??= new();
        payload.Tree.Name = "rotary_build_v1";

        var forcedEngineCodeSet = new HashSet<string>(forcedEngineCodes ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
        if (payload.EngineCodes is not null)
        {
            foreach (var code in payload.EngineCodes)
                if (!string.IsNullOrWhiteSpace(code))
                    forcedEngineCodeSet.Add(code);
        }

        string NormalizeCategorySlug(string? slug)
        {
            if (string.IsNullOrWhiteSpace(slug)) return "engine-internals";
            var normalized = Slugify(slug);
            if (CanonicalCategories.ContainsKey(normalized)) return normalized;
            if (CategoryAlias.TryGetValue(normalized, out var mapped)) return mapped;

            foreach (var alias in CategoryAlias.Keys)
            {
                if (normalized.Contains(alias, StringComparison.OrdinalIgnoreCase))
                    return CategoryAlias[alias];
            }

            if (normalized.Contains("side-oil", StringComparison.OrdinalIgnoreCase)) return "side-oil-seals";
            if (normalized.Contains("apex", StringComparison.OrdinalIgnoreCase)) return "apex-seals";
            if (normalized.Contains("corner", StringComparison.OrdinalIgnoreCase)) return "corner-seals";
            if (normalized.Contains("oil-control", StringComparison.OrdinalIgnoreCase)) return "oil-control-ring-springs";
            if (normalized.Contains("rotor", StringComparison.OrdinalIgnoreCase)) return "rotors";
            if (normalized.Contains("seal", StringComparison.OrdinalIgnoreCase)) return "seal-springs";

            return "engine-internals";
        }

        var slugsToInclude = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void AddWithAncestors(string slug)
        {
            string? current = slug;
            var guard = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            while (!string.IsNullOrWhiteSpace(current) && guard.Add(current))
            {
                if (CanonicalCategories.TryGetValue(current, out var info))
                {
                    slugsToInclude.Add(current);
                    current = info.ParentSlug;
                }
                else
                {
                    current = "engine-internals";
                }
            }
        }

        // Normalize requirements and gather category/engine usage
        var fitmentCodes = new HashSet<string>(payload.Fitment.Where(f => !string.IsNullOrWhiteSpace(f.EngineCode)).Select(f => f.EngineCode!), StringComparer.OrdinalIgnoreCase);
        fitmentCodes.UnionWith(forcedEngineCodeSet);

        foreach (var req in payload.Requirements)
        {
            req.CategorySlug = NormalizeCategorySlug(req.CategorySlug);
            AddWithAncestors(req.CategorySlug);

            req.RequirementType = req.RequirementType?.Trim().ToLowerInvariant() switch
            {
                "exact_count" => "exact_count",
                "min_count" => "min_count",
                "formula" => "formula",
                _ => "min_count"
            };

            var normalizedMode = req.ReqMode?.Trim().ToLowerInvariant();
            if (string.IsNullOrWhiteSpace(normalizedMode))
            {
                normalizedMode = req.RequirementType == "min_count" ? "min_count" : req.RequirementType == "formula" ? "formula" : "exact_count";
            }

            if (normalizedMode == "structured" && (!req.Multiplier.HasValue || string.IsNullOrWhiteSpace(req.OperandField)))
            {
                normalizedMode = req.RequirementType == "min_count" ? "min_count" : "exact_count";
            }

            req.ReqMode = normalizedMode switch
            {
                "structured" or "min_count" or "exact_count" or "formula" => normalizedMode,
                _ => req.RequirementType == "min_count" ? "min_count" : req.RequirementType == "formula" ? "formula" : "exact_count"
            };

            if (!string.Equals(req.ReqMode, "structured", StringComparison.OrdinalIgnoreCase) && !req.RequiredQty.HasValue)
                req.RequiredQty = 1m;

            req.RoundMode = string.IsNullOrWhiteSpace(req.RoundMode) ? "none" : req.RoundMode;

            var codes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (req.EngineCodes is not null)
            {
                foreach (var code in req.EngineCodes)
                    if (!string.IsNullOrWhiteSpace(code))
                        codes.Add(code);
            }

            if (!string.IsNullOrWhiteSpace(payload.Engine.Code))
                codes.Add(payload.Engine.Code);

            foreach (var fc in fitmentCodes)
                codes.Add(fc);

            codes.UnionWith(forcedEngineCodeSet);

            codes = new HashSet<string>(ExpandEngineCodes(codes), StringComparer.OrdinalIgnoreCase);

            req.EngineCodes = codes.ToList();
        }

        // Ensure requirements exist for any categories inferred from parts
        var requirementSlugSet = new HashSet<string>(payload.Requirements.Select(r => r.CategorySlug), StringComparer.OrdinalIgnoreCase);

        var usedSkus = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var part in payload.Parts)
        {
            if (string.IsNullOrWhiteSpace(part.Name))
                part.Name = "Unnamed Part";

            if (string.IsNullOrWhiteSpace(part.Sku))
            {
                var baseSku = Slugify(part.Name).Replace('-', '_').ToUpperInvariant();
                if (string.IsNullOrEmpty(baseSku)) baseSku = "PART";
                var candidate = baseSku;
                var idx = 2;
                while (!usedSkus.Add(candidate))
                {
                    candidate = $"{baseSku}_{idx++}";
                }
                part.Sku = candidate;
            }
            else
            {
                var trimmedSku = part.Sku.Trim();
                if (!usedSkus.Add(trimmedSku))
                {
                    var baseSku = trimmedSku;
                    var idx = 2;
                    var candidate = $"{baseSku}-{idx++}";
                    while (!usedSkus.Add(candidate))
                    {
                        candidate = $"{baseSku}-{idx++}";
                    }
                    part.Sku = candidate;
                }
                else
                {
                    part.Sku = trimmedSku;
                }
            }

            part.IsKit ??= false;
            part.Uom ??= "piece";
            part.PiecesPerUnit ??= 1m;
            part.Status ??= "active";
        }

        foreach (var component in payload.Components)
        {
            if (component.QtyPerParent <= 0)
                component.QtyPerParent = 1m;
        }

        foreach (var pc in payload.PartCategories)
        {
            var normalized = NormalizeCategorySlug(pc.CategorySlug);
            pc.CategorySlug = normalized;
            AddWithAncestors(normalized);

            if (string.IsNullOrWhiteSpace(pc.PartSku))
                pc.PartSku = string.Empty;

            pc.IsPrimary ??= true;
            pc.CoverageWeight ??= 1m;
        }

        foreach (var part in payload.Parts)
        {
            if (string.IsNullOrWhiteSpace(part.Sku)) continue;
            var hasMapping = payload.PartCategories.Any(pc => string.Equals(pc.PartSku, part.Sku, StringComparison.OrdinalIgnoreCase));
            if (!hasMapping)
            {
                string inferred = "engine-internals";
                var nameSlug = Slugify(part.Name);
                if (nameSlug.Contains("apex")) inferred = "apex-seals";
                else if (nameSlug.Contains("corner")) inferred = "corner-seals";
                else if (nameSlug.Contains("side-oil")) inferred = "side-oil-seals";
                else if (nameSlug.Contains("side-seal")) inferred = "side-seals";
                else if (nameSlug.Contains("oil-control")) inferred = "oil-control-ring-springs";
                else if (nameSlug.Contains("rotor")) inferred = "rotors";

                AddWithAncestors(inferred);
                payload.PartCategories.Add(new PartCategoryDef
                {
                    PartSku = part.Sku,
                    CategorySlug = inferred,
                    IsPrimary = true,
                    CoverageWeight = 1m,
                    DisplayOrder = 0
                });
                requirementSlugSet.Add(inferred);
            }
        }

        payload.PartCategories = payload.PartCategories
            .Where(pc => !string.IsNullOrWhiteSpace(pc.PartSku))
            .ToList();

        var partCategorySlugs = payload.PartCategories
            .Select(pc => pc.CategorySlug)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        foreach (var slug in partCategorySlugs)
        {
            if (!requirementSlugSet.Contains(slug))
            {
                var codes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                if (!string.IsNullOrWhiteSpace(payload.Engine.Code))
                    codes.Add(payload.Engine.Code);
                foreach (var fc in fitmentCodes)
                    codes.Add(fc);

                codes.UnionWith(forcedEngineCodeSet);

                codes = new HashSet<string>(ExpandEngineCodes(codes), StringComparer.OrdinalIgnoreCase);

                payload.Requirements.Add(new CategoryRequirementDef
                {
                    CategorySlug = slug,
                    RequirementType = "min_count",
                    ReqMode = "min_count",
                    RequiredQty = 1m,
                    EngineCodes = codes.ToList()
                });
                requirementSlugSet.Add(slug);
                AddWithAncestors(slug);
            }
        }

        foreach (var req in payload.Requirements.Where(r => !requirementSlugSet.Contains(r.CategorySlug)))
            AddWithAncestors(req.CategorySlug);
        foreach (var pc in payload.PartCategories)
            AddWithAncestors(pc.CategorySlug);

        if (slugsToInclude.Count == 0)
            slugsToInclude.Add("engine-internals");

        var normalizedCategories = slugsToInclude
            .Where(CanonicalCategories.ContainsKey)
            .Select(slug => (slug, CanonicalCategories[slug]))
            .OrderBy(tuple => tuple.Item2.ParentSlug is null ? 0 : CanonicalCategories[tuple.Item2.ParentSlug].Position)
            .ThenBy(tuple => tuple.Item2.Position)
            .Select(tuple => new CategoryDef
            {
                Name = tuple.Item2.Name,
                Slug = tuple.slug,
                Description = tuple.Item2.Description,
                IsSelectable = tuple.Item2.IsSelectable
            })
            .ToList();

        payload.Categories = normalizedCategories;

        var treeEdges = new List<CategoryEdgeDef>();
        foreach (var slug in slugsToInclude)
        {
            if (!CanonicalCategories.TryGetValue(slug, out var info)) continue;
            if (string.IsNullOrWhiteSpace(info.ParentSlug)) continue;
            if (!CanonicalCategories.ContainsKey(info.ParentSlug)) continue;

            treeEdges.Add(new CategoryEdgeDef
            {
                ParentSlug = info.ParentSlug,
                ChildSlug = slug,
                Position = info.Position
            });
        }

        var fitmentLookup = new HashSet<(string part, string engine)>(payload.Fitment.Select(f => (f.PartSku ?? string.Empty, f.EngineCode ?? string.Empty)), FitmentKeyComparerInstance);

        var newFitment = new List<FitmentDef>();
        foreach (var fit in payload.Fitment)
        {
            if (string.IsNullOrWhiteSpace(fit.PartSku) || string.IsNullOrWhiteSpace(fit.EngineCode)) continue;
            foreach (var code in ExpandEngineCodes(new[] { fit.EngineCode }))
            {
                var key = (fit.PartSku, code);
                if (fitmentLookup.Contains(key)) continue;
                newFitment.Add(new FitmentDef
                {
                    PartSku = fit.PartSku,
                    EngineCode = code,
                    YearsStart = fit.YearsStart,
                    YearsEnd = fit.YearsEnd,
                    Notes = fit.Notes
                });
                fitmentLookup.Add(key);
            }
        }
        if (newFitment.Count > 0)
            payload.Fitment.AddRange(newFitment);

        var aggregateEngines = new HashSet<string>(forcedEngineCodeSet, StringComparer.OrdinalIgnoreCase);
        foreach (var req in payload.Requirements)
        {
            if (req.EngineCodes is null) continue;
            foreach (var code in req.EngineCodes)
                if (!string.IsNullOrWhiteSpace(code))
                    aggregateEngines.Add(code);
        }
        foreach (var fit in payload.Fitment)
            if (!string.IsNullOrWhiteSpace(fit.EngineCode))
                aggregateEngines.Add(fit.EngineCode);

        payload.EngineCodes = new HashSet<string>(ExpandEngineCodes(aggregateEngines), StringComparer.OrdinalIgnoreCase).ToList();

        payload.Tree.Edges = treeEdges
            .GroupBy(e => (e.ParentSlug, e.ChildSlug))
            .Select(g => g.First())
            .OrderBy(e => CanonicalCategories[e.ParentSlug!].Position)
            .ThenBy(e => CanonicalCategories[e.ChildSlug].Position)
            .ToList();

        return payload;
    }

    private static string Slugify(string value)
    {
        var slug = value.Trim().ToLowerInvariant();
        slug = Regex.Replace(slug, "[^a-z0-9]+", "-");
        slug = slug.Trim('-');
        return string.IsNullOrEmpty(slug) ? "item" : slug;
    }

    private sealed record CanonicalCategory(string Name, bool IsSelectable, string? ParentSlug, int Position, string? Description);

    private static IEnumerable<string> ExpandEngineCodes(IEnumerable<string> codes)
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var code in codes)
        {
            if (string.IsNullOrWhiteSpace(code)) continue;
            if (EngineCodeExpansion.TryGetValue(code, out var expansions))
            {
                foreach (var expansion in expansions)
                    result.Add(expansion);
            }
            else
            {
                foreach (var kvp in EngineCodeExpansion)
                {
                    if (code.StartsWith(kvp.Key, StringComparison.OrdinalIgnoreCase))
                    {
                        foreach (var expansion in kvp.Value)
                            result.Add(expansion);
                    }
                }
            }
            result.Add(code);
        }
        return result;
    }

    private sealed class FitmentKeyComparer : IEqualityComparer<(string Part, string Engine)>
    {
        public bool Equals((string Part, string Engine) x, (string Part, string Engine) y) =>
            string.Equals(x.Part, y.Part, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(x.Engine, y.Engine, StringComparison.OrdinalIgnoreCase);

        public int GetHashCode((string Part, string Engine) obj) =>
            HashCode.Combine(obj.Part?.ToLowerInvariant(), obj.Engine?.ToLowerInvariant());
    }

    private static readonly IEqualityComparer<(string Part, string Engine)> FitmentKeyComparerInstance = new FitmentKeyComparer();

    public async Task<IngestionResult> IngestAsync(IngestionPayload payload, CancellationToken ct)
    {
        payload = PrepareForBuilder(payload, payload.EngineCodes);
        await using var conn = new MySqlConnection(_connString);
        await conn.OpenAsync(ct);
        await SchemaHelpers.EnsureCategoryRequirementColumnsAsync(conn, ct);
        await using var tx = await conn.BeginTransactionAsync(IsolationLevel.ReadCommitted, ct);
        try
        {
            var engineMap = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
            long? primaryEngineId = null;
            string? primaryEngineCode = payload.Engine?.Code;

            if (payload.Engine is not null)
            {
                primaryEngineId = await UpsertEngineAsync(conn, tx, payload.Engine);
                engineMap[payload.Engine.Code] = primaryEngineId.Value;
            }

            var engineCodesNeeded = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (!string.IsNullOrWhiteSpace(primaryEngineCode))
                engineCodesNeeded.Add(primaryEngineCode);

            foreach (var req in payload.Requirements)
            {
                if (req.EngineCodes is null) continue;
                foreach (var code in req.EngineCodes)
                    if (!string.IsNullOrWhiteSpace(code))
                        engineCodesNeeded.Add(code);
            }

            foreach (var fit in payload.Fitment)
            {
                if (!string.IsNullOrWhiteSpace(fit.EngineCode))
                    engineCodesNeeded.Add(fit.EngineCode);
            }

            engineCodesNeeded = new HashSet<string>(ExpandEngineCodes(engineCodesNeeded), StringComparer.OrdinalIgnoreCase);

            foreach (var code in engineCodesNeeded)
            {
                if (engineMap.ContainsKey(code)) continue;
                var id = await UpsertEngineByCodeAsync(conn, tx, code);
                engineMap[code] = id;
            }

            var brandIds = await UpsertBrandsAsync(conn, tx, payload.Brands);
            var categoryIds = await UpsertCategoriesAsync(conn, tx, payload.Categories);
            var treeId = await UpsertTreeAsync(conn, tx, payload.Tree ?? new CategoryTreeDef { Name = "Default" });
            await UpsertEdgesAsync(conn, tx, treeId, payload.Tree?.Edges ?? new List<CategoryEdgeDef>());
            await UpsertRequirementsAsync(conn, tx, engineMap, treeId, categoryIds, payload.Requirements, primaryEngineCode);
            var partIds = await UpsertPartsAsync(conn, tx, payload.Parts, brandIds);
            await UpsertComponentsAsync(conn, tx, partIds, payload.Components);
            await UpsertPartCategoriesAsync(conn, tx, partIds, categoryIds, payload.PartCategories);
            await UpsertFitmentAsync(conn, tx, partIds, payload.Fitment);
            var vendorIds = await UpsertVendorsAsync(conn, tx, payload.Vendors);
            await UpsertOfferingsAsync(conn, tx, partIds, vendorIds, payload.Offerings);
            await UpsertPlansAsync(conn, tx, payload.Plans);

            await tx.CommitAsync(ct);
            return new IngestionResult
            {
                EngineFamilyId = primaryEngineId ?? engineMap.Values.FirstOrDefault(),
                TreeId = treeId,
                BrandCount = brandIds.Count,
                CategoryCount = categoryIds.Count,
                PartCount = partIds.Count,
                VendorCount = vendorIds.Count,
            };
        }
        catch
        {
            await tx.RollbackAsync(ct);
            throw;
        }
    }

    private static async Task<long> UpsertEngineAsync(MySqlConnection conn, MySqlTransaction tx, EngineInfo engine)
    {
        const string sql = @"INSERT INTO EngineFamily(code, rotor_count, years_start, years_end, hp_min, hp_max, notes)
                             VALUES(@code,@rotors,@ys,@ye,@hpmin,@hpmax,@notes)
                             ON DUPLICATE KEY UPDATE rotor_count=VALUES(rotor_count), years_start=VALUES(years_start), years_end=VALUES(years_end), hp_min=VALUES(hp_min), hp_max=VALUES(hp_max), notes=VALUES(notes);
                             SELECT engine_family_id FROM EngineFamily WHERE code=@code;";
        await using var cmd = new MySqlCommand(sql, conn, tx);
        cmd.Parameters.AddWithValue("@code", engine.Code);
        cmd.Parameters.AddWithValue("@rotors", (object?)engine.RotorCount ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@ys", (object?)engine.YearsStart ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@ye", (object?)engine.YearsEnd ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@hpmin", (object?)engine.HpMin ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@hpmax", (object?)engine.HpMax ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@notes", (object?)engine.Notes ?? DBNull.Value);
        var idObj = await cmd.ExecuteScalarAsync();
        return Convert.ToInt64(idObj);
    }

    private static async Task<long> UpsertEngineByCodeAsync(MySqlConnection conn, MySqlTransaction tx, string code)
    {
        const string sql = @"INSERT INTO EngineFamily(code) VALUES(@code)
                             ON DUPLICATE KEY UPDATE code=VALUES(code);
                             SELECT engine_family_id FROM EngineFamily WHERE code=@code;";
        await using var cmd = new MySqlCommand(sql, conn, tx);
        cmd.Parameters.AddWithValue("@code", code);
        var idObj = await cmd.ExecuteScalarAsync();
        return Convert.ToInt64(idObj);
    }

    private static async Task<Dictionary<string, long>> UpsertBrandsAsync(MySqlConnection conn, MySqlTransaction tx, IEnumerable<BrandDef> brands)
    {
        var map = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        foreach (var b in brands)
        {
            const string sql = @"INSERT INTO Brand(name, website) VALUES(@n,@w)
                                 ON DUPLICATE KEY UPDATE website=VALUES(website);
                                 SELECT brand_id FROM Brand WHERE name=@n;";
            await using var cmd = new MySqlCommand(sql, conn, tx);
            cmd.Parameters.AddWithValue("@n", b.Name);
            cmd.Parameters.AddWithValue("@w", (object?)b.Website ?? DBNull.Value);
            var id = Convert.ToInt64(await cmd.ExecuteScalarAsync());
            map[b.Name] = id;
        }
        return map;
    }

    private static async Task<Dictionary<string, long>> UpsertCategoriesAsync(MySqlConnection conn, MySqlTransaction tx, IEnumerable<CategoryDef> categories)
    {
        var map = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        foreach (var c in categories)
        {
            const string sql = @"INSERT INTO Category(name, slug, description, is_selectable) VALUES(@n,@s,@d,COALESCE(@sel,TRUE))
                                 ON DUPLICATE KEY UPDATE name=VALUES(name), description=VALUES(description), is_selectable=VALUES(is_selectable);
                                 SELECT category_id FROM Category WHERE slug=@s;";
            await using var cmd = new MySqlCommand(sql, conn, tx);
            cmd.Parameters.AddWithValue("@n", c.Name);
            cmd.Parameters.AddWithValue("@s", c.Slug);
            cmd.Parameters.AddWithValue("@d", (object?)c.Description ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@sel", (object?)c.IsSelectable ?? DBNull.Value);
            var id = Convert.ToInt64(await cmd.ExecuteScalarAsync());
            map[c.Slug] = id;
        }
        return map;
    }

    private static async Task<long> UpsertTreeAsync(MySqlConnection conn, MySqlTransaction tx, CategoryTreeDef tree)
    {
        const string sql = @"INSERT INTO CategoryTree(name) VALUES(@n)
                             ON DUPLICATE KEY UPDATE name=name;
                             SELECT tree_id FROM CategoryTree WHERE name=@n;";
        await using var cmd = new MySqlCommand(sql, conn, tx);
        cmd.Parameters.AddWithValue("@n", tree.Name);
        var id = Convert.ToInt64(await cmd.ExecuteScalarAsync());
        return id;
    }

    private static async Task UpsertEdgesAsync(MySqlConnection conn, MySqlTransaction tx, long treeId, IEnumerable<CategoryEdgeDef> edges)
    {
        foreach (var e in edges)
        {
            const string sql = @"INSERT IGNORE INTO CategoryEdge(tree_id, parent_category_id, child_category_id, position)
                                 SELECT @t, p.category_id, c.category_id, @pos
                                 FROM Category p, Category c
                                 WHERE p.slug=@p AND c.slug=@c;";
            await using var cmd = new MySqlCommand(sql, conn, tx);
            cmd.Parameters.AddWithValue("@t", treeId);
            cmd.Parameters.AddWithValue("@p", e.ParentSlug);
            cmd.Parameters.AddWithValue("@c", e.ChildSlug);
            cmd.Parameters.AddWithValue("@pos", (object?)e.Position ?? 0);
            await cmd.ExecuteNonQueryAsync();
        }
    }

    private static async Task UpsertRequirementsAsync(MySqlConnection conn, MySqlTransaction tx, Dictionary<string, long> engineMap, long treeId, Dictionary<string, long> catMap, IEnumerable<CategoryRequirementDef> reqs, string? defaultEngineCode)
    {
        foreach (var r in reqs)
        {
            if (!catMap.TryGetValue(r.CategorySlug, out var cid)) continue;

            var requirementType = NormalizeRequirementType(r.RequirementType);
            var reqMode = NormalizeRequirementMode(r.ReqMode, requirementType, r.Multiplier.HasValue && !string.IsNullOrWhiteSpace(r.OperandField));
            var operandField = NormalizeOperandField(r.OperandField);
            var roundMode = NormalizeRoundMode(r.RoundMode);

            var targetCodes = (r.EngineCodes is not null && r.EngineCodes.Count > 0)
                ? r.EngineCodes
                : (defaultEngineCode is not null ? new List<string> { defaultEngineCode } : new List<string>());

            foreach (var code in targetCodes)
            {
                if (string.IsNullOrWhiteSpace(code)) continue;
                if (!engineMap.TryGetValue(code, out var engineId))
                {
                    engineId = await UpsertEngineByCodeAsync(conn, tx, code);
                    engineMap[code] = engineId;
                }

                const string sql = @"INSERT INTO CategoryRequirement(engine_family_id, category_id, tree_id, tree_scope, requirement_type, req_mode, required_qty, formula, multiplier, operand_field, round_mode, notes)
                                     VALUES(@e,@c,@t,@scope,@type,@mode,@qty,@f,@mult,@operand,@round,@notes)
                                     ON DUPLICATE KEY UPDATE
                                         tree_scope=VALUES(tree_scope),
                                         requirement_type=VALUES(requirement_type),
                                         req_mode=VALUES(req_mode),
                                         required_qty=VALUES(required_qty),
                                         formula=VALUES(formula),
                                         multiplier=VALUES(multiplier),
                                         operand_field=VALUES(operand_field),
                                         round_mode=VALUES(round_mode),
                                         notes=VALUES(notes)";
                await using var cmd = new MySqlCommand(sql, conn, tx);
                cmd.Parameters.AddWithValue("@e", engineId);
                cmd.Parameters.AddWithValue("@c", cid);
                cmd.Parameters.AddWithValue("@t", treeId);
                cmd.Parameters.AddWithValue("@scope", treeId);
                cmd.Parameters.AddWithValue("@type", requirementType);
                cmd.Parameters.AddWithValue("@mode", reqMode);
                cmd.Parameters.AddWithValue("@qty", (object?)r.RequiredQty ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@f", (object?)r.Formula ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@mult", (object?)r.Multiplier ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@operand", (object?)operandField ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@round", roundMode);
                cmd.Parameters.AddWithValue("@notes", (object?)r.Notes ?? DBNull.Value);
                await cmd.ExecuteNonQueryAsync();
            }
        }
    }

    private static async Task<Dictionary<string, long>> UpsertPartsAsync(MySqlConnection conn, MySqlTransaction tx, IEnumerable<PartDef> parts, Dictionary<string, long> brandMap)
    {
        var map = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in parts)
        {
            long? brandId = null;
            if (!string.IsNullOrWhiteSpace(p.BrandName) && brandMap.TryGetValue(p.BrandName!, out var bid)) brandId = bid;
            const string sql = @"INSERT INTO Part(sku, name, description, image_url, brand_id, is_kit, uom, pieces_per_unit, status, mpn, upc, gtin, core_charge)
                                 VALUES(@sku,@name,@desc,@img,@brand,@kit,@uom,@ppu,@status,@mpn,@upc,@gtin,@core)
                                 ON DUPLICATE KEY UPDATE name=VALUES(name), description=VALUES(description), image_url=VALUES(image_url), brand_id=VALUES(brand_id), is_kit=VALUES(is_kit), uom=VALUES(uom), pieces_per_unit=VALUES(pieces_per_unit), status=VALUES(status), mpn=VALUES(mpn), upc=VALUES(upc), gtin=VALUES(gtin), core_charge=VALUES(core_charge);
                                 SELECT part_id FROM Part WHERE sku<=>@sku AND name=@name;";
            await using var cmd = new MySqlCommand(sql, conn, tx);
            cmd.Parameters.AddWithValue("@sku", (object?)p.Sku ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@name", p.Name);
            cmd.Parameters.AddWithValue("@desc", (object?)p.Description ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@img", (object?)p.ImageUrl ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@brand", (object?)brandId ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@kit", (object?)(p.IsKit ?? false));
            cmd.Parameters.AddWithValue("@uom", (object?)(p.Uom ?? "piece"));
            cmd.Parameters.AddWithValue("@ppu", (object?)(p.PiecesPerUnit ?? 1m));
            cmd.Parameters.AddWithValue("@status", (object?)(p.Status ?? "active"));
            cmd.Parameters.AddWithValue("@mpn", (object?)p.Mpn ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@upc", (object?)p.Upc ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@gtin", (object?)p.Gtin ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@core", (object?)p.CoreCharge ?? DBNull.Value);
            var id = Convert.ToInt64(await cmd.ExecuteScalarAsync());
            if (!string.IsNullOrEmpty(p.Sku)) map[p.Sku] = id;
        }
        return map;
    }

    private static async Task UpsertComponentsAsync(MySqlConnection conn, MySqlTransaction tx, Dictionary<string, long> partMap, IEnumerable<PartComponentDef> components)
    {
        foreach (var c in components)
        {
            if (!partMap.TryGetValue(c.ParentSku, out var parent) || !partMap.TryGetValue(c.ChildSku, out var child)) continue;
            const string sql = @"INSERT INTO PartComponent(parent_part_id, child_part_id, qty_per_parent) VALUES(@pp,@cp,@q)
                                 ON DUPLICATE KEY UPDATE qty_per_parent=VALUES(qty_per_parent)";
            await using var cmd = new MySqlCommand(sql, conn, tx);
            cmd.Parameters.AddWithValue("@pp", parent);
            cmd.Parameters.AddWithValue("@cp", child);
            cmd.Parameters.AddWithValue("@q", c.QtyPerParent);
            await cmd.ExecuteNonQueryAsync();
        }
    }

    private static async Task UpsertPartCategoriesAsync(MySqlConnection conn, MySqlTransaction tx, Dictionary<string, long> partMap, Dictionary<string, long> catMap, IEnumerable<PartCategoryDef> pcs)
    {
        foreach (var pc in pcs)
        {
            if (!partMap.TryGetValue(pc.PartSku, out var pid) || !catMap.TryGetValue(pc.CategorySlug, out var cid)) continue;
            const string sql = @"INSERT INTO PartCategory(part_id, category_id, is_primary, coverage_weight, display_order)
                                 VALUES(@p,@c,COALESCE(@prim,TRUE),COALESCE(@w,1.0),COALESCE(@o,0))
                                 ON DUPLICATE KEY UPDATE is_primary=VALUES(is_primary), coverage_weight=VALUES(coverage_weight), display_order=VALUES(display_order)";
            await using var cmd = new MySqlCommand(sql, conn, tx);
            cmd.Parameters.AddWithValue("@p", pid);
            cmd.Parameters.AddWithValue("@c", cid);
            cmd.Parameters.AddWithValue("@prim", (object?)pc.IsPrimary ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@w", (object?)pc.CoverageWeight ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@o", (object?)pc.DisplayOrder ?? DBNull.Value);
            await cmd.ExecuteNonQueryAsync();
        }
    }

    private static async Task UpsertFitmentAsync(MySqlConnection conn, MySqlTransaction tx, Dictionary<string, long> partMap, IEnumerable<FitmentDef> fits)
    {
        foreach (var f in fits)
        {
            if (!partMap.TryGetValue(f.PartSku, out var pid)) continue;
            const string sql = @"INSERT IGNORE INTO PartFitment(part_id, engine_family_id, years_start, years_end, notes)
                                 SELECT @p, ef.engine_family_id, @ys, @ye, @n FROM EngineFamily ef WHERE ef.code=@code";
            await using var cmd = new MySqlCommand(sql, conn, tx);
            cmd.Parameters.AddWithValue("@p", pid);
            cmd.Parameters.AddWithValue("@code", f.EngineCode);
            cmd.Parameters.AddWithValue("@ys", (object?)f.YearsStart ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@ye", (object?)f.YearsEnd ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@n", (object?)f.Notes ?? DBNull.Value);
            await cmd.ExecuteNonQueryAsync();
        }
    }

    private static async Task<Dictionary<string, long>> UpsertVendorsAsync(MySqlConnection conn, MySqlTransaction tx, IEnumerable<VendorDef> vendors)
    {
        var map = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        foreach (var v in vendors)
        {
            const string sql = @"INSERT INTO Vendor(name, website) VALUES(@n,@w)
                                 ON DUPLICATE KEY UPDATE website=VALUES(website);
                                 SELECT vendor_id FROM Vendor WHERE name=@n;";
            await using var cmd = new MySqlCommand(sql, conn, tx);
            cmd.Parameters.AddWithValue("@n", v.Name);
            cmd.Parameters.AddWithValue("@w", (object?)v.Website ?? DBNull.Value);
            var id = Convert.ToInt64(await cmd.ExecuteScalarAsync());
            map[v.Name] = id;
        }
        return map;
    }

    private static async Task UpsertOfferingsAsync(MySqlConnection conn, MySqlTransaction tx, Dictionary<string, long> partMap, Dictionary<string, long> vendorMap, IEnumerable<OfferingDef> offs)
    {
        foreach (var o in offs)
        {
            if (!partMap.TryGetValue(o.PartSku, out var pid) || !vendorMap.TryGetValue(o.VendorName, out var vid)) continue;
            const string sql = @"INSERT INTO PartOffering(part_id, vendor_id, price, msrp, currency, availability, url, affiliate_url, affiliate_notes, effective_from, effective_to)
                                 VALUES(@p,@v,@price,@msrp,@cur,@avail,@url,@aff,@notes,@from,@to)";
            await using var cmd = new MySqlCommand(sql, conn, tx);
            cmd.Parameters.AddWithValue("@p", pid);
            cmd.Parameters.AddWithValue("@v", vid);
            cmd.Parameters.AddWithValue("@price", (object?)o.Price ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@msrp", (object?)o.Msrp ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@cur", NormalizeCurrency(o.Currency));
            cmd.Parameters.AddWithValue("@avail", NormalizeAvailability(o.Availability));
            cmd.Parameters.AddWithValue("@url", (object?)o.Url ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@aff", (object?)o.AffiliateUrl ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@notes", DBNull.Value);
            var from = o.EffectiveFrom?.UtcDateTime ?? DateTime.UtcNow;
            cmd.Parameters.AddWithValue("@from", from);
            cmd.Parameters.AddWithValue("@to", (object?)(o.EffectiveTo?.UtcDateTime) ?? DBNull.Value);
            await cmd.ExecuteNonQueryAsync();
        }
    }

    private static string NormalizeRequirementType(string? value)
    {
        var normalized = value?.Trim().ToLowerInvariant();
        return normalized switch
        {
            "min_count" => "min_count",
            "formula" => "formula",
            "exact_count" => "exact_count",
            _ => "exact_count"
        };
    }

    private static string NormalizeRequirementMode(string? mode, string requirementType, bool hasStructuredHints)
    {
        var normalized = mode?.Trim().ToLowerInvariant();
        return normalized switch
        {
            "exact_count" => "exact_count",
            "min_count" => "min_count",
            "formula" => "formula",
            "structured" => "structured",
            _ when hasStructuredHints => "structured",
            _ => requirementType switch
            {
                "min_count" => "min_count",
                "formula" => "formula",
                _ => "exact_count"
            }
        };
    }

    private static string? NormalizeOperandField(string? operand)
    {
        if (string.IsNullOrWhiteSpace(operand)) return null;
        var normalized = operand.Trim().ToLowerInvariant();
        return normalized switch
        {
            "rotor_count" => "rotor_count",
            "hp_min" => "hp_min",
            "hp_max" => "hp_max",
            "primary_injector_cc" => "primary_injector_cc",
            "secondary_injector_cc" => "secondary_injector_cc",
            "fuel_pressure_base" => "fuel_pressure_base",
            "intake_port_area_mm2" => "intake_port_area_mm2",
            "exhaust_port_area_mm2" => "exhaust_port_area_mm2",
            _ => null
        };
    }

    private static string NormalizeRoundMode(string? roundMode)
    {
        var normalized = roundMode?.Trim().ToLowerInvariant();
        return normalized switch
        {
            "ceil" => "ceil",
            "floor" => "floor",
            "round" => "round",
            "none" => "none",
            _ => "none"
        };
    }

    private static object NormalizeCurrency(string? currency)
    {
        if (string.IsNullOrWhiteSpace(currency)) return "USD";
        var c = currency.Trim().ToUpperInvariant();
        return c.Length == 3 ? c : "USD";
    }

    private static object NormalizeAvailability(string? availability)
    {
        if (string.IsNullOrWhiteSpace(availability)) return "in_stock";
        var a = availability.Trim().ToLowerInvariant();
        // Common variants mapping to permitted ENUM values: in_stock, backorder, discontinued, unknown
        if (a == "in_stock" || a == "instock" || a == "available" || a == "in stock") return "in_stock";
        if (a == "backorder" || a == "back order" || a == "preorder" || a == "pre-order" || a.Contains("preorder") || a.Contains("backorder")) return "backorder";
        if (a == "discontinued" || a == "obsolete") return "discontinued";
        if (a == "out_of_stock" || a == "out of stock" || a == "oos" || a == "unavailable" || a == "not available") return "unknown";
        // Fallback to 'unknown' for anything else to satisfy ENUM constraint
        return "unknown";
    }

    private static async Task UpsertPlansAsync(MySqlConnection conn, MySqlTransaction tx, IEnumerable<PlanDef> plans)
    {
        foreach (var p in plans)
        {
            const string sql = @"INSERT INTO Plan(code, name, monthly_price, currency) VALUES(@c,@n,@m,@cur)
                                 ON DUPLICATE KEY UPDATE name=VALUES(name), monthly_price=VALUES(monthly_price), currency=VALUES(currency)";
            await using var cmd = new MySqlCommand(sql, conn, tx);
            cmd.Parameters.AddWithValue("@c", p.Code);
            cmd.Parameters.AddWithValue("@n", p.Name);
            cmd.Parameters.AddWithValue("@m", p.MonthlyPrice);
            cmd.Parameters.AddWithValue("@cur", p.Currency);
            await cmd.ExecuteNonQueryAsync();
        }
    }
}

public class IngestionResult
{
    public long EngineFamilyId { get; set; }
    public long TreeId { get; set; }
    public int BrandCount { get; set; }
    public int CategoryCount { get; set; }
    public int PartCount { get; set; }
    public int VendorCount { get; set; }
}
