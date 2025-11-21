using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Linq;
using System.Net.Mail;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Mvc;
using MySqlConnector;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Hosting;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.StaticFiles;
using RotorBase;
using RotorBase.Components;
using RotorBase.Extensions;
using RotorBase.Security;
using RotorBase.Services;
using Dapper;
using Stripe;
using CheckoutSession = Stripe.Checkout.Session;
using CheckoutSessionCreateOptions = Stripe.Checkout.SessionCreateOptions;
using CheckoutSessionService = Stripe.Checkout.SessionService;
using BillingPortalSessionCreateOptions = Stripe.BillingPortal.SessionCreateOptions;
using BillingPortalSessionService = Stripe.BillingPortal.SessionService;
using CheckoutSessionLineItemOptions = Stripe.Checkout.SessionLineItemOptions;
using CheckoutSubscriptionDataOptions = Stripe.Checkout.SessionSubscriptionDataOptions;

const string PremiumPlanCode = "PREMIUM";
const string FreePlanCode = "FREE";

static bool EnsureAdmin(HttpContext? ctx) => ctx?.User.IsAdmin() ?? false;

static bool CoerceToBool(object? value)
{
    return value switch
    {
        bool b => b,
        sbyte sb => sb != 0,
        byte by => by != 0,
        short s => s != 0,
        ushort us => us != 0,
        int i => i != 0,
        uint ui => ui != 0,
        long l => l != 0,
        ulong ul => ul != 0,
        decimal dec => dec != 0m,
        double d => Math.Abs(d) > double.Epsilon,
        float f => Math.Abs(f) > float.Epsilon,
        string str when bool.TryParse(str, out var parsed) => parsed,
        string str when int.TryParse(str, out var parsedInt) => parsedInt != 0,
        _ => false
    };
}

var builder = WebApplication.CreateBuilder(args);

// Support optional appsettings.{Environment}.local.json for developer-specific secrets
builder.Configuration.AddJsonFile(
    $"appsettings.{builder.Environment.EnvironmentName}.local.json",
    optional: true,
    reloadOnChange: true);

// Basic console logging so API exceptions surface during development
builder.Logging.ClearProviders();
builder.Logging.AddConsole();

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// HTTP client for components to call our own APIs
builder.Services.AddHttpContextAccessor();
builder.Services.AddHttpClient("self", (sp, client) =>
{
    var accessor = sp.GetRequiredService<IHttpContextAccessor>();
    var req = accessor.HttpContext?.Request;
    if (req is not null)
    {
        client.BaseAddress = new Uri($"{req.Scheme}://{req.Host}");
    }
});
builder.Services.AddHttpClient("mailgun");
builder.Services.AddScoped(sp => sp.GetRequiredService<IHttpClientFactory>().CreateClient("self"));
builder.Services.AddScoped<ProtectedLocalStorage>();
builder.Services.AddScoped<UserSession>();
builder.Services.AddScoped<CompareTrayService>();
builder.Services.AddScoped<ThemeService>();
builder.Services.AddScoped<ToastService>();
builder.Services.Configure<MailOptions>(builder.Configuration.GetSection("Mail"));
builder.Services.AddSingleton<IEmailSender>(EmailSenderFactory.Create);

builder.Services.AddScoped<Func<MySqlConnection>>(_ => () =>
{
    var cs =
        builder.Configuration.GetConnectionString("DefaultConnection")
        ?? builder.Configuration.GetConnectionString("Default")
        ?? builder.Configuration["ConnectionStrings:DefaultConnection"]
        ?? builder.Configuration["ConnectionStrings:Default"];

    if (string.IsNullOrWhiteSpace(cs))
    {
        throw new InvalidOperationException("Missing database connection string (DefaultConnection).");
    }

    if (!cs.Contains("Allow User Variables", StringComparison.OrdinalIgnoreCase))
    {
        cs = cs.TrimEnd(';') + ";Allow User Variables=true;";
    }

    return new MySqlConnection(cs);
});

builder.Services.AddScoped<IGamification, Gamification>();

var stripeApiKey = builder.Configuration["Stripe:ApiKey"];
if (!string.IsNullOrWhiteSpace(stripeApiKey))
{
    StripeConfiguration.ApiKey = stripeApiKey;
}

var jwtSecret = builder.Configuration["JWT:Key"];
if (string.IsNullOrWhiteSpace(jwtSecret) || jwtSecret.Length < 32)
{
    throw new InvalidOperationException("JWT:Key configuration missing or too short (min 32 characters).");
}
var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret));
var signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = signingKey,
            ClockSkew = TimeSpan.FromMinutes(2)
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("IsSignedIn", policy => policy.RequireAuthenticatedUser());
    options.AddPolicy("BuildOwnerOrEditor", policy => policy.Requirements.Add(BuildAccessRequirement.Instance));
});

builder.Services.AddSingleton<IAuthorizationHandler, BuildAccessHandler>();

string GenerateJwt(long userId, string email, string? displayName = null, bool isAdmin = false, bool emailVerified = false, bool isBanned = false)
{
    var claims = new List<Claim>
    {
        new(ClaimTypes.NameIdentifier, userId.ToString()),
        new(ClaimTypes.Email, email),
        new("is_admin", isAdmin ? "true" : "false"),
        new("email_verified", emailVerified ? "true" : "false"),
        new("is_banned", isBanned ? "true" : "false")
    };

    if (!string.IsNullOrWhiteSpace(displayName))
    {
        claims.Add(new Claim(ClaimTypes.Name, displayName!));
    }

    if (isAdmin)
    {
        claims.Add(new Claim(ClaimTypes.Role, "admin"));
    }

    var token = new JwtSecurityToken(
        claims: claims,
        expires: DateTime.UtcNow.AddDays(30),
        signingCredentials: signingCredentials);

    return new JwtSecurityTokenHandler().WriteToken(token);
}

static Dictionary<string, string> CreateEnumMap(params string[] values) => values.ToDictionary(v => v, v => v, StringComparer.OrdinalIgnoreCase);

static Dictionary<string, object?> DefaultBuildSummary(long buildId)
    => new(StringComparer.OrdinalIgnoreCase)
    {
        ["build_id"] = buildId,
        ["categories_total"] = 0,
        ["categories_complete"] = 0,
        ["categories_incomplete"] = 0,
        ["completion_pct"] = 0m,
        ["total_pieces_missing"] = 0,
        ["estimated_cost_lowest"] = null
    };

static void ApplyNoStoreCacheHeaders(HttpContext ctx)
{
    ctx.Response.Headers.CacheControl = "no-store, no-cache, must-revalidate, max-age=0";
    ctx.Response.Headers.Pragma = "no-cache";
    ctx.Response.Headers.Expires = "0";
}

static async Task<RuleHintResult> EvaluateRuleHintsAsync(MySqlConnection db, long buildId, CancellationToken ct)
{
    static List<string> Normalize(IEnumerable<string> values) => values
        .Where(s => !string.IsNullOrWhiteSpace(s))
        .Select(s => s.Trim())
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToList();

    const string requiresSql = @"
        SELECT DISTINCT CONCAT('Socket_', st.key) AS socket_name
          FROM SlotEdge e
          JOIN Slot sf ON sf.slot_id = e.from_slot_id
          JOIN Slot st ON st.slot_id = e.to_slot_id
          JOIN BuildSlotSelection bsf ON bsf.slot_id = sf.slot_id AND bsf.build_id = @buildId
          LEFT JOIN BuildSlotSelection bst ON bst.slot_id = st.slot_id AND bst.build_id = @buildId
         WHERE e.edge = 'REQUIRES'
           AND bst.build_slot_selection_id IS NULL";

    const string matchAttrSql = @"
        SELECT DISTINCT CONCAT('Socket_', sf.key) AS socket_name
          FROM SlotEdge e
          JOIN Slot sf ON sf.slot_id = e.from_slot_id
          JOIN Slot st ON st.slot_id = e.to_slot_id
          JOIN BuildSlotSelection bsf ON bsf.slot_id = sf.slot_id AND bsf.build_id = @buildId
          JOIN BuildSlotSelection bst ON bst.slot_id = st.slot_id AND bst.build_id = @buildId
          JOIN Attribute a ON a.`key` = JSON_UNQUOTE(JSON_EXTRACT(e.rule, '$.attribute_key'))
          LEFT JOIN PartAttribute paf ON paf.part_id = bsf.part_id AND paf.attribute_id = a.attribute_id
          LEFT JOIN PartAttribute pat ON pat.part_id = bst.part_id AND pat.attribute_id = a.attribute_id
         WHERE e.edge = 'MATCH_ATTR'
           AND JSON_EXTRACT(e.rule, '$.attribute_key') IS NOT NULL
           AND (
                (a.type = 'TEXT'   AND (paf.value_text IS NULL OR pat.value_text IS NULL OR paf.value_text <> pat.value_text))
             OR (a.type = 'NUMBER' AND (paf.value_num IS NULL OR pat.value_num IS NULL OR paf.value_num <> pat.value_num))
             OR (a.type = 'BOOL'   AND (paf.value_bool IS NULL OR pat.value_bool IS NULL OR paf.value_bool <> pat.value_bool))
           )
        UNION
        SELECT DISTINCT CONCAT('Socket_', st.key) AS socket_name
          FROM SlotEdge e
          JOIN Slot sf ON sf.slot_id = e.from_slot_id
          JOIN Slot st ON st.slot_id = e.to_slot_id
          JOIN BuildSlotSelection bsf ON bsf.slot_id = sf.slot_id AND bsf.build_id = @buildId
          JOIN BuildSlotSelection bst ON bst.slot_id = st.slot_id AND bst.build_id = @buildId
          JOIN Attribute a ON a.`key` = JSON_UNQUOTE(JSON_EXTRACT(e.rule, '$.attribute_key'))
          LEFT JOIN PartAttribute paf ON paf.part_id = bsf.part_id AND paf.attribute_id = a.attribute_id
          LEFT JOIN PartAttribute pat ON pat.part_id = bst.part_id AND pat.attribute_id = a.attribute_id
         WHERE e.edge = 'MATCH_ATTR'
           AND JSON_EXTRACT(e.rule, '$.attribute_key') IS NOT NULL
           AND (
                (a.type = 'TEXT'   AND (paf.value_text IS NULL OR pat.value_text IS NULL OR paf.value_text <> pat.value_text))
             OR (a.type = 'NUMBER' AND (paf.value_num IS NULL OR pat.value_num IS NULL OR paf.value_num <> pat.value_num))
             OR (a.type = 'BOOL'   AND (paf.value_bool IS NULL OR pat.value_bool IS NULL OR paf.value_bool <> pat.value_bool))
           )";

    const string excludesSql = @"
        SELECT DISTINCT CONCAT('Socket_', sf.key) AS socket_name
          FROM SlotEdge e
          JOIN Slot sf ON sf.slot_id = e.from_slot_id
          JOIN Slot st ON st.slot_id = e.to_slot_id
          JOIN BuildSlotSelection bsf ON bsf.slot_id = sf.slot_id AND bsf.build_id = @buildId
          JOIN BuildSlotSelection bst ON bst.slot_id = st.slot_id AND bst.build_id = @buildId
         WHERE e.edge = 'EXCLUDES'
        UNION
        SELECT DISTINCT CONCAT('Socket_', st.key) AS socket_name
          FROM SlotEdge e
          JOIN Slot sf ON sf.slot_id = e.from_slot_id
          JOIN Slot st ON st.slot_id = e.to_slot_id
          JOIN BuildSlotSelection bsf ON bsf.slot_id = sf.slot_id AND bsf.build_id = @buildId
          JOIN BuildSlotSelection bst ON bst.slot_id = st.slot_id AND bst.build_id = @buildId
         WHERE e.edge = 'EXCLUDES'";

    var requires = Normalize(await db.QueryAsync<string>(new CommandDefinition(
        requiresSql,
        new { buildId },
        cancellationToken: ct)));

    var matchAttr = Normalize(await db.QueryAsync<string>(new CommandDefinition(
        matchAttrSql,
        new { buildId },
        cancellationToken: ct)));

    var excludes = Normalize(await db.QueryAsync<string>(new CommandDefinition(
        excludesSql,
        new { buildId },
        cancellationToken: ct)));

    return new RuleHintResult(requires, matchAttr, excludes);
}


async Task<List<Dictionary<string, object?>>> ReadBuildCompletionAsync(MySqlConnection conn, long buildId, CancellationToken ct)
{
    var rows = new List<Dictionary<string, object?>>(64);
    await using var cmd = new MySqlCommand(@"SELECT build_id, engine_family_id, tree_id_or_global, category_id, category_name, req_mode, requirement_type, formula, required_qty, pieces_supplied, pieces_missing, status
                                            FROM v_build_category_completion WHERE build_id = @id ORDER BY category_name", conn);
    cmd.Parameters.AddWithValue("@id", buildId);
    await using var reader = await cmd.ExecuteReaderAsync(ct);
    while (await reader.ReadAsync(ct))
    {
        var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < reader.FieldCount; i++)
        {
            row[reader.GetName(i)] = reader.IsDBNull(i) ? null : reader.GetValue(i);
        }
        rows.Add(row);
    }

    return rows;
}

async Task<Dictionary<string, object?>> ReadBuildSummaryAsync(MySqlConnection conn, long buildId, ILogger logger, CancellationToken ct)
{
    try
    {
        await EnsureBuildSummaryViewsAsync(conn, ct);
    }
    catch (Exception ensureEx)
    {
        logger.LogError(ensureEx, "EnsureBuildSummaryViewsAsync failed for build {BuildId}", buildId);
        return DefaultBuildSummary(buildId);
    }

    try
    {
        await using var cmd = new MySqlCommand(@"SELECT build_id, categories_total, categories_complete, categories_incomplete, completion_pct, total_pieces_missing, estimated_cost_lowest FROM v_build_summary WHERE build_id=@b", conn);
        cmd.Parameters.AddWithValue("@b", buildId);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct))
        {
            return DefaultBuildSummary(buildId);
        }

        var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < reader.FieldCount; i++)
        {
            row[reader.GetName(i)] = reader.IsDBNull(i) ? null : reader.GetValue(i);
        }
        return row;
    }
    catch (Exception queryEx)
    {
        logger.LogError(queryEx, "Failed to read build summary for build {BuildId}", buildId);
        return DefaultBuildSummary(buildId);
    }
}

async Task<List<Dictionary<string, object?>>> ReadBuildSelectionsAsync(MySqlConnection conn, long buildId, CancellationToken ct)
{
    const string sql = @"SELECT bs.build_id, bs.category_id, c.name AS category_name, bs.part_id, p.name AS part_name, p.sku, bs.qty
                          FROM BuildSelection bs JOIN Part p ON p.part_id=bs.part_id JOIN Category c ON c.category_id=bs.category_id
                          WHERE bs.build_id=@id ORDER BY c.name, p.name";
    await using var cmd = new MySqlCommand(sql, conn);
    cmd.Parameters.AddWithValue("@id", buildId);
    var list = new List<Dictionary<string, object?>>(32);
    await using var reader = await cmd.ExecuteReaderAsync(ct);
    while (await reader.ReadAsync(ct))
    {
        var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < reader.FieldCount; i++)
        {
            row[reader.GetName(i)] = reader.IsDBNull(i) ? null : reader.GetValue(i);
        }
        list.Add(row);
    }

    return list;
}

Dictionary<string, object?> BuildCostPayloadFromSummary(Dictionary<string, object?> summary, long buildId)
{
    summary ??= DefaultBuildSummary(buildId);
    summary.TryGetValue("estimated_cost_lowest", out var value);
    return new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
    {
        ["build_id"] = buildId,
        ["estimated_cost_lowest"] = value
    };
}

Dictionary<string, object?> ComposeSummaryFromCompletion(List<Dictionary<string, object?>> completionRows, Dictionary<string, object?>? baseSummary, long buildId)
{
    var summary = baseSummary is null
        ? DefaultBuildSummary(buildId)
        : new Dictionary<string, object?>(baseSummary, StringComparer.OrdinalIgnoreCase);

    var total = completionRows.Count;
    var complete = 0;
    var incomplete = 0;
    decimal missing = 0m;

    foreach (var row in completionRows)
    {
        if (row.TryGetValue("status", out var statusObj) && statusObj is not null && statusObj is not DBNull)
        {
            var status = statusObj.ToString();
            if (string.Equals(status, "complete", StringComparison.OrdinalIgnoreCase))
            {
                complete++;
            }
            else if (string.Equals(status, "incomplete", StringComparison.OrdinalIgnoreCase))
            {
                incomplete++;
            }
        }

        if (row.TryGetValue("pieces_missing", out var piecesMissingObj) && piecesMissingObj is not null && piecesMissingObj is not DBNull)
        {
            try
            {
                missing += Convert.ToDecimal(piecesMissingObj, CultureInfo.InvariantCulture);
            }
            catch
            {
                if (decimal.TryParse(piecesMissingObj.ToString(), NumberStyles.Any, CultureInfo.InvariantCulture, out var parsed))
                {
                    missing += parsed;
                }
            }
        }
    }

    summary["categories_total"] = total;
    summary["categories_complete"] = complete;
    summary["categories_incomplete"] = incomplete;
    summary["total_pieces_missing"] = missing;
    summary["completion_pct"] = total == 0
        ? 0m
        : Math.Round((decimal)complete / total * 100m, 2, MidpointRounding.AwayFromZero);

    return summary;
}

async Task TrackGamificationAsync(
    IGamification gamification,
    MySqlConnection conn,
    long userId,
    long buildId,
    bool wasFirstSelection,
    IReadOnlyDictionary<long, string>? categoriesBefore,
    IReadOnlyDictionary<long, string>? categoriesAfter,
    SummarySnapshot summaryBefore,
    SummarySnapshot summaryAfter,
    CancellationToken ct)
{
    var now = DateTime.UtcNow;
    var tick = false;

    if (wasFirstSelection)
    {
        var awarded = await gamification.AwardAsync(userId, 25, "first_selection", buildId, $"first_selection:{buildId}");
        if (awarded)
        {
            await gamification.GrantBadgeAsync(userId, "FIRST_SELECTION", buildId);
        }
        tick = true;
    }

    if (categoriesAfter is not null)
    {
        static bool IsComplete(string? status)
            => !string.IsNullOrWhiteSpace(status) && string.Equals(status, "complete", StringComparison.OrdinalIgnoreCase);

        var newlyCompleted = categoriesAfter
            .Where(kvp => IsComplete(kvp.Value)
                && !(categoriesBefore?.TryGetValue(kvp.Key, out var prev) == true && IsComplete(prev)))
            .Select(kvp => kvp.Key)
            .ToList();

        if (newlyCompleted.Count > 0)
        {
            var hadCategoryAwards = await conn.ExecuteScalarAsync<long>(new CommandDefinition(
                "SELECT COUNT(*) FROM UserPointsLedger WHERE user_id=@user AND reason='category_completed'",
                new { user = userId },
                cancellationToken: ct)) > 0;

            var categoryAwarded = false;
            foreach (var categoryId in newlyCompleted)
            {
                var inserted = await gamification.AwardAsync(userId, 30, "category_completed", buildId, $"cat_complete:{buildId}:{categoryId}");
                if (inserted)
                {
                    categoryAwarded = true;
                    if (!hadCategoryAwards)
                    {
                        await gamification.GrantBadgeAsync(userId, "FIRST_CATEGORY", buildId);
                        hadCategoryAwards = true;
                    }
                }
            }

            if (categoryAwarded)
            {
                tick = true;
            }
        }
    }

    var readyBefore = summaryBefore.Total > 0 && summaryBefore.Incomplete == 0;
    var readyAfter = summaryAfter.Total > 0 && summaryAfter.Incomplete == 0;

    if (!readyBefore && readyAfter)
    {
        var inserted = await gamification.AwardAsync(userId, 150, "build_complete", buildId, $"build_complete:{buildId}");
        if (inserted)
        {
            await gamification.GrantBadgeAsync(userId, "FIRST_START", buildId);
            tick = true;
        }
    }

    if (tick)
    {
        await gamification.TickStreakAsync(userId, now);
    }
}

async Task<Dictionary<long, string>> LoadCategoryStatusesAsync(MySqlConnection conn, long buildId, CancellationToken ct)
{
    var rows = await conn.QueryAsync<(long CategoryId, string? Status)>(new CommandDefinition(
        "SELECT category_id AS CategoryId, status AS Status FROM v_build_category_completion WHERE build_id=@build",
        new { build = buildId },
        cancellationToken: ct));

    var dict = new Dictionary<long, string>();
    foreach (var row in rows)
    {
        dict[row.CategoryId] = row.Status ?? string.Empty;
    }

    return dict;
}

async Task<SummarySnapshot> LoadSummarySnapshotAsync(MySqlConnection conn, long buildId, CancellationToken ct)
{
    var row = await conn.QuerySingleOrDefaultAsync<(int Total, int Incomplete)>(new CommandDefinition(
        "SELECT categories_total AS Total, categories_incomplete AS Incomplete FROM v_build_summary WHERE build_id=@build",
        new { build = buildId },
        cancellationToken: ct));

    return new SummarySnapshot(row.Total, row.Incomplete);
}

Dictionary<long, string> BuildCategoryStatusMap(IEnumerable<Dictionary<string, object?>> rows)
{
    var dict = new Dictionary<long, string>();
    foreach (var row in rows)
    {
        if (!row.TryGetValue("category_id", out var idObj) || idObj is null)
            continue;

        if (!long.TryParse(Convert.ToString(idObj, CultureInfo.InvariantCulture), out var categoryId))
            continue;

        var status = row.TryGetValue("status", out var statusObj) ? statusObj?.ToString() ?? string.Empty : string.Empty;
        dict[categoryId] = status;
    }

    return dict;
}

SummarySnapshot ExtractSummarySnapshot(Dictionary<string, object?>? summary)
{
    if (summary is null)
        return new SummarySnapshot(0, 0);

    int GetInt(string key)
    {
        if (!summary.TryGetValue(key, out var value) || value is null)
            return 0;

        return value switch
        {
            int i => i,
            long l => unchecked((int)l),
            decimal dec => (int)dec,
            double dbl => (int)dbl,
            string str when int.TryParse(str, NumberStyles.Any, CultureInfo.InvariantCulture, out var parsed) => parsed,
            _ => int.TryParse(Convert.ToString(value, CultureInfo.InvariantCulture), out var parsed2) ? parsed2 : 0
        };
    }

    return new SummarySnapshot(GetInt("categories_total"), GetInt("categories_incomplete"));
}

async Task<string?> GetBuildRoleAsync(MySqlConnection conn, long buildId, long userId, CancellationToken ct)
{
    await using (var ownerCmd = new MySqlCommand("SELECT 1 FROM Build WHERE build_id=@b AND user_id=@u LIMIT 1", conn))
    {
        ownerCmd.Parameters.AddWithValue("@b", buildId);
        ownerCmd.Parameters.AddWithValue("@u", userId);
        if (await ownerCmd.ExecuteScalarAsync(ct) is not null)
            return "owner";
    }

    await EnsureShareTablesAsync(conn, ct);
    await using (var shareCmd = new MySqlCommand("SELECT role FROM BuildShare WHERE build_id=@b AND user_id=@u LIMIT 1", conn))
    {
        shareCmd.Parameters.AddWithValue("@b", buildId);
        shareCmd.Parameters.AddWithValue("@u", userId);
        var roleObj = await shareCmd.ExecuteScalarAsync(ct);
        return roleObj?.ToString();
    }
}

async Task EnsureUserAccountTableAsync(MySqlConnection conn, CancellationToken ct)
{
    const string sql = @"CREATE TABLE IF NOT EXISTS UserAccount (
        user_id        BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
        email          VARCHAR(320) NOT NULL,
        display_name   VARCHAR(200) NULL,
        password_hash  VARCHAR(200) NOT NULL,
        is_admin       BOOLEAN NOT NULL DEFAULT FALSE,
        is_banned      BOOLEAN NOT NULL DEFAULT FALSE,
        created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY uq_user_email (email)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";

    await using var cmd = new MySqlCommand(sql, conn);
    await cmd.ExecuteNonQueryAsync(ct);

    const string checkOptInSql = "SHOW COLUMNS FROM UserAccount LIKE 'email_opt_in'";
    await using (var checkOptIn = new MySqlCommand(checkOptInSql, conn))
    {
        var exists = await checkOptIn.ExecuteScalarAsync(ct) is not null;
        if (!exists)
        {
            await using var alter = new MySqlCommand("ALTER TABLE UserAccount ADD COLUMN email_opt_in TINYINT(1) NOT NULL DEFAULT 0 AFTER is_admin", conn);
            await alter.ExecuteNonQueryAsync(ct);
        }
    }

    await EnsureUserColumnAsync(conn, ct, "is_banned", "ALTER TABLE UserAccount ADD COLUMN is_banned TINYINT(1) NOT NULL DEFAULT 0 AFTER is_admin");
    await EnsureUserColumnAsync(conn, ct, "email_verified_at", "ALTER TABLE UserAccount ADD COLUMN email_verified_at DATETIME NULL AFTER email_opt_in");
    await EnsureUserColumnAsync(conn, ct, "email_verification_token", "ALTER TABLE UserAccount ADD COLUMN email_verification_token CHAR(64) NULL AFTER email_verified_at");
    await EnsureUserColumnAsync(conn, ct, "email_verification_expires", "ALTER TABLE UserAccount ADD COLUMN email_verification_expires DATETIME NULL AFTER email_verification_token");
    await EnsureUserColumnAsync(conn, ct, "email_bounced", "ALTER TABLE UserAccount ADD COLUMN email_bounced TINYINT(1) NOT NULL DEFAULT 0 AFTER email_verification_expires");
    await EnsureUserColumnAsync(conn, ct, "email_unsubscribed", "ALTER TABLE UserAccount ADD COLUMN email_unsubscribed TINYINT(1) NOT NULL DEFAULT 0 AFTER email_bounced");

    const string indexSql = "CREATE INDEX IF NOT EXISTS ix_user_email_verification_token ON UserAccount(email_verification_token)";
    await using (var indexCmd = new MySqlCommand(indexSql, conn))
    {
        await indexCmd.ExecuteNonQueryAsync(ct);
    }

    static async Task EnsureUserColumnAsync(MySqlConnection connection, CancellationToken token, string columnName, string alterSql)
    {
        var checkSql = $"SHOW COLUMNS FROM UserAccount LIKE '{columnName}'";
        await using var check = new MySqlCommand(checkSql, connection);
        if (await check.ExecuteScalarAsync(token) is not null)
        {
            return;
        }

        await using var alter = new MySqlCommand(alterSql, connection);
        await alter.ExecuteNonQueryAsync(token);
    }
}

async Task EnsureBuildColumnsAsync(MySqlConnection conn, CancellationToken ct)
{
    const string checkSql = "SHOW COLUMNS FROM Build LIKE 'is_archived'";
    await using (var checkCmd = new MySqlCommand(checkSql, conn))
    {
        var archivedExists = await checkCmd.ExecuteScalarAsync(ct) is not null;
        if (!archivedExists)
        {
            await using var alterArchived = new MySqlCommand("ALTER TABLE Build ADD COLUMN is_archived TINYINT(1) NOT NULL DEFAULT FALSE AFTER name", conn);
            await alterArchived.ExecuteNonQueryAsync(ct);
        }
    }

    await using (var checkCmd = new MySqlCommand("SHOW COLUMNS FROM Build LIKE 'is_shared'", conn))
    {
        var sharedExists = await checkCmd.ExecuteScalarAsync(ct) is not null;
        if (!sharedExists)
        {
            await using var alterShared = new MySqlCommand("ALTER TABLE Build ADD COLUMN is_shared TINYINT(1) NOT NULL DEFAULT FALSE AFTER is_archived", conn);
            await alterShared.ExecuteNonQueryAsync(ct);
        }
    }

    await using (var checkCmd = new MySqlCommand("SHOW COLUMNS FROM Build LIKE 'is_public'", conn))
    {
        var publicExists = await checkCmd.ExecuteScalarAsync(ct) is not null;
        if (!publicExists)
        {
            await using var alterPublic = new MySqlCommand("ALTER TABLE Build ADD COLUMN is_public TINYINT(1) NOT NULL DEFAULT FALSE AFTER is_shared", conn);
            await alterPublic.ExecuteNonQueryAsync(ct);
        }
    }

    await using (var checkCmd = new MySqlCommand("SHOW COLUMNS FROM Build LIKE 'public_slug'", conn))
    {
        var slugExists = await checkCmd.ExecuteScalarAsync(ct) is not null;
        if (!slugExists)
        {
            await using var alterSlug = new MySqlCommand("ALTER TABLE Build ADD COLUMN public_slug VARCHAR(40) NULL AFTER is_public", conn);
            await alterSlug.ExecuteNonQueryAsync(ct);
        }
    }

    await using (var indexCheck = new MySqlCommand("SHOW INDEX FROM Build WHERE Key_name='uq_build_public_slug'", conn))
    {
        var hasIndex = await indexCheck.ExecuteScalarAsync(ct) is not null;
        if (!hasIndex)
        {
            try
            {
                await using var addIndex = new MySqlCommand("ALTER TABLE Build ADD UNIQUE KEY uq_build_public_slug (public_slug)", conn);
                await addIndex.ExecuteNonQueryAsync(ct);
            }
            catch (MySqlException ex) when (ex.Number == 1061)
            {
                // Index already exists; safe to ignore.
            }
        }
    }
}

async Task EnsurePartColumnsAsync(MySqlConnection conn, CancellationToken ct)
{
    await using (var check = new MySqlCommand("SHOW COLUMNS FROM Part LIKE 'image_url'", conn))
    {
        var exists = await check.ExecuteScalarAsync(ct) is not null;
        if (!exists)
        {
            await using var alter = new MySqlCommand("ALTER TABLE Part ADD COLUMN image_url VARCHAR(600) NULL AFTER description", conn);
            await alter.ExecuteNonQueryAsync(ct);
        }
    }
}

async Task EnsurePartCategoryTriggersAsync(MySqlConnection conn, CancellationToken ct)
{
    var statements = new[]
    {
        "DROP TRIGGER IF EXISTS trg_partcategory_leaf_only",
        @"CREATE TRIGGER trg_partcategory_leaf_only
            BEFORE INSERT ON PartCategory
            FOR EACH ROW
        BEGIN
            IF COALESCE((SELECT is_selectable FROM Category WHERE category_id = NEW.category_id), 0) = 0 THEN
                SIGNAL SQLSTATE '45000'
                    SET MESSAGE_TEXT = 'PartCategory must reference a leaf category.';
            END IF;
        END",
        "DROP TRIGGER IF EXISTS trg_partcategory_leaf_only_u",
        @"CREATE TRIGGER trg_partcategory_leaf_only_u
            BEFORE UPDATE ON PartCategory
            FOR EACH ROW
        BEGIN
            IF COALESCE((SELECT is_selectable FROM Category WHERE category_id = NEW.category_id), 0) = 0 THEN
                SIGNAL SQLSTATE '45000'
                    SET MESSAGE_TEXT = 'PartCategory must reference a leaf category.';
            END IF;
        END"
    };

    foreach (var sql in statements)
    {
        await using var cmd = new MySqlCommand(sql, conn);
        await cmd.ExecuteNonQueryAsync(ct);
    }
}

AdminIngestPayloadEnvelope NormalizeAdminIngestPayload(AdminIngestPayloadEnvelope? raw)
{
    raw ??= new AdminIngestPayloadEnvelope();

    var part = raw.Part ?? new AdminIngestPartPayload();
    var normalized = new AdminIngestPayloadEnvelope
    {
        Part = new AdminIngestPartPayload
        {
            Sku = part.Sku?.Trim() ?? string.Empty,
            Name = part.Name?.Trim() ?? string.Empty,
            BrandName = part.BrandName?.Trim() ?? string.Empty,
            IsKit = part.IsKit ?? false,
            Uom = string.IsNullOrWhiteSpace(part.Uom) ? "each" : part.Uom!.Trim(),
            PiecesPerUnit = part.PiecesPerUnit is > 0 ? decimal.Round(part.PiecesPerUnit.Value, 3, MidpointRounding.AwayFromZero) : 1m,
            Status = string.IsNullOrWhiteSpace(part.Status) ? "active" : part.Status!.Trim().ToLowerInvariant(),
            ImageUrl = string.IsNullOrWhiteSpace(part.ImageUrl) ? null : part.ImageUrl!.Trim()
        }
    };

    var categories = new List<string>();
    var seenCategories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    if (raw.Categories is not null)
    {
        foreach (var entry in raw.Categories)
        {
            var slug = (entry ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(slug))
                continue;

            var normalizedSlug = slug.ToLowerInvariant();
            if (seenCategories.Add(normalizedSlug))
                categories.Add(normalizedSlug);
        }
    }
    normalized.Categories = categories;

    var fitment = new List<string>();
    var seenFitment = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    if (raw.Fitment is not null)
    {
        foreach (var entry in raw.Fitment)
        {
            var code = (entry ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(code))
                continue;

            var normalizedCode = code.ToUpperInvariant();
            if (seenFitment.Add(normalizedCode))
                fitment.Add(normalizedCode);
        }
    }
    normalized.Fitment = fitment;

    var offerings = new List<AdminIngestOfferingPayload>();
    if (raw.Offerings is not null)
    {
        foreach (var off in raw.Offerings)
        {
            if (off is null)
                continue;

            offerings.Add(new AdminIngestOfferingPayload
            {
                VendorName = string.IsNullOrWhiteSpace(off.VendorName) ? null : off.VendorName!.Trim(),
                Price = off.Price,
                Currency = string.IsNullOrWhiteSpace(off.Currency) ? "USD" : off.Currency!.Trim().ToUpperInvariant(),
                Url = string.IsNullOrWhiteSpace(off.Url) ? null : off.Url!.Trim(),
                Availability = string.IsNullOrWhiteSpace(off.Availability) ? null : off.Availability!.Trim().ToLowerInvariant()
            });
        }
    }
    normalized.Offerings = offerings;

    return normalized;
}

static bool TryGetElementByPath(JsonElement root, string path, out JsonElement result)
{
    result = root;
    if (string.IsNullOrWhiteSpace(path))
        return false;

    var segments = path.Split('.', StringSplitOptions.RemoveEmptyEntries);
    foreach (var segment in segments)
    {
        if (!TryDescend(ref result, segment))
        {
            result = default;
            return false;
        }
    }

    return true;

    static bool TryDescend(ref JsonElement current, string segment)
    {
        if (string.IsNullOrEmpty(segment))
            return false;

        if (segment[0] == '[')
        {
            if (segment[^1] != ']' || current.ValueKind != JsonValueKind.Array)
                return false;

            if (!int.TryParse(segment[1..^1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var rootIndex))
                return false;

            var i = 0;
            foreach (var item in current.EnumerateArray())
            {
                if (i++ == rootIndex)
                {
                    current = item;
                    return true;
                }
            }
            return false;
        }

        var bracketIndex = segment.IndexOf('[');
        if (bracketIndex >= 0)
        {
            if (segment[^1] != ']')
                return false;

            var propertyName = segment[..bracketIndex];
            if (current.ValueKind != JsonValueKind.Object || !current.TryGetProperty(propertyName, out var array))
                return false;

            if (array.ValueKind != JsonValueKind.Array)
                return false;

            if (!int.TryParse(segment[(bracketIndex + 1)..^1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var index))
                return false;

            var i = 0;
            foreach (var item in array.EnumerateArray())
            {
                if (i++ == index)
                {
                    current = item;
                    return true;
                }
            }

            return false;
        }

        if (current.ValueKind != JsonValueKind.Object)
            return false;

        if (!current.TryGetProperty(segment, out var next))
            return false;

        current = next;
        return true;
    }
}

static string? TryGetStringByPath(JsonElement root, params string[] paths)
{
    foreach (var path in paths)
    {
        if (TryGetElementByPath(root, path, out var element))
        {
            switch (element.ValueKind)
            {
                case JsonValueKind.String:
                    return element.GetString();
                case JsonValueKind.Number:
                    return element.TryGetDecimal(out var dec)
                        ? dec.ToString(CultureInfo.InvariantCulture)
                        : null;
                case JsonValueKind.True:
                    return "true";
                case JsonValueKind.False:
                    return "false";
            }
        }
    }

    return null;
}

static decimal? TryGetDecimalByPath(JsonElement root, params string[] paths)
{
    foreach (var path in paths)
    {
        if (TryGetElementByPath(root, path, out var element))
        {
            switch (element.ValueKind)
            {
                case JsonValueKind.Number:
                    if (element.TryGetDecimal(out var dec))
                        return dec;
                    break;
                case JsonValueKind.String:
                    if (decimal.TryParse(element.GetString(), NumberStyles.Float, CultureInfo.InvariantCulture, out var parsed))
                        return parsed;
                    break;
            }
        }
    }

    return null;
}

static bool? TryGetBoolByPath(JsonElement root, params string[] paths)
{
    foreach (var path in paths)
    {
        if (TryGetElementByPath(root, path, out var element))
        {
            switch (element.ValueKind)
            {
                case JsonValueKind.True:
                    return true;
                case JsonValueKind.False:
                    return false;
                case JsonValueKind.String:
                    var text = element.GetString();
                    if (bool.TryParse(text, out var parsedBool))
                        return parsedBool;
                    if (string.Equals(text, "yes", StringComparison.OrdinalIgnoreCase))
                        return true;
                    if (string.Equals(text, "no", StringComparison.OrdinalIgnoreCase))
                        return false;
                    break;
            }
        }
    }

    return null;
}

static string NormalizeSlugCandidate(string value)
{
    if (string.IsNullOrWhiteSpace(value))
        return string.Empty;

    var span = value.Trim();
    var buffer = new StringBuilder(span.Length);

    foreach (var ch in span)
    {
        if (char.IsLetterOrDigit(ch))
        {
            buffer.Append(char.ToLowerInvariant(ch));
        }
        else if (char.IsWhiteSpace(ch) || ch is '-' or '_' || ch == '/' || ch == '\\')
        {
            if (buffer.Length == 0 || buffer[^1] != '-')
                buffer.Append('-');
        }
    }

    var slug = buffer.ToString().Trim('-');
    while (slug.Contains("--", StringComparison.Ordinal))
        slug = slug.Replace("--", "-", StringComparison.Ordinal);

    return slug;
}

static List<string> ExtractCategorySlugs(JsonElement root)
{
    var slugs = new List<string>();
    var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    void AddCandidate(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return;

        var slug = NormalizeSlugCandidate(value);
        if (string.IsNullOrWhiteSpace(slug))
            return;

        if (seen.Add(slug))
            slugs.Add(slug);
    }

    if (root.ValueKind == JsonValueKind.Object)
    {
        if (root.TryGetProperty("categories", out var categories) && categories.ValueKind == JsonValueKind.Array)
        {
            foreach (var entry in categories.EnumerateArray())
            {
                if (entry.ValueKind == JsonValueKind.String)
                {
                    AddCandidate(entry.GetString());
                }
                else if (entry.ValueKind == JsonValueKind.Object)
                {
                    if (entry.TryGetProperty("slug", out var slugProp) && slugProp.ValueKind == JsonValueKind.String)
                        AddCandidate(slugProp.GetString());
                    else if (entry.TryGetProperty("category_slug", out var categorySlug) && categorySlug.ValueKind == JsonValueKind.String)
                        AddCandidate(categorySlug.GetString());
                    else if (entry.TryGetProperty("leaf_slug", out var leafSlug) && leafSlug.ValueKind == JsonValueKind.String)
                        AddCandidate(leafSlug.GetString());
                }
            }
        }

        if (root.TryGetProperty("part", out var partNode) && partNode.ValueKind == JsonValueKind.Object)
        {
            if (partNode.TryGetProperty("categories", out var partCats) && partCats.ValueKind == JsonValueKind.Array)
            {
                foreach (var entry in partCats.EnumerateArray())
                {
                    if (entry.ValueKind == JsonValueKind.String)
                        AddCandidate(entry.GetString());
                    else if (entry.ValueKind == JsonValueKind.Object && entry.TryGetProperty("slug", out var slugProp) && slugProp.ValueKind == JsonValueKind.String)
                        AddCandidate(slugProp.GetString());
                }
            }
        }

        if (root.TryGetProperty("part_categories", out var partCategories) && partCategories.ValueKind == JsonValueKind.Array)
        {
            foreach (var entry in partCategories.EnumerateArray())
            {
                if (entry.ValueKind == JsonValueKind.String)
                {
                    AddCandidate(entry.GetString());
                    continue;
                }

                if (entry.ValueKind == JsonValueKind.Object)
                {
                    if (entry.TryGetProperty("slug", out var slugProp) && slugProp.ValueKind == JsonValueKind.String)
                        AddCandidate(slugProp.GetString());
                    if (entry.TryGetProperty("category_slug", out var categorySlug) && categorySlug.ValueKind == JsonValueKind.String)
                        AddCandidate(categorySlug.GetString());
                }
            }
        }

        if (root.TryGetProperty("leaf_categories", out var leafCategories) && leafCategories.ValueKind == JsonValueKind.Array)
        {
            foreach (var entry in leafCategories.EnumerateArray())
                if (entry.ValueKind == JsonValueKind.String)
                    AddCandidate(entry.GetString());
        }

        if (root.TryGetProperty("category_slugs", out var categorySlugs) && categorySlugs.ValueKind == JsonValueKind.Array)
        {
            foreach (var entry in categorySlugs.EnumerateArray())
                if (entry.ValueKind == JsonValueKind.String)
                    AddCandidate(entry.GetString());
        }
    }

    return slugs;
}

static List<string> ExtractFitmentCodes(JsonElement root)
{
    var codes = new List<string>();
    var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    void Add(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return;

        var normalized = value.Trim().ToUpperInvariant();
        if (seen.Add(normalized))
            codes.Add(normalized);
    }

    if (root.ValueKind == JsonValueKind.Object)
    {
        if (root.TryGetProperty("fitment", out var fitment) && fitment.ValueKind == JsonValueKind.Array)
        {
            foreach (var entry in fitment.EnumerateArray())
            {
                if (entry.ValueKind == JsonValueKind.String)
                {
                    Add(entry.GetString());
                }
                else if (entry.ValueKind == JsonValueKind.Object)
                {
                    if (entry.TryGetProperty("engine_code", out var codeProp) && codeProp.ValueKind == JsonValueKind.String)
                        Add(codeProp.GetString());
                    else if (entry.TryGetProperty("code", out var altProp) && altProp.ValueKind == JsonValueKind.String)
                        Add(altProp.GetString());
                }
            }
        }

        if (root.TryGetProperty("engine_codes", out var engineCodes) && engineCodes.ValueKind == JsonValueKind.Array)
        {
            foreach (var entry in engineCodes.EnumerateArray())
                if (entry.ValueKind == JsonValueKind.String)
                    Add(entry.GetString());
        }

        if (root.TryGetProperty("engines", out var engines) && engines.ValueKind == JsonValueKind.Array)
        {
            foreach (var entry in engines.EnumerateArray())
            {
                if (entry.ValueKind == JsonValueKind.Object && entry.TryGetProperty("code", out var codeProp) && codeProp.ValueKind == JsonValueKind.String)
                    Add(codeProp.GetString());
            }
        }

        if (root.TryGetProperty("engine", out var engine) && engine.ValueKind == JsonValueKind.Object)
        {
            if (engine.TryGetProperty("code", out var engineCode) && engineCode.ValueKind == JsonValueKind.String)
                Add(engineCode.GetString());
        }
    }

    return codes;
}

static List<AdminIngestOfferingPayload> ExtractOfferings(JsonElement root)
{
    var offerings = new List<AdminIngestOfferingPayload>();

    if (root.ValueKind != JsonValueKind.Object)
        return offerings;

    if (!root.TryGetProperty("offerings", out var node) || node.ValueKind != JsonValueKind.Array)
        return offerings;

    foreach (var entry in node.EnumerateArray())
    {
        if (entry.ValueKind != JsonValueKind.Object)
            continue;

        var vendor = TryGetStringByPath(entry, "vendor_name", "vendor", "seller", "supplier.name");
        if (string.IsNullOrWhiteSpace(vendor))
            continue;

        var price = TryGetDecimalByPath(entry, "price", "amount", "offer_price");
        var currency = TryGetStringByPath(entry, "currency", "currency_code", "currencyCode");
        var url = TryGetStringByPath(entry, "url", "product_url", "link", "href");
        var availability = TryGetStringByPath(entry, "availability", "status", "stock_status");

        offerings.Add(new AdminIngestOfferingPayload
        {
            VendorName = vendor?.Trim(),
            Price = price,
            Currency = string.IsNullOrWhiteSpace(currency) ? "USD" : currency?.Trim(),
            Url = string.IsNullOrWhiteSpace(url) ? null : url?.Trim(),
            Availability = string.IsNullOrWhiteSpace(availability) ? "in_stock" : availability?.Trim()
        });
    }

    return offerings;
}

static (string Value, string? Warning) NormalizePartStatus(string? status)
{
    if (string.IsNullOrWhiteSpace(status))
        return ("active", null);

    var normalized = status.Trim().ToLowerInvariant();
    return normalized switch
    {
        "active" => ("active", null),
        "draft" => ("draft", null),
        "discontinued" => ("discontinued", null),
        "inactive" => ("discontinued", "Status 'inactive' normalized to 'discontinued'."),
        _ => ("active", $"Status '{normalized}' not recognized; defaulted to 'active'.")
    };
}

static (string Value, string? Warning) NormalizeAvailability(string? availability)
{
    if (string.IsNullOrWhiteSpace(availability))
        return ("in_stock", null);

    var normalized = availability.Trim().ToLowerInvariant();
    return normalized switch
    {
        "in_stock" or "instock" => ("in_stock", normalized == "instock" ? "Availability 'instock' normalized to 'in_stock'." : null),
        "backorder" or "back_order" or "back-ordered" or "backordered" => ("backorder", normalized is "back_order" or "back-ordered" or "backordered" ? "Availability normalized to 'backorder'." : null),
        "discontinued" => ("discontinued", null),
        "unknown" => ("unknown", null),
        _ => ("unknown", $"Availability '{normalized}' not recognized; set to 'unknown'.")
    };
}

static bool IsLikelyCurrencyCode(string? currency)
{
    if (string.IsNullOrWhiteSpace(currency))
        return false;

    var trimmed = currency.Trim();
    if (trimmed.Length is 3 && trimmed.All(char.IsLetter))
        return true;
    return false;
}

async Task<AdminIngestValidationResult> ValidateAdminIngestPayloadAsync(MySqlConnection conn, AdminIngestPayloadEnvelope? input, CancellationToken ct)
{
    var normalized = NormalizeAdminIngestPayload(input);
    var result = new AdminIngestValidationResult(normalized);

    var part = normalized.Part ?? new AdminIngestPartPayload();

    if (string.IsNullOrWhiteSpace(part.Sku))
        result.Errors.Add("SKU required.");

    if (string.IsNullOrWhiteSpace(part.Name))
        result.Errors.Add("Name required.");

    if (string.IsNullOrWhiteSpace(part.BrandName))
        result.Errors.Add("Brand required.");

    if (part.PiecesPerUnit is null || part.PiecesPerUnit <= 0)
    {
        part.PiecesPerUnit = 1m;
        result.Warnings.Add("Pieces per unit <= 0; defaulted to 1.");
    }

    var (statusValue, statusWarning) = NormalizePartStatus(part.Status);
    part.Status = statusValue;
    if (!string.IsNullOrEmpty(statusWarning))
        result.Warnings.Add(statusWarning);

    if (!string.IsNullOrWhiteSpace(part.ImageUrl) && !Uri.TryCreate(part.ImageUrl, UriKind.Absolute, out _))
        result.Warnings.Add("Image URL is not a valid absolute URL.");

    if (normalized.Categories is null || normalized.Categories.Count == 0)
    {
        result.Errors.Add("At least one leaf category slug required.");
    }
    else
    {
        var order = 0;
        foreach (var slug in normalized.Categories)
        {
            await using var cmd = new MySqlCommand("SELECT category_id, is_selectable FROM Category WHERE slug=@slug", conn);
            cmd.Parameters.AddWithValue("@slug", slug);
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            if (!await reader.ReadAsync(ct))
            {
                result.Errors.Add($"Category '{slug}' not found.");
                await reader.DisposeAsync();
                continue;
            }

            var categoryId = reader.GetInt64(0);
            var isSelectable = reader.GetBoolean(1);
            await reader.DisposeAsync();

            if (!isSelectable)
            {
                result.Errors.Add($"Category '{slug}' is not selectable.");
                continue;
            }

            result.Categories.Add(new AdminIngestCategoryResult(categoryId, slug, order));
            order++;
        }
    }

    if (normalized.Fitment is not null && normalized.Fitment.Count > 0)
    {
        foreach (var code in normalized.Fitment)
        {
            await using var cmd = new MySqlCommand("SELECT engine_family_id FROM EngineFamily WHERE code=@code", conn);
            cmd.Parameters.AddWithValue("@code", code);
            var engineResult = await cmd.ExecuteScalarAsync(ct);
            if (engineResult is null)
            {
                result.Errors.Add($"Engine code '{code}' not found.");
                continue;
            }

            var engineId = Convert.ToInt64(engineResult);
            if (result.Engines.All(e => e.EngineFamilyId != engineId))
                result.Engines.Add(new AdminIngestEngineResult(engineId, code));
        }
    }

    var offerings = normalized.Offerings ?? new List<AdminIngestOfferingPayload>();
    foreach (var off in offerings)
    {
        var vendor = off.VendorName;
        if (string.IsNullOrWhiteSpace(vendor))
        {
            result.Errors.Add("Offering vendor required.");
            continue;
        }

        if (off.Price is null)
        {
            result.Errors.Add($"Offering price required for vendor '{vendor}'.");
            continue;
        }

        if (off.Price < 0)
        {
            result.Errors.Add($"Offering price for vendor '{vendor}' must be non-negative.");
            continue;
        }

        var currency = string.IsNullOrWhiteSpace(off.Currency) ? "USD" : off.Currency!;
        if (!IsLikelyCurrencyCode(currency))
        {
            result.Warnings.Add($"Currency '{currency}' for vendor '{vendor}' is unusual; expected a three-letter code.");
        }
        currency = currency.ToUpperInvariant();

        var (availabilityValue, availabilityWarning) = NormalizeAvailability(off.Availability);
        if (!string.IsNullOrEmpty(availabilityWarning))
            result.Warnings.Add(availabilityWarning);

        string? url = off.Url;
        if (!string.IsNullOrWhiteSpace(url) && !Uri.TryCreate(url, UriKind.Absolute, out _))
            result.Warnings.Add($"Offering URL for vendor '{vendor}' is not a valid absolute URL.");
        else if (string.IsNullOrWhiteSpace(url))
            url = null;

        result.Offerings.Add(new AdminIngestOfferingNormalized(vendor, off.Price.Value, currency, url, availabilityValue));
    }

    if (result.Offerings.Count == 0)
        result.Errors.Add("At least one offering with vendor and price is required.");

    await using (var skuLookup = new MySqlCommand("SELECT part_id FROM Part WHERE sku=@sku", conn))
    {
        skuLookup.Parameters.AddWithValue("@sku", part.Sku ?? string.Empty);
        var existing = await skuLookup.ExecuteScalarAsync(ct);
        if (existing is not null)
        {
            result.ExistingPartId = Convert.ToInt64(existing);
            result.Warnings.Add($"SKU '{part.Sku}' already exists (part_id {result.ExistingPartId}). Save will upsert.");
        }
    }

    return result;
}

async Task EnsureGuideTablesAsync(MySqlConnection conn, CancellationToken ct)
{
    const string guideSql = @"CREATE TABLE IF NOT EXISTS Guide (
        guide_id      BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
        slug          VARCHAR(120) NOT NULL,
        title         VARCHAR(255) NOT NULL,
        content_md    LONGTEXT NULL,
        published_at  DATETIME NULL,
        updated_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY uq_guide_slug (slug)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";

    await using (var guideCmd = new MySqlCommand(guideSql, conn))
    {
        await guideCmd.ExecuteNonQueryAsync(ct);
    }

    const string guidePartSql = @"CREATE TABLE IF NOT EXISTS GuidePart (
        guide_part_id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
        guide_id      BIGINT UNSIGNED NOT NULL,
        part_id       BIGINT UNSIGNED NOT NULL,
        position      INT NOT NULL DEFAULT 0,
        created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        CONSTRAINT fk_guidepart_guide FOREIGN KEY (guide_id) REFERENCES Guide(guide_id) ON DELETE CASCADE,
        CONSTRAINT fk_guidepart_part FOREIGN KEY (part_id) REFERENCES Part(part_id) ON DELETE CASCADE,
        UNIQUE KEY uq_guide_part (guide_id, part_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";

    await using (var guidePartCmd = new MySqlCommand(guidePartSql, conn))
    {
        await guidePartCmd.ExecuteNonQueryAsync(ct);
    }

    await using (var indexCheck = new MySqlCommand("SHOW INDEX FROM GuidePart WHERE Key_name='ix_guidepart_position'", conn))
    {
        var hasIndex = await indexCheck.ExecuteScalarAsync(ct) is not null;
        if (!hasIndex)
        {
            await using var createIdx = new MySqlCommand("CREATE INDEX ix_guidepart_position ON GuidePart(guide_id, position)", conn);
            await createIdx.ExecuteNonQueryAsync(ct);
        }
    }
}

static async Task<string> GenerateUniquePublicSlugAsync(MySqlConnection conn, CancellationToken ct)
{
    const int slugLength = 8;
    for (var attempt = 0; attempt < 6; attempt++)
    {
        var candidate = Guid.NewGuid().ToString("n").Substring(0, slugLength);
        await using var check = new MySqlCommand("SELECT 1 FROM Build WHERE public_slug=@slug LIMIT 1", conn);
        check.Parameters.AddWithValue("@slug", candidate);
        if (await check.ExecuteScalarAsync(ct) is null)
        {
            return candidate;
        }
    }

    return Guid.NewGuid().ToString("n");
}

static async Task<IResult> GenerateBuyPlanAsync(string? connectionString, long buildId, string mode, CancellationToken ct)
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    var normalizedMode = string.IsNullOrWhiteSpace(mode) ? "cheapest" : mode.Trim().ToLowerInvariant();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        var lines = (await conn.QueryAsync<BuildSelectionLine>(@"
          SELECT CAST(bs.part_id AS SIGNED) AS PartId,
                 CAST(bs.qty AS DECIMAL(18,4)) AS Qty
          FROM BuildSelection bs
          WHERE bs.build_id=@b", new { b = buildId })).ToList();

        if (!lines.Any())
        {
            return Results.Ok(new { mode = normalizedMode, items = Array.Empty<object>(), totals = new { items = 0m } });
        }

        if (normalizedMode == "singlevendor")
        {
            var candidates = (await conn.QueryAsync<VendorCandidate>(@"
              SELECT CAST(v.vendor_id AS SIGNED) AS VendorId,
                     v.name AS Vendor
              FROM Vendor v
              WHERE EXISTS (
                SELECT 1 FROM PartOffering po
                WHERE po.vendor_id = v.vendor_id
                  AND po.part_id IN (SELECT part_id FROM BuildSelection WHERE build_id=@b)
                  AND (po.effective_to IS NULL OR po.effective_to > NOW())
              )", new { b = buildId })).ToList();

            decimal? bestTotal = null;
            VendorCandidate? bestVendor = null;
            List<SingleVendorPlanItem> bestPlan = new();

            foreach (var vendor in candidates)
            {
                var vendorItems = (await conn.QueryAsync<SingleVendorPlanItem>(@"
                  SELECT CAST(part_id AS SIGNED) AS PartId,
                         CAST(qty AS DECIMAL(18,4)) AS Qty,
                         unit_price AS UnitPrice,
                         offering_id AS OfferingId
                  FROM (
                    SELECT bs.part_id,
                           bs.qty,
                           po.price AS unit_price,
                           po.offering_id,
                           ROW_NUMBER() OVER (PARTITION BY bs.part_id ORDER BY po.price, po.offering_id) AS rn
                    FROM BuildSelection bs
                    JOIN PartOffering po ON po.part_id = bs.part_id AND po.vendor_id = @vid
                    WHERE bs.build_id=@b AND (po.effective_to IS NULL OR po.effective_to > NOW())
                  ) ranked
                  WHERE rn = 1", new { b = buildId, vid = vendor.VendorId })).ToList();

                if (vendorItems.Count != lines.Count)
                {
                    continue;
                }

                var vendorTotal = vendorItems.Sum(x => x.UnitPrice * x.Qty);
                if (bestTotal is null || vendorTotal < bestTotal)
                {
                    bestTotal = vendorTotal;
                    bestVendor = vendor;
                    bestPlan = vendorItems;
                }
            }

            if (bestVendor is null || !bestPlan.Any())
            {
                return Results.Ok(new { mode = normalizedMode, items = Array.Empty<object>(), totals = new { items = 0m } });
            }

            var payload = bestPlan.Select(item => new
            {
                part_id = item.PartId,
                qty = item.Qty,
                unit_price = item.UnitPrice,
                vendor = bestVendor!.Vendor,
                vendor_id = bestVendor.VendorId,
                offering_id = item.OfferingId
            }).ToList();

            return Results.Ok(new
            {
                mode = normalizedMode,
                vendor_id = bestVendor.VendorId,
                vendor = bestVendor.Vendor,
                items = payload,
                totals = new { items = bestTotal ?? 0m }
            });
        }
        else
        {
            var items = (await conn.QueryAsync<(long PartId, decimal Qty, decimal UnitPrice, string Vendor, long VendorId, long OfferingId)>(@"
                SELECT CAST(x.part_id AS SIGNED) AS PartId,
                       CAST(x.qty AS DECIMAL(18,4)) AS Qty,
                       m.price AS UnitPrice,
                       v.name AS Vendor,
                       CAST(m.vendor_id AS SIGNED) AS VendorId,
                       CAST(m.offering_id AS SIGNED) AS OfferingId
                FROM (
                  SELECT bs.part_id, bs.qty FROM BuildSelection bs WHERE bs.build_id=@b
                ) x
                JOIN (
                  SELECT po.part_id, MIN(po.price) AS price
                  FROM PartOffering po
                  WHERE (po.effective_to IS NULL OR po.effective_to > NOW())
                  GROUP BY po.part_id
                ) minp ON minp.part_id = x.part_id
                JOIN PartOffering m ON m.part_id = x.part_id AND m.price = minp.price
                JOIN Vendor v ON v.vendor_id = m.vendor_id
                WHERE (m.effective_to IS NULL OR m.effective_to > NOW())",
                new { b = buildId })).ToList();

            var total = items.Sum(item => item.UnitPrice * item.Qty);

            return Results.Ok(new
            {
                mode = normalizedMode,
                items,
                totals = new { items = total }
            });
        }
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Buy plan failed", detail: ex.ToString(), statusCode: 500);
    }
}

Regex PublicSlugRegex = new("^[a-z0-9-]{3,40}$", RegexOptions.Compiled | RegexOptions.CultureInvariant);

async Task EnsureClickAttributionSchemaAsync(MySqlConnection conn, CancellationToken ct)
{
    const string createSql = @"CREATE TABLE IF NOT EXISTS ClickAttribution (
        click_id         BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
        build_id         BIGINT UNSIGNED NULL,
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
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";

    await using (var createCmd = new MySqlCommand(createSql, conn))
    {
        await createCmd.ExecuteNonQueryAsync(ct);
    }

    const string nullableSql = @"SELECT IS_NULLABLE
                                 FROM information_schema.COLUMNS
                                 WHERE TABLE_SCHEMA = DATABASE()
                                   AND TABLE_NAME = 'ClickAttribution'
                                   AND COLUMN_NAME = 'build_id'
                                 LIMIT 1";

    await using var checkCmd = new MySqlCommand(nullableSql, conn);
    var result = await checkCmd.ExecuteScalarAsync(ct);
    if (result is string isNullable && !string.Equals(isNullable, "YES", StringComparison.OrdinalIgnoreCase))
    {
        await using var alterCmd = new MySqlCommand("ALTER TABLE ClickAttribution MODIFY build_id BIGINT UNSIGNED NULL", conn);
        await alterCmd.ExecuteNonQueryAsync(ct);
    }
}

static bool TryNormalizeEnum(string? value, IReadOnlyDictionary<string, string> options, out string? normalized)
{
    if (string.IsNullOrWhiteSpace(value))
    {
        normalized = null;
        return true;
    }

    var trimmed = value.Trim();
    if (options.TryGetValue(trimmed, out var canonical))
    {
        normalized = canonical;
        return true;
    }

    normalized = null;
    return false;
}

static bool TryParseDateQuery(string? value, out DateTime? date)
{
    if (string.IsNullOrWhiteSpace(value))
    {
        date = null;
        return true;
    }

    var formats = new[]
    {
        "yyyy-MM-dd",
        "yyyy-MM-ddTHH:mm:ss",
        "yyyy-MM-ddTHH:mm:ssZ",
        "yyyy-MM-ddTHH:mm:ss.fff",
        "yyyy-MM-ddTHH:mm:ss.fffZ",
        "o"
    };

    if (DateTime.TryParseExact(value, formats, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var exact))
    {
        date = exact;
        return true;
    }

    if (DateTime.TryParse(value, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed))
    {
        date = parsed;
        return true;
    }

    if (DateTime.TryParse(value, CultureInfo.CurrentCulture,
            DateTimeStyles.AssumeLocal | DateTimeStyles.AdjustToUniversal, out parsed))
    {
        date = parsed;
        return true;
    }

    date = null;
    return false;
}

static string NormalizeRequirementModeForApi(string? mode)
{
    var normalized = mode?.Trim().ToLowerInvariant();
    return normalized switch
    {
        "exact_count" => "exact_count",
        "min_count" => "min_count",
        "structured" => "structured",
        "formula" => "formula",
        _ => "exact_count"
    };
}

static string NormalizeRoundModeForApi(string? round)
{
    var normalized = round?.Trim().ToLowerInvariant();
    return normalized switch
    {
        "ceil" => "ceil",
        "floor" => "floor",
        "round" => "round",
        _ => "none"
    };
}

static string? NormalizeOperandFieldForApi(string? operand)
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

static string ResolveRequirementTypeForApi(string? requirementType, string reqMode)
{
    var normalized = requirementType?.Trim().ToLowerInvariant();
    var mapped = normalized switch
    {
        "exact_count" => "exact_count",
        "min_count" => "min_count",
        "formula" => "formula",
        "structured" => "formula",
        _ => null
    };

    if (mapped is not null) return mapped;

    return reqMode switch
    {
        "structured" => "formula",
        "formula" => "formula",
        "min_count" => "min_count",
        _ => "exact_count"
    };
}

static async Task<(bool exists, bool isSelectable)> FetchCategorySelectableAsync(MySqlConnection conn, long categoryId, CancellationToken ct)
{
    await using var cmd = new MySqlCommand("SELECT is_selectable FROM Category WHERE category_id=@id", conn);
    cmd.Parameters.AddWithValue("@id", categoryId);
    var result = await cmd.ExecuteScalarAsync(ct);
    if (result is null) return (false, false);
    var isSelectable = result != DBNull.Value && Convert.ToBoolean(result);
    return (true, isSelectable);
}

static async Task<bool> PartExistsAsync(MySqlConnection conn, long partId, CancellationToken ct)
{
    await using var cmd = new MySqlCommand("SELECT 1 FROM Part WHERE part_id=@id LIMIT 1", conn);
    cmd.Parameters.AddWithValue("@id", partId);
    return await cmd.ExecuteScalarAsync(ct) is not null;
}

static async Task<bool> PartIsKitAsync(MySqlConnection conn, long partId, CancellationToken ct)
{
    await using var cmd = new MySqlCommand("SELECT is_kit FROM Part WHERE part_id=@id", conn);
    cmd.Parameters.AddWithValue("@id", partId);
    var value = await cmd.ExecuteScalarAsync(ct);
    if (value is null || value == DBNull.Value) return false;
    return Convert.ToBoolean(value);
}


async Task EnsureShareTablesAsync(MySqlConnection conn, CancellationToken ct)
{
    const string buildShareSql = @"CREATE TABLE IF NOT EXISTS BuildShare (
        build_id   BIGINT UNSIGNED NOT NULL,
        user_id    BIGINT UNSIGNED NOT NULL,
        role       ENUM('viewer','editor') NOT NULL DEFAULT 'viewer',
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (build_id, user_id),
        FOREIGN KEY (build_id) REFERENCES Build(build_id) ON DELETE CASCADE,
        FOREIGN KEY (user_id)  REFERENCES UserAccount(user_id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";

    const string buildInviteSql = @"CREATE TABLE IF NOT EXISTS BuildInvite (
        invite_id   BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
        build_id    BIGINT UNSIGNED NOT NULL,
        email       VARCHAR(254) NOT NULL,
        role        ENUM('viewer','editor') NOT NULL DEFAULT 'viewer',
        token       CHAR(36) NOT NULL,
        expires_at  DATETIME NOT NULL,
        accepted_by BIGINT UNSIGNED NULL,
        created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uq_invite_token (token),
        FOREIGN KEY (build_id)    REFERENCES Build(build_id) ON DELETE CASCADE,
        FOREIGN KEY (accepted_by) REFERENCES UserAccount(user_id) ON DELETE SET NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";

    await using (var cmd = new MySqlCommand(buildShareSql, conn))
    {
        await cmd.ExecuteNonQueryAsync(ct);
    }

    await using (var cmd = new MySqlCommand(buildInviteSql, conn))
    {
        await cmd.ExecuteNonQueryAsync(ct);
    }
}

async Task EnsureEngineFamilyTreeSchemaAsync(MySqlConnection conn, CancellationToken ct)
{
    await SchemaHelpers.EnsureEngineFamilyColumnsAsync(conn, ct);

    const string tableSql = @"CREATE TABLE IF NOT EXISTS EngineFamilyTree (
        engine_family_id BIGINT UNSIGNED NOT NULL,
        tree_id          BIGINT UNSIGNED NOT NULL,
        is_default       BOOLEAN NOT NULL DEFAULT FALSE,
        PRIMARY KEY (engine_family_id, tree_id),
        CONSTRAINT fk_eft_engine FOREIGN KEY (engine_family_id) REFERENCES EngineFamily(engine_family_id) ON DELETE CASCADE,
        CONSTRAINT fk_eft_tree   FOREIGN KEY (tree_id)          REFERENCES CategoryTree(tree_id)        ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";

    await using (var tableCmd = new MySqlCommand(tableSql, conn))
    {
        await tableCmd.ExecuteNonQueryAsync(ct);
    }

    const string treeIndexSql = "CREATE INDEX IF NOT EXISTS ix_eft_tree ON EngineFamilyTree(tree_id);";
    await using (var treeIdx = new MySqlCommand(treeIndexSql, conn))
    {
        await treeIdx.ExecuteNonQueryAsync(ct);
    }

    const string defaultIndexSql = "CREATE INDEX IF NOT EXISTS ix_eft_engine_default ON EngineFamilyTree(engine_family_id, is_default);";
    await using (var defaultIdx = new MySqlCommand(defaultIndexSql, conn))
    {
        await defaultIdx.ExecuteNonQueryAsync(ct);
    }

    const string viewSql = @"CREATE OR REPLACE VIEW v_engine_default_tree AS
        SELECT ef.engine_family_id,
               ef.code,
               eft.tree_id,
               t.name AS tree_name
        FROM EngineFamily ef
        LEFT JOIN EngineFamilyTree eft
          ON eft.engine_family_id = ef.engine_family_id
         AND eft.is_default = TRUE
        LEFT JOIN CategoryTree t
          ON t.tree_id = eft.tree_id;";

    await using (var viewCmd = new MySqlCommand(viewSql, conn))
    {
        await viewCmd.ExecuteNonQueryAsync(ct);
    }
}

async Task<(bool EngineExists, long? TreeId, string? TreeName, string? EngineCode)> ResolveDefaultTreeForEngineAsync(MySqlConnection conn, long engineFamilyId, CancellationToken ct)
{
    await EnsureEngineFamilyTreeSchemaAsync(conn, ct);

    const string sql = @"SELECT ef.code,
                                 t.tree_id,
                                 t.name
                          FROM EngineFamily ef
                          LEFT JOIN EngineFamilyTree eft
                            ON eft.engine_family_id = ef.engine_family_id
                           AND eft.is_default = TRUE
                          LEFT JOIN CategoryTree t
                            ON t.tree_id = eft.tree_id
                          WHERE ef.engine_family_id = @ef
                          LIMIT 1;";

    string? engineCode = null;
    long? treeId = null;
    string? treeName = null;

    await using (var cmd = new MySqlCommand(sql, conn))
    {
        cmd.Parameters.AddWithValue("@ef", engineFamilyId);
        await using (var reader = await cmd.ExecuteReaderAsync(ct))
        {
            if (!await reader.ReadAsync(ct))
            {
                return (false, null, null, null);
            }

            engineCode = reader.IsDBNull(0) ? null : reader.GetString(0);
            treeId = reader.IsDBNull(1) ? null : reader.GetInt64(1);
            treeName = reader.IsDBNull(2) ? null : reader.GetString(2);
        }
    }

    if (treeId is null && !string.IsNullOrWhiteSpace(engineCode))
    {
        const string fallbackSql = @"SELECT tree_id, name
                                     FROM CategoryTree
                                     WHERE name IN (@name1, @name2)
                                     ORDER BY CASE name WHEN @name1 THEN 0 ELSE 1 END
                                     LIMIT 1;";

        var primaryFallback = $"engine_{engineCode}";
        var secondaryFallback = $"{engineCode}-tree";

        await using var fallbackCmd = new MySqlCommand(fallbackSql, conn);
        fallbackCmd.Parameters.AddWithValue("@name1", primaryFallback);
        fallbackCmd.Parameters.AddWithValue("@name2", secondaryFallback);
        await using var fallbackReader = await fallbackCmd.ExecuteReaderAsync(ct);
        if (await fallbackReader.ReadAsync(ct))
        {
            treeId = fallbackReader.GetInt64(0);
            treeName = fallbackReader.IsDBNull(1) ? null : fallbackReader.GetString(1);
        }
    }

    return (true, treeId, string.IsNullOrWhiteSpace(treeName) && treeId.HasValue ? $"Tree {treeId.Value}" : treeName, engineCode);
}

async Task EnsurePriceWatchTableAsync(MySqlConnection conn, CancellationToken ct)
{
    const string tableSql = @"CREATE TABLE IF NOT EXISTS PriceWatch (
        watch_id      BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
        user_id       BIGINT UNSIGNED NULL,
        email         VARCHAR(254) NULL,
        part_id       BIGINT UNSIGNED NOT NULL,
        target_price  DECIMAL(12,2) NULL,
        stock_only    BOOLEAN NOT NULL DEFAULT FALSE,
        is_verified   BOOLEAN NOT NULL DEFAULT FALSE,
        verify_token  CHAR(64) NULL,
        verify_expires DATETIME NULL,
        created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_notified_at DATETIME NULL,
        active        BOOLEAN NOT NULL DEFAULT TRUE,
        FOREIGN KEY (user_id) REFERENCES UserAccount(user_id) ON DELETE SET NULL,
        FOREIGN KEY (part_id) REFERENCES Part(part_id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";

    await using (var cmd = new MySqlCommand(tableSql, conn))
    {
        await cmd.ExecuteNonQueryAsync(ct);
    }

    await EnsurePriceWatchColumnAsync(conn, ct, "is_verified", "ALTER TABLE PriceWatch ADD COLUMN is_verified BOOLEAN NOT NULL DEFAULT FALSE AFTER stock_only");
    await EnsurePriceWatchColumnAsync(conn, ct, "verify_token", "ALTER TABLE PriceWatch ADD COLUMN verify_token CHAR(64) NULL AFTER is_verified");
    await EnsurePriceWatchColumnAsync(conn, ct, "verify_expires", "ALTER TABLE PriceWatch ADD COLUMN verify_expires DATETIME NULL AFTER verify_token");

    const string indexSql = "CREATE INDEX IF NOT EXISTS ix_pricewatch_part ON PriceWatch(part_id, active);";
    await using (var indexCmd = new MySqlCommand(indexSql, conn))
    {
        await indexCmd.ExecuteNonQueryAsync(ct);
    }

    const string verifyIndexSql = "CREATE INDEX IF NOT EXISTS ix_pricewatch_verify_token ON PriceWatch(verify_token);";
    await using (var verifyIndexCmd = new MySqlCommand(verifyIndexSql, conn))
    {
        await verifyIndexCmd.ExecuteNonQueryAsync(ct);
    }

    static async Task EnsurePriceWatchColumnAsync(MySqlConnection connection, CancellationToken token, string columnName, string alterSql)
    {
        var checkSql = $"SHOW COLUMNS FROM PriceWatch LIKE '{columnName}'";
        await using var check = new MySqlCommand(checkSql, connection);
        if (await check.ExecuteScalarAsync(token) is not null)
        {
            return;
        }

        await using var alter = new MySqlCommand(alterSql, connection);
        await alter.ExecuteNonQueryAsync(token);
    }
}

static string ResolveBaseUrl(IConfiguration configuration, HttpRequest? request = null)
{
    var baseUrl = configuration["Mail:BaseUrl"];
    if (string.IsNullOrWhiteSpace(baseUrl))
    {
        baseUrl = configuration["App:BaseUrl"];
    }

    if (string.IsNullOrWhiteSpace(baseUrl) && request is not null)
    {
        baseUrl = $"{request.Scheme}://{request.Host}";
    }

    return string.IsNullOrWhiteSpace(baseUrl) ? string.Empty : baseUrl.TrimEnd('/');
}

static string BuildAbsoluteUrl(IConfiguration configuration, HttpRequest request, string path)
{
    var baseUrl = ResolveBaseUrl(configuration, request);
    if (string.IsNullOrWhiteSpace(path))
    {
        return baseUrl;
    }

    if (Uri.TryCreate(path, UriKind.Absolute, out var absolute))
    {
        return absolute.ToString();
    }

    if (string.IsNullOrWhiteSpace(baseUrl))
    {
        return path.StartsWith('/') ? path : $"/{path}";
    }

    var normalizedPath = path.StartsWith('/') ? path : $"/{path}";
    return string.Concat(baseUrl, normalizedPath);
}

async Task EnsureRoleTablesAsync(MySqlConnection conn, CancellationToken ct)
{
    const string roleSql = @"CREATE TABLE IF NOT EXISTS AppRole (
        role_id      BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
        code         VARCHAR(64) NOT NULL,
        name         VARCHAR(120) NOT NULL,
        description  VARCHAR(255) NULL,
        is_system    BOOLEAN NOT NULL DEFAULT FALSE,
        created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        CONSTRAINT uq_app_role_code UNIQUE (code)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";

    await using (var cmd = new MySqlCommand(roleSql, conn))
    {
        await cmd.ExecuteNonQueryAsync(ct);
    }

    const string userRoleSql = @"CREATE TABLE IF NOT EXISTS UserRole (
        user_id  BIGINT UNSIGNED NOT NULL,
        role_id  BIGINT UNSIGNED NOT NULL,
        granted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (user_id, role_id),
        FOREIGN KEY (user_id) REFERENCES UserAccount(user_id) ON DELETE CASCADE ON UPDATE CASCADE,
        FOREIGN KEY (role_id) REFERENCES AppRole(role_id) ON DELETE CASCADE ON UPDATE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";

    await using (var cmd = new MySqlCommand(userRoleSql, conn))
    {
        await cmd.ExecuteNonQueryAsync(ct);
    }

    const string seedAdminSql = @"INSERT IGNORE INTO AppRole(code, name, description, is_system) VALUES('admin','Administrator','Full access', TRUE);";
    await using (var seedCmd = new MySqlCommand(seedAdminSql, conn))
    {
        await seedCmd.ExecuteNonQueryAsync(ct);
    }
}

async Task EnsurePlanTablesAsync(MySqlConnection conn, CancellationToken ct)
{
    const string planSql = @"CREATE TABLE IF NOT EXISTS Plan (
        plan_id       BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
        code          VARCHAR(60) NOT NULL,
        name          VARCHAR(120) NOT NULL,
        monthly_price DECIMAL(12,2) NOT NULL DEFAULT 0.00,
        currency      CHAR(3) NOT NULL DEFAULT 'USD',
        features_json JSON NULL,
        CONSTRAINT uq_plan_code UNIQUE (code)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";

    const string userPlanSql = @"CREATE TABLE IF NOT EXISTS UserPlan (
        user_plan_id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
        user_id      BIGINT UNSIGNED NOT NULL,
        plan_id      BIGINT UNSIGNED NOT NULL,
        status       ENUM('active','past_due','canceled') NOT NULL DEFAULT 'active',
        current_period_start DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        current_period_end   DATETIME NULL,
        FOREIGN KEY (plan_id) REFERENCES Plan(plan_id),
        INDEX ix_userplan_user (user_id, status)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";

    await using (var cmd = new MySqlCommand(planSql, conn))
    {
        await cmd.ExecuteNonQueryAsync(ct);
    }

    await using (var cmd = new MySqlCommand(userPlanSql, conn))
    {
        await cmd.ExecuteNonQueryAsync(ct);
    }

    // Ensure soft-delete column exists for existing deployments
    const string checkIsArchivedSql = "SHOW COLUMNS FROM Plan LIKE 'is_archived'";
    await using (var checkArchived = new MySqlCommand(checkIsArchivedSql, conn))
    {
        var exists = await checkArchived.ExecuteScalarAsync(ct) is not null;
        if (!exists)
        {
            await using var alter = new MySqlCommand("ALTER TABLE Plan ADD COLUMN is_archived TINYINT(1) NOT NULL DEFAULT 0 AFTER currency", conn);
            await alter.ExecuteNonQueryAsync(ct);
        }
    }

    // Ensure plan_code unique key exists
    const string checkUniqueSql = "SHOW INDEX FROM Plan WHERE Key_name='uq_plan_code'";
    await using (var checkUnique = new MySqlCommand(checkUniqueSql, conn))
    {
        var hasUnique = await checkUnique.ExecuteScalarAsync(ct) is not null;
        if (!hasUnique)
        {
            try
            {
                await using var addUnique = new MySqlCommand("ALTER TABLE Plan ADD UNIQUE KEY uq_plan_code (code)", conn);
                await addUnique.ExecuteNonQueryAsync(ct);
            }
            catch (MySqlException ex) when (ex.Number == 1061)
            {
                // duplicate key, safe to ignore
            }
        }
    }

    const string planLimitSql = @"CREATE TABLE IF NOT EXISTS PlanLimits (
        plan_id           BIGINT UNSIGNED PRIMARY KEY,
        max_active_builds INT NOT NULL,
        max_total_builds  INT NOT NULL,
        CONSTRAINT fk_planlimits_plan FOREIGN KEY (plan_id) REFERENCES Plan(plan_id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";

    await using (var limitTableCmd = new MySqlCommand(planLimitSql, conn))
    {
        await limitTableCmd.ExecuteNonQueryAsync(ct);
    }

    const string seedPlansSql = @"INSERT INTO Plan(code, name, monthly_price, currency, features_json)
                                  VALUES('FREE', 'Free', 0.00, 'USD', JSON_OBJECT('max_active_builds', 3, 'max_total_builds', 10))
                                  ON DUPLICATE KEY UPDATE name=VALUES(name), features_json=VALUES(features_json)";
    await using (var seedPlansCmd = new MySqlCommand(seedPlansSql, conn))
    {
        await seedPlansCmd.ExecuteNonQueryAsync(ct);
    }

    const string seedLimitsSql = @"INSERT INTO PlanLimits (plan_id, max_active_builds, max_total_builds)
                                  SELECT p.plan_id,
                                         CASE p.code WHEN 'FREE' THEN 3 WHEN 'PRO' THEN 20 ELSE 200 END,
                                         CASE p.code WHEN 'FREE' THEN 10 WHEN 'PRO' THEN 200 ELSE 5000 END
                                  FROM Plan p
                                  LEFT JOIN PlanLimits pl ON pl.plan_id = p.plan_id
                                  WHERE pl.plan_id IS NULL";
    await using (var seedLimitsCmd = new MySqlCommand(seedLimitsSql, conn))
    {
        await seedLimitsCmd.ExecuteNonQueryAsync(ct);
    }

    const string viewEffectiveSql = @"CREATE OR REPLACE VIEW v_user_effective_plan AS
                                      SELECT up.user_id,
                                             up.plan_id,
                                             p.code AS plan_code,
                                             p.name AS plan_name
                                      FROM UserPlan up
                                      JOIN Plan p ON p.plan_id = up.plan_id
                                      WHERE up.status = 'active'
                                        AND (up.current_period_end IS NULL OR up.current_period_end > NOW())";
    await using (var ensureEffectiveViewCmd = new MySqlCommand(viewEffectiveSql, conn))
    {
        await ensureEffectiveViewCmd.ExecuteNonQueryAsync(ct);
    }

    const string viewLimitsSql = @"CREATE OR REPLACE VIEW v_user_limits AS
                                   SELECT v.user_id,
                                          v.plan_id,
                                          v.plan_code,
                                          v.plan_name,
                                          pl.max_active_builds,
                                          pl.max_total_builds
                                   FROM v_user_effective_plan v
                                   JOIN PlanLimits pl ON pl.plan_id = v.plan_id";
    await using (var ensureLimitsViewCmd = new MySqlCommand(viewLimitsSql, conn))
    {
        await ensureLimitsViewCmd.ExecuteNonQueryAsync(ct);
    }

    var hasBuildTable = await TableExistsAsync(conn, "Build", ct);
    if (hasBuildTable)
    {
        await EnsurePlanQuotaFunctionsAsync(conn, ct);
        await EnsurePlanQuotaTriggersAsync(conn, ct);
    }
}

async Task<bool> ActivateUserPlanAsync(string? connString, long userId, string planCode, CancellationToken ct)
{
    if (string.IsNullOrWhiteSpace(connString))
        return false;

    await using var conn = new MySqlConnection(connString);
    await conn.OpenAsync(ct);
    await EnsurePlanTablesAsync(conn, ct);
    await using var tx = await conn.BeginTransactionAsync(ct);

    long? planId;
    await using (var planCmd = new MySqlCommand("SELECT plan_id FROM Plan WHERE code=@code", conn, (MySqlTransaction)tx))
    {
        planCmd.Parameters.AddWithValue("@code", planCode);
        var result = await planCmd.ExecuteScalarAsync(ct);
        planId = result is null ? null : Convert.ToInt64(result);
    }

    if (planId is null)
    {
        await tx.RollbackAsync(ct);
        return false;
    }

    await using (var cancel = new MySqlCommand("UPDATE UserPlan SET status='canceled', current_period_end=NOW() WHERE user_id=@uid AND status='active'", conn, (MySqlTransaction)tx))
    {
        cancel.Parameters.AddWithValue("@uid", userId);
        await cancel.ExecuteNonQueryAsync(ct);
    }

    await using (var insert = new MySqlCommand("INSERT INTO UserPlan (user_id, plan_id, status, current_period_start) VALUES (@uid, @pid, 'active', NOW())", conn, (MySqlTransaction)tx))
    {
        insert.Parameters.AddWithValue("@uid", userId);
        insert.Parameters.AddWithValue("@pid", planId.Value);
        await insert.ExecuteNonQueryAsync(ct);
    }

    await tx.CommitAsync(ct);
    return true;
}

static bool TryGetSubscriptionContext(IDictionary<string, string>? metadata, out long userId, out string? planCode)
{
    userId = 0;
    planCode = null;
    if (metadata is null)
        return false;

    if (metadata.TryGetValue("user_id", out var raw) && long.TryParse(raw, out var parsed))
    {
        userId = parsed;
        if (metadata.TryGetValue("plan_code", out var plan) && !string.IsNullOrWhiteSpace(plan))
            planCode = plan;
        return true;
    }

    return false;
}

static string NormalizePlanCode(string? planCode)
    => string.IsNullOrWhiteSpace(planCode)
        ? PremiumPlanCode
        : planCode.Trim().ToUpperInvariant();

static string? TryMapPriceToPlanCode(IConfiguration configuration, string? priceId)
{
    if (string.IsNullOrWhiteSpace(priceId))
        return null;

    foreach (var child in configuration.GetSection("Stripe:Prices").GetChildren())
    {
        var configuredPriceId = child.Value;
        if (!string.IsNullOrWhiteSpace(configuredPriceId) &&
            string.Equals(configuredPriceId, priceId, StringComparison.OrdinalIgnoreCase))
        {
            return NormalizePlanCode(child.Key);
        }
    }

    return null;
}

static string ResolveEffectivePlanCode(IConfiguration configuration, string? metadataPlan, string? priceId)
{
    var normalizedFromMetadata = string.IsNullOrWhiteSpace(metadataPlan) ? null : NormalizePlanCode(metadataPlan);
    var mappedFromPrice = TryMapPriceToPlanCode(configuration, priceId);

    if (!string.IsNullOrWhiteSpace(mappedFromPrice))
    {
        return mappedFromPrice;
    }

    return normalizedFromMetadata ?? PremiumPlanCode;
}

async Task EnsureBillingTablesAsync(MySqlConnection conn, CancellationToken ct)
{
    const string customerSql = @"CREATE TABLE IF NOT EXISTS BillingCustomer (
        user_id BIGINT UNSIGNED PRIMARY KEY,
        stripe_customer_id VARCHAR(64) NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        CONSTRAINT fk_billing_customer_user FOREIGN KEY (user_id) REFERENCES UserAccount(user_id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";

    await using (var cmd = new MySqlCommand(customerSql, conn))
    {
        await cmd.ExecuteNonQueryAsync(ct);
    }

    const string subscriptionSql = @"CREATE TABLE IF NOT EXISTS BillingSubscription (
        user_id BIGINT UNSIGNED PRIMARY KEY,
        stripe_subscription_id VARCHAR(64) NOT NULL,
        plan_code VARCHAR(60) NOT NULL,
        status VARCHAR(32) NOT NULL,
        current_period_end DATETIME NULL,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        CONSTRAINT fk_billing_sub_user FOREIGN KEY (user_id) REFERENCES UserAccount(user_id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";

    await using (var cmd = new MySqlCommand(subscriptionSql, conn))
    {
        await cmd.ExecuteNonQueryAsync(ct);
    }

    const string customerIndexSql = "CREATE INDEX IF NOT EXISTS ix_billing_customer_stripe ON BillingCustomer(stripe_customer_id)";
    await using (var indexCmd = new MySqlCommand(customerIndexSql, conn))
    {
        await indexCmd.ExecuteNonQueryAsync(ct);
    }
}

async Task EnsureAnalyticsEventTableAsync(MySqlConnection conn, CancellationToken ct)
{
    const string analyticsSql = @"CREATE TABLE IF NOT EXISTS AnalyticsEvent (
  event_id        BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  event_uuid      CHAR(36)  NOT NULL,
  event_version   TINYINT   NOT NULL DEFAULT 1,
  env             ENUM('prod','stg','dev') NOT NULL DEFAULT 'prod',

  occurred_at     DATETIME(3) NOT NULL,
  received_at     DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

  event_name      VARCHAR(64) NOT NULL,
  user_id         BIGINT UNSIGNED NULL,
  session_id      CHAR(36)  NOT NULL,
  build_id        BIGINT UNSIGNED NULL,
  engine_family_id BIGINT UNSIGNED NULL,
  category_id     BIGINT UNSIGNED NULL,
  part_id         BIGINT UNSIGNED NULL,
  rule_id         BIGINT UNSIGNED NULL,
  severity        ENUM('info','warn','error') NULL,
  source          ENUM('create','open','clone') NULL,

  numeric_value   DECIMAL(12,3) NULL,
  extra           JSON NULL CHECK (JSON_VALID(extra)),

  user_agent      VARCHAR(255) NULL,
  ip_hash         BINARY(32) NULL,

  rule_code   VARCHAR(64) GENERATED ALWAYS AS
              (JSON_UNQUOTE(JSON_EXTRACT(extra, '$.rule_code'))) STORED,
  message_key VARCHAR(64) GENERATED ALWAYS AS
              (JSON_UNQUOTE(JSON_EXTRACT(extra, '$.message_key'))) STORED,

  CONSTRAINT uq_event_uuid UNIQUE (event_uuid),

  INDEX ix_evt_when            (occurred_at),
  INDEX ix_evt_name_when       (event_name, occurred_at),
  INDEX ix_evt_session_when    (session_id, occurred_at),
  INDEX ix_evt_user_when       (user_id, occurred_at),
  INDEX ix_evt_build_when      (build_id, occurred_at),
  INDEX ix_evt_engine_when     (engine_family_id, occurred_at),
  INDEX ix_evt_rule_when       (rule_id, occurred_at),
  INDEX ix_evt_rule_code_when  (rule_code, occurred_at),
  INDEX ix_evt_source_when     (source, occurred_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";

    await using var cmd = new MySqlCommand(analyticsSql, conn);
    await cmd.ExecuteNonQueryAsync(ct);
}

async Task SaveBillingCustomerAsync(string? connString, long userId, string customerId, CancellationToken ct)
{
    if (string.IsNullOrWhiteSpace(connString) || string.IsNullOrWhiteSpace(customerId))
        return;

    await using var conn = new MySqlConnection(connString);
    await conn.OpenAsync(ct);
    await EnsureUserAccountTableAsync(conn, ct);
    await EnsureBillingTablesAsync(conn, ct);

    const string upsertSql = @"INSERT INTO BillingCustomer(user_id, stripe_customer_id)
                               VALUES(@uid, @cid)
                               ON DUPLICATE KEY UPDATE stripe_customer_id=@cid";
    await using var cmd = new MySqlCommand(upsertSql, conn);
    cmd.Parameters.AddWithValue("@uid", userId);
    cmd.Parameters.AddWithValue("@cid", customerId);
    await cmd.ExecuteNonQueryAsync(ct);
}

async Task SaveBillingSubscriptionAsync(string? connString, long userId, string subscriptionId, string planCode, string status, DateTime? periodEnd, CancellationToken ct)
{
    if (string.IsNullOrWhiteSpace(connString) || string.IsNullOrWhiteSpace(subscriptionId))
        return;

    await using var conn = new MySqlConnection(connString);
    await conn.OpenAsync(ct);
    await EnsureUserAccountTableAsync(conn, ct);
    await EnsureBillingTablesAsync(conn, ct);

    const string upsertSql = @"INSERT INTO BillingSubscription(user_id, stripe_subscription_id, plan_code, status, current_period_end)
                               VALUES(@uid, @sid, @plan, @status, @periodEnd)
                               ON DUPLICATE KEY UPDATE stripe_subscription_id=@sid, plan_code=@plan, status=@status, current_period_end=@periodEnd";
    await using var cmd = new MySqlCommand(upsertSql, conn);
    cmd.Parameters.AddWithValue("@uid", userId);
    cmd.Parameters.AddWithValue("@sid", subscriptionId);
    cmd.Parameters.AddWithValue("@plan", planCode);
    cmd.Parameters.AddWithValue("@status", status);
    cmd.Parameters.AddWithValue("@periodEnd", (object?)periodEnd ?? DBNull.Value);
    await cmd.ExecuteNonQueryAsync(ct);
}

async Task<long?> FindUserIdByCustomerAsync(string? connString, string customerId, CancellationToken ct)
{
    if (string.IsNullOrWhiteSpace(connString) || string.IsNullOrWhiteSpace(customerId))
        return null;

    await using var conn = new MySqlConnection(connString);
    await conn.OpenAsync(ct);
    await EnsureBillingTablesAsync(conn, ct);

    const string sql = "SELECT user_id FROM BillingCustomer WHERE stripe_customer_id=@cid LIMIT 1";
    await using var cmd = new MySqlCommand(sql, conn);
    cmd.Parameters.AddWithValue("@cid", customerId);
    var result = await cmd.ExecuteScalarAsync(ct);
    return result is null ? null : Convert.ToInt64(result);
}

async Task<bool> ViewExistsAsync(MySqlConnection conn, string viewName, CancellationToken ct)
{
    await using var cmd = new MySqlCommand("SELECT 1 FROM information_schema.VIEWS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = @view LIMIT 1", conn);
    cmd.Parameters.AddWithValue("@view", viewName);
    var result = await cmd.ExecuteScalarAsync(ct);
    return result is not null;
}

async Task<bool> TableExistsAsync(MySqlConnection conn, string tableName, CancellationToken ct)
{
    await using var cmd = new MySqlCommand("SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = @table LIMIT 1", conn);
    cmd.Parameters.AddWithValue("@table", tableName);
    var result = await cmd.ExecuteScalarAsync(ct);
    return result is not null;
}

async Task EnsurePlanQuotaFunctionsAsync(MySqlConnection conn, CancellationToken ct)
{
    var statements = new[]
    {
        "DROP FUNCTION IF EXISTS user_max_active_builds",
        @"CREATE FUNCTION user_max_active_builds(p_user_id BIGINT) RETURNS INT
            READS SQL DATA
        BEGIN
            DECLARE v INT;
            SELECT pl.max_active_builds INTO v
            FROM v_user_limits ul
            JOIN PlanLimits pl ON pl.plan_id = ul.plan_id
            WHERE ul.user_id = p_user_id
            LIMIT 1;
            RETURN COALESCE(v, 0);
        END",
        "DROP FUNCTION IF EXISTS user_max_total_builds",
        @"CREATE FUNCTION user_max_total_builds(p_user_id BIGINT) RETURNS INT
            READS SQL DATA
        BEGIN
            DECLARE v INT;
            SELECT pl.max_total_builds INTO v
            FROM v_user_limits ul
            JOIN PlanLimits pl ON pl.plan_id = ul.plan_id
            WHERE ul.user_id = p_user_id
            LIMIT 1;
            RETURN COALESCE(v, 0);
        END",
        "DROP FUNCTION IF EXISTS user_active_builds",
        @"CREATE FUNCTION user_active_builds(p_user_id BIGINT) RETURNS INT
            READS SQL DATA
        BEGIN
            DECLARE v INT;
            SELECT COUNT(*) INTO v FROM Build WHERE user_id = p_user_id AND is_archived = FALSE;
            RETURN COALESCE(v, 0);
        END",
        "DROP FUNCTION IF EXISTS user_total_builds",
        @"CREATE FUNCTION user_total_builds(p_user_id BIGINT) RETURNS INT
            READS SQL DATA
        BEGIN
            DECLARE v INT;
            SELECT COUNT(*) INTO v FROM Build WHERE user_id = p_user_id;
            RETURN COALESCE(v, 0);
        END"
    };

    foreach (var sql in statements)
    {
        await using var cmd = new MySqlCommand(sql, conn);
        await cmd.ExecuteNonQueryAsync(ct);
    }
}

async Task EnsurePlanQuotaTriggersAsync(MySqlConnection conn, CancellationToken ct)
{
    var statements = new[]
    {
        "DROP TRIGGER IF EXISTS trg_build_before_insert",
        @"CREATE TRIGGER trg_build_before_insert
            BEFORE INSERT ON Build
            FOR EACH ROW
        BEGIN
            IF NEW.user_id IS NULL THEN
                SIGNAL SQLSTATE '45000'
                    SET MESSAGE_TEXT = 'User is required to create a build.';
            END IF;

            IF user_total_builds(NEW.user_id) >= user_max_total_builds(NEW.user_id) THEN
                SIGNAL SQLSTATE '45000'
                    SET MESSAGE_TEXT = 'Total build quota exceeded for this plan.';
            END IF;

            IF COALESCE(NEW.is_archived, FALSE) = FALSE AND
               user_active_builds(NEW.user_id) >= user_max_active_builds(NEW.user_id) THEN
                SIGNAL SQLSTATE '45000'
                    SET MESSAGE_TEXT = 'Active build quota exceeded for this plan.';
            END IF;
        END",
        "DROP TRIGGER IF EXISTS trg_build_before_update",
        @"CREATE TRIGGER trg_build_before_update
            BEFORE UPDATE ON Build
            FOR EACH ROW
        BEGIN
            IF OLD.is_archived = TRUE AND NEW.is_archived = FALSE THEN
                IF user_active_builds(OLD.user_id) >= user_max_active_builds(OLD.user_id) THEN
                    SIGNAL SQLSTATE '45000'
                        SET MESSAGE_TEXT = 'Cannot unarchive: active build quota would be exceeded.';
                END IF;
            END IF;

            IF NEW.user_id IS NOT NULL AND NEW.user_id <> OLD.user_id THEN
                IF user_total_builds(NEW.user_id) >= user_max_total_builds(NEW.user_id) THEN
                    SIGNAL SQLSTATE '45000'
                        SET MESSAGE_TEXT = 'Cannot transfer: recipient total build quota would be exceeded.';
                END IF;

                IF COALESCE(NEW.is_archived, FALSE) = FALSE AND
                   user_active_builds(NEW.user_id) >= user_max_active_builds(NEW.user_id) THEN
                    SIGNAL SQLSTATE '45000'
                        SET MESSAGE_TEXT = 'Cannot transfer: recipient active build quota would be exceeded.';
                END IF;
            END IF;
        END"
    };

    foreach (var sql in statements)
    {
        await using var cmd = new MySqlCommand(sql, conn);
        await cmd.ExecuteNonQueryAsync(ct);
    }
}

async Task EnsureBuildSummaryViewsAsync(MySqlConnection conn, CancellationToken ct)
{
    await SchemaHelpers.EnsureEngineFamilyColumnsAsync(conn, ct);
    await SchemaHelpers.EnsureCategoryRequirementColumnsAsync(conn, ct);

    const string categoryViewSql = """
CREATE OR REPLACE VIEW v_build_category_completion AS
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
engine_attr AS (
  SELECT
    eav.engine_family_id,
    MAX(CASE WHEN ad.code = 'primary_injector_cc' THEN eav.val_int END)        AS primary_injector_cc,
    MAX(CASE WHEN ad.code = 'secondary_injector_cc' THEN eav.val_int END)       AS secondary_injector_cc,
    MAX(CASE WHEN ad.code = 'fuel_pressure_base' THEN eav.val_decimal END)      AS fuel_pressure_base,
    MAX(CASE WHEN ad.code = 'intake_port_area_mm2' THEN eav.val_decimal END)    AS intake_port_area_mm2,
    MAX(CASE WHEN ad.code = 'exhaust_port_area_mm2' THEN eav.val_decimal END)   AS exhaust_port_area_mm2
  FROM EngineAttributeValue eav
  JOIN EngineAttributeDef ad ON ad.engine_attr_id = eav.engine_attr_id
  WHERE ad.code IN ('primary_injector_cc','secondary_injector_cc','fuel_pressure_base','intake_port_area_mm2','exhaust_port_area_mm2')
  GROUP BY eav.engine_family_id
),
req_resolved AS (
  SELECT
    r.engine_family_id,
    COALESCE(r.tree_id, 0) AS tree_id0,
    r.category_id,
    r.requirement_type,
    r.req_mode,
    r.required_qty,
    r.formula,
    r.multiplier,
    r.operand_field,
    r.round_mode
  FROM CategoryRequirement r
),
base_requirements AS (
  SELECT
    inner_req.build_id,
    inner_req.engine_family_id,
    inner_req.tree_id0,
    inner_req.category_id,
    inner_req.requirement_type,
    inner_req.req_mode,
    inner_req.formula,
    inner_req.multiplier,
    inner_req.operand_field,
    inner_req.round_mode,
    CASE
      WHEN inner_req.req_mode = 'structured' THEN
        CASE inner_req.round_mode
          WHEN 'ceil'  THEN CEILING(inner_req.struct_operand)
          WHEN 'floor' THEN FLOOR(inner_req.struct_operand)
          WHEN 'round' THEN ROUND(inner_req.struct_operand)
          ELSE inner_req.struct_operand
        END
      WHEN inner_req.req_mode IN ('exact_count','min_count') THEN inner_req.required_qty_raw
      ELSE inner_req.required_qty_raw
    END AS required_qty,
    inner_req.struct_operand
  FROM (
    SELECT
      b.build_id,
      b.engine_family_id,
      b.tree_id0,
      rr.category_id,
      rr.requirement_type,
      rr.req_mode,
      rr.formula,
      rr.multiplier,
      rr.operand_field,
      rr.round_mode,
      rr.required_qty AS required_qty_raw,
      CASE
        WHEN rr.req_mode = 'structured' AND rr.multiplier IS NOT NULL THEN
          rr.multiplier * (
            CASE rr.operand_field
              WHEN 'rotor_count'           THEN CAST(ef.rotor_count AS DECIMAL(18,6))
              WHEN 'hp_min'                THEN CAST(ef.hp_min AS DECIMAL(18,6))
              WHEN 'hp_max'                THEN CAST(ef.hp_max AS DECIMAL(18,6))
              WHEN 'primary_injector_cc'   THEN CAST(ea.primary_injector_cc AS DECIMAL(18,6))
              WHEN 'secondary_injector_cc' THEN CAST(ea.secondary_injector_cc AS DECIMAL(18,6))
              WHEN 'fuel_pressure_base'    THEN ea.fuel_pressure_base
              WHEN 'intake_port_area_mm2'  THEN ea.intake_port_area_mm2
              WHEN 'exhaust_port_area_mm2' THEN ea.exhaust_port_area_mm2
              ELSE NULL
            END
          )
        ELSE NULL
      END AS struct_operand
    FROM (SELECT DISTINCT build_id, engine_family_id, tree_id0 FROM selected) b
    JOIN req_resolved rr
      ON rr.engine_family_id = b.engine_family_id
     AND (rr.tree_id0 = b.tree_id0 OR rr.tree_id0 = 0)
    JOIN EngineFamily ef ON ef.engine_family_id = b.engine_family_id
    LEFT JOIN engine_attr ea ON ea.engine_family_id = b.engine_family_id
  ) inner_req
),
finalized AS (
  SELECT
    br.build_id,
    br.engine_family_id,
    br.tree_id0,
    br.category_id,
    c.name AS category_name,
    br.requirement_type,
    br.req_mode,
    br.formula,
    br.required_qty,
    COALESCE(cs.pieces_supplied, 0) AS pieces_supplied,
    br.struct_operand,
    br.multiplier,
    br.operand_field,
    br.round_mode
  FROM base_requirements br
  LEFT JOIN category_supply cs
    ON cs.build_id = br.build_id
   AND cs.category_id = br.category_id
  JOIN Category c ON c.category_id = br.category_id
)
SELECT
  f.build_id,
  f.engine_family_id,
  f.tree_id0 AS tree_id_or_global,
  f.category_id,
  f.category_name,
  f.req_mode,
  f.requirement_type,
  f.formula,
  f.required_qty,
  f.pieces_supplied,
  CASE
    WHEN f.req_mode IN ('exact_count','min_count','structured') AND f.required_qty IS NOT NULL
      THEN GREATEST(f.required_qty - f.pieces_supplied, 0)
    ELSE NULL
  END AS pieces_missing,
  CASE
    WHEN f.req_mode = 'formula' OR f.required_qty IS NULL THEN 'needs_formula_eval'
    WHEN f.req_mode = 'exact_count' THEN CASE WHEN f.pieces_supplied = f.required_qty THEN 'complete' ELSE 'incomplete' END
    WHEN f.req_mode IN ('min_count','structured') THEN CASE WHEN f.pieces_supplied >= f.required_qty THEN 'complete' ELSE 'incomplete' END
    ELSE 'needs_formula_eval'
  END AS status,
  f.multiplier,
  f.operand_field,
  f.round_mode,
  f.struct_operand
FROM finalized f;
""";

    await using (var cmd = new MySqlCommand(categoryViewSql, conn))
    {
        await cmd.ExecuteNonQueryAsync(ct);
    }

    const string costViewSql = @"CREATE OR REPLACE VIEW v_build_cost_summary AS
        SELECT
          bs.build_id,
          SUM(bs.qty * bo.best_price) AS estimated_cost_lowest
        FROM BuildSelection bs
        JOIN v_part_best_offering bo ON bo.part_id = bs.part_id
        GROUP BY bs.build_id;";

    await using (var cmd = new MySqlCommand(costViewSql, conn))
    {
        await cmd.ExecuteNonQueryAsync(ct);
    }

    const string summaryViewSql = @"CREATE OR REPLACE VIEW v_build_summary AS
        SELECT
          b.build_id,
          COUNT(v.category_id)                        AS categories_total,
          SUM(CASE WHEN v.status = 'complete' THEN 1 ELSE 0 END)       AS categories_complete,
          SUM(CASE WHEN v.status = 'incomplete' THEN 1 ELSE 0 END)     AS categories_incomplete,
          CASE
            WHEN COUNT(v.category_id) = 0 THEN 0
            ELSE ROUND(SUM(CASE WHEN v.status = 'complete' THEN 1 ELSE 0 END) / COUNT(v.category_id) * 100, 2)
          END AS completion_pct,
          SUM(COALESCE(v.pieces_missing, 0))          AS total_pieces_missing,
          cost.estimated_cost_lowest
        FROM Build b
        LEFT JOIN v_build_category_completion v ON v.build_id = b.build_id
        LEFT JOIN v_build_cost_summary cost ON cost.build_id = b.build_id
        GROUP BY b.build_id, cost.estimated_cost_lowest;";

    await using (var cmd = new MySqlCommand(summaryViewSql, conn))
    {
        await cmd.ExecuteNonQueryAsync(ct);
    }
}

// Perplexity + Ingestion
builder.Services.Configure<PerplexityOptions>(builder.Configuration.GetSection("Perplexity"));
// Fallback: map common env var names if 'Perplexity__*' not used
builder.Services.PostConfigure<PerplexityOptions>(opts =>
{
    var cfg = builder.Configuration;
    if (string.IsNullOrWhiteSpace(opts.ApiKey))
        opts.ApiKey = cfg["Perplexity__ApiKey"] ?? cfg["PERPLEXITY_API_KEY"] ?? cfg["Perplexity:ApiKey"];
    if (string.IsNullOrWhiteSpace(opts.BaseUrl) || opts.BaseUrl == "https://api.perplexity.ai")
        opts.BaseUrl = cfg["Perplexity__BaseUrl"] ?? cfg["PERPLEXITY_API_BASE"] ?? cfg["Perplexity:BaseUrl"] ?? opts.BaseUrl;
    if (string.IsNullOrWhiteSpace(opts.Model) || opts.Model == "sonar-large-online")
        opts.Model = cfg["Perplexity__Model"] ?? cfg["PERPLEXITY_MODEL"] ?? cfg["Perplexity:Model"] ?? opts.Model;
});
builder.Services.AddHttpClient<PerplexityClient>(client => { });
builder.Services.AddScoped<IngestionService>();

var app = builder.Build();

// Pull the connection string (supports both Default and DefaultConnection keys)
var connectionString =
    app.Configuration.GetConnectionString("Default")
    ?? app.Configuration.GetConnectionString("DefaultConnection")
    ?? app.Configuration["ConnectionStrings:Default"]
    ?? app.Configuration["ConnectionStrings:DefaultConnection"];

var analyticsEnv = app.Environment.IsDevelopment()
    ? "dev"
    : app.Environment.IsStaging()
        ? "stg"
        : "prod";

var analyticsAllowedEvents = new HashSet<string>(new[]
{
    "build_opened",
    "part_added_to_build",
    "category_completed",
    "build_completed",
    "rule_error_shown",
    "rule_warn_shown",
    "offer_click"
}, StringComparer.OrdinalIgnoreCase);

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

if (!app.Environment.IsDevelopment())
{
    app.UseHttpsRedirection();
}

app.UseAuthentication();
app.UseAuthorization();

app.UseAntiforgery();

var staticFileProvider = new FileExtensionContentTypeProvider();
staticFileProvider.Mappings[".glb"] = "model/gltf-binary";
staticFileProvider.Mappings[".gltf"] = "model/gltf+json";
app.UseStaticFiles(new StaticFileOptions
{
    ContentTypeProvider = staticFileProvider
});
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

// DB Health check
app.MapGet("/health/db", async () =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings:Default not set", statusCode: 500);

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync();
        await using var cmd = new MySqlCommand("SELECT VERSION()", conn);
        var version = (string?)await cmd.ExecuteScalarAsync();
        return Results.Json(new { ok = true, version });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "DB connection failed", detail: ex.Message, statusCode: 500);
    }
});

app.MapGet("/api/me/gamification/summary", async (IGamification g, HttpContext ctx) =>
{
    var userId = ctx.User.TryGetUserId();
    if (userId is null) return Results.Unauthorized();

    var (points, streak, best, badges) = await g.GetSummaryAsync(userId.Value);
    return Results.Ok(new { points, streak, best, badges });
}).RequireAuthorization("IsSignedIn");

app.MapGet("/api/me/points", async (Func<MySqlConnection> dbFactory, HttpContext ctx, int page, int pageSize, CancellationToken ct) =>
{
    var userId = ctx.User.TryGetUserId();
    if (userId is null) return Results.Unauthorized();

    page = page <= 0 ? 1 : page;
    pageSize = pageSize <= 0 ? 50 : Math.Clamp(pageSize, 1, 200);

    await using var db = dbFactory();
    await db.OpenAsync(ct);

    var rows = await db.QueryAsync(new CommandDefinition(
        @"SELECT occurred_at, points, reason, build_id, uniq_key
            FROM UserPointsLedger
           WHERE user_id=@userId
           ORDER BY occurred_at DESC
           LIMIT @take OFFSET @skip",
        new { userId = userId.Value, take = pageSize, skip = (page - 1) * pageSize },
        cancellationToken: ct));

    return Results.Ok(rows);
}).RequireAuthorization("IsSignedIn");

app.MapGet("/api/me/badges", async (Func<MySqlConnection> dbFactory, HttpContext ctx, CancellationToken ct) =>
{
    var userId = ctx.User.TryGetUserId();
    if (userId is null) return Results.Unauthorized();

    await using var db = dbFactory();
    await db.OpenAsync(ct);

    var rows = await db.QueryAsync(new CommandDefinition(
        @"SELECT b.code, b.name, b.description, b.icon_url, ub.earned_at, ub.build_id
            FROM UserBadge ub
            JOIN Badge b ON b.badge_id = ub.badge_id
           WHERE ub.user_id=@userId
           ORDER BY ub.earned_at DESC",
        new { userId = userId.Value },
        cancellationToken: ct));

    return Results.Ok(rows);
}).RequireAuthorization("IsSignedIn");

app.MapGet("/api/me/gamification/prefs", async (Func<MySqlConnection> dbFactory, HttpContext ctx, CancellationToken ct) =>
{
    var userId = ctx.User.TryGetUserId();
    if (userId is null) return Results.Unauthorized();

    await using var db = dbFactory();
    await db.OpenAsync(ct);

    var row = await db.QuerySingleOrDefaultAsync(new CommandDefinition(
        @"SELECT show_points, show_badges, email_opt_in, streak_grace_days, timezone
            FROM UserGamificationPrefs
           WHERE user_id=@userId",
        new { userId = userId.Value },
        cancellationToken: ct));

    return Results.Ok(row);
}).RequireAuthorization("IsSignedIn");

app.MapPut("/api/me/gamification/prefs", async (Func<MySqlConnection> dbFactory, HttpContext ctx, UserPrefsDto dto, CancellationToken ct) =>
{
    var userId = ctx.User.TryGetUserId();
    if (userId is null) return Results.Unauthorized();

    var grace = Math.Clamp(dto.StreakGraceDays, 0, 3);
    var tz = string.IsNullOrWhiteSpace(dto.Timezone) ? "UTC" : dto.Timezone.Trim();

    await using var db = dbFactory();
    await db.OpenAsync(ct);

    await db.ExecuteAsync(new CommandDefinition(
        @"INSERT INTO UserGamificationPrefs(user_id, show_points, show_badges, email_opt_in, streak_grace_days, timezone)
          VALUES(@userId, @sp, @sb, @io, @grace, @tz)
          ON DUPLICATE KEY UPDATE
            show_points=@sp,
            show_badges=@sb,
            email_opt_in=@io,
            streak_grace_days=@grace,
            timezone=@tz",
        new
        {
            userId = userId.Value,
            sp = dto.ShowPoints,
            sb = dto.ShowBadges,
            io = dto.EmailOptIn,
            grace,
            tz
        },
        cancellationToken: ct));

    return Results.NoContent();
}).RequireAuthorization("IsSignedIn");

app.MapGet("/api/me/gamification/recent", async (Func<MySqlConnection> dbFactory, HttpContext ctx, DateTime? since, CancellationToken ct) =>
{
    var userId = ctx.User.TryGetUserId();
    if (userId is null) return Results.Unauthorized();

    var cutoff = since ?? DateTime.UtcNow.AddMinutes(-2);

    await using var db = dbFactory();
    await db.OpenAsync(ct);

    var rows = await db.QueryAsync(new CommandDefinition(
        @"SELECT occurred_at, points, reason, build_id, uniq_key
            FROM UserPointsLedger
           WHERE user_id=@userId AND occurred_at >= @cutoff
           ORDER BY occurred_at ASC",
        new { userId = userId.Value, cutoff },
        cancellationToken: ct));

    return Results.Ok(rows);
}).RequireAuthorization("IsSignedIn");

app.MapGet("/api/builds/{buildId:long}/slots/status", async (
    long buildId,
    Func<MySqlConnection> dbFactory,
    CancellationToken ct) =>
{
    await using var db = dbFactory();
    await db.OpenAsync(ct);

    const string sql = @"
      WITH counts AS (
        SELECT slot_id, COUNT(*) AS cnt
          FROM BuildSlotSelection
         WHERE build_id = @buildId
         GROUP BY slot_id
      ),
      selection AS (
        SELECT bss.slot_id,
               bss.part_id,
               p.name             AS part_name,
               p.gltf_uri         AS gltf_uri,
               p.gltf_attach_node AS gltf_attach_node
          FROM BuildSlotSelection bss
          JOIN Part p ON p.part_id = bss.part_id
         WHERE bss.build_id = @buildId
      )
      SELECT
        s.slot_id                        AS slot_id,
        s.key                             AS slot_key,
        s.gltf_node_path,
        s.min_required,
        s.capacity,
        COALESCE(c.cnt, 0)               AS selected_count,
        CASE
          WHEN COALESCE(c.cnt, 0) BETWEEN s.min_required AND s.capacity THEN 1
          ELSE 0
        END                              AS local_complete,
        sel.part_id,
        sel.part_name,
        sel.gltf_uri,
        sel.gltf_attach_node
      FROM Slot s
      JOIN Build b ON b.engine_family_id = s.engine_family_id
      LEFT JOIN counts c ON c.slot_id = s.slot_id
      LEFT JOIN selection sel ON sel.slot_id = s.slot_id
     WHERE b.build_id = @buildId
     ORDER BY s.key;";

    var rows = await db.QueryAsync(new CommandDefinition(sql, new { buildId }, cancellationToken: ct));
    return Results.Ok(rows);
});

app.MapGet("/api/builds/{buildId:long}/badges", async (
    long buildId,
    Func<MySqlConnection> dbFactory,
    HttpContext ctx,
    ILogger<Program> logger,
    CancellationToken ct) =>
{
    await using var db = dbFactory();
    await db.OpenAsync(ct);

    const string sql = @"
WITH counts AS (
    SELECT slot_id, COUNT(*) AS cnt
      FROM BuildSlotSelection
     WHERE build_id = @buildId
     GROUP BY slot_id
),
latest_selection AS (
    SELECT bs.slot_id, bs.part_id
      FROM BuildSlotSelection bs
     WHERE bs.build_id = @buildId
     ORDER BY bs.added_at DESC
)
SELECT
    CAST(s.slot_id AS SIGNED)        AS SlotId,
    s.`key`                          AS SlotKey,
    s.`name`                         AS SlotName,
    s.gltf_node_path                 AS GltfNodePath,
    CAST(ss.subsystem_id AS SIGNED)  AS SubsystemId,
    ss.`key`                         AS SubsystemKey,
    ss.`name`                        AS SubsystemName,
    COALESCE(c.cnt, 0)               AS SelectedCount,
    s.min_required                   AS MinRequired,
    s.capacity                       AS Capacity,
    CAST(ls.part_id AS SIGNED)       AS PartId,
    p.`name`                         AS PartName,
    p.gltf_uri                       AS PartGltfUri,
    p.gltf_attach_node               AS PartGltfAttachNode,
    CASE
        WHEN COALESCE(c.cnt, 0) BETWEEN s.min_required AND s.capacity THEN TRUE
        ELSE FALSE
    END                              AS LocalOk
  FROM Slot s
  JOIN Build b ON b.engine_family_id = s.engine_family_id
  LEFT JOIN counts c ON c.slot_id = s.slot_id
  LEFT JOIN latest_selection ls ON ls.slot_id = s.slot_id
  LEFT JOIN Part p ON p.part_id = ls.part_id
  LEFT JOIN Subsystem ss ON ss.subsystem_id = s.subsystem_id
 WHERE b.build_id = @buildId
 ORDER BY ss.sort_order, s.`key`;";

    var slotRows = (await db.QueryAsync<SlotBadgeRow>(new CommandDefinition(
        sql,
        new { buildId },
        cancellationToken: ct))).ToList();

    var hints = await EvaluateRuleHintsAsync(db, buildId, ct);

    var subsystems = slotRows
        .Where(s => s.SubsystemId.HasValue)
        .GroupBy(s => s.SubsystemId!.Value)
        .Select(g =>
        {
            var okSlots = g.Count(x => x.LocalOk);
            var total = g.Count();
            var first = g.First();
            return new
            {
                subsystem_id = g.Key,
                subsystem_key = first.SubsystemKey,
                subsystem_name = first.SubsystemName,
                ok_slots = okSlots,
                total_slots = total,
                badge = okSlots == total && total > 0 ? "✅" : "🔴"
            };
        })
        .ToList();

    var totalSlots = slotRows.Count;
    var okCount = slotRows.Count(s => s.LocalOk);
    var completionPct = totalSlots == 0
        ? 0d
        : Math.Round(100d * okCount / totalSlots, 1, MidpointRounding.AwayFromZero);

    var slotsPayload = slotRows.Select(s => new
    {
        slot_id = s.SlotId,
        slot_key = s.SlotKey,
        slot_name = s.SlotName,
        gltf_node_path = s.GltfNodePath,
        subsystem_id = s.SubsystemId,
        subsystem_key = s.SubsystemKey,
        subsystem_name = s.SubsystemName,
        selected_count = s.SelectedCount,
        min_required = s.MinRequired,
        capacity = s.Capacity,
        local_ok = s.LocalOk,
        part_id = s.PartId,
        part_name = s.PartName,
        gltf_uri = s.PartGltfUri,
        gltf_attach_node = s.PartGltfAttachNode
    }).ToList();

    var debugMode = ctx.Request.Query.TryGetValue("debug", out var debugParam)
        && string.Equals(debugParam.ToString(), "1", StringComparison.OrdinalIgnoreCase);

    if (logger.IsEnabled(LogLevel.Debug))
    {
        logger.LogDebug("Badges request build {BuildId}: slots={SlotCount}, ok={OkCount}, completion={CompletionPct}",
            buildId, totalSlots, okCount, completionPct);
    }

    if (debugMode)
    {
        ctx.Response.Headers["X-Engine-Badges-Debug"] = JsonSerializer.Serialize(new
        {
            slot_count = totalSlots,
            ok_count = okCount,
            sockets = slotRows
                .Select(s => s.GltfNodePath)
                .Where(p => !string.IsNullOrWhiteSpace(p))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(12)
        });
    }

    return Results.Ok(new
    {
        slots = slotsPayload,
        subsystems,
        completion_pct = completionPct,
        hints = new
        {
            requires = hints.Requires,
            match_attr = hints.MatchAttr,
            excludes = hints.Excludes
        },
        debug = debugMode
            ? new
            {
                slot_count = totalSlots,
                ok_count = okCount,
                sample_slots = slotRows
                    .Take(8)
                    .Select(s => new { s.SlotId, s.SlotKey, s.GltfNodePath, s.LocalOk })
            }
            : null
    });
});

app.MapGet("/api/builds/{buildId:long}/rules/violations", async (
    long buildId,
    Func<MySqlConnection> dbFactory,
    CancellationToken ct) =>
{
    await using var db = dbFactory();
    await db.OpenAsync(ct);
    var hints = await EvaluateRuleHintsAsync(db, buildId, ct);
    return Results.Ok(new
    {
        requires = hints.Requires,
        match_attr = hints.MatchAttr,
        excludes = hints.Excludes
    });
});

static async Task<long?> ResolveSlotIdAsync(MySqlConnection db, long buildId, string socketKey, string normalizedSocket, CancellationToken ct)
{
    var raw = socketKey;
    var underscored = socketKey.Replace(' ', '_');
    var spaced = socketKey.Replace('_', ' ');
    var normalizedKey = string.IsNullOrWhiteSpace(normalizedSocket) ? null : normalizedSocket;

    const string sql = @"
SELECT CAST(s.slot_id AS SIGNED)
  FROM Build b
  JOIN Slot s ON s.engine_family_id = b.engine_family_id
  LEFT JOIN slot_socket_alias a ON a.slot_id = s.slot_id
 WHERE b.build_id = @buildId
   AND (
          s.gltf_node_path = @raw
       OR s.gltf_node_path = @underscored
       OR s.gltf_node_path = @spaced
       OR REPLACE(s.gltf_node_path, ' ', '_') = @underscored
       OR REPLACE(s.gltf_node_path, '_', ' ') = @spaced
       OR (@normalizedKey IS NOT NULL AND LOWER(s.`key`) = @normalizedKey)
       OR (@normalizedKey IS NOT NULL AND s.`key` = @normalizedKey)
       OR (@normalizedKey IS NOT NULL AND s.gltf_node_path = @normalizedKey)
       OR (@normalizedKey IS NOT NULL AND REPLACE(s.gltf_node_path, ' ', '_') = @normalizedKey)
       OR a.alias = @raw
      )
 ORDER BY s.slot_id
 LIMIT 1;";

    return await db.ExecuteScalarAsync<long?>(new CommandDefinition(
        sql,
        new { buildId, raw, underscored, spaced, normalizedKey },
        cancellationToken: ct));
}

static async Task<List<SocketMatchRow>> ResolveSocketCandidatesAsync(MySqlConnection db, long buildId, string socketKey, string normalizedSocket, CancellationToken ct)
{
    const string resolveSql = @"
SELECT CAST(s.slot_id AS SIGNED) AS SlotId,
       s.`key`                   AS SlotKey,
       s.gltf_node_path          AS GltfNodePath,
       ss.`name`                 AS SubsystemName
  FROM Build b
  JOIN Slot s ON s.engine_family_id = b.engine_family_id
  LEFT JOIN Subsystem ss ON ss.subsystem_id = s.subsystem_id
 WHERE b.build_id = @buildId;";

    var raw = await db.QueryAsync<SocketMatchRow>(new CommandDefinition(resolveSql, new { buildId }, cancellationToken: ct));
    var list = new List<SocketMatchRow>();

    foreach (var row in raw)
    {
        var reason = "no_match";
        var priority = 9;

        if (!string.IsNullOrEmpty(row.GltfNodePath) && string.Equals(row.GltfNodePath, socketKey, StringComparison.OrdinalIgnoreCase))
        {
            priority = 0;
            reason = "gltf_exact";
        }
        else if (!string.IsNullOrEmpty(row.GltfNodePath) && row.GltfNodePath.Contains(socketKey, StringComparison.OrdinalIgnoreCase))
        {
            priority = 1;
            reason = "gltf_contains";
        }
        else
        {
            var normalizedPath = NormalizeSocketKey(row.GltfNodePath);
            if (!string.IsNullOrEmpty(normalizedPath) && normalizedPath == normalizedSocket)
            {
                priority = 2;
                reason = "gltf_normalized";
            }
            else
            {
                var normalizedKey = NormalizeSocketKey(row.SlotKey);
                if (!string.IsNullOrEmpty(normalizedKey) && normalizedKey == normalizedSocket)
                {
                    priority = 3;
                    reason = "slot_key";
                }
                else if (!string.IsNullOrEmpty(row.SlotKey) && row.SlotKey.Equals(socketKey, StringComparison.OrdinalIgnoreCase))
                {
                    priority = 4;
                    reason = "slot_key_exact";
                }
            }
        }

        row.Priority = priority;
        row.Reason = reason;
        list.Add(row);
    }

    return list
        .OrderBy(r => r.Priority)
        .ThenBy(r => r.SlotId)
        .ToList();
}

static void AttachSocketDebugHeader(HttpContext ctx, bool debugMode, string socketKey, string normalized, IEnumerable<SocketMatchRow> candidates, SocketMatchRow? match, int? optionCount)
{
    if (!debugMode)
    {
        return;
    }

    var payload = new
    {
        socket = socketKey,
        normalized,
        match,
        option_count = optionCount,
        candidates = candidates
            .OrderBy(c => c.Priority)
            .ThenBy(c => c.SlotId)
            .Take(10)
            .Select(c => new { c.SlotId, c.SlotKey, c.GltfNodePath, c.Priority, c.Reason, c.SubsystemName })
    };

    ctx.Response.Headers["X-EngineSocket-Debug"] = JsonSerializer.Serialize(payload);
}

app.MapGet("/api/builds/{buildId:long}/categories", async (
    long buildId,
    Func<MySqlConnection> dbFactory,
    CancellationToken ct) =>
{
    await using var db = dbFactory();
    await db.OpenAsync(ct);

    var rows = await db.QueryAsync(new CommandDefinition(
        @"SELECT DISTINCT
                 CAST(c.category_id AS SIGNED) AS CategoryId,
                 COALESCE(c.slug, CONCAT('cat:', c.category_id)) AS CategoryKey,
                 c.`name`                      AS CategoryName,
                 CAST(s.slot_id AS SIGNED)     AS SlotId,
                 s.`key`                       AS SlotKey,
                 s.gltf_node_path              AS GltfNodePath,
                 ss.`name`                     AS SubsystemName
            FROM Build b
            JOIN Slot s ON s.engine_family_id = b.engine_family_id
            JOIN PartSlot ps ON ps.slot_id = s.slot_id AND ps.category_id IS NOT NULL AND ps.allow = 1
            JOIN Category c ON c.category_id = ps.category_id
            LEFT JOIN Subsystem ss ON ss.subsystem_id = s.subsystem_id
           WHERE b.build_id = @buildId
             AND EXISTS (
                   SELECT 1
                     FROM PartCategory pc
                     JOIN Part p ON p.part_id = pc.part_id
                    WHERE pc.category_id = c.category_id
                      AND (
                           NOT EXISTS (
                               SELECT 1
                                 FROM PartFitment pf
                                WHERE pf.part_id = p.part_id
                           )
                        OR EXISTS (
                               SELECT 1
                                 FROM PartFitment pf
                                WHERE pf.part_id = p.part_id
                                  AND pf.engine_family_id = b.engine_family_id
                           )
                      )
                 )
        ORDER BY ss.sort_order, c.`name`, s.`key`;",
        new { buildId },
        cancellationToken: ct));

    return Results.Ok(rows);
});

app.MapGet("/api/builds/{buildId:long}/category/{categoryId:long}/parts", async (
    long buildId,
    long categoryId,
    Func<MySqlConnection> dbFactory,
    CancellationToken ct) =>
{
    await using var db = dbFactory();
    await db.OpenAsync(ct);

    var parts = await db.QueryAsync(new CommandDefinition(
        @"WITH category_slots AS (
              SELECT DISTINCT s.slot_id
                FROM Build b
                JOIN Slot s ON s.engine_family_id = b.engine_family_id
                JOIN PartSlot ps ON ps.slot_id = s.slot_id
               WHERE b.build_id = @buildId
                 AND ps.category_id = @categoryId
           ),
           allowed_parts AS (
              SELECT DISTINCT COALESCE(ps.part_id, pc.part_id) AS part_id
                FROM category_slots cs
                JOIN PartSlot ps ON ps.slot_id = cs.slot_id
                LEFT JOIN PartCategory pc ON pc.category_id = ps.category_id
               WHERE ps.allow = 1
                 AND (ps.category_id IS NULL OR ps.category_id = @categoryId)
           ),
           blocked_parts AS (
              SELECT DISTINCT ps.part_id
                FROM category_slots cs
                JOIN PartSlot ps ON ps.slot_id = cs.slot_id
               WHERE ps.allow = 0
                 AND ps.part_id IS NOT NULL
           )
           SELECT DISTINCT
                  CAST(p.part_id AS SIGNED)                   AS Id,
                  p.`name`                                    AS Name,
                  p.sku                                       AS Sku,
                  p.gltf_uri                                  AS GltfUri,
                  COALESCE(p.gltf_attach_node, 'Attach_Main') AS GltfAttachNode
             FROM allowed_parts ap
             JOIN Part p ON p.part_id = ap.part_id
             JOIN PartCategory pc ON pc.part_id = p.part_id
             LEFT JOIN blocked_parts bp ON bp.part_id = p.part_id
             JOIN Build b ON b.build_id = @buildId
            WHERE pc.category_id = @categoryId
              AND bp.part_id IS NULL
              AND (
                   NOT EXISTS (
                       SELECT 1
                         FROM PartFitment pf
                        WHERE pf.part_id = p.part_id
                   )
                OR EXISTS (
                       SELECT 1
                         FROM PartFitment pf
                        WHERE pf.part_id = p.part_id
                          AND pf.engine_family_id = b.engine_family_id
                   )
              )
            ORDER BY p.`name`;",
        new { buildId, categoryId },
        cancellationToken: ct));

    return Results.Ok(parts);
});

app.MapGet("/api/builds/{buildId:long}/socket-to-category", async (
    long buildId,
    string socketKey,
    Func<MySqlConnection> dbFactory,
    CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(socketKey))
    {
        return Results.BadRequest(new { error = "socket_required" });
    }

    await using var db = dbFactory();
    await db.OpenAsync(ct);

    var normalized = NormalizeSocketKey(socketKey);
    var candidates = await ResolveSocketCandidatesAsync(db, buildId, socketKey, normalized, ct);
    var match = candidates
        .Where(c => c.Priority < 9)
        .OrderBy(c => c.Priority)
        .ThenBy(c => c.SlotId)
        .FirstOrDefault();

    if (match is null)
    {
        return Results.NotFound(new { error = "no_category_for_socket" });
    }

    var category = await db.QuerySingleOrDefaultAsync(new CommandDefinition(
        @"SELECT DISTINCT
                 CAST(c.category_id AS SIGNED) AS CategoryId,
                 c.`name`                      AS CategoryName
            FROM PartSlot ps
            JOIN Category c ON c.category_id = ps.category_id
           WHERE ps.slot_id = @slotId
             AND ps.category_id IS NOT NULL
        ORDER BY c.`name`
           LIMIT 1;",
        new { slotId = match.SlotId },
        cancellationToken: ct));

    if (category is null)
    {
        category = await db.QuerySingleOrDefaultAsync(new CommandDefinition(
            @"SELECT DISTINCT
                     CAST(pc.category_id AS SIGNED) AS CategoryId,
                     c.`name`                      AS CategoryName
                FROM PartSlot ps
                JOIN Part p ON p.part_id = ps.part_id
                JOIN PartCategory pc ON pc.part_id = p.part_id AND pc.is_primary = TRUE
                JOIN Category c ON c.category_id = pc.category_id
               WHERE ps.slot_id = @slotId
                 AND ps.part_id IS NOT NULL
                 AND ps.allow = 1
            ORDER BY c.`name`
               LIMIT 1;",
            new { slotId = match.SlotId },
            cancellationToken: ct));
    }

    if (category is null)
    {
        return Results.NotFound(new { error = "no_category_for_socket" });
    }

    return Results.Ok(category);
});

static string NormalizeSocketKey(string? raw)
{
    if (string.IsNullOrWhiteSpace(raw))
    {
        return string.Empty;
    }

    var value = raw.Trim();
    if (value.StartsWith("Socket_", StringComparison.OrdinalIgnoreCase))
    {
        value = value.Substring("Socket_".Length);
    }

    var sb = new StringBuilder(value.Length);
    foreach (var ch in value)
    {
        if (char.IsLetterOrDigit(ch))
        {
            sb.Append(char.ToLowerInvariant(ch));
        }
        else
        {
            sb.Append('_');
        }
    }

    var normalized = sb.ToString();
    while (normalized.Contains("__", StringComparison.Ordinal))
    {
        normalized = normalized.Replace("__", "_", StringComparison.Ordinal);
    }

    return normalized.Trim('_');
}

app.MapGet("/api/builds/{buildId:long}/socket/{socketKey}/options", async (
    long buildId,
    string socketKey,
    Func<MySqlConnection> dbFactory,
    HttpContext ctx,
    ILogger<Program> logger,
    CancellationToken ct) =>
{
    await using var db = dbFactory();
    await db.OpenAsync(ct);

    var normalized = NormalizeSocketKey(socketKey);
    var debugMode = ctx.Request.Query.TryGetValue("debug", out var debugParam)
        && string.Equals(debugParam.ToString(), "1", StringComparison.OrdinalIgnoreCase);

    var candidates = await ResolveSocketCandidatesAsync(db, buildId, socketKey, normalized, ct);

    var slotId = await ResolveSlotIdAsync(db, buildId, socketKey, normalized, ct);
    var match = slotId.HasValue
        ? candidates.FirstOrDefault(c => c.SlotId == slotId.Value)
        : null;

    if (slotId is null)
    {
        logger.LogWarning("Socket options: build {BuildId} socket {SocketKey} (norm {Normalized}) not matched to any slot",
            buildId, socketKey, normalized);
        AttachSocketDebugHeader(ctx, debugMode, socketKey, normalized, candidates, null, null);
        return Results.NotFound(new { error = "socket_not_found", socket = socketKey, normalized });
    }

    logger.LogInformation("Socket options resolved: build {BuildId} socket {SocketKey} -> slot {SlotId} ({SlotKey}) via {Reason}",
        buildId, socketKey, slotId.Value, match?.SlotKey ?? string.Empty, match?.Reason ?? "resolver");

    var slotIdValue = slotId.Value;

    var byPart = (await db.QueryAsync(new CommandDefinition(
        @"SELECT DISTINCT
                 CAST(p.part_id AS SIGNED) AS id,
                 p.name,
                 p.gltf_uri,
                 p.gltf_attach_node,
                 p.sku,
                 cat.name AS category
            FROM PartSlot ps
            JOIN Part p ON p.part_id = ps.part_id
            LEFT JOIN PartCategory pc ON pc.part_id = p.part_id AND pc.is_primary = TRUE
            LEFT JOIN Category cat ON cat.category_id = pc.category_id
           WHERE ps.slot_id = @slotId
             AND ps.part_id IS NOT NULL
             AND ps.allow = 1
           ORDER BY p.name",
        new { slotId = slotIdValue },
        cancellationToken: ct))).ToList();

    var byCategory = (await db.QueryAsync(new CommandDefinition(
        @"SELECT DISTINCT
                 CAST(p.part_id AS SIGNED) AS id,
                 p.name,
                 p.gltf_uri,
                 p.gltf_attach_node,
                 p.sku,
                 c.name AS category
            FROM PartSlot ps
            JOIN Category c ON c.category_id = ps.category_id
            JOIN PartCategory pc ON pc.category_id = ps.category_id
            JOIN Part p ON p.part_id = pc.part_id
           WHERE ps.slot_id = @slotId
             AND ps.category_id IS NOT NULL
             AND ps.allow = 1
           ORDER BY p.name",
        new { slotId = slotIdValue },
        cancellationToken: ct))).ToList();

    var options = byPart
        .Concat(byCategory)
        .GroupBy(x => (long)x.id)
        .Select(g => g.First())
        .OrderBy(x => (string?)x.name)
        .ToList();

    if (logger.IsEnabled(LogLevel.Debug))
    {
        logger.LogDebug("Socket options: slot {SlotId} returned {Count} parts",
            slotIdValue, options.Count);
    }

    AttachSocketDebugHeader(ctx, debugMode, socketKey, normalized, candidates, match, options.Count);

    return Results.Ok(options);
});

app.MapPost("/api/builds/select", async (
    SelectPart request,
    Func<MySqlConnection> dbFactory,
    ILogger<Program> logger,
    CancellationToken ct) =>
{
    await using var db = dbFactory();
    await db.OpenAsync(ct);

    long? slotId = request.SlotId;

    if (slotId is null && request.CategoryId is not null)
    {
        slotId = await db.ExecuteScalarAsync<long?>(new CommandDefinition(
            @"SELECT s.slot_id
                FROM Build b
                JOIN Slot s ON s.engine_family_id = b.engine_family_id
                JOIN PartSlot ps ON ps.slot_id = s.slot_id AND ps.category_id = @categoryId
               WHERE b.build_id = @buildId
            ORDER BY s.slot_id
               LIMIT 1;",
            new { buildId = request.BuildId, categoryId = request.CategoryId },
            cancellationToken: ct));
    }

    if (slotId is null)
    {
        logger.LogWarning("Select: build {BuildId} unable to resolve slot for part {PartId}", request.BuildId, request.PartId);
        return Results.BadRequest(new { error = "slot_not_resolved" });
    }

    var allowed = await db.ExecuteScalarAsync<long?>(new CommandDefinition(
        @"
SELECT 1
  FROM Part p
 WHERE p.part_id = @partId
   AND EXISTS (
         SELECT 1
           FROM PartSlot ps
          WHERE ps.slot_id = @slotId
            AND ps.allow = 1
            AND (
                 ps.part_id = p.part_id
              OR (
                    ps.category_id IS NOT NULL
                AND EXISTS (
                      SELECT 1
                        FROM PartCategory pc
                       WHERE pc.part_id = p.part_id
                         AND pc.category_id = ps.category_id
                   )
              )
            )
       )
 LIMIT 1;",
        new { slotId, partId = request.PartId },
        cancellationToken: ct));

    if (allowed is null)
    {
        logger.LogWarning("Select: part {PartId} not allowed for slot {SlotId}", request.PartId, slotId);
        return Results.BadRequest(new { error = "part_not_allowed_for_slot" });
    }

    var resolvedCategoryId = await db.ExecuteScalarAsync<long?>(new CommandDefinition(
        @"SELECT pc.category_id
            FROM PartCategory pc
           WHERE pc.part_id = @partId
             AND EXISTS (
                   SELECT 1
                     FROM PartSlot ps
                    WHERE ps.slot_id = @slotId
                      AND ps.allow = 1
                      AND (
                           ps.category_id = pc.category_id
                        OR ps.part_id = pc.part_id
                      )
               )
             AND EXISTS (
                   SELECT 1
                     FROM PartSlot map
                    WHERE map.slot_id = @slotId
                      AND map.category_id = pc.category_id
                      AND map.allow = 1
               )
        ORDER BY CASE WHEN @preferred IS NOT NULL AND pc.category_id = @preferred THEN 0 ELSE 1 END,
                 pc.is_primary DESC,
                 pc.display_order ASC
        LIMIT 1;",
        new { partId = request.PartId, slotId, preferred = request.CategoryId },
        cancellationToken: ct));

    if (resolvedCategoryId is null)
    {
        if (request.CategoryId.HasValue)
        {
            logger.LogWarning("Select: category {CategoryId} not mapped to slot {SlotId}; BuildSelection sync skipped", request.CategoryId, slotId);
        }
        else
        {
            logger.LogWarning("Select: unable to resolve category mapping for slot {SlotId} and part {PartId}; BuildSelection sync skipped", slotId, request.PartId);
        }
    }

    await using var tx = await db.BeginTransactionAsync(ct);
    try
    {
        await db.ExecuteAsync(new CommandDefinition(
            @"INSERT INTO BuildSlotSelection(build_id, slot_id, part_id, quantity)
                  VALUES (@buildId, @slotId, @partId, 1)
            ON DUPLICATE KEY UPDATE part_id = VALUES(part_id), quantity = 1",
            new { buildId = request.BuildId, slotId, partId = request.PartId },
            transaction: tx,
            cancellationToken: ct));

        if (resolvedCategoryId.HasValue)
        {
            await db.ExecuteAsync(new CommandDefinition(
                @"DELETE bs
                    FROM BuildSelection bs
                    JOIN PartSlot ps ON ps.category_id = bs.category_id
                   WHERE bs.build_id = @buildId
                     AND ps.slot_id = @slotId
                     AND ps.category_id IS NOT NULL
                     AND ps.allow = 1",
                new { buildId = request.BuildId, slotId },
                transaction: tx,
                cancellationToken: ct));

            await db.ExecuteAsync(new CommandDefinition(
                @"INSERT INTO BuildSelection(build_id, category_id, part_id, qty)
                      VALUES (@buildId, @categoryId, @partId, 1)
                ON DUPLICATE KEY UPDATE qty = VALUES(qty)",
                new { buildId = request.BuildId, categoryId = resolvedCategoryId.Value, partId = request.PartId },
                transaction: tx,
                cancellationToken: ct));
        }

        await tx.CommitAsync(ct);
    }
    catch
    {
        await tx.RollbackAsync(ct);
        throw;
    }

    var place = await db.QuerySingleOrDefaultAsync<(string? Uri, string? AttachNode, string? SocketPath)>(new CommandDefinition(
        @"SELECT p.gltf_uri AS Uri,
                 COALESCE(p.gltf_attach_node, 'Attach_Main') AS AttachNode,
                 s.gltf_node_path AS SocketPath
            FROM BuildSlotSelection bs
            JOIN Part p ON p.part_id = bs.part_id
            JOIN Slot s ON s.slot_id = bs.slot_id
           WHERE bs.build_id = @buildId
             AND bs.slot_id = @slotId",
        new { buildId = request.BuildId, slotId },
        cancellationToken: ct));

    await EnsureBuildSummaryViewsAsync(db, ct);

    var completion = await ReadBuildCompletionAsync(db, request.BuildId, ct);
    var summaryRaw = await ReadBuildSummaryAsync(db, request.BuildId, logger, ct);
    var summary = ComposeSummaryFromCompletion(completion, summaryRaw, request.BuildId);
    var cost = BuildCostPayloadFromSummary(summaryRaw, request.BuildId);
    var selections = await ReadBuildSelectionsAsync(db, request.BuildId, ct);

    var badge = (await db.QueryAsync(new CommandDefinition(
        @"SELECT *
            FROM v_build_slot_summary
           WHERE build_id = @buildId AND slot_id = @slotId",
        new { buildId = request.BuildId, slotId },
        cancellationToken: ct))).ToList();

    logger.LogInformation("Select: build {BuildId} slot {SlotId} -> part {PartId}", request.BuildId, slotId, request.PartId);

    return Results.Ok(new
    {
        ok = true,
        place = place == default ? null : new
        {
            uri = place.Uri,
            attachNode = place.AttachNode,
            socketPath = place.SocketPath
        },
        badge,
        completion,
        summary,
        cost,
        selections
    });
}).Accepts<SelectPart>("application/json");

app.MapPost("/api/builds/clear", async (
    ClearPick pick,
    Func<MySqlConnection> dbFactory,
    HttpContext ctx,
    ILogger<Program> logger,
    CancellationToken ct) =>
{
    await using var db = dbFactory();
    await db.OpenAsync(ct);

    var debugMode = ctx.Request.Query.TryGetValue("debug", out var debugParam)
        && string.Equals(debugParam.ToString(), "1", StringComparison.OrdinalIgnoreCase);

    var requestedSocketKey = string.IsNullOrWhiteSpace(pick.SocketKey) ? null : pick.SocketKey;
    var normalized = requestedSocketKey is null ? string.Empty : NormalizeSocketKey(requestedSocketKey);
    var candidates = new List<SocketMatchRow>();
    SocketMatchRow? match = null;
    long? slotId = pick.SlotId;

    if (slotId is null)
    {
        if (!string.IsNullOrWhiteSpace(requestedSocketKey))
        {
            candidates = await ResolveSocketCandidatesAsync(db, pick.BuildId, requestedSocketKey, normalized, ct);

            if (candidates.Count == 0)
            {
                logger.LogWarning("Clear: build {BuildId} socket {SocketKey} (norm {Normalized}) not matched to any slot",
                    pick.BuildId, requestedSocketKey, normalized);
                AttachSocketDebugHeader(ctx, debugMode, requestedSocketKey, normalized, candidates, null, null);
                return Results.NotFound(new { error = "socket_not_found", socket = requestedSocketKey, normalized });
            }

            match = candidates
                .Where(c => c.Priority < 9)
                .OrderBy(c => c.Priority)
                .ThenBy(c => c.SlotId)
                .FirstOrDefault();

            if (match is null)
            {
                logger.LogWarning("Clear: build {BuildId} socket {SocketKey} (norm {Normalized}) matched candidates but none passed priority threshold",
                    pick.BuildId, requestedSocketKey, normalized);
                AttachSocketDebugHeader(ctx, debugMode, requestedSocketKey, normalized, candidates, null, null);
                return Results.NotFound(new { error = "socket_not_found", socket = requestedSocketKey, normalized });
            }

            slotId = match.SlotId;
        }
        else if (pick.CategoryId.HasValue)
        {
            slotId = await db.ExecuteScalarAsync<long?>(new CommandDefinition(
                @"SELECT s.slot_id
                    FROM Build b
                    JOIN Slot s ON s.engine_family_id = b.engine_family_id
                    JOIN PartSlot ps ON ps.slot_id = s.slot_id
                   WHERE b.build_id = @buildId
                     AND ps.category_id = @categoryId
                     AND ps.allow = 1
                ORDER BY s.slot_id
                   LIMIT 1;",
                new { buildId = pick.BuildId, categoryId = pick.CategoryId.Value },
                cancellationToken: ct));

            if (slotId is null)
            {
                logger.LogWarning("Clear: build {BuildId} category {CategoryId} not resolved to any slot",
                    pick.BuildId, pick.CategoryId);
                AttachSocketDebugHeader(ctx, debugMode, $"category:{pick.CategoryId}", normalized, candidates, null, null);
                return Results.BadRequest(new { error = "slot_not_resolved", categoryId = pick.CategoryId });
            }
        }
        else
        {
            return Results.BadRequest(new { error = "socket_required" });
        }
    }

    if (slotId is null)
    {
        return Results.BadRequest(new { error = "slot_not_resolved" });
    }

    var slotInfo = await db.QuerySingleOrDefaultAsync<(long SlotId, string SlotKey, string? SocketPath, string? SubsystemName)>(new CommandDefinition(
        @"SELECT s.slot_id       AS SlotId,
                 s.`key`         AS SlotKey,
                 s.gltf_node_path AS SocketPath,
                 ss.`name`       AS SubsystemName
            FROM Slot s
            LEFT JOIN Subsystem ss ON ss.subsystem_id = s.subsystem_id
           WHERE s.slot_id = @slotId",
        new { slotId },
        cancellationToken: ct));

    if (slotInfo == default)
    {
        logger.LogWarning("Clear: build {BuildId} slot {SlotId} not found",
            pick.BuildId, slotId);
        AttachSocketDebugHeader(ctx, debugMode, requestedSocketKey ?? $"slot:{slotId}", normalized, candidates, null, null);
        return Results.NotFound(new { error = "slot_not_found", slotId });
    }

    if (match is null)
    {
        match = new SocketMatchRow
        {
            SlotId = slotInfo.SlotId,
            SlotKey = slotInfo.SlotKey,
            GltfNodePath = slotInfo.SocketPath,
            SubsystemName = slotInfo.SubsystemName,
            Priority = pick.CategoryId.HasValue ? 1 : 0,
            Reason = pick.CategoryId.HasValue ? "category_id" : "slot_id"
        };
        candidates = new List<SocketMatchRow> { match };
    }

    var socketLabel = requestedSocketKey ?? slotInfo.SocketPath ?? slotInfo.SlotKey;
    if (string.IsNullOrWhiteSpace(normalized))
    {
        normalized = NormalizeSocketKey(socketLabel);
    }

    logger.LogInformation("Clear: build {BuildId} -> slot {SlotId} ({SlotKey}) via {Reason}",
        pick.BuildId, slotInfo.SlotId, slotInfo.SlotKey, match.Reason);

    await db.ExecuteAsync(new CommandDefinition(
        @"DELETE FROM BuildSlotSelection
           WHERE build_id = @buildId AND slot_id = @slotId",
        new { pick.BuildId, slotId = slotInfo.SlotId },
        cancellationToken: ct));

    await db.ExecuteAsync(new CommandDefinition(
        @"DELETE bs
            FROM BuildSelection bs
            JOIN PartSlot ps ON ps.category_id = bs.category_id
           WHERE bs.build_id = @buildId
             AND ps.slot_id = @slotId
             AND ps.category_id IS NOT NULL
             AND ps.allow = 1",
        new { buildId = pick.BuildId, slotId = slotInfo.SlotId },
        cancellationToken: ct));

    await EnsureBuildSummaryViewsAsync(db, ct);

    var completion = await ReadBuildCompletionAsync(db, pick.BuildId, ct);
    var summaryRaw = await ReadBuildSummaryAsync(db, pick.BuildId, logger, ct);
    var summary = ComposeSummaryFromCompletion(completion, summaryRaw, pick.BuildId);
    var cost = BuildCostPayloadFromSummary(summaryRaw, pick.BuildId);
    var selections = await ReadBuildSelectionsAsync(db, pick.BuildId, ct);

    var badge = await db.QuerySingleOrDefaultAsync(new CommandDefinition(
        @"SELECT s.slot_id AS slot_id,
                 CASE WHEN 0 BETWEEN s.min_required AND s.capacity THEN '✅' ELSE '🔴' END AS badge,
                 CASE WHEN 0 BETWEEN s.min_required AND s.capacity THEN 1 ELSE 0 END AS local_complete
            FROM Slot s
           WHERE s.slot_id = @slotId",
        new { slotId = slotInfo.SlotId },
        cancellationToken: ct));

    AttachSocketDebugHeader(ctx, debugMode, socketLabel, normalized, candidates, match, null);

    var socketPath = slotInfo.SocketPath ?? slotInfo.SlotKey;

    return Results.Ok(new { ok = true, socketPath, slotId = slotInfo.SlotId, badge, completion, summary, cost, selections });
}).Accepts<ClearPick>("application/json");

// Brands list
app.MapGet("/api/brands", async () =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);
    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync();
        const string sql = @"SELECT b.brand_id, b.name, b.website, COUNT(p.part_id) AS part_count
                             FROM Brand b
                             LEFT JOIN Part p ON p.brand_id=b.brand_id
                             GROUP BY b.brand_id
                             ORDER BY b.name";
        var list = new List<Dictionary<string, object?>>();
        await using var cmd = new MySqlCommand(sql, conn);
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
            for (int i=0;i<reader.FieldCount;i++) row[reader.GetName(i)] = reader.IsDBNull(i)?null:reader.GetValue(i);
            list.Add(row);
        }
        return Results.Json(list);
    }
    catch (Exception ex) { return Results.Problem(title: "Query failed", detail: ex.Message, statusCode: 500); }
});

// Shop catalog search
app.MapGet("/api/shop", async (
    string? q,
    string? engine,
    string? category,
    string? brand,
    decimal? min,
    decimal? max,
    int? in_stock,
    string sort,
    string dir,
    int page,
    int pageSize) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    q = string.IsNullOrWhiteSpace(q) ? null : q.Trim();
    engine = string.IsNullOrWhiteSpace(engine) ? null : engine.Trim();
    category = string.IsNullOrWhiteSpace(category) ? null : category.Trim();
    brand = string.IsNullOrWhiteSpace(brand) ? null : brand.Trim();
    sort = string.IsNullOrWhiteSpace(sort) ? "price" : sort.Trim();
    dir = string.IsNullOrWhiteSpace(dir) ? "asc" : dir.Trim();

    page = Math.Max(1, page == 0 ? 1 : page);
    pageSize = Math.Clamp(pageSize == 0 ? 24 : pageSize, 1, 60);
    var offset = (page - 1) * pageSize;

    var sortKey = sort.ToLowerInvariant();
    var dirKey = dir.ToLowerInvariant();

    var orderClause = sortKey switch
    {
        "updated" when dirKey == "asc" => "updated_at ASC, best_price ASC",
        "updated" => "updated_at DESC, best_price ASC",
        "price" when dirKey == "desc" => "CASE WHEN best_price IS NULL THEN 1 ELSE 0 END ASC, best_price DESC, updated_at DESC",
        _ => "CASE WHEN best_price IS NULL THEN 1 ELSE 0 END ASC, best_price ASC, updated_at DESC"
    };

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync();

        var filteredCte = @"
WITH best AS (
  SELECT po.part_id, MIN(po.price) AS price
  FROM PartOffering po
  WHERE (po.effective_to IS NULL OR po.effective_to > NOW())
    AND (@instock IS NULL OR @instock <> 1 OR po.availability = 'in_stock')
  GROUP BY po.part_id
),
filtered AS (
  SELECT
    p.part_id,
    p.sku,
    p.name,
    COALESCE(b.name,'') AS brand,
    p.image_url,
    p.is_kit,
    p.pieces_per_unit,
    p.status,
    p.updated_at,
    (
      SELECT c.slug
      FROM PartCategory pc2
      JOIN Category c ON c.category_id = pc2.category_id
      WHERE pc2.part_id = p.part_id AND c.is_selectable = TRUE
      ORDER BY pc2.is_primary DESC, pc2.display_order, c.name
      LIMIT 1
    ) AS category_slug,
    (
      SELECT c.name
      FROM PartCategory pc3
      JOIN Category c ON c.category_id = pc3.category_id
      WHERE pc3.part_id = p.part_id AND c.is_selectable = TRUE
      ORDER BY pc3.is_primary DESC, pc3.display_order, c.name
      LIMIT 1
    ) AS category_name,
    bo.price AS best_price,
    CASE
      WHEN @engine IS NULL OR @engine = '' THEN FALSE
      ELSE EXISTS (
        SELECT 1
        FROM PartFitment pf
        JOIN EngineFamily ef ON ef.engine_family_id = pf.engine_family_id
        WHERE pf.part_id = p.part_id AND ef.code = @engine
      )
    END AS fits_engine
  FROM Part p
  LEFT JOIN Brand b ON b.brand_id = p.brand_id
  LEFT JOIN best bo ON bo.part_id = p.part_id
  WHERE
    (@q IS NULL OR p.sku LIKE CONCAT('%', @q, '%') OR p.name LIKE CONCAT('%', @q, '%'))
    AND (@brand IS NULL OR b.name = @brand)
    AND (@category IS NULL OR EXISTS (
        SELECT 1
        FROM PartCategory pc
        JOIN Category c ON c.category_id = pc.category_id
        WHERE pc.part_id = p.part_id
          AND c.is_selectable = TRUE
          AND c.slug = @category
    ))
    AND (@engine IS NULL OR EXISTS (
        SELECT 1
        FROM PartFitment pf
        JOIN EngineFamily ef ON ef.engine_family_id = pf.engine_family_id
        WHERE pf.part_id = p.part_id AND ef.code = @engine
    ))
    AND (@min IS NULL OR bo.price >= @min)
    AND (@max IS NULL OR bo.price <= @max)
)
";

        var dataSql = filteredCte + "SELECT * FROM filtered ORDER BY " + orderClause + " LIMIT @ps OFFSET @off";
        var countSql = filteredCte + "SELECT COUNT(*) FROM filtered";

        var queryParameters = new
        {
            q,
            engine,
            category,
            brand,
            min,
            max,
            instock = in_stock,
            ps = pageSize,
            off = offset
        };

        var rows = (await conn.QueryAsync(dataSql, queryParameters)).ToList();
        var total = await conn.ExecuteScalarAsync<long>(countSql, queryParameters);

        var mapped = rows.Select(row => new ShopSearchRow(
            PartId: Convert.ToInt64(row.part_id),
            Sku: Convert.ToString(row.sku) ?? string.Empty,
            Name: Convert.ToString(row.name) ?? string.Empty,
            Brand: Convert.ToString(row.brand) ?? string.Empty,
            ImageUrl: row.image_url is null ? null : Convert.ToString(row.image_url),
            IsKit: Convert.ToBoolean(row.is_kit),
            Status: Convert.ToString(row.status) ?? string.Empty,
            BestPrice: row.best_price is null ? null : Convert.ToDecimal(row.best_price),
            FitsEngine: Convert.ToBoolean(row.fits_engine),
            CategorySlug: row.category_slug is null ? null : Convert.ToString(row.category_slug),
            CategoryName: row.category_name is null ? null : Convert.ToString(row.category_name),
            PiecesPerUnit: row.pieces_per_unit is null ? null : Convert.ToDecimal(row.pieces_per_unit),
            UpdatedAt: row.updated_at is null ? null : Convert.ToDateTime(row.updated_at)
        )).ToList();

        var response = new ShopSearchResponse(
            Items: mapped,
            Total: total,
            Page: page,
            PageSize: pageSize,
            HasMore: (long)offset + mapped.Count < total);

        return Results.Ok(response);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Shop query failed", detail: ex.Message, statusCode: 500);
    }
});

// Part details for shop/catalog
app.MapGet("/api/shop/parts/{key}", async (string key) => await GetShopPartAsync(connectionString, key));
app.MapGet("/api/parts/by-sku/{sku}", async (string sku) => await GetShopPartAsync(connectionString, sku));

static async Task<IResult> GetShopPartAsync(string? connectionString, string key)
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    key = key?.Trim() ?? string.Empty;
    if (key.Length == 0)
        return Results.BadRequest(new { error = "part identifier required" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync();

        var part = await conn.QuerySingleOrDefaultAsync(@"
          SELECT p.*, b.name AS brand_name
          FROM Part p LEFT JOIN Brand b ON b.brand_id=p.brand_id
          WHERE p.part_id = (CASE WHEN @key REGEXP '^[0-9]+$' THEN @key ELSE 0 END)
             OR p.sku = @key
          LIMIT 1", new { key });

        if (part is null)
            return Results.NotFound();

        var partId = Convert.ToInt64(part.part_id);

        var categories = await conn.QueryAsync(@"
          SELECT c.category_id, c.name, c.slug, pc.is_primary
          FROM PartCategory pc JOIN Category c ON c.category_id=pc.category_id
          WHERE pc.part_id=@pid ORDER BY pc.is_primary DESC, pc.display_order", new { pid = partId });

        var fitment = await conn.QueryAsync(@"
          SELECT ef.code, pf.years_start, pf.years_end, pf.notes
          FROM PartFitment pf JOIN EngineFamily ef ON ef.engine_family_id=pf.engine_family_id
          WHERE pf.part_id=@pid ORDER BY ef.code", new { pid = partId });

        var offerings = await conn.QueryAsync(@"
          SELECT po.offering_id, v.name AS vendor, po.price, po.currency, po.availability, po.url, po.affiliate_url
          FROM PartOffering po JOIN Vendor v ON v.vendor_id=po.vendor_id
          WHERE po.part_id=@pid AND (po.effective_to IS NULL OR po.effective_to > NOW())
          ORDER BY po.price", new { pid = partId });

        var components = await conn.QueryAsync(@"
          SELECT p.child_part_id, csku.sku, csku.name, p.qty_per_parent
          FROM PartComponent p JOIN Part csku ON csku.part_id=p.child_part_id
          WHERE p.parent_part_id=@pid", new { pid = partId });

        return Results.Ok(new { part, categories, fitment, offerings, components });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Part lookup failed", detail: ex.Message, statusCode: 500);
    }
}

static async Task<OfferingLookup?> ResolveOfferingAsync(MySqlConnection conn, long partId, long? offeringId, string? vendorName)
{
    if (offeringId.HasValue)
    {
        var offer = await conn.QuerySingleOrDefaultAsync<OfferingLookup>(@"
          SELECT po.offering_id   AS OfferingId,
                 po.part_id       AS PartId,
                 po.vendor_id     AS VendorId,
                 po.affiliate_url AS AffiliateUrl,
                 po.url           AS Url
          FROM PartOffering po
          WHERE po.offering_id=@id", new { id = offeringId.Value });

        if (offer is not null && offer.PartId != (ulong)partId)
            return null;

        return offer;
    }

    if (!string.IsNullOrWhiteSpace(vendorName))
    {
        return await conn.QuerySingleOrDefaultAsync<OfferingLookup>(@"
          SELECT po.offering_id   AS OfferingId,
                 po.part_id       AS PartId,
                 po.vendor_id     AS VendorId,
                 po.affiliate_url AS AffiliateUrl,
                 po.url           AS Url
          FROM PartOffering po JOIN Vendor v ON v.vendor_id=po.vendor_id
          WHERE po.part_id=@pid AND v.name=@vendor
            AND (po.effective_to IS NULL OR po.effective_to > NOW())
          ORDER BY po.price
          LIMIT 1", new { pid = partId, vendor = vendorName });
    }

    return await conn.QuerySingleOrDefaultAsync<OfferingLookup>(@"
      SELECT po.offering_id   AS OfferingId,
             po.part_id       AS PartId,
             po.vendor_id     AS VendorId,
             po.affiliate_url AS AffiliateUrl,
             po.url           AS Url
      FROM PartOffering po
      WHERE po.part_id=@pid
        AND (po.effective_to IS NULL OR po.effective_to > NOW())
      ORDER BY po.price
      LIMIT 1", new { pid = partId });
}

async Task<IResult> HandleClickAsync(string? connectionString, long partId, long? offeringId, long? buildId, string? vendorName, bool redirect, CancellationToken ct)
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (partId <= 0)
        return Results.BadRequest(new { error = "part_id required" });

    var normalizedVendor = string.IsNullOrWhiteSpace(vendorName) ? null : vendorName.Trim();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureClickAttributionSchemaAsync(conn, ct);

        var offer = await ResolveOfferingAsync(conn, partId, offeringId, normalizedVendor);
        if (offer is null || offer.OfferingId == 0 || offer.VendorId == 0)
            return Results.NotFound(new { error = "No matching offering" });

        var targetUrl = string.IsNullOrWhiteSpace(offer.AffiliateUrl) ? offer.Url : offer.AffiliateUrl;
        if (string.IsNullOrWhiteSpace(targetUrl))
            return Results.NotFound(new { error = "Offering missing URL" });

        await conn.ExecuteAsync(@"
          INSERT INTO ClickAttribution (build_id, part_id, vendor_id, offering_id, clicked_at)
          VALUES (@build_id, @part_id, @vendor_id, @offering_id, NOW())",
          new
          {
              build_id = buildId,
              part_id = Convert.ToInt64(offer.PartId),
              vendor_id = Convert.ToInt64(offer.VendorId),
              offering_id = Convert.ToInt64(offer.OfferingId)
          });

        return redirect
            ? Results.Redirect(targetUrl!, permanent: false)
            : Results.Ok(new { url = targetUrl });
    }
    catch (Exception ex)
    {
        var title = redirect ? "Redirect failed" : "Click attribution failed";
        return Results.Problem(title: title, detail: ex.Message, statusCode: 500);
    }
}

// Bundles/Kits listing
app.MapGet("/api/bundles", async (string? engine, string? category, string? q, string? sort, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    var orderClause = (sort?.Trim().ToLowerInvariant()) switch
    {
        "price" => "bo.best_price IS NULL, bo.best_price ASC",
        _ => "p.updated_at DESC"
    };

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        var query = $@"
          SELECT p.part_id, p.sku, p.name, COALESCE(b.name, '') AS brand, p.image_url, bo.best_price,
                 EXISTS (
                   SELECT 1
                   FROM PartFitment pf
                   JOIN EngineFamily ef ON ef.engine_family_id = pf.engine_family_id
                   WHERE pf.part_id = p.part_id AND ef.code = @engine
                 ) AS fits_engine
          FROM Part p
          LEFT JOIN Brand b ON b.brand_id = p.brand_id
          LEFT JOIN v_part_best_offering bo ON bo.part_id = p.part_id
          WHERE p.is_kit = TRUE
            AND (@q IS NULL OR p.name LIKE CONCAT('%', @q, '%') OR p.sku LIKE CONCAT('%', @q, '%'))
            AND (@category IS NULL OR EXISTS (
                 SELECT 1
                 FROM PartCategory pc
                 JOIN Category c ON c.category_id = pc.category_id
                 WHERE pc.part_id = p.part_id AND c.slug = @category))
            AND (@engine IS NULL OR EXISTS (
                 SELECT 1
                 FROM PartFitment pf
                 JOIN EngineFamily ef ON ef.engine_family_id = pf.engine_family_id
                 WHERE pf.part_id = p.part_id AND ef.code = @engine))
          ORDER BY {orderClause}";

        var rows = await conn.QueryAsync(query, new
        {
            engine = string.IsNullOrWhiteSpace(engine) ? null : engine.Trim(),
            category = string.IsNullOrWhiteSpace(category) ? null : category.Trim(),
            q = string.IsNullOrWhiteSpace(q) ? null : q.Trim()
        });

        static bool ToBool(object? value)
        {
            return value switch
            {
                bool b => b,
                null => false,
                sbyte sb => sb != 0,
                byte b => b != 0,
                short s => s != 0,
                int i => i != 0,
                long l => l != 0,
                uint ui => ui != 0,
                ulong ul => ul != 0,
                decimal dec => dec != 0,
                double dbl => Math.Abs(dbl) > double.Epsilon,
                float fl => Math.Abs(fl) > float.Epsilon,
                string str when int.TryParse(str, out var parsed) => parsed != 0,
                _ => true
            };
        }

        static decimal? ToNullableDecimal(object? value)
        {
            return value switch
            {
                null => null,
                DBNull => null,
                decimal dec => dec,
                double dbl => Convert.ToDecimal(dbl),
                float fl => Convert.ToDecimal(fl),
                int i => i,
                long l => l,
                uint ui => ui,
                ulong ul => Convert.ToDecimal(ul),
                string str when decimal.TryParse(str, out var parsed) => parsed,
                _ => Convert.ToDecimal(value)
            };
        }

        var payload = rows.Select(r => new
        {
            part_id = Convert.ToInt64(r.part_id),
            sku = r.sku as string ?? Convert.ToString(r.sku) ?? string.Empty,
            name = r.name as string ?? Convert.ToString(r.name) ?? string.Empty,
            brand = r.brand as string ?? Convert.ToString(r.brand) ?? string.Empty,
            image_url = r.image_url as string ?? Convert.ToString(r.image_url),
            best_price = ToNullableDecimal(r.best_price),
            fits_engine = ToBool(r.fits_engine)
        });

        return Results.Ok(payload);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Bundle listing failed", detail: ex.Message, statusCode: 500);
    }
});

// Bundle details
app.MapGet("/api/bundles/{id:long}", async (long id, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        var part = await conn.QuerySingleOrDefaultAsync(@"
          SELECT p.*, b.name AS brand_name
          FROM Part p
          LEFT JOIN Brand b ON b.brand_id = p.brand_id
          WHERE p.part_id = @id AND p.is_kit = TRUE", new { id });

        if (part is null)
            return Results.NotFound();

        var components = await conn.QueryAsync(@"
          SELECT pc.child_part_id, cp.sku, cp.name, pc.qty_per_parent, bo.best_price
          FROM PartComponent pc
          JOIN Part cp ON cp.part_id = pc.child_part_id
          LEFT JOIN v_part_best_offering bo ON bo.part_id = cp.part_id
          WHERE pc.parent_part_id = @id", new { id });

        var offerings = await conn.QueryAsync(@"
          SELECT po.offering_id, v.name AS vendor, po.price, po.currency, po.url, po.affiliate_url
          FROM PartOffering po
          JOIN Vendor v ON v.vendor_id = po.vendor_id
          WHERE po.part_id = @id AND (po.effective_to IS NULL OR po.effective_to > NOW())
          ORDER BY po.price", new { id });

        return Results.Ok(new { part, components, offerings });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Bundle lookup failed", detail: ex.Message, statusCode: 500);
    }
});

// Compare parts by SKU
app.MapPost("/api/compare", async (CompareRequest? request, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    var arr = (request?.Skus ?? new List<string>())
        .Where(s => !string.IsNullOrWhiteSpace(s))
        .Select(s => s.Trim())
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .Take(16)
        .ToArray();

    if (arr.Length < 2)
        return Results.BadRequest(new { error = "need_at_least_two" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        var normalized = arr.Select(s => s.ToLowerInvariant()).ToArray();
        var queryArgs = new { normalized };

        var items = await conn.QueryAsync(@"
          SELECT p.part_id, p.sku, p.name, COALESCE(b.name, '') AS brand, bo.best_price, p.status
          FROM Part p
          LEFT JOIN Brand b ON b.brand_id = p.brand_id
          LEFT JOIN v_part_best_offering bo ON bo.part_id = p.part_id
          WHERE LOWER(p.sku) IN @normalized", queryArgs);

        var itemList = items.ToList();

        var partIds = itemList.Select(i => (long)i.part_id).Distinct().ToArray();

        List<object> attributes;
        if (partIds.Length == 0)
        {
            attributes = new List<object>();
        }
        else
        {
            try
            {
                attributes = (await conn.QueryAsync(@"
                  SELECT pav.part_id, ad.code, COALESCE(pav.val_text, CAST(COALESCE(pav.val_decimal, pav.val_int) AS CHAR)) AS val
                  FROM PartAttributeValue pav
                  JOIN AttributeDef ad ON ad.attribute_id = pav.attribute_id
                  WHERE pav.part_id IN @partIds", new { partIds })).Cast<object>().ToList();
            }
            catch (MySqlException ex) when (ex.Number == 1146)
            {
                attributes = new List<object>();
            }
        }

        return Results.Ok(new { items = itemList, attributes });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Compare lookup failed", detail: ex.Message, statusCode: 500);
    }
});

// Substitute finder
app.MapGet("/api/substitutes/{sku}", async (string sku, int limit, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    sku = sku?.Trim() ?? string.Empty;
    if (sku.Length == 0)
        return Results.BadRequest(new { error = "sku_required" });

    var take = limit <= 0 ? 8 : Math.Min(limit, 32);

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        var source = await conn.QuerySingleOrDefaultAsync<long?>("SELECT part_id FROM Part WHERE sku = @sku LIMIT 1", new { sku });
        if (source is null)
            return Results.NotFound();

        var categoryId = await conn.QuerySingleOrDefaultAsync<long?>(@"
          SELECT pc.category_id
          FROM PartCategory pc
          WHERE pc.part_id = @partId AND pc.is_primary = 1
          ORDER BY pc.display_order
          LIMIT 1", new { partId = source.Value });

        if (categoryId is null or 0)
            return Results.Ok(Array.Empty<object>());

        var keys = (await conn.QueryAsync<(string code, string val)>(@"
          SELECT ad.code,
                 COALESCE(pav.val_text, CAST(COALESCE(pav.val_decimal, pav.val_int) AS CHAR)) AS val
          FROM PartAttributeValue pav
          JOIN AttributeDef ad ON ad.attribute_id = pav.attribute_id
          WHERE pav.part_id = @partId", new { partId = source.Value })).ToList();

        var candidates = (await conn.QueryAsync(@"
          SELECT p.part_id, p.sku, p.name, COALESCE(b.name, '') AS brand, bo.best_price
          FROM PartCategory pc
          JOIN Part p ON p.part_id = pc.part_id
          LEFT JOIN Brand b ON b.brand_id = p.brand_id
          LEFT JOIN v_part_best_offering bo ON bo.part_id = p.part_id
          WHERE pc.category_id = @cat AND p.sku <> @sku
          ORDER BY bo.best_price ASC, p.name
          LIMIT 200", new { cat = categoryId.Value, sku })).ToList();

        if (candidates.Count == 0)
            return Results.Ok(Array.Empty<object>());

        var candidateIds = candidates.Select(c => Convert.ToInt64(c.part_id)).ToArray();

        var attrRows = (await conn.QueryAsync(@"
          SELECT pav.part_id, ad.code,
                 COALESCE(pav.val_text, CAST(COALESCE(pav.val_decimal, pav.val_int) AS CHAR)) AS val
          FROM PartAttributeValue pav
          JOIN AttributeDef ad ON ad.attribute_id = pav.attribute_id
          WHERE pav.part_id IN @ids", new { ids = candidateIds })).ToList();

        var keyMap = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var (code, val) in keys)
        {
            if (string.IsNullOrWhiteSpace(code) || string.IsNullOrWhiteSpace(val))
                continue;

            if (!keyMap.TryGetValue(code, out var set))
            {
                set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                keyMap[code] = set;
            }

            set.Add(val);
        }

        static string? AsString(object? value) => value switch
        {
            null => null,
            DBNull => null,
            string s => s,
            _ => Convert.ToString(value)
        };

        static decimal NormalizePrice(object? value) => value switch
        {
            null => 0m,
            DBNull => 0m,
            decimal d => d,
            double d => Convert.ToDecimal(d),
            float f => Convert.ToDecimal(f),
            long l => Convert.ToDecimal(l),
            int i => Convert.ToDecimal(i),
            _ => Convert.ToDecimal(value)
        };

        var attrLookup = attrRows
            .GroupBy(row => Convert.ToInt64(row.part_id))
            .ToDictionary(g => g.Key, g => g.ToList());

        var list = candidates
            .Select(c =>
            {
                var partId = Convert.ToInt64(c.part_id);
                var attrs = attrLookup.TryGetValue(partId, out List<dynamic> group) ? group : new List<dynamic>();
                var score = 0;

                if (keyMap.Count > 0)
                {
                    foreach (var attr in attrs)
                    {
                        var code = AsString(attr.code);
                        var val = AsString(attr.val);
                        if (code is null || val is null)
                            continue;

                        if (keyMap.TryGetValue(code, out var set) && set.Contains(val))
                        {
                            score++;
                        }
                    }
                }

                var price = NormalizePrice(c.best_price);

                return new
                {
                    part_id = partId,
                    sku = AsString(c.sku) ?? string.Empty,
                    name = AsString(c.name) ?? string.Empty,
                    brand = AsString(c.brand) ?? string.Empty,
                    price,
                    score
                };
            })
            .OrderByDescending(x => x.score)
            .ThenBy(x => x.price == 0m ? decimal.MaxValue : x.price)
            .ThenBy(x => x.name)
            .Take(take)
            .ToList();

        return Results.Ok(list);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Substitute lookup failed", detail: ex.Message, statusCode: 500);
    }
});

// Price alert capture with double opt-in
app.MapPost("/api/alerts/price", async (PriceAlertRequest request, ClaimsPrincipal user, IConfiguration cfg, IEmailSender emailSender, HttpContext httpContext, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (request?.PartId is null or <= 0)
        return Results.BadRequest(new { error = "part_id_required" });

    var normalizedEmail = string.IsNullOrWhiteSpace(request.Email) ? null : request.Email.Trim();
    if (!string.IsNullOrWhiteSpace(normalizedEmail))
    {
        normalizedEmail = normalizedEmail.ToLowerInvariant();
    }

    var stockOnly = request.StockOnly ?? false;
    var target = request.TargetPrice;

    long? userId = null;
    if (user.Identity?.IsAuthenticated == true)
    {
        var claim = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (long.TryParse(claim, out var parsed))
        {
            userId = parsed;
        }
    }

    if (userId is null && string.IsNullOrWhiteSpace(normalizedEmail))
        return Results.BadRequest(new { error = "email_or_user_required" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsurePriceWatchTableAsync(conn, ct);

        string? partName = null;
        await using (var partCmd = new MySqlCommand("SELECT name FROM Part WHERE part_id=@pid", conn))
        {
            partCmd.Parameters.AddWithValue("@pid", request.PartId.Value);
            var rawName = await partCmd.ExecuteScalarAsync(ct);
            partName = rawName switch
            {
                null => null,
                DBNull => null,
                string s => s,
                _ => Convert.ToString(rawName)
            };
        }

        if (userId.HasValue)
        {
            string? userEmail = null;
            bool emailVerified = false;
            bool emailBounced = false;
            bool emailUnsubscribed = false;

            await using (var userCmd = new MySqlCommand("SELECT email, email_verified_at, email_bounced, email_unsubscribed FROM UserAccount WHERE user_id=@uid", conn))
            {
                userCmd.Parameters.AddWithValue("@uid", userId.Value);
                await using var reader = await userCmd.ExecuteReaderAsync(ct);
                if (!await reader.ReadAsync(ct))
                {
                    return Results.NotFound(new { error = "user_not_found" });
                }

                userEmail = reader.IsDBNull(0) ? null : reader.GetString(0);
                emailVerified = !reader.IsDBNull(1);
                emailBounced = !reader.IsDBNull(2) && reader.GetBoolean(2);
                emailUnsubscribed = !reader.IsDBNull(3) && reader.GetBoolean(3);
            }

            if (!emailVerified)
            {
                return Results.Json(new { error = "email_not_verified" }, statusCode: StatusCodes.Status403Forbidden);
            }

            if (emailBounced)
            {
                return Results.Json(new { error = "email_bounced" }, statusCode: StatusCodes.Status403Forbidden);
            }

            if (emailUnsubscribed)
            {
                return Results.Json(new { error = "email_unsubscribed" }, statusCode: StatusCodes.Status403Forbidden);
            }

            if (string.IsNullOrWhiteSpace(userEmail))
            {
                return Results.BadRequest(new { error = "email_missing" });
            }

            normalizedEmail = userEmail.ToLowerInvariant();

            await conn.ExecuteAsync(@"
              INSERT INTO PriceWatch (user_id, email, part_id, target_price, stock_only, is_verified, verify_token, verify_expires)
              VALUES (@userId, @email, @partId, @target, @stockOnly, TRUE, NULL, NULL)", new
            {
                userId = userId.Value,
                email = normalizedEmail,
                partId = request.PartId.Value,
                target,
                stockOnly
            });

            return Results.Ok(new { ok = true, pending_verification = false });
        }

        // Anonymous alert: require confirmation
        await using (var statusCmd = new MySqlCommand("SELECT email_bounced, email_unsubscribed FROM UserAccount WHERE email=@mail", conn))
        {
            statusCmd.Parameters.AddWithValue("@mail", normalizedEmail);
            await using var reader = await statusCmd.ExecuteReaderAsync(ct);
            if (await reader.ReadAsync(ct))
            {
                var bounced = !reader.IsDBNull(0) && reader.GetBoolean(0);
                var unsubscribed = !reader.IsDBNull(1) && reader.GetBoolean(1);
                if (bounced)
                {
                    return Results.Json(new { error = "email_bounced" }, statusCode: StatusCodes.Status403Forbidden);
                }

                if (unsubscribed)
                {
                    return Results.Json(new { error = "email_unsubscribed" }, statusCode: StatusCodes.Status403Forbidden);
                }
            }
        }

        var verifyToken = SecureTokenGenerator.CreateToken();
        var verifyExpires = DateTime.UtcNow.AddDays(3);

        await conn.ExecuteAsync(@"
          INSERT INTO PriceWatch (user_id, email, part_id, target_price, stock_only, is_verified, verify_token, verify_expires)
          VALUES (NULL, @email, @partId, @target, @stockOnly, FALSE, @verifyToken, @verifyExpires)", new
        {
            email = normalizedEmail,
            partId = request.PartId.Value,
            target,
            stockOnly,
            verifyToken,
            verifyExpires
        });

        var baseUrl = ResolveBaseUrl(cfg, httpContext.Request);
        var confirmLink = string.IsNullOrWhiteSpace(baseUrl) ? $"/alerts/confirm?token={verifyToken}" : $"{baseUrl}/alerts/confirm?token={verifyToken}";
        var partLabel = string.IsNullOrWhiteSpace(partName) ? "this part" : partName;
        var subject = string.IsNullOrWhiteSpace(partName) ? "Confirm your RotorBase price alert" : $"Confirm price alert for {partLabel}";
        var html = $"""
            <p>Almost done! Confirm your price alert for <strong>{partLabel}</strong>.</p>
            <p><a href="{confirmLink}">Activate price alerts</a></p>
            <p>We will email you when the price drops or the part is back in stock.</p>
            <p>If you did not request this, you can ignore this message.</p>
        """;
        var text = $"Activate your price alert for {partLabel}: {confirmLink}";
        await emailSender.SendAsync(new EmailMessage(normalizedEmail!, subject, html, text), ct);

        return Results.Ok(new { ok = true, pending_verification = true });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Price alert registration failed", detail: ex.Message, statusCode: 500);
    }
});

app.MapGet("/alerts/confirm", async (HttpContext ctx, IConfiguration cfg, string? token, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (string.IsNullOrWhiteSpace(token))
    {
        return Results.Redirect(BuildAbsoluteUrl(cfg, ctx.Request, "/?alert=invalid"));
    }

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsurePriceWatchTableAsync(conn, ct);

        long? watchId = null;
        DateTime? expires = null;

        await using (var cmd = new MySqlCommand("SELECT watch_id, verify_expires FROM PriceWatch WHERE verify_token=@token AND is_verified=FALSE", conn))
        {
            cmd.Parameters.AddWithValue("@token", token);
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            if (await reader.ReadAsync(ct))
            {
                watchId = reader.GetInt64(0);
                expires = reader.IsDBNull(1) ? null : reader.GetDateTime(1);
            }
        }

        if (watchId is null)
        {
            return Results.Redirect(BuildAbsoluteUrl(cfg, ctx.Request, "/?alert=invalid"));
        }

        if (expires.HasValue && expires.Value < DateTime.UtcNow)
        {
            return Results.Redirect(BuildAbsoluteUrl(cfg, ctx.Request, "/?alert=expired"));
        }

        await using (var update = new MySqlCommand("UPDATE PriceWatch SET is_verified=TRUE, verify_token=NULL, verify_expires=NULL WHERE watch_id=@watch", conn))
        {
            update.Parameters.AddWithValue("@watch", watchId.Value);
            await update.ExecuteNonQueryAsync(ct);
        }

        return Results.Redirect(BuildAbsoluteUrl(cfg, ctx.Request, "/?alert=ok"));
    }
    catch (Exception ex)
    {
        var logger = ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("ConfirmAlert");
        logger.LogError(ex, "Price alert confirmation failed for token {Token}", token);
        return Results.Redirect(BuildAbsoluteUrl(cfg, ctx.Request, "/?alert=error"));
    }
});

app.MapDelete("/api/alerts/price/{watchId:long}", async (long watchId, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsurePriceWatchTableAsync(conn, ct);

        await conn.ExecuteAsync("UPDATE PriceWatch SET active = FALSE WHERE watch_id = @watchId", new { watchId });
        return Results.Ok(new { ok = true });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Price alert cancel failed", detail: ex.Message, statusCode: 500);
    }
});

// Track click-through from shop/builder and return target URL
app.MapPost("/api/shop/click", async (ShopClickRequest request, CancellationToken ct) =>
{
    if (request is null)
        return Results.BadRequest(new { error = "invalid_payload" });

    return await HandleClickAsync(connectionString, request.PartId, request.OfferingId, request.BuildId, request.VendorName, redirect: false, ct);
});

app.MapPost("/api/analytics/ingest", async (HttpRequest req, IConfiguration cfg, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    var providedKey = req.Headers["X-Analytics-Key"].ToString();
    var expectedKey = cfg["Analytics:IngestKey"]?.Trim();
    var normalizedProvidedKey = string.IsNullOrWhiteSpace(providedKey) ? null : providedKey.Trim();

    if (string.IsNullOrWhiteSpace(expectedKey) || string.IsNullOrEmpty(normalizedProvidedKey))
    {
        return Results.Unauthorized();
    }

    var expectedBytes = Encoding.UTF8.GetBytes(expectedKey);
    var providedBytes = Encoding.UTF8.GetBytes(normalizedProvidedKey);

    if (!CryptographicOperations.FixedTimeEquals(expectedBytes, providedBytes))
    {
        return Results.Unauthorized();
    }

    AnalyticsDto? dto;
    try
    {
        dto = await req.ReadFromJsonAsync<AnalyticsDto>(cancellationToken: ct);
    }
    catch (JsonException)
    {
        return Results.BadRequest(new { error = "invalid_json" });
    }

    if (dto is null || string.IsNullOrWhiteSpace(dto.EventName))
    {
        return Results.BadRequest(new { error = "invalid_event" });
    }

    var eventName = dto.EventName.Trim();
    if (!analyticsAllowedEvents.Contains(eventName))
    {
        return Results.BadRequest(new { error = "event_not_allowed" });
    }

    var now = DateTime.UtcNow;
    DateTime occurredAt;
    if (dto.OccurredAtUtc.HasValue)
    {
        var raw = dto.OccurredAtUtc.Value;
        occurredAt = raw.Kind switch
        {
            DateTimeKind.Utc => raw,
            DateTimeKind.Local => raw.ToUniversalTime(),
            _ => DateTime.SpecifyKind(raw, DateTimeKind.Utc)
        };
    }
    else
    {
        occurredAt = now;
    }

    if (occurredAt > now.AddHours(24))
    {
        occurredAt = now;
    }

    var eventUuid = string.IsNullOrWhiteSpace(dto.EventUuid) ? Guid.NewGuid().ToString() : dto.EventUuid.Trim();
    var sessionId = string.IsNullOrWhiteSpace(dto.SessionId) ? Guid.NewGuid().ToString() : dto.SessionId.Trim();
    var severity = string.IsNullOrWhiteSpace(dto.Severity) ? null : dto.Severity.Trim().ToLowerInvariant();
    var source = string.IsNullOrWhiteSpace(dto.Source) ? null : dto.Source.Trim().ToLowerInvariant();

    string? extraJson = null;
    if (dto.Extra.HasValue && dto.Extra.Value.ValueKind is not JsonValueKind.Undefined and not JsonValueKind.Null)
    {
        extraJson = dto.Extra.Value.GetRawText();
    }

    var remoteAddressBytes = req.HttpContext.Connection.RemoteIpAddress?.GetAddressBytes() ?? Array.Empty<byte>();
    var ipSalt = cfg["Analytics:IpSalt"];
    if (string.IsNullOrWhiteSpace(ipSalt))
    {
        ipSalt = "changeme";
    }

    byte[] ipHash;
    using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(ipSalt)))
    {
        ipHash = hmac.ComputeHash(remoteAddressBytes);
    }

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureAnalyticsEventTableAsync(conn, ct);

        const string insertSql = @"
      INSERT IGNORE INTO AnalyticsEvent
      (event_uuid,event_version,env,occurred_at,received_at,event_name,
       user_id,session_id,build_id,engine_family_id,category_id,part_id,rule_id,
       severity,source,numeric_value,extra,user_agent,ip_hash)
      VALUES
      (@uuid,1,@env,@occurred,@received,@name,
       @user,@sid,@build,@engine,@cat,@part,@rule,
       @sev,@src,@num,@extra,@ua,@ip)";

        var parameters = new
        {
            uuid = eventUuid,
            env = analyticsEnv,
            occurred = occurredAt,
            received = now,
            name = eventName,
            user = dto.UserId,
            sid = sessionId,
            build = dto.BuildId,
            engine = dto.EngineFamilyId,
            cat = dto.CategoryId,
            part = dto.PartId,
            rule = dto.RuleId,
            sev = severity,
            src = source,
            num = dto.NumericValue,
            extra = extraJson,
            ua = req.Headers.UserAgent.ToString(),
            ip = ipHash
        };

        var command = new CommandDefinition(insertSql, parameters, cancellationToken: ct);
        var affected = await conn.ExecuteAsync(command);

        return Results.Ok(new { ok = true, inserted = affected > 0 });
    }
    catch (Exception ex)
    {
        var logger = req.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("AnalyticsIngest");
        logger.LogError(ex, "Analytics ingest failed for event {EventName}", eventName);
        return Results.Problem(title: "Analytics ingest failed", detail: ex.Message, statusCode: 500);
    }
});

// Click redirect endpoint (affiliate-friendly)
app.MapGet("/api/click", async (long partId, long offeringId, long? buildId, CancellationToken ct)
    => await HandleClickAsync(connectionString, partId, offeringId, buildId, vendorName: null, redirect: true, ct));

// Redirect shortcut for buy links (logs click then 302s to vendor)
app.MapGet("/shop/go", async (long partId, long? offeringId, long? buildId, CancellationToken ct)
    => await HandleClickAsync(connectionString, partId, offeringId, buildId, vendorName: null, redirect: true, ct));

// Build buy plan (cheapest mix or single vendor) – limited to owners/editors
app.MapPost("/api/builds/{buildId:long}/buyplan", async (long buildId, string mode, CancellationToken ct)
    => await GenerateBuyPlanAsync(connectionString, buildId, mode, ct))
    .RequireAuthorization("BuildOwnerOrEditor");

// Ingestion: bootstrap via Perplexity for an engine code (admin only)
app.MapPost("/api/ingest/bootstrap-engine", async (HttpContext ctx, IngestionService svc, HttpRequest req, CancellationToken ct) =>
{
    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    var body = await req.ReadFromJsonAsync<Dictionary<string, string?>>(cancellationToken: ct);
    if (body is null) return Results.BadRequest(new { error = "Invalid JSON" });
    var engineCode = body.TryGetValue("engine_code", out var code) ? code : null;
    var treeName = body.TryGetValue("tree_name", out var tn) ? tn : null;
    if (string.IsNullOrWhiteSpace(engineCode)) return Results.BadRequest(new { error = "engine_code required" });
    var payload = await svc.GenerateForEngineAsync(engineCode!, treeName, null, ct);
    var result = await svc.IngestAsync(payload, ct);
    return Results.Json(result);
}).RequireAuthorization("IsSignedIn");

// Ingestion: post a prepared payload JSON (bypass Perplexity)
app.MapPost("/api/ingest/from-json", async (HttpContext ctx, IngestionService svc, HttpRequest req, CancellationToken ct) =>
{
    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    var payload = await req.ReadFromJsonAsync<IngestionPayload>(cancellationToken: ct);
    if (payload is null) return Results.BadRequest(new { error = "Invalid JSON" });
    var result = await svc.IngestAsync(payload, ct);
    return Results.Json(result);
}).RequireAuthorization("IsSignedIn");

// Ingestion: preview from a URL (no DB writes)
app.MapPost("/api/ingest/preview-from-url", async (HttpContext ctx, IngestionService svc, HttpRequest req, CancellationToken ct) =>
{
    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    IngestPreviewRequest? body = null;
    try { body = await req.ReadFromJsonAsync<IngestPreviewRequest>(cancellationToken: ct); }
    catch { }

    var url = body?.url;
    var engineCode = body?.engine_code;
    var treeName = body?.tree_name;
    var useDbEngines = false;
    if (req.Query.TryGetValue("use_db_engines", out var qv))
    {
        bool.TryParse(qv, out useDbEngines);
    }
    if (body?.use_db_engines is bool bEng) useDbEngines = bEng;
    var useDbCategories = false;
    if (req.Query.TryGetValue("use_db_categories", out var qvc))
    {
        bool.TryParse(qvc, out useDbCategories);
    }
    if (body?.use_db_categories is bool bCats) useDbCategories = bCats;
    var useDbTreeEdges = false;
    if (req.Query.TryGetValue("use_db_tree_edges", out var qve))
    {
        bool.TryParse(qve, out useDbTreeEdges);
    }
    if (body?.use_db_tree_edges is bool bEdges) useDbTreeEdges = bEdges;
    var enrichParts = true;
    if (req.Query.TryGetValue("enrich_parts", out var qvp))
    {
        bool.TryParse(qvp, out enrichParts);
    }
    if (body?.enrich_parts is bool bEnrich) enrichParts = bEnrich;

    var forcedCodes = body?.engine_codes?.Where(code => !string.IsNullOrWhiteSpace(code)).Select(code => code!.Trim()).Where(code => code.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList() ?? new List<string>();

    if (string.IsNullOrWhiteSpace(url)) return Results.BadRequest(new { error = "url required" });
    var payload = await svc.GenerateFromUrlAsync(url!, engineCode, treeName, useDbEngines, useDbCategories, useDbTreeEdges, forcedCodes, ct);
    if (enrichParts) payload = await svc.EnrichPartsAsync(payload, ct);
    payload = svc.NormalizePayload(payload, forcedCodes);
    return Results.Json(payload);
}).RequireAuthorization("IsSignedIn");

// List engine families
app.MapGet("/api/engine-families", async () =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);
    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync();
        var list = new List<Dictionary<string, object?>>();
        const string sql = @"
SELECT
    ef.engine_family_id,
    ef.code,
    ef.rotor_count,
    ef.years_start,
    ef.years_end,
    COALESCE(sc.slot_count, 0) AS slot_count,
    ef.scene_gltf_uri
FROM EngineFamily ef
LEFT JOIN (
    SELECT engine_family_id, COUNT(*) AS slot_count
    FROM Slot
    GROUP BY engine_family_id
) sc ON sc.engine_family_id = ef.engine_family_id
ORDER BY
    CASE WHEN COALESCE(sc.slot_count, 0) > 0 THEN 0 ELSE 1 END,
    CASE WHEN ef.scene_gltf_uri IS NOT NULL AND ef.scene_gltf_uri <> '' THEN 0 ELSE 1 END,
    ef.code;";
        await using var cmd = new MySqlCommand(sql, conn);
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < reader.FieldCount; i++) row[reader.GetName(i)] = reader.IsDBNull(i) ? null : reader.GetValue(i);
            list.Add(row);
        }
        return Results.Json(list);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Query failed", detail: ex.Message, statusCode: 500);
    }
});

// Resolve default category tree for an engine family
app.MapGet("/api/engine-families/{engineFamilyId:long}/default-tree", async (long engineFamilyId, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        var resolved = await ResolveDefaultTreeForEngineAsync(conn, engineFamilyId, ct);
        if (!resolved.EngineExists)
            return Results.NotFound(new { error = "engine_family_not_found" });

        if (!resolved.TreeId.HasValue)
            return Results.NotFound(new { error = "no_default_tree" });

        return Results.Json(new
        {
            engine_family_id = engineFamilyId,
            engine_code = resolved.EngineCode,
            tree_id = resolved.TreeId.Value,
            tree_name = resolved.TreeName
        });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Fetch default tree failed", detail: ex.Message, statusCode: 500);
    }
});

// Guides listing (public)
app.MapGet("/api/guides", async (CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureGuideTablesAsync(conn, ct);

        const string sql = @"SELECT guide_id   AS GuideId,
                                    slug        AS Slug,
                                    title       AS Title,
                                    published_at AS PublishedAt,
                                    updated_at   AS UpdatedAt
                             FROM Guide
                             WHERE published_at IS NOT NULL
                             ORDER BY published_at DESC, updated_at DESC";

        var items = (await conn.QueryAsync<GuideSummaryDto>(sql)).ToList();
        return Results.Ok(new { items });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "List guides failed", detail: ex.Message, statusCode: 500);
    }
});

// Guide detail with related parts
app.MapGet("/api/guides/{slug}", async (string slug, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);
    if (string.IsNullOrWhiteSpace(slug))
        return Results.BadRequest(new { error = "slug_required" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureGuideTablesAsync(conn, ct);

        var normalizedSlug = slug.Trim().ToLowerInvariant();

        var guide = await conn.QuerySingleOrDefaultAsync<GuideDetailDto>(@"
            SELECT guide_id   AS GuideId,
                   slug        AS Slug,
                   title       AS Title,
                   content_md  AS ContentMarkdown,
                   published_at AS PublishedAt,
                   updated_at   AS UpdatedAt
            FROM Guide
            WHERE slug=@slug AND published_at IS NOT NULL", new { slug = normalizedSlug });

        if (guide is null)
            return Results.NotFound(new { error = "guide_not_found" });

        var parts = (await conn.QueryAsync<GuidePartDto>(@"
            SELECT gp.part_id AS PartId,
                   gp.position AS Position,
                   p.name AS Name,
                   p.sku  AS Sku
            FROM GuidePart gp
            LEFT JOIN Part p ON p.part_id = gp.part_id
            WHERE gp.guide_id=@id
            ORDER BY gp.position, p.name", new { id = guide.GuideId })).ToList();

        return Results.Ok(new { guide, parts });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Load guide failed", detail: ex.Message, statusCode: 500);
    }
});

// List category trees
app.MapGet("/api/category-trees", async () =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);
    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync();
        var list = new List<Dictionary<string, object?>>();
        await using var cmd = new MySqlCommand("SELECT tree_id, name FROM CategoryTree ORDER BY name", conn);
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
            {
                ["tree_id"] = reader.GetInt64(0),
                ["name"] = reader.GetString(1)
            };
            list.Add(row);
        }
        return Results.Json(list);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Query failed", detail: ex.Message, statusCode: 500);
    }
});

var EngineInductionOptions = CreateEnumMap("NA", "Turbo", "TwinTurboSeq", "Supercharged");
var EngineInjectionOptions = CreateEnumMap("Carb", "TBI", "EFI");
var EngineOmpOptions = CreateEnumMap("None", "Mechanical", "Electric");
var EngineIgnitionOptions = CreateEnumMap("LeadingTrailing", "CoilOnPlug", "Distributor");
var EngineIntakeArchOptions = CreateEnumMap("4-Port", "6-Port", "Bridge", "Peripheral");
var EnginePortFamilyOptions = CreateEnumMap("Side", "Peripheral", "Mixed");
var EngineEcuTypeOptions = CreateEnumMap("OEM", "Aftermarket", "None");
var EngineTurboSystemOptions = CreateEnumMap("None", "Single", "SequentialTwin", "ParallelTwin");
var EngineHousingStepOptions = CreateEnumMap("Standard", "RX8_RENESIS", "Ceramic", "Aftermarket_Coated");
var EngineExhaustPortOptions = CreateEnumMap("Side", "Peripheral");
var EngineEmissionsOptions = CreateEnumMap("None", "JDM", "USDM", "Euro");

// Admin: engine families list (paged, searchable)
app.MapGet("/api/admin/engine-families", async (HttpContext ctx, string? q, int page = 1, int pageSize = 50, CancellationToken ct = default) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    var search = string.IsNullOrWhiteSpace(q) ? null : q!.Trim();
    var pageNumber = Math.Max(1, page);
    var limit = Math.Clamp(pageSize, 1, 200);
    var offset = (pageNumber - 1) * limit;

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureEngineFamilyTreeSchemaAsync(conn, ct);

        const string sql = @"SELECT ef.engine_family_id AS EngineFamilyId,
                                     ef.code AS Code,
                                     ef.rotor_count AS RotorCount,
                                     ef.years_start AS YearsStart,
                                     ef.years_end AS YearsEnd,
                                     ef.hp_min AS HpMin,
                                     ef.hp_max AS HpMax,
                                     ef.induction AS Induction,
                                     ef.injection AS Injection,
                                     ef.omp_type AS OmpType,
                                     ef.ignition_layout AS IgnitionLayout,
                                     ef.intake_arch AS IntakeArch,
                                     ef.port_family AS PortFamily,
                                     ef.egt_sensors AS EgtSensors,
                                     ef.o2_sensors AS O2Sensors,
                                     ef.ecu_type AS EcuType,
                                     ef.turbo_system AS TurboSystem,
                                     ef.intercooler AS Intercooler,
                                     ef.apex_seal_thickness_mm AS ApexSealThicknessMm,
                                     ef.rotor_mass_g AS RotorMassG,
                                     ef.housing_step AS HousingStep,
                                     ef.exhaust_port_type AS ExhaustPortType,
                                     ef.emissions_pkg AS EmissionsPkg,
                                     ef.compression_min_psi AS CompressionMinPsi,
                                     ef.compression_max_psi AS CompressionMaxPsi,
                                     ef.notes AS Notes,
                                     ef.created_at AS CreatedAt,
                                     ef.updated_at AS UpdatedAt,
                                     eft.tree_id AS DefaultTreeId,
                                     t.name AS DefaultTreeName
                              FROM EngineFamily ef
                              LEFT JOIN EngineFamilyTree eft
                                ON eft.engine_family_id = ef.engine_family_id
                               AND eft.is_default = TRUE
                              LEFT JOIN CategoryTree t ON t.tree_id = eft.tree_id
                              WHERE (@q IS NULL OR ef.code LIKE CONCAT('%', @q, '%'))
                              ORDER BY ef.code
                              LIMIT @limit OFFSET @offset";

        var rows = (await conn.QueryAsync<AdminEngineFamilyRow>(sql, new { q = search, limit, offset }))
            .ToList();

        const string countSql = @"SELECT COUNT(*)
                                  FROM EngineFamily ef
                                  WHERE (@q IS NULL OR ef.code LIKE CONCAT('%', @q, '%'))";

        var total = await conn.ExecuteScalarAsync<int>(countSql, new { q = search });

        return Results.Ok(new { rows, total, page = pageNumber, pageSize = limit });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Fetch engine families failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: engine family detail
app.MapGet("/api/admin/engine-families/{engineFamilyId:long}", async (HttpContext ctx, long engineFamilyId, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureEngineFamilyTreeSchemaAsync(conn, ct);

        const string sql = @"SELECT ef.engine_family_id AS EngineFamilyId,
                                     ef.code AS Code,
                                     ef.rotor_count AS RotorCount,
                                     ef.years_start AS YearsStart,
                                     ef.years_end AS YearsEnd,
                                     ef.hp_min AS HpMin,
                                     ef.hp_max AS HpMax,
                                     ef.induction AS Induction,
                                     ef.injection AS Injection,
                                     ef.omp_type AS OmpType,
                                     ef.ignition_layout AS IgnitionLayout,
                                     ef.intake_arch AS IntakeArch,
                                     ef.port_family AS PortFamily,
                                     ef.egt_sensors AS EgtSensors,
                                     ef.o2_sensors AS O2Sensors,
                                     ef.ecu_type AS EcuType,
                                     ef.turbo_system AS TurboSystem,
                                     ef.intercooler AS Intercooler,
                                     ef.apex_seal_thickness_mm AS ApexSealThicknessMm,
                                     ef.rotor_mass_g AS RotorMassG,
                                     ef.housing_step AS HousingStep,
                                     ef.exhaust_port_type AS ExhaustPortType,
                                     ef.emissions_pkg AS EmissionsPkg,
                                     ef.compression_min_psi AS CompressionMinPsi,
                                     ef.compression_max_psi AS CompressionMaxPsi,
                                     ef.notes AS Notes,
                                     ef.created_at AS CreatedAt,
                                     ef.updated_at AS UpdatedAt,
                                     eft.tree_id AS DefaultTreeId,
                                     t.name AS DefaultTreeName
                              FROM EngineFamily ef
                              LEFT JOIN EngineFamilyTree eft
                                ON eft.engine_family_id = ef.engine_family_id
                               AND eft.is_default = TRUE
                              LEFT JOIN CategoryTree t ON t.tree_id = eft.tree_id
                              WHERE ef.engine_family_id = @id";

        var row = await conn.QuerySingleOrDefaultAsync<AdminEngineFamilyRow>(sql, new { id = engineFamilyId });
        return row is null ? Results.NotFound() : Results.Ok(row);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Fetch engine family failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: create engine family
app.MapPost("/api/admin/engine-families", async (HttpContext ctx, AdminEngineFamilyCreateRequest? body, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    if (body is null)
        return Results.BadRequest(new { error = "invalid_payload" });

    var code = body.Code?.Trim();
    if (string.IsNullOrWhiteSpace(code))
        return Results.BadRequest(new { error = "code_required" });

    var notes = string.IsNullOrWhiteSpace(body.Notes) ? null : body.Notes!.Trim();

    if (!TryNormalizeEnum(body.Induction, EngineInductionOptions, out var induction))
        return Results.BadRequest(new { error = "invalid_induction" });
    if (!TryNormalizeEnum(body.Injection, EngineInjectionOptions, out var injection))
        return Results.BadRequest(new { error = "invalid_injection" });
    if (!TryNormalizeEnum(body.OmpType, EngineOmpOptions, out var ompType))
        return Results.BadRequest(new { error = "invalid_omp_type" });
    if (!TryNormalizeEnum(body.IgnitionLayout, EngineIgnitionOptions, out var ignitionLayout))
        return Results.BadRequest(new { error = "invalid_ignition_layout" });
    if (!TryNormalizeEnum(body.IntakeArch, EngineIntakeArchOptions, out var intakeArch))
        return Results.BadRequest(new { error = "invalid_intake_arch" });
    if (!TryNormalizeEnum(body.PortFamily, EnginePortFamilyOptions, out var portFamily))
        return Results.BadRequest(new { error = "invalid_port_family" });
    if (!TryNormalizeEnum(body.EcuType, EngineEcuTypeOptions, out var ecuType))
        return Results.BadRequest(new { error = "invalid_ecu_type" });
    if (!TryNormalizeEnum(body.TurboSystem, EngineTurboSystemOptions, out var turboSystem))
        return Results.BadRequest(new { error = "invalid_turbo_system" });
    if (!TryNormalizeEnum(body.HousingStep, EngineHousingStepOptions, out var housingStep))
        return Results.BadRequest(new { error = "invalid_housing_step" });
    if (!TryNormalizeEnum(body.ExhaustPortType, EngineExhaustPortOptions, out var exhaustPortType))
        return Results.BadRequest(new { error = "invalid_exhaust_port_type" });
    if (!TryNormalizeEnum(body.EmissionsPkg, EngineEmissionsOptions, out var emissionsPkg))
        return Results.BadRequest(new { error = "invalid_emissions_pkg" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureEngineFamilyTreeSchemaAsync(conn, ct);
        await using var tx = await conn.BeginTransactionAsync(ct);

        const string insertSql = @"INSERT INTO EngineFamily
            (code, rotor_count, years_start, years_end, hp_min, hp_max,
             induction, injection, omp_type, ignition_layout, intake_arch, port_family,
             egt_sensors, o2_sensors, ecu_type, turbo_system, intercooler,
             apex_seal_thickness_mm, rotor_mass_g, housing_step,
             exhaust_port_type, emissions_pkg, compression_min_psi, compression_max_psi,
             notes, created_at, updated_at)
            VALUES (@code, @rotor, @yearsStart, @yearsEnd, @hpMin, @hpMax,
                    @induction, @injection, @ompType, @ignitionLayout, @intakeArch, @portFamily,
                    @egtSensors, @o2Sensors, @ecuType, @turboSystem, @intercooler,
                    @apexSealThickness, @rotorMass, @housingStep,
                    @exhaustPort, @emissionsPkg, @compressionMin, @compressionMax,
                    @notes, NOW(), NOW())";

        var insertParams = new
        {
            code,
            rotor = body.RotorCount,
            yearsStart = body.YearsStart,
            yearsEnd = body.YearsEnd,
            hpMin = body.HpMin,
            hpMax = body.HpMax,
            induction,
            injection,
            ompType,
            ignitionLayout,
            intakeArch,
            portFamily,
            egtSensors = body.EgtSensors,
            o2Sensors = body.O2Sensors,
            ecuType,
            turboSystem,
            intercooler = body.Intercooler,
            apexSealThickness = body.ApexSealThicknessMm,
            rotorMass = body.RotorMassG,
            housingStep,
            exhaustPort = exhaustPortType,
            emissionsPkg,
            compressionMin = body.CompressionMinPsi,
            compressionMax = body.CompressionMaxPsi,
            notes
        };

        await conn.ExecuteAsync(insertSql, insertParams, tx);

        var id = await conn.ExecuteScalarAsync<long>("SELECT engine_family_id FROM EngineFamily WHERE code=@code", new { code }, tx);

        if (body.DefaultTreeId.HasValue)
        {
            var treeExists = await conn.ExecuteScalarAsync<long?>("SELECT tree_id FROM CategoryTree WHERE tree_id=@tree", new { tree = body.DefaultTreeId.Value }, tx);
            if (treeExists is null)
            {
                await tx.RollbackAsync(ct);
                return Results.NotFound(new { error = "tree_not_found" });
            }

            const string clearSql = "UPDATE EngineFamilyTree SET is_default=FALSE WHERE engine_family_id=@id";
            await conn.ExecuteAsync(clearSql, new { id }, tx);

            const string upsertSql = @"INSERT INTO EngineFamilyTree(engine_family_id, tree_id, is_default)
                                      VALUES(@id, @treeId, TRUE)
                                      ON DUPLICATE KEY UPDATE is_default=TRUE";
            await conn.ExecuteAsync(upsertSql, new { id, treeId = body.DefaultTreeId.Value }, tx);
        }

        await tx.CommitAsync(ct);
        return Results.Created($"/api/admin/engine-families/{id}", new { engine_family_id = id });
    }
    catch (MySqlException ex) when (ex.Number == 1062)
    {
        return Results.Conflict(new { error = "duplicate_code" });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Create engine family failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: update engine family
app.MapPatch("/api/admin/engine-families/{engineFamilyId:long}", async (HttpContext ctx, long engineFamilyId, JsonElement payload, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    if (payload.ValueKind != JsonValueKind.Object)
        return Results.BadRequest(new { error = "invalid_payload" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureEngineFamilyTreeSchemaAsync(conn, ct);
        await using var tx = await conn.BeginTransactionAsync(ct);

        var exists = await conn.ExecuteScalarAsync<long?>("SELECT engine_family_id FROM EngineFamily WHERE engine_family_id=@id", new { id = engineFamilyId }, tx);
        if (exists is null)
        {
            await tx.RollbackAsync(ct);
            return Results.NotFound();
        }

        var parameters = new DynamicParameters();
        parameters.Add("id", engineFamilyId);
        var assignments = new List<string>();

        if (payload.TryGetProperty("code", out var codeProp))
        {
            var codeValue = codeProp.ValueKind switch
            {
                JsonValueKind.Null => null,
                JsonValueKind.String => codeProp.GetString()?.Trim(),
                _ => codeProp.GetRawText()?.Trim('"')
            };

            if (string.IsNullOrWhiteSpace(codeValue))
            {
                await tx.RollbackAsync(ct);
                return Results.BadRequest(new { error = "code_required" });
            }

            assignments.Add("code = @code");
            parameters.Add("code", codeValue);
        }

        void HandleIntProperty(string jsonName, string columnName)
        {
            if (!payload.TryGetProperty(jsonName, out var prop))
                return;

            if (prop.ValueKind == JsonValueKind.Null)
            {
                assignments.Add($"{columnName} = @{columnName}");
                parameters.Add(columnName, null);
                return;
            }

            if (!prop.TryGetInt32(out var val))
            {
                throw new InvalidOperationException($"invalid_{jsonName}");
            }

            assignments.Add($"{columnName} = @{columnName}");
            parameters.Add(columnName, val);
        }

        void HandleDecimalProperty(string jsonName, string columnName)
        {
            if (!payload.TryGetProperty(jsonName, out var prop))
                return;

            if (prop.ValueKind == JsonValueKind.Null)
            {
                assignments.Add($"{columnName} = @{columnName}");
                parameters.Add(columnName, null);
                return;
            }

            decimal value;
            if (prop.ValueKind == JsonValueKind.Number)
            {
                if (!prop.TryGetDecimal(out value))
                    throw new InvalidOperationException($"invalid_{jsonName}");
            }
            else if (prop.ValueKind == JsonValueKind.String)
            {
                var raw = prop.GetString();
                if (string.IsNullOrWhiteSpace(raw))
                {
                    assignments.Add($"{columnName} = @{columnName}");
                    parameters.Add(columnName, null);
                    return;
                }

                if (!decimal.TryParse(raw, NumberStyles.Number, CultureInfo.InvariantCulture, out value))
                    throw new InvalidOperationException($"invalid_{jsonName}");
            }
            else
            {
                throw new InvalidOperationException($"invalid_{jsonName}");
            }

            assignments.Add($"{columnName} = @{columnName}");
            parameters.Add(columnName, value);
        }

        void HandleBoolProperty(string jsonName, string columnName)
        {
            if (!payload.TryGetProperty(jsonName, out var prop))
                return;

            if (prop.ValueKind == JsonValueKind.Null)
            {
                assignments.Add($"{columnName} = @{columnName}");
                parameters.Add(columnName, null);
                return;
            }

            bool? value = prop.ValueKind switch
            {
                JsonValueKind.True => true,
                JsonValueKind.False => false,
                JsonValueKind.Number => prop.TryGetInt32(out var numVal)
                    ? numVal switch
                    {
                        0 => false,
                        1 => true,
                        _ => throw new InvalidOperationException($"invalid_{jsonName}")
                    }
                    : throw new InvalidOperationException($"invalid_{jsonName}"),
                JsonValueKind.String => prop.GetString() switch
                {
                    null => null,
                    var raw when string.IsNullOrWhiteSpace(raw) => null,
                    var raw when raw.Equals("true", StringComparison.OrdinalIgnoreCase) => true,
                    var raw when raw.Equals("false", StringComparison.OrdinalIgnoreCase) => false,
                    var raw when raw == "1" => true,
                    var raw when raw == "0" => false,
                    _ => throw new InvalidOperationException($"invalid_{jsonName}")
                },
                _ => throw new InvalidOperationException($"invalid_{jsonName}")
            };

            assignments.Add($"{columnName} = @{columnName}");
            parameters.Add(columnName, (object?)value ?? DBNull.Value);
        }

        void HandleEnumProperty(string jsonName, string columnName, IReadOnlyDictionary<string, string> options)
        {
            if (!payload.TryGetProperty(jsonName, out var prop))
                return;

            if (prop.ValueKind == JsonValueKind.Null)
            {
                assignments.Add($"{columnName} = @{columnName}");
                parameters.Add(columnName, null);
                return;
            }

            if (prop.ValueKind != JsonValueKind.String)
                throw new InvalidOperationException($"invalid_{jsonName}");

            var raw = prop.GetString();
            if (!TryNormalizeEnum(raw, options, out var normalized))
                throw new InvalidOperationException($"invalid_{jsonName}");

            assignments.Add($"{columnName} = @{columnName}");
            parameters.Add(columnName, normalized);
        }

        HandleIntProperty("rotor_count", "rotor_count");
        HandleIntProperty("hp_min", "hp_min");
        HandleIntProperty("hp_max", "hp_max");
        HandleIntProperty("egt_sensors", "egt_sensors");
        HandleIntProperty("o2_sensors", "o2_sensors");
        HandleIntProperty("rotor_mass_g", "rotor_mass_g");
        HandleIntProperty("compression_min_psi", "compression_min_psi");
        HandleIntProperty("compression_max_psi", "compression_max_psi");

        HandleDecimalProperty("apex_seal_thickness_mm", "apex_seal_thickness_mm");
        HandleBoolProperty("intercooler", "intercooler");

        HandleEnumProperty("induction", "induction", EngineInductionOptions);
        HandleEnumProperty("injection", "injection", EngineInjectionOptions);
        HandleEnumProperty("omp_type", "omp_type", EngineOmpOptions);
        HandleEnumProperty("ignition_layout", "ignition_layout", EngineIgnitionOptions);
        HandleEnumProperty("intake_arch", "intake_arch", EngineIntakeArchOptions);
        HandleEnumProperty("port_family", "port_family", EnginePortFamilyOptions);
        HandleEnumProperty("ecu_type", "ecu_type", EngineEcuTypeOptions);
        HandleEnumProperty("turbo_system", "turbo_system", EngineTurboSystemOptions);
        HandleEnumProperty("housing_step", "housing_step", EngineHousingStepOptions);
        HandleEnumProperty("exhaust_port_type", "exhaust_port_type", EngineExhaustPortOptions);
        HandleEnumProperty("emissions_pkg", "emissions_pkg", EngineEmissionsOptions);

        if (payload.TryGetProperty("years_start", out var yearsStartProp))
        {
            if (yearsStartProp.ValueKind == JsonValueKind.Null)
            {
                assignments.Add("years_start = @years_start");
                parameters.Add("years_start", null);
            }
            else if (yearsStartProp.TryGetInt32(out var yearsStart))
            {
                assignments.Add("years_start = @years_start");
                parameters.Add("years_start", yearsStart);
            }
            else
            {
                await tx.RollbackAsync(ct);
                return Results.BadRequest(new { error = "invalid_years_start" });
            }
        }

        if (payload.TryGetProperty("years_end", out var yearsEndProp))
        {
            if (yearsEndProp.ValueKind == JsonValueKind.Null)
            {
                assignments.Add("years_end = @years_end");
                parameters.Add("years_end", null);
            }
            else if (yearsEndProp.TryGetInt32(out var yearsEnd))
            {
                assignments.Add("years_end = @years_end");
                parameters.Add("years_end", yearsEnd);
            }
            else
            {
                await tx.RollbackAsync(ct);
                return Results.BadRequest(new { error = "invalid_years_end" });
            }
        }

        if (payload.TryGetProperty("notes", out var notesProp))
        {
            string? notesValue = notesProp.ValueKind switch
            {
                JsonValueKind.Null => null,
                JsonValueKind.String => notesProp.GetString(),
                _ => notesProp.GetRawText()
            };

            notesValue = string.IsNullOrWhiteSpace(notesValue) ? null : notesValue!.Trim();

            assignments.Add("notes = @notes");
            parameters.Add("notes", notesValue);
        }

        assignments.Add("updated_at = NOW()");

        var updateSql = $"UPDATE EngineFamily SET {string.Join(", ", assignments)} WHERE engine_family_id=@id";
        await conn.ExecuteAsync(updateSql, parameters, tx);

        long? defaultTreeId = null;
        var defaultProvided = false;
        if (payload.TryGetProperty("default_tree_id", out var defaultProp))
        {
            defaultProvided = true;
            if (defaultProp.ValueKind == JsonValueKind.Null)
            {
                defaultTreeId = null;
            }
            else if (defaultProp.ValueKind == JsonValueKind.Number && defaultProp.TryGetInt64(out var treeId))
            {
                defaultTreeId = treeId;
            }
            else if (defaultProp.ValueKind == JsonValueKind.String && long.TryParse(defaultProp.GetString(), out var parsed))
            {
                defaultTreeId = parsed;
            }
            else
            {
                await tx.RollbackAsync(ct);
                return Results.BadRequest(new { error = "invalid_default_tree_id" });
            }
        }

        if (defaultProvided)
        {
            const string clearSql = "UPDATE EngineFamilyTree SET is_default=FALSE WHERE engine_family_id=@id";
            await conn.ExecuteAsync(clearSql, new { id = engineFamilyId }, tx);

            if (defaultTreeId.HasValue)
            {
                var treeExists = await conn.ExecuteScalarAsync<long?>("SELECT tree_id FROM CategoryTree WHERE tree_id=@tree", new { tree = defaultTreeId.Value }, tx);
                if (treeExists is null)
                {
                    await tx.RollbackAsync(ct);
                    return Results.NotFound(new { error = "tree_not_found" });
                }

                const string upsertSql = @"INSERT INTO EngineFamilyTree(engine_family_id, tree_id, is_default)
                                          VALUES(@id, @treeId, TRUE)
                                          ON DUPLICATE KEY UPDATE is_default=TRUE";
                await conn.ExecuteAsync(upsertSql, new { id = engineFamilyId, treeId = defaultTreeId.Value }, tx);
            }
        }

        await tx.CommitAsync(ct);
        return Results.Ok(new { ok = true });
    }
    catch (InvalidOperationException ex) when (ex.Message.StartsWith("invalid_", StringComparison.OrdinalIgnoreCase))
    {
        return Results.BadRequest(new { error = ex.Message });
    }
    catch (MySqlException ex) when (ex.Number == 1062)
    {
        return Results.Conflict(new { error = "duplicate_code" });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Update engine family failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: delete engine family
app.MapDelete("/api/admin/engine-families/{engineFamilyId:long}", async (HttpContext ctx, long engineFamilyId, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureEngineFamilyTreeSchemaAsync(conn, ct);

        const string usageSql = @"SELECT
                    (SELECT COUNT(*) FROM Build WHERE engine_family_id=@id) AS Builds,
                    (SELECT COUNT(*) FROM PartFitment WHERE engine_family_id=@id) AS Fitments,
                    (SELECT COUNT(*) FROM EngineFamilyTree WHERE engine_family_id=@id) AS Mappings";

        var usage = await conn.QuerySingleAsync<AdminEngineFamilyUsageRow>(usageSql, new { id = engineFamilyId });

        if (usage.Builds > 0 || usage.Fitments > 0 || usage.Mappings > 0)
        {
            return Results.Conflict(new
            {
                error = "in_use",
                message = $"In use by Builds:{usage.Builds}, Fitment:{usage.Fitments}, Tree mappings:{usage.Mappings}. Merge or remove references first."
            });
        }

        var rows = await conn.ExecuteAsync("DELETE FROM EngineFamily WHERE engine_family_id=@id", new { id = engineFamilyId });
        return rows == 0 ? Results.NotFound() : Results.Ok(new { ok = true });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Delete engine family failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: merge engine families
app.MapPost("/api/admin/engine-families/merge", async (HttpContext ctx, AdminEngineFamilyMergeRequest? body, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    if (body is null)
        return Results.BadRequest(new { error = "invalid_payload" });

    if (body.FromId == body.ToId)
        return Results.BadRequest(new { error = "same_id" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureEngineFamilyTreeSchemaAsync(conn, ct);
        await using var tx = await conn.BeginTransactionAsync(ct);

        var fromExists = await conn.ExecuteScalarAsync<long?>("SELECT engine_family_id FROM EngineFamily WHERE engine_family_id=@id", new { id = body.FromId }, tx);
        var toExists = await conn.ExecuteScalarAsync<long?>("SELECT engine_family_id FROM EngineFamily WHERE engine_family_id=@id", new { id = body.ToId }, tx);

        if (fromExists is null || toExists is null)
        {
            await tx.RollbackAsync(ct);
            return Results.NotFound(new { error = "engine_not_found" });
        }

        await conn.ExecuteAsync("UPDATE Build SET engine_family_id=@to WHERE engine_family_id=@from", new { from = body.FromId, to = body.ToId }, tx);
        await conn.ExecuteAsync("UPDATE PartFitment SET engine_family_id=@to WHERE engine_family_id=@from", new { from = body.FromId, to = body.ToId }, tx);
        await conn.ExecuteAsync("DELETE FROM EngineFamilyTree WHERE engine_family_id=@from", new { from = body.FromId }, tx);
        await conn.ExecuteAsync("DELETE FROM EngineFamily WHERE engine_family_id=@from", new { from = body.FromId }, tx);

        await tx.CommitAsync(ct);
        return Results.Ok(new { ok = true });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Merge engine families failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: list engine attribute definitions
app.MapGet("/api/admin/engine-attrs", async (HttpContext ctx, string? q, int page = 1, int pageSize = 50, CancellationToken ct = default) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    var search = string.IsNullOrWhiteSpace(q) ? null : q.Trim();
    var pageNumber = Math.Max(1, page);
    var limit = Math.Clamp(pageSize, 1, 200);
    var offset = (pageNumber - 1) * limit;

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await SchemaHelpers.EnsureEngineFamilyColumnsAsync(conn, ct);

        const string sql = @"SELECT engine_attr_id AS EngineAttrId,
                                     code,
                                     name,
                                     data_type AS DataType,
                                     unit
                              FROM EngineAttributeDef
                              WHERE (@q IS NULL OR code LIKE CONCAT('%', @q, '%') OR name LIKE CONCAT('%', @q, '%'))
                              ORDER BY code
                              LIMIT @limit OFFSET @offset";

        var rows = (await conn.QueryAsync<AdminEngineAttributeDefRow>(sql, new { q = search, limit, offset })).ToList();

        const string countSql = @"SELECT COUNT(*)
                                  FROM EngineAttributeDef
                                  WHERE (@q IS NULL OR code LIKE CONCAT('%', @q, '%') OR name LIKE CONCAT('%', @q, '%'))";

        var total = await conn.ExecuteScalarAsync<int>(countSql, new { q = search });

        return Results.Ok(new { rows, total, page = pageNumber, pageSize = limit });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Fetch engine attribute definitions failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: create engine attribute definition
app.MapPost("/api/admin/engine-attrs", async (HttpContext ctx, AdminEngineAttributeDefCreateRequest? body, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    if (body is null)
        return Results.BadRequest(new { error = "invalid_payload" });

    var code = body.Code?.Trim();
    var name = body.Name?.Trim();
    var unit = string.IsNullOrWhiteSpace(body.Unit) ? null : body.Unit!.Trim();
    var dataType = body.DataType?.Trim().ToLowerInvariant();

    if (string.IsNullOrWhiteSpace(code))
        return Results.BadRequest(new { error = "code_required" });
    if (string.IsNullOrWhiteSpace(name))
        return Results.BadRequest(new { error = "name_required" });
    if (string.IsNullOrWhiteSpace(dataType) || dataType is not ("int" or "decimal" or "bool" or "text"))
        return Results.BadRequest(new { error = "invalid_data_type" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await SchemaHelpers.EnsureEngineFamilyColumnsAsync(conn, ct);

        const string insertSql = @"INSERT INTO EngineAttributeDef (code, name, data_type, unit)
                                   VALUES (@code, @name, @dataType, @unit)";

        var normalizedCode = code.ToLowerInvariant();
        await conn.ExecuteAsync(insertSql, new { code = normalizedCode, name, dataType, unit });

        var id = await conn.ExecuteScalarAsync<long>("SELECT engine_attr_id FROM EngineAttributeDef WHERE code=@code", new { code = normalizedCode });
        return Results.Created($"/api/admin/engine-attrs/{id}", new { engine_attr_id = id });
    }
    catch (MySqlException ex) when (ex.Number == 1062)
    {
        return Results.Conflict(new { error = "duplicate_code" });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Create engine attribute failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: update engine attribute definition
app.MapPatch("/api/admin/engine-attrs/{engineAttrId:long}", async (HttpContext ctx, long engineAttrId, AdminEngineAttributeDefUpdateRequest? body, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    if (body is null)
        return Results.BadRequest(new { error = "invalid_payload" });

    var dataType = body.DataType?.Trim().ToLowerInvariant();
    if (dataType is not null && dataType is not ("int" or "decimal" or "bool" or "text"))
        return Results.BadRequest(new { error = "invalid_data_type" });

    var assignments = new List<string>();
    var parameters = new DynamicParameters();
    parameters.Add("id", engineAttrId);

    if (!string.IsNullOrWhiteSpace(body.Name))
    {
        assignments.Add("name = @name");
        parameters.Add("name", body.Name.Trim());
    }

    if (!string.IsNullOrWhiteSpace(dataType))
    {
        assignments.Add("data_type = @dataType");
        parameters.Add("dataType", dataType);
    }

    if (body.Unit is not null)
    {
        var unit = string.IsNullOrWhiteSpace(body.Unit) ? null : body.Unit.Trim();
        assignments.Add("unit = @unit");
        parameters.Add("unit", unit);
    }

    if (assignments.Count == 0)
        return Results.BadRequest(new { error = "nothing_to_update" });

    var updateSql = $"UPDATE EngineAttributeDef SET {string.Join(", ", assignments)} WHERE engine_attr_id=@id";

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await SchemaHelpers.EnsureEngineFamilyColumnsAsync(conn, ct);

        var affected = await conn.ExecuteAsync(updateSql, parameters);
        return affected == 0 ? Results.NotFound() : Results.Ok(new { ok = true });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Update engine attribute failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: delete engine attribute definition
app.MapDelete("/api/admin/engine-attrs/{engineAttrId:long}", async (HttpContext ctx, long engineAttrId, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await SchemaHelpers.EnsureEngineFamilyColumnsAsync(conn, ct);

        var affected = await conn.ExecuteAsync("DELETE FROM EngineAttributeDef WHERE engine_attr_id=@id", new { id = engineAttrId });
        return affected == 0 ? Results.NotFound() : Results.Ok(new { ok = true });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Delete engine attribute failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: list attribute values for an engine family
app.MapGet("/api/admin/engine-families/{engineFamilyId:long}/attrs", async (HttpContext ctx, long engineFamilyId, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await SchemaHelpers.EnsureEngineFamilyColumnsAsync(conn, ct);

        var engineExists = await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM EngineFamily WHERE engine_family_id=@id", new { id = engineFamilyId });
        if (engineExists == 0)
            return Results.NotFound(new { error = "engine_not_found" });

        const string sql = @"SELECT d.engine_attr_id AS EngineAttrId,
                                     d.code,
                                     d.name,
                                     d.data_type AS DataType,
                                     d.unit,
                                     v.val_int AS ValInt,
                                     v.val_decimal AS ValDecimal,
                                     v.val_bool AS ValBool,
                                     v.val_text AS ValText
                              FROM EngineAttributeDef d
                              LEFT JOIN EngineAttributeValue v
                                ON v.engine_attr_id = d.engine_attr_id
                               AND v.engine_family_id = @engineId
                              ORDER BY d.code";

        var rows = (await conn.QueryAsync<AdminEngineAttributeValueRow>(sql, new { engineId = engineFamilyId })).ToList();
        return Results.Ok(rows);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Fetch engine attribute values failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: upsert attribute value for an engine family
app.MapPost("/api/admin/engine-families/{engineFamilyId:long}/attrs", async (HttpContext ctx, long engineFamilyId, JsonElement payload, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    if (payload.ValueKind != JsonValueKind.Object)
        return Results.BadRequest(new { error = "invalid_payload" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await SchemaHelpers.EnsureEngineFamilyColumnsAsync(conn, ct);

        var engineExists = await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM EngineFamily WHERE engine_family_id=@id", new { id = engineFamilyId });
        if (engineExists == 0)
            return Results.NotFound(new { error = "engine_not_found" });

        if (!payload.TryGetProperty("code", out var codeProp) || codeProp.ValueKind != JsonValueKind.String)
            return Results.BadRequest(new { error = "code_required" });

        var code = codeProp.GetString()?.Trim().ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(code))
            return Results.BadRequest(new { error = "code_required" });

        if (!payload.TryGetProperty("value", out var valueProp))
            return Results.BadRequest(new { error = "value_required" });

        var def = await conn.QuerySingleOrDefaultAsync<(long Id, string DataType)>("SELECT engine_attr_id AS Id, data_type AS DataType FROM EngineAttributeDef WHERE code=@code", new { code });
        if (def == default)
            return Results.NotFound(new { error = "attr_def_not_found" });

        long? valInt = null;
        decimal? valDecimal = null;
        bool? valBool = null;
        string? valText = null;

        switch (def.DataType)
        {
            case "int":
                if (valueProp.ValueKind == JsonValueKind.Null)
                    return Results.BadRequest(new { error = "value_required" });
                if (valueProp.ValueKind == JsonValueKind.Number && valueProp.TryGetInt64(out var intVal))
                {
                    valInt = intVal;
                }
                else if (valueProp.ValueKind == JsonValueKind.String && long.TryParse(valueProp.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsedInt))
                {
                    valInt = parsedInt;
                }
                else
                {
                    return Results.BadRequest(new { error = "invalid_value_type", expected = "int" });
                }
                break;

            case "decimal":
                if (valueProp.ValueKind == JsonValueKind.Null)
                    return Results.BadRequest(new { error = "value_required" });
                if (valueProp.ValueKind == JsonValueKind.Number && valueProp.TryGetDecimal(out var decVal))
                {
                    valDecimal = decVal;
                }
                else if (valueProp.ValueKind == JsonValueKind.String && decimal.TryParse(valueProp.GetString(), NumberStyles.Float, CultureInfo.InvariantCulture, out var parsedDec))
                {
                    valDecimal = parsedDec;
                }
                else
                {
                    return Results.BadRequest(new { error = "invalid_value_type", expected = "decimal" });
                }
                break;

            case "bool":
                if (valueProp.ValueKind == JsonValueKind.Null)
                    return Results.BadRequest(new { error = "value_required" });
                valBool = valueProp.ValueKind switch
                {
                    JsonValueKind.True => true,
                    JsonValueKind.False => false,
                    JsonValueKind.Number when valueProp.TryGetInt32(out var boolNum) && (boolNum == 0 || boolNum == 1) => boolNum == 1,
                    JsonValueKind.String => valueProp.GetString() switch
                    {
                        null => (bool?)null,
                        var raw when raw.Equals("true", StringComparison.OrdinalIgnoreCase) => true,
                        var raw when raw.Equals("false", StringComparison.OrdinalIgnoreCase) => false,
                        var raw when raw == "1" => true,
                        var raw when raw == "0" => false,
                        _ => null
                    },
                    _ => null
                };

                if (valBool is null)
                    return Results.BadRequest(new { error = "invalid_value_type", expected = "bool" });
                break;

            default:
                if (valueProp.ValueKind == JsonValueKind.Null)
                {
                    valText = null;
                }
                else if (valueProp.ValueKind == JsonValueKind.String)
                {
                    valText = valueProp.GetString();
                }
                else
                {
                    return Results.BadRequest(new { error = "invalid_value_type", expected = "text" });
                }
                break;
        }

        const string upsertSql = @"INSERT INTO EngineAttributeValue (engine_family_id, engine_attr_id, val_int, val_decimal, val_bool, val_text)
                                   VALUES (@engineId, @attrId, @valInt, @valDecimal, @valBool, @valText)
                                   ON DUPLICATE KEY UPDATE
                                     val_int=@valInt,
                                     val_decimal=@valDecimal,
                                     val_bool=@valBool,
                                     val_text=@valText";

        await conn.ExecuteAsync(upsertSql, new
        {
            engineId = engineFamilyId,
            attrId = def.Id,
            valInt,
            valDecimal,
            valBool,
            valText
        });

        return Results.Ok(new { ok = true });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Upsert engine attribute value failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: delete attribute value for an engine family
app.MapDelete("/api/admin/engine-families/{engineFamilyId:long}/attrs/{code}", async (HttpContext ctx, long engineFamilyId, string code, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    var normalizedCode = code?.Trim().ToLowerInvariant();
    if (string.IsNullOrWhiteSpace(normalizedCode))
        return Results.BadRequest(new { error = "code_required" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await SchemaHelpers.EnsureEngineFamilyColumnsAsync(conn, ct);

        var defId = await conn.ExecuteScalarAsync<long?>("SELECT engine_attr_id FROM EngineAttributeDef WHERE code=@code", new { code = normalizedCode });
        if (defId is null)
            return Results.NotFound(new { error = "attr_def_not_found" });

        await conn.ExecuteAsync("DELETE FROM EngineAttributeValue WHERE engine_family_id=@engine AND engine_attr_id=@attr", new { engine = engineFamilyId, attr = defId.Value });
        return Results.Ok(new { ok = true });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Delete engine attribute value failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: vendor lookup for ingest pickers
app.MapGet("/api/admin/vendors", async (HttpContext ctx, string? q, int limit = 100, CancellationToken ct = default) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        var search = string.IsNullOrWhiteSpace(q) ? null : q.Trim();
        var take = Math.Clamp(limit, 1, 200);

        const string sql = @"SELECT vendor_id, name
                              FROM Vendor
                              WHERE (@q IS NULL OR name LIKE CONCAT('%', @q, '%'))
                              ORDER BY name
                              LIMIT @limit";

        var rows = new List<Dictionary<string, object?>>(take);
        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@q", (object?)search ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@limit", take);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            rows.Add(new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
            {
                ["vendor_id"] = reader.GetInt64(0),
                ["name"] = reader.GetString(1)
            });
        }

        return Results.Json(rows);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Fetch vendors failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: brand lookup for ingest pickers
app.MapGet("/api/admin/brands", async (HttpContext ctx, string? q, int limit = 100, CancellationToken ct = default) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        var search = string.IsNullOrWhiteSpace(q) ? null : q.Trim();
        var take = Math.Clamp(limit, 1, 200);

        const string sql = @"SELECT brand_id, name
                              FROM Brand
                              WHERE (@q IS NULL OR name LIKE CONCAT('%', @q, '%'))
                              ORDER BY name
                              LIMIT @limit";

        var rows = new List<Dictionary<string, object?>>(take);
        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@q", (object?)search ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@limit", take);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            rows.Add(new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
            {
                ["brand_id"] = reader.GetInt64(0),
                ["name"] = reader.GetString(1)
            });
        }

        return Results.Json(rows);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Fetch brands failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: create brand (or ensure exists)
app.MapPost("/api/admin/brands", async (HttpContext ctx, string name, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    var trimmed = name?.Trim();
    if (string.IsNullOrWhiteSpace(trimmed))
        return Results.BadRequest(new { error = "name_required" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        await using (var upsert = new MySqlCommand("INSERT INTO Brand(name) VALUES(@name) ON DUPLICATE KEY UPDATE name=VALUES(name)", conn))
        {
            upsert.Parameters.AddWithValue("@name", trimmed);
            await upsert.ExecuteNonQueryAsync(ct);
        }

        await using var lookup = new MySqlCommand("SELECT brand_id FROM Brand WHERE name=@name", conn);
        lookup.Parameters.AddWithValue("@name", trimmed);
        var id = await lookup.ExecuteScalarAsync(ct);
        if (id is null)
            return Results.Problem(title: "Create brand failed", detail: "Could not resolve brand id", statusCode: 500);

        return Results.Json(new { brand_id = Convert.ToInt64(id), name = trimmed });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Create brand failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: create vendor (or ensure exists)
app.MapPost("/api/admin/vendors", async (HttpContext ctx, string name, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    var trimmed = name?.Trim();
    if (string.IsNullOrWhiteSpace(trimmed))
        return Results.BadRequest(new { error = "name_required" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        await using (var upsert = new MySqlCommand("INSERT INTO Vendor(name) VALUES(@name) ON DUPLICATE KEY UPDATE name=VALUES(name)", conn))
        {
            upsert.Parameters.AddWithValue("@name", trimmed);
            await upsert.ExecuteNonQueryAsync(ct);
        }

        await using var lookup = new MySqlCommand("SELECT vendor_id FROM Vendor WHERE name=@name", conn);
        lookup.Parameters.AddWithValue("@name", trimmed);
        var id = await lookup.ExecuteScalarAsync(ct);
        if (id is null)
            return Results.Problem(title: "Create vendor failed", detail: "Could not resolve vendor id", statusCode: 500);

        return Results.Json(new { vendor_id = Convert.ToInt64(id), name = trimmed });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Create vendor failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: rename brand
app.MapPatch("/api/admin/brands/{brandId:long}", async (HttpContext ctx, long brandId, string name, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    var trimmed = name?.Trim();
    if (string.IsNullOrWhiteSpace(trimmed))
        return Results.BadRequest(new { error = "name_required" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        await using var update = new MySqlCommand("UPDATE Brand SET name=@name WHERE brand_id=@id", conn);
        update.Parameters.AddWithValue("@name", trimmed);
        update.Parameters.AddWithValue("@id", brandId);
        var affected = await update.ExecuteNonQueryAsync(ct);
        return affected == 0 ? Results.NotFound(new { error = "brand_not_found" }) : Results.Json(new { ok = true });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Rename brand failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: rename vendor
app.MapPatch("/api/admin/vendors/{vendorId:long}", async (HttpContext ctx, long vendorId, string name, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    var trimmed = name?.Trim();
    if (string.IsNullOrWhiteSpace(trimmed))
        return Results.BadRequest(new { error = "name_required" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        await using var update = new MySqlCommand("UPDATE Vendor SET name=@name WHERE vendor_id=@id", conn);
        update.Parameters.AddWithValue("@name", trimmed);
        update.Parameters.AddWithValue("@id", vendorId);
        var affected = await update.ExecuteNonQueryAsync(ct);
        return affected == 0 ? Results.NotFound(new { error = "vendor_not_found" }) : Results.Json(new { ok = true });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Rename vendor failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: merge vendors (moves offerings, deletes source)
app.MapPost("/api/admin/vendors/merge", async (HttpContext ctx, long fromVendorId, long toVendorId, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    if (fromVendorId == toVendorId)
        return Results.BadRequest(new { error = "same_vendor" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await using var tx = await conn.BeginTransactionAsync(ct);

        async Task<bool> VendorExists(long id)
        {
            await using var cmd = new MySqlCommand("SELECT 1 FROM Vendor WHERE vendor_id=@id", conn, (MySqlTransaction)tx);
            cmd.Parameters.AddWithValue("@id", id);
            var result = await cmd.ExecuteScalarAsync(ct);
            return result is not null;
        }

        if (!await VendorExists(fromVendorId))
        {
            await tx.RollbackAsync(ct);
            return Results.NotFound(new { error = "from_vendor_not_found" });
        }

        if (!await VendorExists(toVendorId))
        {
            await tx.RollbackAsync(ct);
            return Results.NotFound(new { error = "to_vendor_not_found" });
        }

        await using (var update = new MySqlCommand("UPDATE PartOffering SET vendor_id=@to WHERE vendor_id=@from", conn, (MySqlTransaction)tx))
        {
            update.Parameters.AddWithValue("@to", toVendorId);
            update.Parameters.AddWithValue("@from", fromVendorId);
            await update.ExecuteNonQueryAsync(ct);
        }

        await using (var delete = new MySqlCommand("DELETE FROM Vendor WHERE vendor_id=@id", conn, (MySqlTransaction)tx))
        {
            delete.Parameters.AddWithValue("@id", fromVendorId);
            await delete.ExecuteNonQueryAsync(ct);
        }

        await tx.CommitAsync(ct);
        return Results.Json(new { ok = true });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Merge vendors failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: delete a tree edge by identifiers
app.MapDelete("/api/admin/trees/{treeId:long}/edges/{parentId:long}/{childId:long}", async (long treeId, long parentId, long childId, HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        await using var cmd = new MySqlCommand("DELETE FROM CategoryEdge WHERE tree_id=@tree AND parent_category_id=@parent AND child_category_id=@child", conn);
        cmd.Parameters.AddWithValue("@tree", treeId);
        cmd.Parameters.AddWithValue("@parent", parentId);
        cmd.Parameters.AddWithValue("@child", childId);

        var affected = await cmd.ExecuteNonQueryAsync(ct);
        if (affected == 0)
            return Results.NotFound(new { error = "edge_not_found" });

        return Results.Json(new { ok = true });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Delete edge failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: list valid parents for move (avoid cycles)
app.MapGet("/api/admin/trees/{treeId:long}/nodes/{nodeId:long}/valid-parents", async (long treeId, long nodeId, HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        const string sql = @"WITH RECURSIVE descendants AS (
                                SELECT ce.child_category_id AS category_id
                                FROM CategoryEdge ce
                                WHERE ce.tree_id = @tree AND ce.parent_category_id = @node
                                UNION
                                SELECT ce.child_category_id
                                FROM CategoryEdge ce
                                JOIN descendants d ON ce.parent_category_id = d.category_id
                                WHERE ce.tree_id = @tree
                              ),
                              nodes AS (
                                SELECT ce.parent_category_id AS category_id
                                FROM CategoryEdge ce
                                WHERE ce.tree_id = @tree
                                UNION
                                SELECT ce.child_category_id
                                FROM CategoryEdge ce
                                WHERE ce.tree_id = @tree
                              )
                              SELECT DISTINCT c.category_id, c.slug, c.name, c.is_selectable
                              FROM nodes n
                              JOIN Category c ON c.category_id = n.category_id
                              WHERE c.category_id <> @node
                                AND c.category_id NOT IN (SELECT category_id FROM descendants)
                              ORDER BY c.name";

        var rows = new List<Dictionary<string, object?>>();
        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@tree", treeId);
        cmd.Parameters.AddWithValue("@node", nodeId);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var categoryOrdinal = reader.GetOrdinal("category_id");
            var slugOrdinal = reader.GetOrdinal("slug");
            var nameOrdinal = reader.GetOrdinal("name");
            var leafOrdinal = reader.GetOrdinal("is_selectable");

            var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
            {
                ["category_id"] = reader.GetInt64(categoryOrdinal),
                ["slug"] = reader.IsDBNull(slugOrdinal) ? null : reader.GetString(slugOrdinal),
                ["name"] = reader.IsDBNull(nameOrdinal) ? null : reader.GetString(nameOrdinal),
                ["is_selectable"] = reader.GetBoolean(leafOrdinal)
            };
            rows.Add(row);
        }

        return Results.Json(rows);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Fetch parents failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: move a node within a tree
app.MapPatch("/api/admin/trees/{treeId:long}/edges/move", async (long treeId, HttpContext ctx, AdminTreeMoveRequest body, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    if (body is null)
        return Results.BadRequest(new { error = "invalid_payload" });

    var childId = body.ChildCategoryId;
    var currentParent = body.CurrentParentCategoryId;
    var newParent = body.NewParentCategoryId;
    var position = body.Position ?? 0;

    if (childId <= 0 || currentParent <= 0 || newParent <= 0)
        return Results.BadRequest(new { error = "invalid_ids" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        await using var tx = await conn.BeginTransactionAsync(ct);

        // Ensure the edge exists
        await using (var checkCmd = new MySqlCommand("SELECT COUNT(*) FROM CategoryEdge WHERE tree_id=@tree AND parent_category_id=@parent AND child_category_id=@child", conn, tx))
        {
            checkCmd.Parameters.AddWithValue("@tree", treeId);
            checkCmd.Parameters.AddWithValue("@parent", currentParent);
            checkCmd.Parameters.AddWithValue("@child", childId);
            var exists = Convert.ToInt32(await checkCmd.ExecuteScalarAsync(ct));
            if (exists == 0)
            {
                await tx.RollbackAsync(ct);
                return Results.NotFound(new { error = "edge_not_found" });
            }
        }

        if (currentParent == newParent)
        {
            await using var updateCmd = new MySqlCommand("UPDATE CategoryEdge SET position=@pos WHERE tree_id=@tree AND parent_category_id=@parent AND child_category_id=@child", conn, tx);
            updateCmd.Parameters.AddWithValue("@pos", position);
            updateCmd.Parameters.AddWithValue("@tree", treeId);
            updateCmd.Parameters.AddWithValue("@parent", currentParent);
            updateCmd.Parameters.AddWithValue("@child", childId);
            await updateCmd.ExecuteNonQueryAsync(ct);

            await tx.CommitAsync(ct);
            return Results.Json(new { ok = true, moved = false, updated_position = true });
        }

        // Cycle guard: ensure new parent is not a descendant of the node
        await using (var cycleCmd = new MySqlCommand(@"WITH RECURSIVE descendants AS (
                                                          SELECT ce.child_category_id
                                                          FROM CategoryEdge ce
                                                          WHERE ce.tree_id=@tree AND ce.parent_category_id=@child
                                                          UNION
                                                          SELECT ce.child_category_id
                                                          FROM CategoryEdge ce
                                                          JOIN descendants d ON ce.parent_category_id = d.child_category_id
                                                          WHERE ce.tree_id=@tree
                                                      )
                                                      SELECT COUNT(*) FROM descendants WHERE child_category_id=@newParent", conn, tx))
        {
            cycleCmd.Parameters.AddWithValue("@tree", treeId);
            cycleCmd.Parameters.AddWithValue("@child", childId);
            cycleCmd.Parameters.AddWithValue("@newParent", newParent);
            var cycle = Convert.ToInt32(await cycleCmd.ExecuteScalarAsync(ct));
            if (cycle > 0 || childId == newParent)
            {
                await tx.RollbackAsync(ct);
                return Results.BadRequest(new { error = "cycle_detected" });
            }
        }

        // Delete old edge
        await using (var deleteCmd = new MySqlCommand("DELETE FROM CategoryEdge WHERE tree_id=@tree AND parent_category_id=@parent AND child_category_id=@child", conn, tx))
        {
            deleteCmd.Parameters.AddWithValue("@tree", treeId);
            deleteCmd.Parameters.AddWithValue("@parent", currentParent);
            deleteCmd.Parameters.AddWithValue("@child", childId);
            await deleteCmd.ExecuteNonQueryAsync(ct);
        }

        // Insert new edge (or update if already exists)
        await using (var insertCmd = new MySqlCommand(@"INSERT INTO CategoryEdge(tree_id, parent_category_id, child_category_id, position)
                                                           VALUES(@tree, @parent, @child, @pos)
                                                           ON DUPLICATE KEY UPDATE position = VALUES(position)", conn, tx))
        {
            insertCmd.Parameters.AddWithValue("@tree", treeId);
            insertCmd.Parameters.AddWithValue("@parent", newParent);
            insertCmd.Parameters.AddWithValue("@child", childId);
            insertCmd.Parameters.AddWithValue("@pos", position);
            await insertCmd.ExecuteNonQueryAsync(ct);
        }

        await tx.CommitAsync(ct);
        return Results.Json(new { ok = true, moved = true });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Move edge failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: reorder siblings under a parent
app.MapPost("/api/admin/trees/{treeId:long}/reorder", async (long treeId, HttpContext ctx, AdminTreeReorderRequest body, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    if (body is null)
        return Results.BadRequest(new { error = "invalid_payload" });

    if (body.ChildIds is null || body.ChildIds.Count == 0)
        return Results.BadRequest(new { error = "child_ids_required" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        await using var tx = await conn.BeginTransactionAsync(ct);

        var pos = 1;
        foreach (var childId in body.ChildIds)
        {
            await using var updateCmd = new MySqlCommand("UPDATE CategoryEdge SET position=@pos WHERE tree_id=@tree AND parent_category_id=@parent AND child_category_id=@child", conn, tx);
            updateCmd.Parameters.AddWithValue("@pos", pos);
            updateCmd.Parameters.AddWithValue("@tree", treeId);
            updateCmd.Parameters.AddWithValue("@parent", body.ParentCategoryId);
            updateCmd.Parameters.AddWithValue("@child", childId);
            await updateCmd.ExecuteNonQueryAsync(ct);
            pos++;
        }

        await tx.CommitAsync(ct);
        return Results.Json(new { ok = true });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Reorder failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: copy an entire tree into another tree
app.MapPost("/api/admin/trees/copy/full", async (HttpContext ctx, AdminTreeCopyFullRequest body, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    if (body is null)
        return Results.BadRequest(new { error = "invalid_payload" });

    var sourceName = body.SourceTreeName?.Trim();
    var targetName = body.TargetTreeName?.Trim();
    var overwrite = body.Overwrite ?? true;

    if (string.IsNullOrWhiteSpace(sourceName) || string.IsNullOrWhiteSpace(targetName))
        return Results.BadRequest(new { error = "source_and_target_required" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        long? sourceId = null;
        await using (var lookup = new MySqlCommand("SELECT tree_id FROM CategoryTree WHERE name=@name", conn))
        {
            lookup.Parameters.AddWithValue("@name", sourceName);
            var scalar = await lookup.ExecuteScalarAsync(ct);
            sourceId = scalar is null ? null : Convert.ToInt64(scalar);
        }

        if (sourceId is null)
            return Results.BadRequest(new { error = "source_tree_not_found", name = sourceName });

        long? targetId = null;
        await using (var lookup = new MySqlCommand("SELECT tree_id FROM CategoryTree WHERE name=@name", conn))
        {
            lookup.Parameters.AddWithValue("@name", targetName);
            var scalar = await lookup.ExecuteScalarAsync(ct);
            targetId = scalar is null ? null : Convert.ToInt64(scalar);
        }

        if (targetId is null)
            return Results.BadRequest(new { error = "target_tree_not_found", name = targetName });

        var edges = new List<(long parentId, long childId, int position)>();
        await using (var edgeCmd = new MySqlCommand(@"SELECT parent_category_id, child_category_id, position
                                                     FROM CategoryEdge
                                                     WHERE tree_id=@tree
                                                     ORDER BY position", conn))
        {
            edgeCmd.Parameters.AddWithValue("@tree", sourceId.Value);
            await using var reader = await edgeCmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                edges.Add((reader.GetInt64(0), reader.GetInt64(1), reader.GetInt32(2)));
            }
        }

        if (edges.Count == 0)
        {
            return Results.Json(new { ok = true, created = 0, updated = 0, total = 0 });
        }

        var created = 0;
        var updated = 0;

        await using var tx = await conn.BeginTransactionAsync(ct);
        try
        {
            foreach (var edge in edges)
            {
                if (overwrite)
                {
                    await using var upsert = new MySqlCommand(@"INSERT INTO CategoryEdge(tree_id, parent_category_id, child_category_id, position)
                                                               VALUES(@tree, @parent, @child, @pos)
                                                               ON DUPLICATE KEY UPDATE position=VALUES(position)", conn, (MySqlTransaction)tx);
                    upsert.Parameters.AddWithValue("@tree", targetId.Value);
                    upsert.Parameters.AddWithValue("@parent", edge.parentId);
                    upsert.Parameters.AddWithValue("@child", edge.childId);
                    upsert.Parameters.AddWithValue("@pos", edge.position);
                    var affected = await upsert.ExecuteNonQueryAsync(ct);
                    if (affected == 1)
                    {
                        created++;
                    }
                    else if (affected >= 2)
                    {
                        updated++;
                    }
                }
                else
                {
                    await using var insert = new MySqlCommand(@"INSERT IGNORE INTO CategoryEdge(tree_id, parent_category_id, child_category_id, position)
                                                               VALUES(@tree, @parent, @child, @pos)", conn, (MySqlTransaction)tx);
                    insert.Parameters.AddWithValue("@tree", targetId.Value);
                    insert.Parameters.AddWithValue("@parent", edge.parentId);
                    insert.Parameters.AddWithValue("@child", edge.childId);
                    insert.Parameters.AddWithValue("@pos", edge.position);
                    var affected = await insert.ExecuteNonQueryAsync(ct);
                    if (affected > 0)
                    {
                        created++;
                    }
                }
            }

            await tx.CommitAsync(ct);
        }
        catch
        {
            await tx.RollbackAsync(ct);
            throw;
        }

        return Results.Json(new { ok = true, created, updated, total = edges.Count });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Copy tree failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: preview subtree copy impact
app.MapGet("/api/admin/trees/copy-subtree/preview", async (HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    var query = ctx.Request.Query;
    var sourceTree = query.TryGetValue("sourceTree", out var stVals) ? stVals.ToString() : query.TryGetValue("source_tree", out var stValsSnake) ? stValsSnake.ToString() : null;
    var rootSlug = query.TryGetValue("rootSlug", out var rsVals) ? rsVals.ToString() : query.TryGetValue("root_slug", out var rsValsSnake) ? rsValsSnake.ToString() : null;
    var targetsRaw = query.TryGetValue("targets", out var tgtVals) ? tgtVals.ToString() : query.TryGetValue("target_tree_names", out var tgtValsSnake) ? tgtValsSnake.ToString() : null;
    var includeRoot = query.TryGetValue("includeRoot", out var irVals) ? string.Equals(irVals.ToString(), "true", StringComparison.OrdinalIgnoreCase)
                      : query.TryGetValue("include_root", out var irValsSnake) && string.Equals(irValsSnake.ToString(), "true", StringComparison.OrdinalIgnoreCase);

    if (string.IsNullOrWhiteSpace(sourceTree) || string.IsNullOrWhiteSpace(rootSlug) || string.IsNullOrWhiteSpace(targetsRaw))
        return Results.BadRequest(new { error = "missing_parameters" });

    var targetNames = targetsRaw
        .Split(new[] { ',', '\n', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToArray();

    if (targetNames.Length == 0)
        return Results.BadRequest(new { error = "no_targets" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        var result = await LoadSubtreeAsync(conn, sourceTree, rootSlug, includeRoot, ct);
        if (!result.Success)
            return result.Error!;

        var edges = result.Edges ?? Array.Empty<SubtreeEdge>();

        var previewEdges = edges.Select(e => new
        {
            parent_category_id = e.ParentCategoryId,
            child_category_id = e.ChildCategoryId,
            e.Position,
            parent_slug = e.ParentSlug,
            child_slug = e.ChildSlug
        }).ToList();

        var targets = new List<object>();
        foreach (var name in targetNames)
        {
            long? treeId = null;
            await using (var lookup = new MySqlCommand("SELECT tree_id FROM CategoryTree WHERE name=@name", conn))
            {
                lookup.Parameters.AddWithValue("@name", name);
                var scalar = await lookup.ExecuteScalarAsync(ct);
                treeId = scalar is null ? null : Convert.ToInt64(scalar);
            }

            if (treeId is null)
            {
                targets.Add(new { tree = name, tree_missing = true, new_edges = 0, total_edges = previewEdges.Count });
                continue;
            }

            var existing = new HashSet<(long parentId, long childId)>();
            await using (var existingCmd = new MySqlCommand("SELECT parent_category_id, child_category_id FROM CategoryEdge WHERE tree_id=@tree", conn))
            {
                existingCmd.Parameters.AddWithValue("@tree", treeId.Value);
                await using var reader = await existingCmd.ExecuteReaderAsync(ct);
                while (await reader.ReadAsync(ct))
                {
                    existing.Add((reader.GetInt64(0), reader.GetInt64(1)));
                }
            }

            var newCount = previewEdges.Count(edge => !existing.Contains((edge.parent_category_id, edge.child_category_id)));
            targets.Add(new { tree = name, new_edges = newCount, total_edges = previewEdges.Count, tree_missing = false });
        }

        return Results.Json(new
        {
            edges = previewEdges,
            targets
        });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Preview failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: apply subtree copy to target trees
app.MapPost("/api/admin/trees/copy-subtree", async (HttpContext ctx, AdminTreeCopySubtreeRequest body, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    if (body is null)
        return Results.BadRequest(new { error = "invalid_payload" });

    var sourceTree = body.SourceTree?.Trim();
    var rootSlug = body.RootSlug?.Trim();
    var includeRoot = body.IncludeRoot ?? false;
    var overwrite = body.Overwrite ?? true;
    var targetNames = body.TargetTreeNames?.Where(n => !string.IsNullOrWhiteSpace(n)).Select(n => n.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToArray() ?? Array.Empty<string>();

    if (string.IsNullOrWhiteSpace(sourceTree) || string.IsNullOrWhiteSpace(rootSlug))
        return Results.BadRequest(new { error = "missing_parameters" });

    if (targetNames.Length == 0)
        return Results.BadRequest(new { error = "no_targets" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        var result = await LoadSubtreeAsync(conn, sourceTree!, rootSlug!, includeRoot, ct);
        if (!result.Success)
            return result.Error!;

        var edges = result.Edges ?? Array.Empty<SubtreeEdge>();

        var report = new List<object>();

        foreach (var name in targetNames)
        {
            long? treeId = null;
            await using (var lookup = new MySqlCommand("SELECT tree_id FROM CategoryTree WHERE name=@name", conn))
            {
                lookup.Parameters.AddWithValue("@name", name);
                var scalar = await lookup.ExecuteScalarAsync(ct);
                treeId = scalar is null ? null : Convert.ToInt64(scalar);
            }

            if (treeId is null)
            {
                report.Add(new { tree = name, missing_tree = true, created = 0, updated = 0 });
                continue;
            }

            var existing = new HashSet<(long parentId, long childId)>();
            await using (var existingCmd = new MySqlCommand("SELECT parent_category_id, child_category_id FROM CategoryEdge WHERE tree_id=@tree", conn))
            {
                existingCmd.Parameters.AddWithValue("@tree", treeId.Value);
                await using var reader = await existingCmd.ExecuteReaderAsync(ct);
                while (await reader.ReadAsync(ct))
                {
                    existing.Add((reader.GetInt64(0), reader.GetInt64(1)));
                }
            }

            var created = 0;
            var updated = 0;

            foreach (var edge in edges)
            {
                var key = (edge.ParentCategoryId, edge.ChildCategoryId);
                var already = existing.Contains(key);

                if (overwrite)
                {
                    await using var cmd = new MySqlCommand(@"INSERT INTO CategoryEdge(tree_id, parent_category_id, child_category_id, position)
                                                               VALUES(@tree, @parent, @child, @pos)
                                                               ON DUPLICATE KEY UPDATE position = VALUES(position)", conn);
                    cmd.Parameters.AddWithValue("@tree", treeId.Value);
                    cmd.Parameters.AddWithValue("@parent", edge.ParentCategoryId);
                    cmd.Parameters.AddWithValue("@child", edge.ChildCategoryId);
                    cmd.Parameters.AddWithValue("@pos", edge.Position);
                    await cmd.ExecuteNonQueryAsync(ct);

                    if (already)
                    {
                        updated++;
                    }
                    else
                    {
                        existing.Add(key);
                        created++;
                    }
                }
                else if (!already)
                {
                    await using var cmd = new MySqlCommand("INSERT IGNORE INTO CategoryEdge(tree_id, parent_category_id, child_category_id, position) VALUES(@tree, @parent, @child, @pos)", conn);
                    cmd.Parameters.AddWithValue("@tree", treeId.Value);
                    cmd.Parameters.AddWithValue("@parent", edge.ParentCategoryId);
                    cmd.Parameters.AddWithValue("@child", edge.ChildCategoryId);
                    cmd.Parameters.AddWithValue("@pos", edge.Position);
                    var affected = await cmd.ExecuteNonQueryAsync(ct);
                    if (affected > 0)
                    {
                        existing.Add(key);
                        created++;
                    }
                }
            }

            report.Add(new { tree = name, missing_tree = false, created, updated });
        }

        return Results.Json(new { ok = true, result = report });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Copy failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

static async Task<SubtreeLoadResult> LoadSubtreeAsync(MySqlConnection conn, string sourceTree, string rootSlug, bool includeRoot, CancellationToken ct)
{
    long? treeId = null;
    await using (var treeCmd = new MySqlCommand("SELECT tree_id FROM CategoryTree WHERE name=@name", conn))
    {
        treeCmd.Parameters.AddWithValue("@name", sourceTree);
        var scalar = await treeCmd.ExecuteScalarAsync(ct);
        treeId = scalar is null ? null : Convert.ToInt64(scalar);
    }

    if (treeId is null)
    {
        return new SubtreeLoadResult
        {
            Success = false,
            Error = Results.NotFound(new { error = "source_tree_not_found" })
        };
    }

    long? rootId = null;
    await using (var rootCmd = new MySqlCommand("SELECT category_id FROM Category WHERE slug=@slug", conn))
    {
        rootCmd.Parameters.AddWithValue("@slug", rootSlug);
        var scalar = await rootCmd.ExecuteScalarAsync(ct);
        rootId = scalar is null ? null : Convert.ToInt64(scalar);
    }

    if (rootId is null)
    {
        return new SubtreeLoadResult
        {
            Success = false,
            Error = Results.NotFound(new { error = "root_category_not_found" })
        };
    }

    var edges = new List<SubtreeEdge>();

    const string subtreeSql = @"WITH RECURSIVE edges AS (
                                    SELECT ce.parent_category_id, ce.child_category_id, ce.position
                                    FROM CategoryEdge ce
                                    WHERE ce.tree_id = @treeId AND ce.parent_category_id = @rootId
                                    UNION ALL
                                    SELECT ce.parent_category_id, ce.child_category_id, ce.position
                                    FROM CategoryEdge ce
                                    JOIN edges e ON ce.parent_category_id = e.child_category_id
                                    WHERE ce.tree_id = @treeId
                                  )
                                  SELECT e.parent_category_id, e.child_category_id, e.position,
                                         parent.slug AS parent_slug,
                                         child.slug AS child_slug
                                  FROM edges e
                                  JOIN Category parent ON parent.category_id = e.parent_category_id
                                  JOIN Category child ON child.category_id = e.child_category_id
                                  ORDER BY e.parent_category_id, e.position";

    await using (var cmd = new MySqlCommand(subtreeSql, conn))
    {
        cmd.Parameters.AddWithValue("@treeId", treeId.Value);
        cmd.Parameters.AddWithValue("@rootId", rootId.Value);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            edges.Add(new SubtreeEdge(
                reader.GetInt64(0),
                reader.GetInt64(1),
                reader.GetInt32(2),
                reader.IsDBNull(3) ? string.Empty : reader.GetString(3),
                reader.IsDBNull(4) ? string.Empty : reader.GetString(4)));
        }
    }

    if (includeRoot)
    {
        const string rootSql = @"SELECT ce.parent_category_id, ce.child_category_id, ce.position,
                                       parent.slug AS parent_slug,
                                       child.slug AS child_slug
                                FROM CategoryEdge ce
                                JOIN Category parent ON parent.category_id = ce.parent_category_id
                                JOIN Category child ON child.category_id = ce.child_category_id
                                WHERE ce.tree_id = @treeId AND ce.child_category_id = @rootId";

        await using var rootCmdEdges = new MySqlCommand(rootSql, conn);
        rootCmdEdges.Parameters.AddWithValue("@treeId", treeId.Value);
        rootCmdEdges.Parameters.AddWithValue("@rootId", rootId.Value);
        await using var rootReader = await rootCmdEdges.ExecuteReaderAsync(ct);
        var seen = new HashSet<(long parent, long child)>(edges.Select(e => (e.ParentCategoryId, e.ChildCategoryId)));
        while (await rootReader.ReadAsync(ct))
        {
            var key = (rootReader.GetInt64(0), rootReader.GetInt64(1));
            if (seen.Add(key))
            {
                edges.Insert(0, new SubtreeEdge(
                    key.Item1,
                    key.Item2,
                    rootReader.GetInt32(2),
                    rootReader.IsDBNull(3) ? string.Empty : rootReader.GetString(3),
                    rootReader.IsDBNull(4) ? string.Empty : rootReader.GetString(4)));
            }
        }
    }

    return new SubtreeLoadResult
    {
        Success = true,
        TreeId = treeId.Value,
        RootCategoryId = rootId.Value,
        Edges = edges.ToArray()
    };
}

app.MapPatch("/api/me", async (UserProfileUpdateRequest body, HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);
    if (body is null)
        return Results.BadRequest(new { error = "Invalid JSON" });

    var userId = ctx.User.TryGetUserId();
    if (userId is null) return Results.Unauthorized();

    var displayName = body.DisplayName is null
        ? (string?)null
        : (string.IsNullOrWhiteSpace(body.DisplayName) ? null : body.DisplayName.Trim());
    var emailOptIn = body.EmailOptIn;

    if (displayName is null && emailOptIn is null)
        return Results.BadRequest(new { error = "no_changes" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureUserAccountTableAsync(conn, ct);

        var assignments = new List<string>();
        await using var updateCmd = new MySqlCommand
        {
            Connection = conn
        };

        if (body.DisplayName is not null)
        {
            assignments.Add("display_name=@display");
            updateCmd.Parameters.AddWithValue("@display", (object?)displayName ?? DBNull.Value);
        }

        if (emailOptIn is not null)
        {
            assignments.Add("email_opt_in=@opt");
            updateCmd.Parameters.AddWithValue("@opt", emailOptIn.Value);
        }

        updateCmd.CommandText = $"UPDATE UserAccount SET {string.Join(", ", assignments)}, updated_at=CURRENT_TIMESTAMP WHERE user_id=@id";
        updateCmd.Parameters.AddWithValue("@id", userId.Value);
        await updateCmd.ExecuteNonQueryAsync(ct);

        await using var fetch = new MySqlCommand("SELECT user_id, email, display_name, is_admin, email_opt_in FROM UserAccount WHERE user_id=@id", conn);
        fetch.Parameters.AddWithValue("@id", userId.Value);
        await using var reader = await fetch.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct))
            return Results.NotFound(new { error = "user_not_found" });

        var payload = new UserProfileDto
        {
            UserId = reader.GetInt64(0),
            Email = reader.IsDBNull(1) ? null : reader.GetString(1),
            DisplayName = reader.IsDBNull(2) ? null : reader.GetString(2),
            IsAdmin = !reader.IsDBNull(3) && reader.GetBoolean(3),
            EmailOptIn = !reader.IsDBNull(4) && reader.GetBoolean(4)
        };

        return Results.Ok(new { user = payload });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Update profile failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: list requirements for a category (global or tree-specific)
app.MapGet("/api/admin/categories/{categoryId:long}/requirements", async (long categoryId, long? treeId, HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await SchemaHelpers.EnsureCategoryRequirementColumnsAsync(conn, ct);

        var (exists, _) = await FetchCategorySelectableAsync(conn, categoryId, ct);
        if (!exists)
            return Results.NotFound(new { error = "category_not_found" });

        const string sql = @"SELECT cr.engine_family_id,
                                     ef.code,
                                     cr.tree_id,
                                     cr.requirement_type,
                                     cr.req_mode,
                                     cr.required_qty,
                                     cr.multiplier,
                                     cr.operand_field,
                                     cr.round_mode,
                                     cr.formula,
                                     cr.notes
                              FROM CategoryRequirement cr
                              JOIN EngineFamily ef ON ef.engine_family_id = cr.engine_family_id
                              WHERE cr.category_id = @cat
                                AND ((@tree IS NULL AND cr.tree_id IS NULL) OR (cr.tree_id = @tree))
                              ORDER BY ef.code";

        var rows = new List<Dictionary<string, object?>>();
        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@cat", categoryId);
        cmd.Parameters.AddWithValue("@tree", (object?)treeId ?? DBNull.Value);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
            {
                ["engine_family_id"] = reader.GetInt64(0),
                ["code"] = reader.GetString(1),
                ["tree_id"] = reader.IsDBNull(2) ? null : reader.GetValue(2),
                ["requirement_type"] = reader.GetString(3),
                ["req_mode"] = reader.IsDBNull(4) ? null : reader.GetString(4),
                ["required_qty"] = reader.IsDBNull(5) ? null : reader.GetValue(5),
                ["multiplier"] = reader.IsDBNull(6) ? null : reader.GetValue(6),
                ["operand_field"] = reader.IsDBNull(7) ? null : reader.GetString(7),
                ["round_mode"] = reader.IsDBNull(8) ? null : reader.GetString(8),
                ["formula"] = reader.IsDBNull(9) ? null : reader.GetString(9),
                ["notes"] = reader.IsDBNull(10) ? null : reader.GetString(10)
            };
            rows.Add(row);
        }

        return Results.Json(rows);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Fetch requirements failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: upsert a requirement row
app.MapPost("/api/admin/categories/{categoryId:long}/requirements", async (long categoryId, HttpContext ctx, AdminCategoryRequirementUpsertRequest body, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    if (body is null)
        return Results.BadRequest(new { error = "invalid_payload" });

    if (body.EngineFamilyId <= 0)
        return Results.BadRequest(new { error = "engine_family_id_required" });

    var reqMode = NormalizeRequirementModeForApi(body.ReqMode);
    var roundMode = NormalizeRoundModeForApi(body.RoundMode);
    var operandField = NormalizeOperandFieldForApi(body.OperandField);
    var requirementType = ResolveRequirementTypeForApi(body.RequirementType, reqMode);
    var treeScope = body.TreeId ?? 0;

    decimal? requiredQty = body.RequiredQty;
    decimal? multiplier = body.Multiplier;
    string? formula = string.IsNullOrWhiteSpace(body.Formula) ? null : body.Formula.Trim();
    string? notes = string.IsNullOrWhiteSpace(body.Notes) ? null : body.Notes.Trim();

    switch (reqMode)
    {
        case "exact_count" or "min_count":
            if (requiredQty is null)
                return Results.BadRequest(new { error = "required_qty_missing" });
            multiplier = null;
            operandField = null;
            formula = null;
            roundMode = "none";
            break;

        case "structured":
            if (multiplier is null)
                return Results.BadRequest(new { error = "structured_missing", message = "multiplier required" });
            if (operandField is null)
                return Results.BadRequest(new { error = "structured_missing", message = "operand_field required" });
            requiredQty = null;
            formula = null;
            break;

        case "formula":
            if (string.IsNullOrWhiteSpace(formula))
                return Results.BadRequest(new { error = "formula_missing" });
            requiredQty = null;
            multiplier = null;
            operandField = null;
            roundMode = "none";
            break;

        default:
            return Results.BadRequest(new { error = "invalid_req_mode" });
    }

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await SchemaHelpers.EnsureCategoryRequirementColumnsAsync(conn, ct);

        var (exists, isSelectable) = await FetchCategorySelectableAsync(conn, categoryId, ct);
        if (!exists)
            return Results.NotFound(new { error = "category_not_found" });
        if (!isSelectable)
            return Results.BadRequest(new { error = "category_not_leaf", message = "Requirements can only be assigned to selectable categories." });

        await using (var engineCheck = new MySqlCommand("SELECT 1 FROM EngineFamily WHERE engine_family_id=@ef LIMIT 1", conn))
        {
            engineCheck.Parameters.AddWithValue("@ef", body.EngineFamilyId);
            if (await engineCheck.ExecuteScalarAsync(ct) is null)
                return Results.NotFound(new { error = "engine_family_not_found" });
        }

        if (body.TreeId is not null)
        {
            await using var treeCheck = new MySqlCommand("SELECT 1 FROM CategoryTree WHERE tree_id=@tree LIMIT 1", conn);
            treeCheck.Parameters.AddWithValue("@tree", body.TreeId.Value);
            if (await treeCheck.ExecuteScalarAsync(ct) is null)
                return Results.NotFound(new { error = "tree_not_found" });
        }

        const string sql = @"INSERT INTO CategoryRequirement (
                                engine_family_id, category_id, tree_id, tree_scope,
                                requirement_type, req_mode, required_qty, formula,
                                multiplier, operand_field, round_mode, notes)
                              VALUES (
                                @ef, @cat, @tree, @scope,
                                @rtype, @rmode, @qty, @formula,
                                @mult, @operand, @round, @notes)
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

        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@ef", body.EngineFamilyId);
        cmd.Parameters.AddWithValue("@cat", categoryId);
        cmd.Parameters.AddWithValue("@tree", (object?)body.TreeId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@scope", treeScope);
        cmd.Parameters.AddWithValue("@rtype", requirementType);
        cmd.Parameters.AddWithValue("@rmode", reqMode);
        cmd.Parameters.AddWithValue("@qty", (object?)requiredQty ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@formula", (object?)formula ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@mult", (object?)multiplier ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@operand", (object?)operandField ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@round", roundMode);
        cmd.Parameters.AddWithValue("@notes", (object?)notes ?? DBNull.Value);
        await cmd.ExecuteNonQueryAsync(ct);

        return Results.Json(new { ok = true });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Upsert requirement failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: delete a requirement row
app.MapDelete("/api/admin/categories/{categoryId:long}/requirements", async (long categoryId, HttpContext ctx, long engineFamilyId, long? treeId, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await SchemaHelpers.EnsureCategoryRequirementColumnsAsync(conn, ct);

        var (exists, isSelectable) = await FetchCategorySelectableAsync(conn, categoryId, ct);
        if (!exists)
            return Results.NotFound(new { error = "category_not_found" });
        if (!isSelectable)
            return Results.BadRequest(new { error = "category_not_leaf" });

        const string sql = @"DELETE FROM CategoryRequirement
                              WHERE category_id=@cat AND engine_family_id=@ef
                                AND ((@tree IS NULL AND tree_id IS NULL) OR tree_id=@tree)";

        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@cat", categoryId);
        cmd.Parameters.AddWithValue("@ef", engineFamilyId);
        cmd.Parameters.AddWithValue("@tree", (object?)treeId ?? DBNull.Value);
        var affected = await cmd.ExecuteNonQueryAsync(ct);
        if (affected == 0)
            return Results.NotFound(new { error = "requirement_not_found" });

        return Results.Json(new { ok = true });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Delete requirement failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: copy requirement from one engine to many others
app.MapPost("/api/admin/categories/{categoryId:long}/requirements/copy", async (long categoryId, HttpContext ctx, AdminCategoryRequirementCopyRequest body, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    if (body is null)
        return Results.BadRequest(new { error = "invalid_payload" });

    var targets = (body.TargetEngineCodes ?? new List<string>())
        .Select(code => (code ?? string.Empty).Trim())
        .Where(code => code.Length > 0)
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToList();

    if (targets.Count == 0)
        return Results.BadRequest(new { error = "no_targets" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await SchemaHelpers.EnsureCategoryRequirementColumnsAsync(conn, ct);

        var (exists, isSelectable) = await FetchCategorySelectableAsync(conn, categoryId, ct);
        if (!exists)
            return Results.NotFound(new { error = "category_not_found" });
        if (!isSelectable)
            return Results.BadRequest(new { error = "category_not_leaf" });

        long? sourceId = body.SourceEngineFamilyId;
        if (sourceId is null && !string.IsNullOrWhiteSpace(body.SourceEngineCode))
        {
            await using var lookup = new MySqlCommand("SELECT engine_family_id FROM EngineFamily WHERE code=@code", conn);
            lookup.Parameters.AddWithValue("@code", body.SourceEngineCode.Trim());
            var result = await lookup.ExecuteScalarAsync(ct);
            if (result is not null)
                sourceId = Convert.ToInt64(result);
        }

        if (sourceId is null)
            return Results.BadRequest(new { error = "source_engine_required" });

        await using (var engineCheck = new MySqlCommand("SELECT 1 FROM EngineFamily WHERE engine_family_id=@ef", conn))
        {
            engineCheck.Parameters.AddWithValue("@ef", sourceId.Value);
            if (await engineCheck.ExecuteScalarAsync(ct) is null)
                return Results.NotFound(new { error = "source_engine_not_found" });
        }

        const string fetchSql = @"SELECT requirement_type, req_mode, required_qty, formula, multiplier, operand_field, round_mode, notes
                                  FROM CategoryRequirement
                                  WHERE engine_family_id=@ef AND category_id=@cat
                                    AND ((@tree IS NULL AND tree_id IS NULL) OR tree_id=@tree)
                                  LIMIT 1";

        await using var fetchCmd = new MySqlCommand(fetchSql, conn);
        fetchCmd.Parameters.AddWithValue("@ef", sourceId.Value);
        fetchCmd.Parameters.AddWithValue("@cat", categoryId);
        fetchCmd.Parameters.AddWithValue("@tree", (object?)body.TreeId ?? DBNull.Value);

        using var reader = await fetchCmd.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct))
            return Results.NotFound(new { error = "source_requirement_not_found" });

        var srcRequirement = new
        {
            RequirementType = reader.GetString(0),
            ReqMode = reader.IsDBNull(1) ? null : reader.GetString(1),
            RequiredQty = reader.IsDBNull(2) ? (decimal?)null : reader.GetDecimal(2),
            Formula = reader.IsDBNull(3) ? null : reader.GetString(3),
            Multiplier = reader.IsDBNull(4) ? (decimal?)null : reader.GetDecimal(4),
            OperandField = reader.IsDBNull(5) ? null : reader.GetString(5),
            RoundMode = reader.IsDBNull(6) ? null : reader.GetString(6),
            Notes = reader.IsDBNull(7) ? null : reader.GetString(7)
        };
        await reader.DisposeAsync();

        var srcReqMode = NormalizeRequirementModeForApi(srcRequirement.ReqMode ?? srcRequirement.RequirementType);
        var srcRoundMode = srcRequirement.RoundMode ?? "none";
        var treeScope = body.TreeId ?? 0;

        var overwrite = body.Overwrite ?? true;
        var cache = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        var missing = new List<string>();
        var applied = 0;

        using var tx = await conn.BeginTransactionAsync(ct);
        try
        {
            foreach (var code in targets)
            {
                if (string.IsNullOrWhiteSpace(code)) continue;

                if (!cache.TryGetValue(code, out var targetId))
                {
                    await using var lookup = new MySqlCommand("SELECT engine_family_id FROM EngineFamily WHERE code=@code", conn, tx);
                    lookup.Parameters.AddWithValue("@code", code);
                    var result = await lookup.ExecuteScalarAsync(ct);
                    if (result is null)
                    {
                        missing.Add(code);
                        continue;
                    }
                    targetId = Convert.ToInt64(result);
                    cache[code] = targetId;
                }

                if (!overwrite)
                {
                    await using var existsCmd = new MySqlCommand(@"SELECT 1 FROM CategoryRequirement
                                                                     WHERE engine_family_id=@ef
                                                                       AND category_id=@cat
                                                                       AND ((@tree IS NULL AND tree_id IS NULL) OR tree_id=@tree)", conn, tx);
                    existsCmd.Parameters.AddWithValue("@ef", targetId);
                    existsCmd.Parameters.AddWithValue("@cat", categoryId);
                    existsCmd.Parameters.AddWithValue("@tree", (object?)body.TreeId ?? DBNull.Value);
                    if (await existsCmd.ExecuteScalarAsync(ct) is not null)
                        continue;
                }

                const string upsertSql = @"INSERT INTO CategoryRequirement (
                                                engine_family_id, category_id, tree_id, tree_scope,
                                                requirement_type, req_mode, required_qty, formula,
                                                multiplier, operand_field, round_mode, notes)
                                              VALUES (
                                                @ef, @cat, @tree, @scope,
                                                @rtype, @rmode, @qty, @formula,
                                                @mult, @operand, @round, @notes)
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

                await using var upsert = new MySqlCommand(upsertSql, conn, tx);
                upsert.Parameters.AddWithValue("@ef", targetId);
                upsert.Parameters.AddWithValue("@cat", categoryId);
                upsert.Parameters.AddWithValue("@tree", (object?)body.TreeId ?? DBNull.Value);
                upsert.Parameters.AddWithValue("@scope", treeScope);
                upsert.Parameters.AddWithValue("@rtype", srcRequirement.RequirementType);
                upsert.Parameters.AddWithValue("@rmode", srcReqMode);
                upsert.Parameters.AddWithValue("@qty", (object?)srcRequirement.RequiredQty ?? DBNull.Value);
                upsert.Parameters.AddWithValue("@formula", (object?)srcRequirement.Formula ?? DBNull.Value);
                upsert.Parameters.AddWithValue("@mult", (object?)srcRequirement.Multiplier ?? DBNull.Value);
                upsert.Parameters.AddWithValue("@operand", (object?)srcRequirement.OperandField ?? DBNull.Value);
                upsert.Parameters.AddWithValue("@round", srcRoundMode);
                upsert.Parameters.AddWithValue("@notes", (object?)srcRequirement.Notes ?? DBNull.Value);
                await upsert.ExecuteNonQueryAsync(ct);
                applied++;
            }

            await tx.CommitAsync(ct);
        }
        catch
        {
            await tx.RollbackAsync(ct);
            throw;
        }

        return Results.Json(new { ok = true, applied_to = applied, missing_codes = missing });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Copy requirements failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: define a rule and apply to many engines
app.MapPost("/api/admin/categories/{categoryId:long}/requirements/apply", async (long categoryId, HttpContext ctx, AdminCategoryRequirementApplyRequest body, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    if (body is null)
        return Results.BadRequest(new { error = "invalid_payload" });

    if (body.Rule is null)
        return Results.BadRequest(new { error = "rule_required" });

    var targets = (body.TargetEngineCodes ?? new List<string>())
        .Select(code => (code ?? string.Empty).Trim())
        .Where(code => code.Length > 0)
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToList();

    if (targets.Count == 0)
        return Results.BadRequest(new { error = "no_targets" });

    var reqMode = NormalizeRequirementModeForApi(body.Rule.ReqMode);
    var roundMode = NormalizeRoundModeForApi(body.Rule.RoundMode);
    var operandField = NormalizeOperandFieldForApi(body.Rule.OperandField);
    var requirementType = ResolveRequirementTypeForApi(body.Rule.RequirementType, reqMode);
    var treeScope = body.TreeId ?? 0;

    decimal? requiredQty = body.Rule.RequiredQty;
    decimal? multiplier = body.Rule.Multiplier;
    string? formula = string.IsNullOrWhiteSpace(body.Rule.Formula) ? null : body.Rule.Formula.Trim();
    string? notes = string.IsNullOrWhiteSpace(body.Rule.Notes) ? null : body.Rule.Notes.Trim();

    switch (reqMode)
    {
        case "exact_count" or "min_count":
            if (requiredQty is null)
                return Results.BadRequest(new { error = "required_qty_missing" });
            multiplier = null;
            operandField = null;
            formula = null;
            roundMode = "none";
            break;

        case "structured":
            if (multiplier is null)
                return Results.BadRequest(new { error = "structured_missing", message = "multiplier required" });
            if (operandField is null)
                return Results.BadRequest(new { error = "structured_missing", message = "operand_field required" });
            requiredQty = null;
            formula = null;
            break;

        case "formula":
            if (string.IsNullOrWhiteSpace(formula))
                return Results.BadRequest(new { error = "formula_missing" });
            requiredQty = null;
            multiplier = null;
            operandField = null;
            roundMode = "none";
            break;

        default:
            return Results.BadRequest(new { error = "invalid_req_mode" });
    }

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await SchemaHelpers.EnsureCategoryRequirementColumnsAsync(conn, ct);

        var (exists, isSelectable) = await FetchCategorySelectableAsync(conn, categoryId, ct);
        if (!exists)
            return Results.NotFound(new { error = "category_not_found" });
        if (!isSelectable)
            return Results.BadRequest(new { error = "category_not_leaf" });

        if (body.TreeId is not null)
        {
            await using var treeCheck = new MySqlCommand("SELECT 1 FROM CategoryTree WHERE tree_id=@tree", conn);
            treeCheck.Parameters.AddWithValue("@tree", body.TreeId.Value);
            if (await treeCheck.ExecuteScalarAsync(ct) is null)
                return Results.NotFound(new { error = "tree_not_found" });
        }

        var overwrite = body.Overwrite ?? true;
        var cache = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        var missing = new List<string>();
        var applied = 0;

        using var tx = await conn.BeginTransactionAsync(ct);
        try
        {
            foreach (var code in targets)
            {
                if (string.IsNullOrWhiteSpace(code)) continue;

                if (!cache.TryGetValue(code, out var targetId))
                {
                    await using var lookup = new MySqlCommand("SELECT engine_family_id FROM EngineFamily WHERE code=@code", conn, tx);
                    lookup.Parameters.AddWithValue("@code", code);
                    var result = await lookup.ExecuteScalarAsync(ct);
                    if (result is null)
                    {
                        missing.Add(code);
                        continue;
                    }
                    targetId = Convert.ToInt64(result);
                    cache[code] = targetId;
                }

                if (!overwrite)
                {
                    await using var existsCmd = new MySqlCommand(@"SELECT 1 FROM CategoryRequirement
                                                                     WHERE engine_family_id=@ef
                                                                       AND category_id=@cat
                                                                       AND ((@tree IS NULL AND tree_id IS NULL) OR tree_id=@tree)", conn, tx);
                    existsCmd.Parameters.AddWithValue("@ef", targetId);
                    existsCmd.Parameters.AddWithValue("@cat", categoryId);
                    existsCmd.Parameters.AddWithValue("@tree", (object?)body.TreeId ?? DBNull.Value);
                    if (await existsCmd.ExecuteScalarAsync(ct) is not null)
                        continue;
                }

                const string upsertSql = @"INSERT INTO CategoryRequirement (
                                                engine_family_id, category_id, tree_id, tree_scope,
                                                requirement_type, req_mode, required_qty, formula,
                                                multiplier, operand_field, round_mode, notes)
                                              VALUES (
                                                @ef, @cat, @tree, @scope,
                                                @rtype, @rmode, @qty, @formula,
                                                @mult, @operand, @round, @notes)
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

                await using var upsert = new MySqlCommand(upsertSql, conn, tx);
                upsert.Parameters.AddWithValue("@ef", targetId);
                upsert.Parameters.AddWithValue("@cat", categoryId);
                upsert.Parameters.AddWithValue("@tree", (object?)body.TreeId ?? DBNull.Value);
                upsert.Parameters.AddWithValue("@scope", treeScope);
                upsert.Parameters.AddWithValue("@rtype", requirementType);
                upsert.Parameters.AddWithValue("@rmode", reqMode);
                upsert.Parameters.AddWithValue("@qty", (object?)requiredQty ?? DBNull.Value);
                upsert.Parameters.AddWithValue("@formula", (object?)formula ?? DBNull.Value);
                upsert.Parameters.AddWithValue("@mult", (object?)multiplier ?? DBNull.Value);
                upsert.Parameters.AddWithValue("@operand", (object?)operandField ?? DBNull.Value);
                upsert.Parameters.AddWithValue("@round", roundMode);
                upsert.Parameters.AddWithValue("@notes", (object?)notes ?? DBNull.Value);
                await upsert.ExecuteNonQueryAsync(ct);
                applied++;
            }

            await tx.CommitAsync(ct);
        }
        catch
        {
            await tx.RollbackAsync(ct);
            throw;
        }

        return Results.Json(new { ok = true, applied_to = applied, missing_codes = missing });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Bulk apply requirements failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: searchable leaf categories (for part picker)
app.MapGet("/api/admin/categories/leaf", async (HttpContext ctx, string? q, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    try
    {
        var search = string.IsNullOrWhiteSpace(q) ? null : q.Trim();
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        const string sql = @"SELECT category_id, name, slug
                              FROM Category
                              WHERE is_selectable = TRUE
                                AND (@q IS NULL OR name LIKE CONCAT('%', @q, '%') OR slug LIKE CONCAT('%', @q, '%'))
                              ORDER BY name";

        var rows = new List<Dictionary<string, object?>>();
        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@q", (object?)search ?? DBNull.Value);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            rows.Add(new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
            {
                ["category_id"] = reader.GetInt64(0),
                ["name"] = reader.GetString(1),
                ["slug"] = reader.GetString(2)
            });
        }

        return Results.Json(rows);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Fetch leaf categories failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: list parts with filters
app.MapGet("/api/admin/parts", async (HttpContext ctx, string? q, string? status, string? brand, int page = 1, int pageSize = 50, CancellationToken ct = default) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    var search = string.IsNullOrWhiteSpace(q) ? null : q.Trim();
    var statusFilter = string.IsNullOrWhiteSpace(status) ? null : status.Trim().ToLowerInvariant();
    var brandFilter = string.IsNullOrWhiteSpace(brand) ? null : brand.Trim();

    var pageNumber = Math.Max(1, page);
    var limit = Math.Clamp(pageSize, 1, 200);
    var offset = (pageNumber - 1) * limit;

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        const string sql = @"SELECT p.part_id, p.sku, p.name, p.status, p.is_kit, p.pieces_per_unit, p.updated_at,
                                     b.name AS brand_name
                              FROM Part p
                              LEFT JOIN Brand b ON b.brand_id = p.brand_id
                              WHERE (@q IS NULL OR p.sku LIKE CONCAT('%', @q, '%') OR p.name LIKE CONCAT('%', @q, '%'))
                                AND (@status IS NULL OR p.status = @status)
                                AND (@brand IS NULL OR b.name = @brand)
                              ORDER BY p.updated_at DESC
                              LIMIT @limit OFFSET @offset";

        var rows = new List<Dictionary<string, object?>>();
        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@q", (object?)search ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@status", (object?)statusFilter ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@brand", (object?)brandFilter ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@limit", limit);
        cmd.Parameters.AddWithValue("@offset", offset);

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
            {
                ["part_id"] = reader.GetInt64(0),
                ["sku"] = reader.IsDBNull(1) ? null : reader.GetString(1),
                ["name"] = reader.GetString(2),
                ["status"] = reader.GetString(3),
                ["is_kit"] = !reader.IsDBNull(4) && reader.GetBoolean(4),
                ["pieces_per_unit"] = reader.IsDBNull(5) ? null : reader.GetValue(5),
                ["updated_at"] = reader.IsDBNull(6) ? null : reader.GetValue(6),
                ["brand_name"] = reader.IsDBNull(7) ? null : reader.GetValue(7)
            };
            rows.Add(row);
        }

        return Results.Json(rows);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Fetch parts failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: fetch single part with related data
app.MapGet("/api/admin/parts/{partId:long}", async (HttpContext ctx, long partId, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        const string partSql = @"SELECT p.part_id, p.sku, p.name, p.description, p.brand_id, p.is_kit, p.uom,
                                        p.pieces_per_unit, p.gltf_uri, p.gltf_attach_node,
                                        p.status, p.image_url, p.created_at, p.updated_at,
                                        b.name AS brand_name
                                 FROM Part p
                                 LEFT JOIN Brand b ON b.brand_id = p.brand_id
                                 WHERE p.part_id = @id";

        Dictionary<string, object?>? partRow = null;
        await using (var cmd = new MySqlCommand(partSql, conn))
        {
            cmd.Parameters.AddWithValue("@id", partId);
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            if (await reader.ReadAsync(ct))
            {
                partRow = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
                for (var i = 0; i < reader.FieldCount; i++)
                {
                    partRow[reader.GetName(i)] = reader.IsDBNull(i) ? null : reader.GetValue(i);
                }
            }
        }

        if (partRow is null)
            return Results.NotFound(new { error = "part_not_found" });

        const string catSql = @"SELECT pc.category_id, c.name, c.slug, pc.is_primary, pc.coverage_weight, pc.display_order
                                 FROM PartCategory pc
                                 JOIN Category c ON c.category_id = pc.category_id
                                 WHERE pc.part_id = @id
                                 ORDER BY pc.is_primary DESC, pc.display_order, c.name";

        var categories = new List<Dictionary<string, object?>>();
        await using (var cmd = new MySqlCommand(catSql, conn))
        {
            cmd.Parameters.AddWithValue("@id", partId);
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                categories.Add(new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
                {
                    ["category_id"] = reader.GetInt64(0),
                    ["name"] = reader.GetString(1),
                    ["slug"] = reader.GetString(2),
                    ["is_primary"] = !reader.IsDBNull(3) && reader.GetBoolean(3),
                    ["coverage_weight"] = reader.IsDBNull(4) ? null : reader.GetValue(4),
                    ["display_order"] = reader.GetInt32(5)
                });
            }
        }

        const string fitSql = @"SELECT pf.part_fitment_id, pf.engine_family_id, ef.code,
                                       pf.years_start, pf.years_end, pf.notes
                                 FROM PartFitment pf
                                 JOIN EngineFamily ef ON ef.engine_family_id = pf.engine_family_id
                                 WHERE pf.part_id = @id
                                 ORDER BY ef.code";

        var fitment = new List<Dictionary<string, object?>>();
        await using (var cmd = new MySqlCommand(fitSql, conn))
        {
            cmd.Parameters.AddWithValue("@id", partId);
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                fitment.Add(new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
                {
                    ["part_fitment_id"] = reader.GetInt64(0),
                    ["engine_family_id"] = reader.GetInt64(1),
                    ["code"] = reader.GetString(2),
                    ["years_start"] = reader.IsDBNull(3) ? null : reader.GetValue(3),
                    ["years_end"] = reader.IsDBNull(4) ? null : reader.GetValue(4),
                    ["notes"] = reader.IsDBNull(5) ? null : reader.GetString(5)
                });
            }
        }

        const string offerSql = @"SELECT po.offering_id, po.vendor_id, v.name AS vendor,
                                        po.price, po.currency, po.availability, po.url, po.affiliate_url
                                 FROM PartOffering po
                                 JOIN Vendor v ON v.vendor_id = po.vendor_id
                                 WHERE po.part_id = @id AND (po.effective_to IS NULL OR po.effective_to > NOW())
                                 ORDER BY po.price IS NULL, po.price";

        var offerings = new List<Dictionary<string, object?>>();
        await using (var cmd = new MySqlCommand(offerSql, conn))
        {
            cmd.Parameters.AddWithValue("@id", partId);
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                offerings.Add(new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
                {
                    ["offering_id"] = reader.GetInt64(0),
                    ["vendor_id"] = reader.GetInt64(1),
                    ["vendor"] = reader.GetString(2),
                    ["price"] = reader.IsDBNull(3) ? null : reader.GetValue(3),
                    ["currency"] = reader.GetString(4),
                    ["availability"] = reader.GetString(5),
                    ["url"] = reader.IsDBNull(6) ? null : reader.GetString(6),
                    ["affiliate_url"] = reader.IsDBNull(7) ? null : reader.GetString(7)
                });
            }
        }

        const string bomSql = @"SELECT pc.child_part_id, child.sku, child.name, pc.qty_per_parent
                                 FROM PartComponent pc
                                 JOIN Part child ON child.part_id = pc.child_part_id
                                 WHERE pc.parent_part_id = @id
                                 ORDER BY child.name";

        var components = new List<Dictionary<string, object?>>();
        await using (var cmd = new MySqlCommand(bomSql, conn))
        {
            cmd.Parameters.AddWithValue("@id", partId);
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                components.Add(new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
                {
                    ["child_part_id"] = reader.GetInt64(0),
                    ["sku"] = reader.IsDBNull(1) ? null : reader.GetString(1),
                    ["name"] = reader.GetString(2),
                    ["qty_per_parent"] = reader.GetValue(3)
                });
            }
        }

        return Results.Json(new
        {
            part = partRow,
            categories,
            fitment,
            offerings,
            components
        });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Fetch part failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: update part core fields
app.MapPatch("/api/admin/parts/{partId:long}", async (HttpContext ctx, long partId, AdminPartUpdateRequest body, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    if (body is null)
        return Results.BadRequest(new { error = "invalid_payload" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        if (!await PartExistsAsync(conn, partId, ct))
            return Results.NotFound(new { error = "part_not_found" });

        long? brandId = null;
        var brandProvided = body.BrandName is not null;
        if (brandProvided)
        {
            var brandName = body.BrandName?.Trim();
            if (!string.IsNullOrWhiteSpace(brandName))
            {
                await using (var brandCmd = new MySqlCommand("INSERT INTO Brand(name) VALUES(@name) ON DUPLICATE KEY UPDATE name = VALUES(name)", conn))
                {
                    brandCmd.Parameters.AddWithValue("@name", brandName);
                    await brandCmd.ExecuteNonQueryAsync(ct);
                }

                await using (var brandLookup = new MySqlCommand("SELECT brand_id FROM Brand WHERE name=@name", conn))
                {
                    brandLookup.Parameters.AddWithValue("@name", brandName);
                    var result = await brandLookup.ExecuteScalarAsync(ct);
                    brandId = result is null ? null : Convert.ToInt64(result);
                }
            }
        }

        var updates = new List<string>();
        var parameters = new Dictionary<string, object?> { ["@id"] = partId };

        if (body.Sku is not null)
        {
            updates.Add("sku=@sku");
            parameters["@sku"] = string.IsNullOrWhiteSpace(body.Sku) ? (object)DBNull.Value : body.Sku.Trim();
        }

        if (body.Name is not null)
        {
            var name = body.Name.Trim();
            if (string.IsNullOrWhiteSpace(name))
                return Results.BadRequest(new { error = "name_required" });
            updates.Add("name=@name");
            parameters["@name"] = name;
        }

        if (brandProvided)
        {
            updates.Add("brand_id=@brand_id");
            parameters["@brand_id"] = (object?)brandId ?? DBNull.Value;
        }

        if (body.Status is not null)
        {
            var status = body.Status.Trim().ToLowerInvariant();
            if (status is not ("active" or "draft" or "discontinued"))
                return Results.BadRequest(new { error = "invalid_status" });
            updates.Add("status=@status");
            parameters["@status"] = status;
        }

        if (body.IsKit.HasValue)
        {
            updates.Add("is_kit=@is_kit");
            parameters["@is_kit"] = body.IsKit.Value;
        }

        if (body.Uom is not null)
        {
            var uom = string.IsNullOrWhiteSpace(body.Uom) ? "piece" : body.Uom.Trim().ToLowerInvariant();
            updates.Add("uom=@uom");
            parameters["@uom"] = uom;
        }

        if (body.PiecesPerUnit.HasValue)
        {
            updates.Add("pieces_per_unit=@ppu");
            parameters["@ppu"] = body.PiecesPerUnit.Value;
        }

        if (body.Description is not null)
        {
            var desc = string.IsNullOrWhiteSpace(body.Description) ? null : body.Description.Trim();
            updates.Add("description=@description");
            parameters["@description"] = (object?)desc ?? DBNull.Value;
        }

        if (body.ImageUrl is not null)
        {
            var img = string.IsNullOrWhiteSpace(body.ImageUrl) ? null : body.ImageUrl.Trim();
            updates.Add("image_url=@image");
            parameters["@image"] = (object?)img ?? DBNull.Value;
        }

        if (updates.Count == 0)
            return Results.BadRequest(new { error = "no_fields" });

        updates.Add("updated_at=NOW()");

        var sql = $"UPDATE Part SET {string.Join(",", updates)} WHERE part_id=@id";
        await using var cmd = new MySqlCommand(sql, conn);
        foreach (var kvp in parameters)
        {
            cmd.Parameters.AddWithValue(kvp.Key, kvp.Value ?? DBNull.Value);
        }
        await cmd.ExecuteNonQueryAsync(ct);

        return Results.Json(new { ok = true });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Update part failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

app.MapPut("/api/admin/parts/{partId:long}/uri", async (
    HttpContext ctx,
    long partId,
    UpdatePartUriRequest body,
    CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    if (body is null)
        return Results.BadRequest(new { error = "invalid_payload" });

    if (body.PartId != 0 && body.PartId != partId)
        return Results.BadRequest(new { error = "part_id_mismatch" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        if (!await PartExistsAsync(conn, partId, ct))
            return Results.NotFound(new { error = "part_not_found" });

        await conn.ExecuteAsync(new CommandDefinition(
            @"UPDATE Part
                 SET gltf_uri = @uri,
                     gltf_attach_node = @attach,
                     updated_at = NOW()
               WHERE part_id = @id",
            new
            {
                id = partId,
                uri = (object?)body.GltfUri ?? DBNull.Value,
                attach = (object?)body.GltfAttachNode ?? DBNull.Value
            },
            cancellationToken: ct));

        return Results.Ok(new { ok = true });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Update part URI failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: upsert part-category mapping (leaf only)
app.MapPost("/api/admin/parts/{partId:long}/categories", async (HttpContext ctx, long partId, AdminPartCategoryRequest body, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    if (body is null)
        return Results.BadRequest(new { error = "invalid_payload" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        if (!await PartExistsAsync(conn, partId, ct))
            return Results.NotFound(new { error = "part_not_found" });

        var (categoryExists, isSelectable) = await FetchCategorySelectableAsync(conn, body.CategoryId, ct);
        if (!categoryExists)
            return Results.NotFound(new { error = "category_not_found" });
        if (!isSelectable)
            return Results.BadRequest(new { error = "category_not_leaf" });

        var isPrimary = body.IsPrimary ?? false;
        var weight = body.CoverageWeight ?? 1m;
        var order = body.DisplayOrder ?? 0;

        const string sql = @"INSERT INTO PartCategory(part_id, category_id, is_primary, coverage_weight, display_order)
                             VALUES(@part, @cat, @primary, @weight, @order)
                             ON DUPLICATE KEY UPDATE
                               is_primary = VALUES(is_primary),
                               coverage_weight = VALUES(coverage_weight),
                               display_order = VALUES(display_order)";

        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@part", partId);
        cmd.Parameters.AddWithValue("@cat", body.CategoryId);
        cmd.Parameters.AddWithValue("@primary", isPrimary);
        cmd.Parameters.AddWithValue("@weight", weight);
        cmd.Parameters.AddWithValue("@order", order);
        await cmd.ExecuteNonQueryAsync(ct);

        return Results.Json(new { ok = true });
    }
    catch (MySqlException ex) when (ex.Number == 1644)
    {
        return Results.BadRequest(new { error = "category_not_leaf", message = ex.Message });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Upsert part category failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: delete part-category mapping
app.MapDelete("/api/admin/parts/{partId:long}/categories/{categoryId:long}", async (HttpContext ctx, long partId, long categoryId, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        const string sql = "DELETE FROM PartCategory WHERE part_id=@part AND category_id=@cat";
        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@part", partId);
        cmd.Parameters.AddWithValue("@cat", categoryId);
        await cmd.ExecuteNonQueryAsync(ct);

        return Results.Json(new { ok = true });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Delete part category failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: upsert fitment row for a part
app.MapPost("/api/admin/parts/{partId:long}/fitment", async (HttpContext ctx, long partId, AdminPartFitmentRequest body, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    if (body is null || string.IsNullOrWhiteSpace(body.EngineCode))
        return Results.BadRequest(new { error = "engine_code_required" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        if (!await PartExistsAsync(conn, partId, ct))
            return Results.NotFound(new { error = "part_not_found" });

        long? engineFamilyId;
        await using (var lookup = new MySqlCommand("SELECT engine_family_id FROM EngineFamily WHERE code=@code", conn))
        {
            lookup.Parameters.AddWithValue("@code", body.EngineCode.Trim());
            var result = await lookup.ExecuteScalarAsync(ct);
            engineFamilyId = result is null ? null : Convert.ToInt64(result);
        }

        if (engineFamilyId is null)
            return Results.BadRequest(new { error = "unknown_engine_code", code = body.EngineCode.Trim() });

        const string sql = @"INSERT INTO PartFitment(part_id, engine_family_id, years_start, years_end, notes)
                             VALUES(@part, @engine, @start, @end, @notes)
                             ON DUPLICATE KEY UPDATE
                               years_start = VALUES(years_start),
                               years_end = VALUES(years_end),
                               notes = VALUES(notes)";

        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@part", partId);
        cmd.Parameters.AddWithValue("@engine", engineFamilyId.Value);
        cmd.Parameters.AddWithValue("@start", (object?)body.YearsStart ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@end", (object?)body.YearsEnd ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@notes", string.IsNullOrWhiteSpace(body.Notes) ? (object)DBNull.Value : body.Notes.Trim());
        await cmd.ExecuteNonQueryAsync(ct);

        return Results.Json(new { ok = true });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Upsert part fitment failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: delete fitment row
app.MapDelete("/api/admin/parts/{partId:long}/fitment/{fitmentId:long}", async (HttpContext ctx, long partId, long fitmentId, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        const string sql = "DELETE FROM PartFitment WHERE part_fitment_id=@fit AND part_id=@part";
        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@fit", fitmentId);
        cmd.Parameters.AddWithValue("@part", partId);
        await cmd.ExecuteNonQueryAsync(ct);

        return Results.Json(new { ok = true });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Delete part fitment failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: add a current offering for a part
app.MapPost("/api/admin/parts/{partId:long}/offerings", async (HttpContext ctx, long partId, AdminPartOfferingRequest body, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    if (body is null || string.IsNullOrWhiteSpace(body.VendorName))
        return Results.BadRequest(new { error = "vendor_required" });

    if (body.Price < 0)
        return Results.BadRequest(new { error = "invalid_price" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        if (!await PartExistsAsync(conn, partId, ct))
            return Results.NotFound(new { error = "part_not_found" });

        long vendorId;
        var vendorName = body.VendorName.Trim();
        await using (var vendorCmd = new MySqlCommand("INSERT INTO Vendor(name) VALUES(@name) ON DUPLICATE KEY UPDATE name=VALUES(name)", conn))
        {
            vendorCmd.Parameters.AddWithValue("@name", vendorName);
            await vendorCmd.ExecuteNonQueryAsync(ct);
        }

        await using (var vendorLookup = new MySqlCommand("SELECT vendor_id FROM Vendor WHERE name=@name", conn))
        {
            vendorLookup.Parameters.AddWithValue("@name", vendorName);
            var result = await vendorLookup.ExecuteScalarAsync(ct);
            vendorId = result is null ? 0 : Convert.ToInt64(result);
        }

        if (vendorId == 0)
            return Results.Problem(title: "Vendor lookup failed", detail: "Could not resolve vendor id", statusCode: 500);

        const string sql = @"INSERT INTO PartOffering(part_id, vendor_id, price, currency, availability, url, affiliate_url, effective_from)
                             VALUES(@part, @vendor, @price, @currency, @availability, @url, @aff, NOW())";

        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@part", partId);
        cmd.Parameters.AddWithValue("@vendor", vendorId);
        cmd.Parameters.AddWithValue("@price", body.Price);
        cmd.Parameters.AddWithValue("@currency", string.IsNullOrWhiteSpace(body.Currency) ? "USD" : body.Currency.Trim().ToUpperInvariant());
        cmd.Parameters.AddWithValue("@availability", string.IsNullOrWhiteSpace(body.Availability) ? "in_stock" : body.Availability.Trim().ToLowerInvariant());
        cmd.Parameters.AddWithValue("@url", string.IsNullOrWhiteSpace(body.Url) ? (object)DBNull.Value : body.Url.Trim());
        cmd.Parameters.AddWithValue("@aff", string.IsNullOrWhiteSpace(body.AffiliateUrl) ? (object)DBNull.Value : body.AffiliateUrl.Trim());
        await cmd.ExecuteNonQueryAsync(ct);

        return Results.Json(new { ok = true });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Create offering failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: delete a part offering
app.MapDelete("/api/admin/parts/{partId:long}/offerings/{offeringId:long}", async (HttpContext ctx, long partId, long offeringId, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        const string sql = "DELETE FROM PartOffering WHERE offering_id=@off AND part_id=@part";
        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@off", offeringId);
        cmd.Parameters.AddWithValue("@part", partId);
        await cmd.ExecuteNonQueryAsync(ct);

        return Results.Json(new { ok = true });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Delete offering failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: quick-create part with optional offering
app.MapPost("/api/admin/parts/quick", async (HttpContext ctx, AdminPartQuickCreateRequest body, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    if (body is null)
        return Results.BadRequest(new { error = "invalid_payload" });

    var sku = body.Sku?.Trim();
    var name = body.Name?.Trim();
    var categorySlug = body.CategorySlug?.Trim().ToLowerInvariant();

    if (string.IsNullOrWhiteSpace(sku) || string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(categorySlug))
        return Results.BadRequest(new { error = "missing_fields" });

    var brandName = string.IsNullOrWhiteSpace(body.BrandName) ? "Generic" : body.BrandName!.Trim();
    var status = string.IsNullOrWhiteSpace(body.Status) ? "active" : body.Status!.Trim().ToLowerInvariant();
    var uom = string.IsNullOrWhiteSpace(body.Uom) ? "each" : body.Uom!.Trim();
    var piecesPerUnit = body.PiecesPerUnit.HasValue && body.PiecesPerUnit.Value > 0 ? body.PiecesPerUnit.Value : 1m;

    if (body.Offering is not null && (body.Offering.Price is null || body.Offering.Price < 0))
        return Results.BadRequest(new { error = "invalid_offering_price" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        await using var tx = await conn.BeginTransactionAsync(ct);
        try
        {
            long? categoryId = null;
            bool isLeaf = false;
            const string categorySql = "SELECT category_id, is_selectable FROM Category WHERE slug=@slug";
            await using (var categoryCmd = new MySqlCommand(categorySql, conn, tx))
            {
                categoryCmd.Parameters.AddWithValue("@slug", categorySlug);
                await using var reader = await categoryCmd.ExecuteReaderAsync(ct);
                if (await reader.ReadAsync(ct))
                {
                    categoryId = reader.IsDBNull(0) ? null : reader.GetInt64(0);
                    isLeaf = !reader.IsDBNull(1) && reader.GetBoolean(1);
                }
            }

            if (categoryId is null || !isLeaf)
            {
                await tx.RollbackAsync(ct);
                return Results.BadRequest(new { error = "not_leaf_or_unknown_category" });
            }

            long? brandId = null;
            if (!string.IsNullOrWhiteSpace(brandName))
            {
                const string brandUpsertSql = "INSERT INTO Brand(name) VALUES(@name) ON DUPLICATE KEY UPDATE name=VALUES(name)";
                await using (var brandCmd = new MySqlCommand(brandUpsertSql, conn, tx))
                {
                    brandCmd.Parameters.AddWithValue("@name", brandName);
                    await brandCmd.ExecuteNonQueryAsync(ct);
                }

                const string brandIdSql = "SELECT brand_id FROM Brand WHERE name=@name";
                await using (var brandIdCmd = new MySqlCommand(brandIdSql, conn, tx))
                {
                    brandIdCmd.Parameters.AddWithValue("@name", brandName);
                    var brandObj = await brandIdCmd.ExecuteScalarAsync(ct);
                    if (brandObj is not null && brandObj is not DBNull)
                        brandId = Convert.ToInt64(brandObj);
                }
            }

            const string partUpsertSql = @"INSERT INTO Part (sku, name, brand_id, is_kit, uom, pieces_per_unit, status)
                                           VALUES (@sku, @name, @brand, FALSE, @uom, @ppu, @status)
                                           ON DUPLICATE KEY UPDATE
                                             name=VALUES(name),
                                             brand_id=VALUES(brand_id),
                                             uom=VALUES(uom),
                                             pieces_per_unit=VALUES(pieces_per_unit),
                                             status=VALUES(status)";

            await using (var partCmd = new MySqlCommand(partUpsertSql, conn, tx))
            {
                partCmd.Parameters.AddWithValue("@sku", sku);
                partCmd.Parameters.AddWithValue("@name", name);
                partCmd.Parameters.AddWithValue("@brand", brandId.HasValue ? brandId.Value : (object)DBNull.Value);
                partCmd.Parameters.AddWithValue("@uom", uom);
                partCmd.Parameters.AddWithValue("@ppu", piecesPerUnit);
                partCmd.Parameters.AddWithValue("@status", status);
                await partCmd.ExecuteNonQueryAsync(ct);
            }

            long partId;
            const string partIdSql = "SELECT part_id FROM Part WHERE sku=@sku";
            await using (var partIdCmd = new MySqlCommand(partIdSql, conn, tx))
            {
                partIdCmd.Parameters.AddWithValue("@sku", sku);
                var idObj = await partIdCmd.ExecuteScalarAsync(ct);
                partId = idObj is null || idObj is DBNull ? 0 : Convert.ToInt64(idObj);
            }

            if (partId == 0)
            {
                await tx.RollbackAsync(ct);
                return Results.Problem(title: "Quick create failed", detail: "Could not resolve part id", statusCode: 500);
            }

            const string categoryInsertSql = @"INSERT INTO PartCategory (part_id, category_id, is_primary, coverage_weight, display_order)
                                               VALUES (@part, @category, TRUE, 1, 0)
                                               ON DUPLICATE KEY UPDATE
                                                 is_primary=TRUE,
                                                 coverage_weight=1,
                                                 display_order=0";
            await using (var categoryInsert = new MySqlCommand(categoryInsertSql, conn, tx))
            {
                categoryInsert.Parameters.AddWithValue("@part", partId);
                categoryInsert.Parameters.AddWithValue("@category", categoryId.Value);
                await categoryInsert.ExecuteNonQueryAsync(ct);
            }

            if (body.Offering is not null && body.Offering.Price is not null)
            {
                var vendorName = string.IsNullOrWhiteSpace(body.Offering.VendorName) ? "Unknown Vendor" : body.Offering.VendorName!.Trim();
                var price = body.Offering.Price.Value;
                var currency = string.IsNullOrWhiteSpace(body.Offering.Currency) ? "USD" : body.Offering.Currency!.Trim().ToUpperInvariant();
                var url = string.IsNullOrWhiteSpace(body.Offering.Url) ? null : body.Offering.Url!.Trim();

                const string vendorUpsertSql = "INSERT INTO Vendor(name) VALUES(@name) ON DUPLICATE KEY UPDATE name=VALUES(name)";
                await using (var vendorCmd = new MySqlCommand(vendorUpsertSql, conn, tx))
                {
                    vendorCmd.Parameters.AddWithValue("@name", vendorName);
                    await vendorCmd.ExecuteNonQueryAsync(ct);
                }

                long vendorId;
                const string vendorIdSql = "SELECT vendor_id FROM Vendor WHERE name=@name";
                await using (var vendorIdCmd = new MySqlCommand(vendorIdSql, conn, tx))
                {
                    vendorIdCmd.Parameters.AddWithValue("@name", vendorName);
                    var vendorObj = await vendorIdCmd.ExecuteScalarAsync(ct);
                    vendorId = vendorObj is null || vendorObj is DBNull ? 0 : Convert.ToInt64(vendorObj);
                }

                if (vendorId == 0)
                {
                    await tx.RollbackAsync(ct);
                    return Results.Problem(title: "Quick create failed", detail: "Could not resolve vendor id", statusCode: 500);
                }

                const string offeringInsertSql = @"INSERT INTO PartOffering (part_id, vendor_id, price, currency, url, availability, effective_from)
                                                   VALUES (@part, @vendor, @price, @currency, @url, 'in_stock', NOW())";
                await using (var offeringCmd = new MySqlCommand(offeringInsertSql, conn, tx))
                {
                    offeringCmd.Parameters.AddWithValue("@part", partId);
                    offeringCmd.Parameters.AddWithValue("@vendor", vendorId);
                    offeringCmd.Parameters.AddWithValue("@price", price);
                    offeringCmd.Parameters.AddWithValue("@currency", currency);
                    offeringCmd.Parameters.AddWithValue("@url", (object?)url ?? DBNull.Value);
                    await offeringCmd.ExecuteNonQueryAsync(ct);
                }
            }

            await tx.CommitAsync(ct);
            return Results.Created($"/api/admin/parts/{partId}", new { part_id = partId, sku });
        }
        catch
        {
            await tx.RollbackAsync(ct);
            throw;
        }
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Quick create failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: upsert kit component
app.MapPost("/api/admin/parts/{partId:long}/components", async (HttpContext ctx, long partId, AdminPartComponentRequest body, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    if (body is null || string.IsNullOrWhiteSpace(body.ChildSku) || body.QtyPerParent <= 0)
        return Results.BadRequest(new { error = "invalid_component" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        if (!await PartExistsAsync(conn, partId, ct))
            return Results.NotFound(new { error = "part_not_found" });

        long? childId;
        await using (var childLookup = new MySqlCommand("SELECT part_id FROM Part WHERE sku=@sku", conn))
        {
            childLookup.Parameters.AddWithValue("@sku", body.ChildSku.Trim());
            var result = await childLookup.ExecuteScalarAsync(ct);
            childId = result is null ? null : Convert.ToInt64(result);
        }

        if (childId is null)
            return Results.BadRequest(new { error = "unknown_child_sku", sku = body.ChildSku.Trim() });

        const string sql = @"INSERT INTO PartComponent(parent_part_id, child_part_id, qty_per_parent)
                             VALUES(@parent, @child, @qty)
                             ON DUPLICATE KEY UPDATE qty_per_parent = VALUES(qty_per_parent)";

        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@parent", partId);
        cmd.Parameters.AddWithValue("@child", childId.Value);
        cmd.Parameters.AddWithValue("@qty", body.QtyPerParent);
        await cmd.ExecuteNonQueryAsync(ct);

        return Results.Json(new { ok = true });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Upsert component failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: delete kit component row
app.MapDelete("/api/admin/parts/{partId:long}/components/{childPartId:long}", async (HttpContext ctx, long partId, long childPartId, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        const string sql = "DELETE FROM PartComponent WHERE parent_part_id=@parent AND child_part_id=@child";
        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@parent", partId);
        cmd.Parameters.AddWithValue("@child", childPartId);
        await cmd.ExecuteNonQueryAsync(ct);

        return Results.Json(new { ok = true });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Delete component failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: list kits only
app.MapGet("/api/admin/kits", async (HttpContext ctx, string? q, string? brand, int page = 1, int pageSize = 50, CancellationToken ct = default) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    var search = string.IsNullOrWhiteSpace(q) ? null : q.Trim();
    var brandFilter = string.IsNullOrWhiteSpace(brand) ? null : brand.Trim();
    var pageNumber = Math.Max(1, page);
    var limit = Math.Clamp(pageSize, 1, 200);
    var offset = (pageNumber - 1) * limit;

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        const string sql = @"SELECT p.part_id, p.sku, p.name, p.status, p.pieces_per_unit, p.updated_at,
                                     b.name AS brand_name
                              FROM Part p
                              LEFT JOIN Brand b ON b.brand_id = p.brand_id
                              WHERE p.is_kit = TRUE
                                AND (@q IS NULL OR p.sku LIKE CONCAT('%', @q, '%') OR p.name LIKE CONCAT('%', @q, '%'))
                                AND (@brand IS NULL OR b.name = @brand)
                              ORDER BY p.updated_at DESC
                              LIMIT @limit OFFSET @offset";

        var rows = new List<Dictionary<string, object?>>();
        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@q", (object?)search ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@brand", (object?)brandFilter ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@limit", limit);
        cmd.Parameters.AddWithValue("@offset", offset);

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
            {
                ["part_id"] = reader.GetInt64(0),
                ["sku"] = reader.IsDBNull(1) ? null : reader.GetString(1),
                ["name"] = reader.GetString(2),
                ["status"] = reader.GetString(3),
                ["pieces_per_unit"] = reader.IsDBNull(4) ? null : reader.GetValue(4),
                ["updated_at"] = reader.IsDBNull(5) ? null : reader.GetValue(5),
                ["brand_name"] = reader.IsDBNull(6) ? null : reader.GetValue(6)
            };
            rows.Add(row);
        }

        return Results.Json(rows);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Fetch kits failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: search existing parts for kit builder
app.MapGet("/api/admin/parts/search", async (HttpContext ctx, string? q, bool excludeKits = true, int limit = 200, CancellationToken ct = default) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    var search = string.IsNullOrWhiteSpace(q) ? null : q.Trim();
    var max = Math.Clamp(limit, 1, 500);

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        const string sql = @"SELECT p.part_id, p.sku, p.name, COALESCE(b.name,'') AS brand, p.is_kit, bo.best_price
                              FROM Part p
                              LEFT JOIN Brand b ON b.brand_id = p.brand_id
                              LEFT JOIN v_part_best_offering bo ON bo.part_id = p.part_id
                              WHERE (@q IS NULL OR p.sku LIKE CONCAT('%', @q, '%') OR p.name LIKE CONCAT('%', @q, '%'))
                                AND (@exclude = 0 OR p.is_kit = 0)
                              ORDER BY p.name
                              LIMIT @limit";

        var rows = new List<Dictionary<string, object?>>();
        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@q", (object?)search ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@exclude", excludeKits ? 1 : 0);
        cmd.Parameters.AddWithValue("@limit", max);

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
            {
                ["part_id"] = reader.GetInt64(0),
                ["sku"] = reader.IsDBNull(1) ? string.Empty : reader.GetString(1),
                ["name"] = reader.IsDBNull(2) ? string.Empty : reader.GetString(2),
                ["brand"] = reader.IsDBNull(3) ? string.Empty : reader.GetString(3),
                ["is_kit"] = !reader.IsDBNull(4) && reader.GetBoolean(4),
                ["best_price"] = reader.IsDBNull(5) ? null : reader.GetValue(5)
            };
            rows.Add(row);
        }

        return Results.Json(rows);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Search failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: create new kit from existing parts
app.MapPost("/api/admin/kits", async (HttpContext ctx, AdminKitCreateRequest body, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    if (body is null || body.Kit is null)
        return Results.BadRequest(new { error = "invalid_payload" });

    var sku = body.Kit.Sku?.Trim();
    var name = body.Kit.Name?.Trim();

    if (string.IsNullOrWhiteSpace(sku) || string.IsNullOrWhiteSpace(name))
        return Results.BadRequest(new { error = "missing_fields", message = "SKU and name are required." });

    if (body.Components is null || body.Components.Count == 0)
        return Results.BadRequest(new { error = "no_components" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        // ensure SKU unique
        await using (var checkCmd = new MySqlCommand("SELECT part_id FROM Part WHERE sku=@sku LIMIT 1", conn))
        {
            checkCmd.Parameters.AddWithValue("@sku", sku);
            if (await checkCmd.ExecuteScalarAsync(ct) is not null)
                return Results.Json(new { error = "sku_in_use" }, statusCode: StatusCodes.Status409Conflict);
        }

        await using var tx = await conn.BeginTransactionAsync(ct);

        long? brandId = null;
        if (!string.IsNullOrWhiteSpace(body.Kit.BrandName))
        {
            var brandName = body.Kit.BrandName.Trim();
            await using (var upsertBrand = new MySqlCommand("INSERT INTO Brand(name) VALUES(@name) ON DUPLICATE KEY UPDATE name=VALUES(name)", conn, tx))
            {
                upsertBrand.Parameters.AddWithValue("@name", brandName);
                await upsertBrand.ExecuteNonQueryAsync(ct);
            }

            await using (var brandIdCmd = new MySqlCommand("SELECT brand_id FROM Brand WHERE name=@name", conn, tx))
            {
                brandIdCmd.Parameters.AddWithValue("@name", brandName);
                var result = await brandIdCmd.ExecuteScalarAsync(ct);
                if (result is not null && result is not DBNull)
                    brandId = Convert.ToInt64(result);
            }
        }

        var uom = string.IsNullOrWhiteSpace(body.Kit.Uom) ? "kit" : body.Kit.Uom!.Trim();
        var status = string.IsNullOrWhiteSpace(body.Kit.Status) ? "active" : body.Kit.Status!.Trim();
        var pieces = body.Kit.PiecesPerUnit ?? 1m;

        const string insertPartSql = @"INSERT INTO Part (sku, name, brand_id, is_kit, uom, pieces_per_unit, status, description, image_url)
                                       VALUES (@sku, @name, @brand, TRUE, @uom, @pieces, @status, @description, @image)";

        await using (var insertPart = new MySqlCommand(insertPartSql, conn, tx))
        {
            insertPart.Parameters.AddWithValue("@sku", sku);
            insertPart.Parameters.AddWithValue("@name", name);
            insertPart.Parameters.AddWithValue("@brand", brandId.HasValue ? brandId.Value : (object)DBNull.Value);
            insertPart.Parameters.AddWithValue("@uom", uom);
            insertPart.Parameters.AddWithValue("@pieces", pieces);
            insertPart.Parameters.AddWithValue("@status", status);
            insertPart.Parameters.AddWithValue("@description", string.IsNullOrWhiteSpace(body.Kit.Description) ? DBNull.Value : body.Kit.Description);
            insertPart.Parameters.AddWithValue("@image", string.IsNullOrWhiteSpace(body.Kit.ImageUrl) ? DBNull.Value : body.Kit.ImageUrl);

            await insertPart.ExecuteNonQueryAsync(ct);
        }

        long kitId;
        await using (var idCmd = new MySqlCommand("SELECT part_id FROM Part WHERE sku=@sku", conn, tx))
        {
            idCmd.Parameters.AddWithValue("@sku", sku);
            kitId = Convert.ToInt64(await idCmd.ExecuteScalarAsync(ct));
        }

        if (!string.IsNullOrWhiteSpace(body.Kit.PrimaryCategorySlug))
        {
            var slug = body.Kit.PrimaryCategorySlug.Trim();
            long? categoryId;
            await using (var catCmd = new MySqlCommand("SELECT category_id FROM Category WHERE slug=@slug AND is_selectable=TRUE", conn, tx))
            {
                catCmd.Parameters.AddWithValue("@slug", slug);
                var result = await catCmd.ExecuteScalarAsync(ct);
                categoryId = result is null || result is DBNull ? null : Convert.ToInt64(result);
            }

            if (categoryId is null)
            {
                await tx.RollbackAsync(ct);
                return Results.BadRequest(new { error = "unknown_category_slug" });
            }

            await using (var upsertCat = new MySqlCommand(@"INSERT INTO PartCategory (part_id, category_id, is_primary, coverage_weight, display_order)
                                                              VALUES (@part,@category,TRUE,1,0)
                                                              ON DUPLICATE KEY UPDATE is_primary=TRUE, coverage_weight=1, display_order=0", conn, tx))
            {
                upsertCat.Parameters.AddWithValue("@part", kitId);
                upsertCat.Parameters.AddWithValue("@category", categoryId.Value);
                await upsertCat.ExecuteNonQueryAsync(ct);
            }
        }

        var seenChildren = new HashSet<long>();
        foreach (var component in body.Components)
        {
            var childSku = component.ChildSku?.Trim();
            if (string.IsNullOrWhiteSpace(childSku))
            {
                await tx.RollbackAsync(ct);
                return Results.BadRequest(new { error = "invalid_child_sku" });
            }

            if (component.Qty <= 0)
            {
                await tx.RollbackAsync(ct);
                return Results.BadRequest(new { error = "invalid_qty", child_sku = childSku });
            }

            long? childId;
            await using (var childCmd = new MySqlCommand("SELECT part_id FROM Part WHERE sku=@sku", conn, tx))
            {
                childCmd.Parameters.AddWithValue("@sku", childSku);
                var result = await childCmd.ExecuteScalarAsync(ct);
                childId = result is null || result is DBNull ? null : Convert.ToInt64(result);
            }

            if (childId is null)
            {
                await tx.RollbackAsync(ct);
                return Results.BadRequest(new { error = "unknown_child_sku", child_sku = childSku });
            }

            if (childId.Value == kitId)
            {
                await tx.RollbackAsync(ct);
                return Results.BadRequest(new { error = "self_reference" });
            }

            if (!seenChildren.Add(childId.Value))
                continue;

            await using (var insertComponent = new MySqlCommand(@"INSERT INTO PartComponent (parent_part_id, child_part_id, qty_per_parent)
                                                                  VALUES (@parent,@child,@qty)
                                                                  ON DUPLICATE KEY UPDATE qty_per_parent=VALUES(qty_per_parent)", conn, tx))
            {
                insertComponent.Parameters.AddWithValue("@parent", kitId);
                insertComponent.Parameters.AddWithValue("@child", childId.Value);
                insertComponent.Parameters.AddWithValue("@qty", component.Qty);
                await insertComponent.ExecuteNonQueryAsync(ct);
            }
        }

        if (body.Price is not null)
        {
            var priceReq = body.Price;
            var mode = string.IsNullOrWhiteSpace(priceReq.Mode) ? "rollup" : priceReq.Mode!.Trim().ToLowerInvariant();
            var vendorName = string.IsNullOrWhiteSpace(priceReq.VendorName) ? "Bundle (Virtual)" : priceReq.VendorName!.Trim();
            var currency = string.IsNullOrWhiteSpace(priceReq.Currency) ? "USD" : priceReq.Currency!.Trim();
            var availability = string.IsNullOrWhiteSpace(priceReq.Availability) ? "in_stock" : priceReq.Availability!.Trim();

            decimal finalPrice;
            if (mode == "manual")
            {
                if (priceReq.ManualPrice is null)
                {
                    await tx.RollbackAsync(ct);
                    return Results.BadRequest(new { error = "manual_price_required" });
                }
                finalPrice = priceReq.ManualPrice.Value;
            }
            else
            {
                var rollup = await ComputeRollupAsync(conn, kitId, tx, ct);
                var margin = priceReq.MarginPct ?? 0m;
                var round = priceReq.Round ?? 0m;
                var basePrice = rollup * (1 + margin);
                finalPrice = round > 0 ? Math.Ceiling(basePrice / round) * round : basePrice;
            }

            await using (var vendorUpsert = new MySqlCommand("INSERT INTO Vendor(name) VALUES(@name) ON DUPLICATE KEY UPDATE name=VALUES(name)", conn, tx))
            {
                vendorUpsert.Parameters.AddWithValue("@name", vendorName);
                await vendorUpsert.ExecuteNonQueryAsync(ct);
            }

            long vendorId;
            await using (var vendorIdCmd = new MySqlCommand("SELECT vendor_id FROM Vendor WHERE name=@name", conn, tx))
            {
                vendorIdCmd.Parameters.AddWithValue("@name", vendorName);
                vendorId = Convert.ToInt64(await vendorIdCmd.ExecuteScalarAsync(ct));
            }

            await using (var offeringInsert = new MySqlCommand(@"INSERT INTO PartOffering (part_id, vendor_id, price, currency, availability, effective_from)
                                                                 VALUES (@part,@vendor,@price,@currency,@availability,NOW())", conn, tx))
            {
                offeringInsert.Parameters.AddWithValue("@part", kitId);
                offeringInsert.Parameters.AddWithValue("@vendor", vendorId);
                offeringInsert.Parameters.AddWithValue("@price", finalPrice);
                offeringInsert.Parameters.AddWithValue("@currency", currency);
                offeringInsert.Parameters.AddWithValue("@availability", availability);
                await offeringInsert.ExecuteNonQueryAsync(ct);
            }
        }

        await tx.CommitAsync(ct);
        return Results.Created($"/api/admin/kits/{kitId}", new { part_id = kitId, sku });

        static async Task<decimal> ComputeRollupAsync(MySqlConnection conn, long kitId, MySqlTransaction tx, CancellationToken ct)
        {
            const string sql = @"SELECT COALESCE(SUM(pc.qty_per_parent * bo.best_price), 0)
                                  FROM PartComponent pc
                                  LEFT JOIN v_part_best_offering bo ON bo.part_id = pc.child_part_id
                                  WHERE pc.parent_part_id=@id";
            await using var cmd = new MySqlCommand(sql, conn, tx);
            cmd.Parameters.AddWithValue("@id", kitId);
            var result = await cmd.ExecuteScalarAsync(ct);
            return result is null || result is DBNull ? 0m : Convert.ToDecimal(result);
        }
    }
    catch (MySqlException ex) when (ex.Number == 1062)
    {
        return Results.Json(new { error = "sku_in_use" }, statusCode: StatusCodes.Status409Conflict);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Create kit failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: build/replace kit components from existing parts
app.MapPost("/api/admin/kits/{kitId:long}/build-from", async (HttpContext ctx, long kitId, AdminKitBuildFromRequest body, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    if (body is null)
        return Results.BadRequest(new { error = "invalid_payload" });

    if (body.Components is null)
        body.Components = new List<AdminKitCreateComponent>();

    if (body.Components.Count == 0)
        return Results.BadRequest(new { error = "no_components" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        if (!await PartExistsAsync(conn, kitId, ct))
            return Results.NotFound(new { error = "part_not_found" });

        await using var tx = await conn.BeginTransactionAsync(ct);

        if (body.SetIsKit ?? true)
        {
            await using var markKit = new MySqlCommand("UPDATE Part SET is_kit=TRUE WHERE part_id=@id", conn, tx);
            markKit.Parameters.AddWithValue("@id", kitId);
            await markKit.ExecuteNonQueryAsync(ct);
        }

        if (!string.IsNullOrWhiteSpace(body.PrimaryCategorySlug))
        {
            var slug = body.PrimaryCategorySlug.Trim();
            long? categoryId;
            await using (var catCmd = new MySqlCommand("SELECT category_id FROM Category WHERE slug=@slug AND is_selectable=TRUE", conn, tx))
            {
                catCmd.Parameters.AddWithValue("@slug", slug);
                var result = await catCmd.ExecuteScalarAsync(ct);
                categoryId = result is null || result is DBNull ? null : Convert.ToInt64(result);
            }

            if (categoryId is not null)
            {
                await using var upsertCat = new MySqlCommand(@"INSERT INTO PartCategory (part_id, category_id, is_primary, coverage_weight, display_order)
                                                                  VALUES (@part,@category,TRUE,1,0)
                                                                  ON DUPLICATE KEY UPDATE is_primary=TRUE, coverage_weight=1, display_order=0", conn, tx);
                upsertCat.Parameters.AddWithValue("@part", kitId);
                upsertCat.Parameters.AddWithValue("@category", categoryId.Value);
                await upsertCat.ExecuteNonQueryAsync(ct);
            }
        }

        if (body.ReplaceBom ?? true)
        {
            await using var deleteBom = new MySqlCommand("DELETE FROM PartComponent WHERE parent_part_id=@id", conn, tx);
            deleteBom.Parameters.AddWithValue("@id", kitId);
            await deleteBom.ExecuteNonQueryAsync(ct);
        }

        var seenChildren = new HashSet<long>();
        foreach (var component in body.Components)
        {
            var childSku = component.ChildSku?.Trim();
            if (string.IsNullOrWhiteSpace(childSku))
            {
                await tx.RollbackAsync(ct);
                return Results.BadRequest(new { error = "invalid_child_sku" });
            }

            if (component.Qty <= 0)
            {
                await tx.RollbackAsync(ct);
                return Results.BadRequest(new { error = "invalid_qty", child_sku = childSku });
            }

            long? childId;
            await using (var childCmd = new MySqlCommand("SELECT part_id FROM Part WHERE sku=@sku", conn, tx))
            {
                childCmd.Parameters.AddWithValue("@sku", childSku);
                var result = await childCmd.ExecuteScalarAsync(ct);
                childId = result is null || result is DBNull ? null : Convert.ToInt64(result);
            }

            if (childId is null)
            {
                await tx.RollbackAsync(ct);
                return Results.BadRequest(new { error = "unknown_child_sku", child_sku = childSku });
            }

            if (childId.Value == kitId)
            {
                await tx.RollbackAsync(ct);
                return Results.BadRequest(new { error = "self_reference" });
            }

            if (!seenChildren.Add(childId.Value) && (body.ReplaceBom ?? true))
                continue;

            await using (var upsertComponent = new MySqlCommand(@"INSERT INTO PartComponent (parent_part_id, child_part_id, qty_per_parent)
                                                                  VALUES (@parent,@child,@qty)
                                                                  ON DUPLICATE KEY UPDATE qty_per_parent=VALUES(qty_per_parent)", conn, tx))
            {
                upsertComponent.Parameters.AddWithValue("@parent", kitId);
                upsertComponent.Parameters.AddWithValue("@child", childId.Value);
                upsertComponent.Parameters.AddWithValue("@qty", component.Qty);
                await upsertComponent.ExecuteNonQueryAsync(ct);
            }
        }

        if (body.Price is not null)
        {
            var priceReq = body.Price;
            var mode = string.IsNullOrWhiteSpace(priceReq.Mode) ? "rollup" : priceReq.Mode!.Trim().ToLowerInvariant();
            var vendorName = string.IsNullOrWhiteSpace(priceReq.VendorName) ? "Bundle (Virtual)" : priceReq.VendorName!.Trim();
            var currency = string.IsNullOrWhiteSpace(priceReq.Currency) ? "USD" : priceReq.Currency!.Trim();
            var availability = string.IsNullOrWhiteSpace(priceReq.Availability) ? "in_stock" : priceReq.Availability!.Trim();

            decimal finalPrice;
            if (mode == "manual")
            {
                if (priceReq.ManualPrice is null)
                {
                    await tx.RollbackAsync(ct);
                    return Results.BadRequest(new { error = "manual_price_required" });
                }
                finalPrice = priceReq.ManualPrice.Value;
            }
            else
            {
                var rollup = await ComputeRollupAsync(conn, kitId, tx, ct);
                var margin = priceReq.MarginPct ?? 0m;
                var round = priceReq.Round ?? 0m;
                var basePrice = rollup * (1 + margin);
                finalPrice = round > 0 ? Math.Ceiling(basePrice / round) * round : basePrice;
            }

            await using (var vendorUpsert = new MySqlCommand("INSERT INTO Vendor(name) VALUES(@name) ON DUPLICATE KEY UPDATE name=VALUES(name)", conn, tx))
            {
                vendorUpsert.Parameters.AddWithValue("@name", vendorName);
                await vendorUpsert.ExecuteNonQueryAsync(ct);
            }

            long vendorId;
            await using (var vendorIdCmd = new MySqlCommand("SELECT vendor_id FROM Vendor WHERE name=@name", conn, tx))
            {
                vendorIdCmd.Parameters.AddWithValue("@name", vendorName);
                vendorId = Convert.ToInt64(await vendorIdCmd.ExecuteScalarAsync(ct));
            }

            await using (var offeringInsert = new MySqlCommand(@"INSERT INTO PartOffering (part_id, vendor_id, price, currency, availability, effective_from)
                                                                 VALUES (@part,@vendor,@price,@currency,@availability,NOW())", conn, tx))
            {
                offeringInsert.Parameters.AddWithValue("@part", kitId);
                offeringInsert.Parameters.AddWithValue("@vendor", vendorId);
                offeringInsert.Parameters.AddWithValue("@price", finalPrice);
                offeringInsert.Parameters.AddWithValue("@currency", currency);
                offeringInsert.Parameters.AddWithValue("@availability", availability);
                await offeringInsert.ExecuteNonQueryAsync(ct);
            }
        }

        await tx.CommitAsync(ct);
        return Results.Json(new { ok = true });

        static async Task<decimal> ComputeRollupAsync(MySqlConnection conn, long kitId, MySqlTransaction tx, CancellationToken ct)
        {
            const string sql = @"SELECT COALESCE(SUM(pc.qty_per_parent * bo.best_price), 0)
                                  FROM PartComponent pc
                                  LEFT JOIN v_part_best_offering bo ON bo.part_id = pc.child_part_id
                                  WHERE pc.parent_part_id=@id";
            await using var cmd = new MySqlCommand(sql, conn, tx);
            cmd.Parameters.AddWithValue("@id", kitId);
            var result = await cmd.ExecuteScalarAsync(ct);
            return result is null || result is DBNull ? 0m : Convert.ToDecimal(result);
        }
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Build kit failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: load kit editor snapshot (components + pricing)
app.MapGet("/api/admin/kits/{partId:long}/edit", async (HttpContext ctx, long partId, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        if (!await PartExistsAsync(conn, partId, ct))
            return Results.NotFound(new { error = "part_not_found" });

        if (!await PartIsKitAsync(conn, partId, ct))
            return Results.BadRequest(new { error = "not_a_kit" });

        const string componentSql = @"WITH latest_offering AS (
                                              SELECT po.part_id,
                                                     po.vendor_id,
                                                     po.price,
                                                     po.currency,
                                                     po.url,
                                                     po.availability,
                                                     ROW_NUMBER() OVER (PARTITION BY po.part_id ORDER BY po.price ASC, po.effective_from DESC, po.offering_id DESC) AS rn
                                              FROM PartOffering po
                                              WHERE (po.effective_to IS NULL OR po.effective_to > NOW())
                                          )
                                          SELECT
                                              pc.child_part_id   AS ChildPartId,
                                              cp.sku             AS Sku,
                                              cp.name            AS Name,
                                              pc.qty_per_parent  AS Qty,
                                              lo.vendor_id       AS VendorId,
                                              v.name             AS VendorName,
                                              lo.price           AS Price,
                                              lo.currency        AS Currency,
                                              lo.url             AS Url,
                                              lo.availability    AS Availability
                                          FROM PartComponent pc
                                          JOIN Part cp ON cp.part_id = pc.child_part_id
                                          LEFT JOIN latest_offering lo ON lo.part_id = cp.part_id AND lo.rn = 1
                                          LEFT JOIN Vendor v ON v.vendor_id = lo.vendor_id
                                          WHERE pc.parent_part_id = @partId
                                          ORDER BY cp.name;";

        var components = (await conn.QueryAsync<AdminKitEditComponentDto>(componentSql, new { partId })).ToList();

        const string kitOfferingSql = @"WITH latest_kit AS (
                                              SELECT po.vendor_id,
                                                     po.price,
                                                     po.currency,
                                                     po.url,
                                                     po.availability,
                                                     ROW_NUMBER() OVER (ORDER BY po.price ASC, po.effective_from DESC, po.offering_id DESC) AS rn
                                              FROM PartOffering po
                                              WHERE po.part_id = @partId
                                                AND (po.effective_to IS NULL OR po.effective_to > NOW())
                                          )
                                          SELECT
                                              lk.vendor_id    AS VendorId,
                                              v.name          AS VendorName,
                                              lk.price        AS Price,
                                              lk.currency     AS Currency,
                                              lk.url          AS Url,
                                              lk.availability AS Availability
                                          FROM latest_kit lk
                                          LEFT JOIN Vendor v ON v.vendor_id = lk.vendor_id
                                          WHERE lk.rn = 1;";

        var kitOffering = await conn.QuerySingleOrDefaultAsync<AdminKitEditOfferingSummary>(kitOfferingSql, new { partId });

        const string vendorSql = "SELECT vendor_id AS VendorId, name AS Name FROM Vendor ORDER BY name";
        var vendors = (await conn.QueryAsync<AdminVendorOption>(vendorSql)).ToList();

        var payload = new AdminKitEditSnapshot
        {
            Components = components,
            KitOffering = kitOffering,
            Vendors = vendors
        };

        return Results.Json(payload);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Load kit editor failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: bulk update kit component quantities and pricing
app.MapPost("/api/admin/kits/{partId:long}/edit", async (HttpContext ctx, long partId, AdminKitEditRequest body, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    if (body is null || (body.Components is null && body.KitOffering is null))
        return Results.BadRequest(new { error = "empty_payload" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        if (!await PartExistsAsync(conn, partId, ct))
            return Results.NotFound(new { error = "part_not_found" });

        if (!await PartIsKitAsync(conn, partId, ct))
            return Results.BadRequest(new { error = "not_a_kit" });

        await using var tx = await conn.BeginTransactionAsync(ct);

        async Task<long> EnsureVendorAsync(string? vendorName)
        {
            var name = string.IsNullOrWhiteSpace(vendorName) ? "Unknown Vendor" : vendorName!.Trim();

            const string insertSql = "INSERT INTO Vendor(name) VALUES(@name) ON DUPLICATE KEY UPDATE name=VALUES(name)";
            await using (var insertCmd = new MySqlCommand(insertSql, conn, tx))
            {
                insertCmd.Parameters.AddWithValue("@name", name);
                await insertCmd.ExecuteNonQueryAsync(ct);
            }

            const string idSql = "SELECT vendor_id FROM Vendor WHERE name=@name";
            await using var idCmd = new MySqlCommand(idSql, conn, tx);
            idCmd.Parameters.AddWithValue("@name", name);
            var idObj = await idCmd.ExecuteScalarAsync(ct);
            return idObj is null ? 0 : Convert.ToInt64(idObj);
        }

        async Task UpsertOfferingAsync(long targetPartId, long vendorId, decimal price, string currency, string? url, string availability)
        {
            const string selectSql = @"SELECT offering_id
                                          FROM PartOffering
                                          WHERE part_id=@part AND vendor_id=@vendor AND (effective_to IS NULL OR effective_to > NOW())
                                          ORDER BY effective_from DESC
                                          LIMIT 1";

            long? existingId = null;
            await using (var selectCmd = new MySqlCommand(selectSql, conn, tx))
            {
                selectCmd.Parameters.AddWithValue("@part", targetPartId);
                selectCmd.Parameters.AddWithValue("@vendor", vendorId);
                var result = await selectCmd.ExecuteScalarAsync(ct);
                existingId = result is null ? null : Convert.ToInt64(result);
            }

            if (existingId is null)
            {
                const string insertSql = @"INSERT INTO PartOffering(part_id, vendor_id, price, currency, url, availability, effective_from)
                                             VALUES(@part, @vendor, @price, @currency, @url, @availability, NOW())";
                await using var insertCmd = new MySqlCommand(insertSql, conn, tx);
                insertCmd.Parameters.AddWithValue("@part", targetPartId);
                insertCmd.Parameters.AddWithValue("@vendor", vendorId);
                insertCmd.Parameters.AddWithValue("@price", price);
                insertCmd.Parameters.AddWithValue("@currency", currency);
                insertCmd.Parameters.AddWithValue("@url", string.IsNullOrWhiteSpace(url) ? DBNull.Value : url);
                insertCmd.Parameters.AddWithValue("@availability", string.IsNullOrWhiteSpace(availability) ? "unknown" : availability);
                await insertCmd.ExecuteNonQueryAsync(ct);
            }
            else
            {
                const string updateSql = @"UPDATE PartOffering
                                             SET price=@price, currency=@currency, url=@url, availability=@availability
                                             WHERE offering_id=@id";
                await using var updateCmd = new MySqlCommand(updateSql, conn, tx);
                updateCmd.Parameters.AddWithValue("@price", price);
                updateCmd.Parameters.AddWithValue("@currency", currency);
                updateCmd.Parameters.AddWithValue("@url", string.IsNullOrWhiteSpace(url) ? DBNull.Value : url);
                updateCmd.Parameters.AddWithValue("@availability", string.IsNullOrWhiteSpace(availability) ? "unknown" : availability);
                updateCmd.Parameters.AddWithValue("@id", existingId.Value);
                await updateCmd.ExecuteNonQueryAsync(ct);
            }
        }

        if (body.Components is not null)
        {
            foreach (var component in body.Components)
            {
                if (component.ChildPartId <= 0)
                {
                    await tx.RollbackAsync(ct);
                    return Results.BadRequest(new { error = "invalid_child" });
                }

                if (component.Qty <= 0)
                {
                    await tx.RollbackAsync(ct);
                    return Results.BadRequest(new { error = "invalid_qty", child_part_id = component.ChildPartId });
                }

                const string upsertComponentSql = @"INSERT INTO PartComponent(parent_part_id, child_part_id, qty_per_parent)
                                                    VALUES(@parent, @child, @qty)
                                                    ON DUPLICATE KEY UPDATE qty_per_parent = VALUES(qty_per_parent)";

                await using (var upsertCmd = new MySqlCommand(upsertComponentSql, conn, tx))
                {
                    upsertCmd.Parameters.AddWithValue("@parent", partId);
                    upsertCmd.Parameters.AddWithValue("@child", component.ChildPartId);
                    upsertCmd.Parameters.AddWithValue("@qty", component.Qty);
                    await upsertCmd.ExecuteNonQueryAsync(ct);
                }

                if (component.Offering is not null)
                {
                    if (component.Offering.Price < 0)
                    {
                        await tx.RollbackAsync(ct);
                        return Results.BadRequest(new { error = "invalid_price", child_part_id = component.ChildPartId });
                    }

                    long vendorId;
                    if (component.Offering.VendorId.HasValue && component.Offering.VendorId.Value > 0)
                    {
                        vendorId = component.Offering.VendorId.Value;
                    }
                    else
                    {
                        vendorId = await EnsureVendorAsync(component.Offering.VendorName);
                        if (vendorId <= 0)
                        {
                            await tx.RollbackAsync(ct);
                            return Results.BadRequest(new { error = "missing_vendor", child_part_id = component.ChildPartId });
                        }
                    }

                    var currency = string.IsNullOrWhiteSpace(component.Offering.Currency) ? "USD" : component.Offering.Currency!.Trim();
                    var availability = string.IsNullOrWhiteSpace(component.Offering.Availability) ? "unknown" : component.Offering.Availability!.Trim();
                    await UpsertOfferingAsync(component.ChildPartId, vendorId, component.Offering.Price, currency, component.Offering.Url, availability);
                }
            }
        }

        if (body.KitOffering is not null)
        {
            if (body.KitOffering.Price < 0)
            {
                await tx.RollbackAsync(ct);
                return Results.BadRequest(new { error = "invalid_price" });
            }

            long vendorId;
            if (body.KitOffering.VendorId.HasValue && body.KitOffering.VendorId.Value > 0)
            {
                vendorId = body.KitOffering.VendorId.Value;
            }
            else
            {
                vendorId = await EnsureVendorAsync(string.IsNullOrWhiteSpace(body.KitOffering.VendorName) ? "Bundle (Virtual)" : body.KitOffering.VendorName);
                if (vendorId <= 0)
                {
                    await tx.RollbackAsync(ct);
                    return Results.BadRequest(new { error = "missing_vendor" });
                }
            }

            var currency = string.IsNullOrWhiteSpace(body.KitOffering.Currency) ? "USD" : body.KitOffering.Currency!.Trim();
            var availability = string.IsNullOrWhiteSpace(body.KitOffering.Availability) ? "in_stock" : body.KitOffering.Availability!.Trim();
            await UpsertOfferingAsync(partId, vendorId, body.KitOffering.Price, currency, body.KitOffering.Url, availability);
        }

        await tx.CommitAsync(ct);
        return Results.Json(new { ok = true });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Save kit editor failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: update kit component quantity
app.MapPatch("/api/admin/kits/{partId:long}/components", async (HttpContext ctx, long partId, AdminKitComponentPatchRequest body, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    if (body is null || body.ChildPartId <= 0 || body.QtyPerParent <= 0)
        return Results.BadRequest(new { error = "invalid_component" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        if (!await PartExistsAsync(conn, partId, ct))
            return Results.NotFound(new { error = "part_not_found" });

        if (!await PartIsKitAsync(conn, partId, ct))
            return Results.BadRequest(new { error = "not_a_kit" });

        const string sql = "UPDATE PartComponent SET qty_per_parent=@qty WHERE parent_part_id=@parent AND child_part_id=@child";
        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@qty", body.QtyPerParent);
        cmd.Parameters.AddWithValue("@parent", partId);
        cmd.Parameters.AddWithValue("@child", body.ChildPartId);
        var affected = await cmd.ExecuteNonQueryAsync(ct);

        if (affected == 0)
            return Results.NotFound(new { error = "component_not_found" });

        return Results.Json(new { ok = true });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Update component failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: add a component to a kit by sku or by creating a new part inline
app.MapPost("/api/admin/kits/{partId:long}/components/add-or-create", async (HttpContext ctx, long partId, AdminKitAddOrCreateComponentRequest body, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    if (body is null)
        return Results.BadRequest(new { error = "invalid_payload" });

    var qty = body.Qty.HasValue && body.Qty.Value > 0 ? body.Qty.Value : 1m;
    var hasChildSku = !string.IsNullOrWhiteSpace(body.ChildSku);
    var hasNewPart = body.NewPart is not null;

    if (!hasChildSku && !hasNewPart)
        return Results.BadRequest(new { error = "child_sku_or_new_part_required" });

    if (hasChildSku && hasNewPart)
        return Results.BadRequest(new { error = "ambiguous_payload" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        if (!await PartExistsAsync(conn, partId, ct))
            return Results.NotFound(new { error = "part_not_found" });

        if (!await PartIsKitAsync(conn, partId, ct))
            return Results.BadRequest(new { error = "target_not_a_kit" });

        await using var tx = await conn.BeginTransactionAsync(ct);
        try
        {
            long childPartId;

            if (hasChildSku)
            {
                var childSku = body.ChildSku!.Trim();
                const string childSql = "SELECT part_id FROM Part WHERE sku=@sku";
                await using (var childCmd = new MySqlCommand(childSql, conn, tx))
                {
                    childCmd.Parameters.AddWithValue("@sku", childSku);
                    var childObj = await childCmd.ExecuteScalarAsync(ct);
                    childPartId = childObj is null || childObj is DBNull ? 0 : Convert.ToInt64(childObj);
                }

                if (childPartId == 0)
                {
                    await tx.RollbackAsync(ct);
                    return Results.BadRequest(new { error = "unknown_child_sku", childSku = body.ChildSku!.Trim() });
                }

                if (childPartId == partId)
                {
                    await tx.RollbackAsync(ct);
                    return Results.BadRequest(new { error = "self_reference" });
                }
            }
            else
            {
                var payload = body.NewPart!;
                var sku = payload.Sku?.Trim();
                var name = payload.Name?.Trim();
                var categorySlug = payload.CategorySlug?.Trim().ToLowerInvariant();

                if (string.IsNullOrWhiteSpace(sku) || string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(categorySlug))
                {
                    await tx.RollbackAsync(ct);
                    return Results.BadRequest(new { error = "missing_fields" });
                }

                var brandName = string.IsNullOrWhiteSpace(payload.BrandName) ? "Generic" : payload.BrandName!.Trim();
                var status = string.IsNullOrWhiteSpace(payload.Status) ? "active" : payload.Status!.Trim().ToLowerInvariant();
                var uom = string.IsNullOrWhiteSpace(payload.Uom) ? "each" : payload.Uom!.Trim();
                var piecesPerUnit = payload.PiecesPerUnit.HasValue && payload.PiecesPerUnit.Value > 0 ? payload.PiecesPerUnit.Value : 1m;

                if (payload.Offering is not null && (payload.Offering.Price is null || payload.Offering.Price < 0))
                {
                    await tx.RollbackAsync(ct);
                    return Results.BadRequest(new { error = "invalid_offering_price" });
                }

                long? categoryId = null;
                bool isLeaf = false;
                const string categorySql = "SELECT category_id, is_selectable FROM Category WHERE slug=@slug";
                await using (var categoryCmd = new MySqlCommand(categorySql, conn, tx))
                {
                    categoryCmd.Parameters.AddWithValue("@slug", categorySlug);
                    await using var reader = await categoryCmd.ExecuteReaderAsync(ct);
                    if (await reader.ReadAsync(ct))
                    {
                        categoryId = reader.IsDBNull(0) ? null : reader.GetInt64(0);
                        isLeaf = !reader.IsDBNull(1) && reader.GetBoolean(1);
                    }
                }

                if (categoryId is null || !isLeaf)
                {
                    await tx.RollbackAsync(ct);
                    return Results.BadRequest(new { error = "not_leaf_or_unknown_category" });
                }

                long? brandId = null;
                if (!string.IsNullOrWhiteSpace(brandName))
                {
                    const string brandUpsertSql = "INSERT INTO Brand(name) VALUES(@name) ON DUPLICATE KEY UPDATE name=VALUES(name)";
                    await using (var brandCmd = new MySqlCommand(brandUpsertSql, conn, tx))
                    {
                        brandCmd.Parameters.AddWithValue("@name", brandName);
                        await brandCmd.ExecuteNonQueryAsync(ct);
                    }

                    const string brandIdSql = "SELECT brand_id FROM Brand WHERE name=@name";
                    await using (var brandIdCmd = new MySqlCommand(brandIdSql, conn, tx))
                    {
                        brandIdCmd.Parameters.AddWithValue("@name", brandName);
                        var brandObj = await brandIdCmd.ExecuteScalarAsync(ct);
                        if (brandObj is not null && brandObj is not DBNull)
                            brandId = Convert.ToInt64(brandObj);
                    }
                }

                const string partUpsertSql = @"INSERT INTO Part (sku, name, brand_id, is_kit, uom, pieces_per_unit, status)
                                               VALUES (@sku, @name, @brand, FALSE, @uom, @ppu, @status)
                                               ON DUPLICATE KEY UPDATE
                                                 name=VALUES(name),
                                                 brand_id=VALUES(brand_id),
                                                 uom=VALUES(uom),
                                                 pieces_per_unit=VALUES(pieces_per_unit),
                                                 status=VALUES(status)";

                await using (var partCmd = new MySqlCommand(partUpsertSql, conn, tx))
                {
                    partCmd.Parameters.AddWithValue("@sku", sku);
                    partCmd.Parameters.AddWithValue("@name", name);
                    partCmd.Parameters.AddWithValue("@brand", brandId.HasValue ? brandId.Value : (object)DBNull.Value);
                    partCmd.Parameters.AddWithValue("@uom", uom);
                    partCmd.Parameters.AddWithValue("@ppu", piecesPerUnit);
                    partCmd.Parameters.AddWithValue("@status", status);
                    await partCmd.ExecuteNonQueryAsync(ct);
                }

                const string partIdSql = "SELECT part_id FROM Part WHERE sku=@sku";
                await using (var partIdCmd = new MySqlCommand(partIdSql, conn, tx))
                {
                    partIdCmd.Parameters.AddWithValue("@sku", sku);
                    var partObj = await partIdCmd.ExecuteScalarAsync(ct);
                    childPartId = partObj is null || partObj is DBNull ? 0 : Convert.ToInt64(partObj);
                }

                if (childPartId == 0)
                {
                    await tx.RollbackAsync(ct);
                    return Results.Problem(title: "Create part failed", detail: "Could not resolve part id", statusCode: 500);
                }

                if (childPartId == partId)
                {
                    await tx.RollbackAsync(ct);
                    return Results.BadRequest(new { error = "self_reference" });
                }

                const string categoryInsertSql = @"INSERT INTO PartCategory (part_id, category_id, is_primary, coverage_weight, display_order)
                                                   VALUES (@part, @category, TRUE, 1, 0)
                                                   ON DUPLICATE KEY UPDATE
                                                     is_primary=TRUE,
                                                     coverage_weight=1,
                                                     display_order=0";
                await using (var categoryInsert = new MySqlCommand(categoryInsertSql, conn, tx))
                {
                    categoryInsert.Parameters.AddWithValue("@part", childPartId);
                    categoryInsert.Parameters.AddWithValue("@category", categoryId.Value);
                    await categoryInsert.ExecuteNonQueryAsync(ct);
                }

                if (payload.Offering is not null && payload.Offering.Price is not null)
                {
                    var vendorName = string.IsNullOrWhiteSpace(payload.Offering.VendorName) ? "Unknown Vendor" : payload.Offering.VendorName!.Trim();
                    var price = payload.Offering.Price.Value;
                    var currency = string.IsNullOrWhiteSpace(payload.Offering.Currency) ? "USD" : payload.Offering.Currency!.Trim().ToUpperInvariant();
                    var url = string.IsNullOrWhiteSpace(payload.Offering.Url) ? null : payload.Offering.Url!.Trim();

                    const string vendorUpsertSql = "INSERT INTO Vendor(name) VALUES(@name) ON DUPLICATE KEY UPDATE name=VALUES(name)";
                    await using (var vendorCmd = new MySqlCommand(vendorUpsertSql, conn, tx))
                    {
                        vendorCmd.Parameters.AddWithValue("@name", vendorName);
                        await vendorCmd.ExecuteNonQueryAsync(ct);
                    }

                    long vendorId;
                    const string vendorIdSql = "SELECT vendor_id FROM Vendor WHERE name=@name";
                    await using (var vendorIdCmd = new MySqlCommand(vendorIdSql, conn, tx))
                    {
                        vendorIdCmd.Parameters.AddWithValue("@name", vendorName);
                        var vendorObj = await vendorIdCmd.ExecuteScalarAsync(ct);
                        vendorId = vendorObj is null || vendorObj is DBNull ? 0 : Convert.ToInt64(vendorObj);
                    }

                    if (vendorId == 0)
                    {
                        await tx.RollbackAsync(ct);
                        return Results.Problem(title: "Create part failed", detail: "Could not resolve vendor id", statusCode: 500);
                    }

                    const string offeringInsertSql = @"INSERT INTO PartOffering (part_id, vendor_id, price, currency, url, availability, effective_from)
                                                       VALUES (@part, @vendor, @price, @currency, @url, 'in_stock', NOW())";
                    await using (var offeringCmd = new MySqlCommand(offeringInsertSql, conn, tx))
                    {
                        offeringCmd.Parameters.AddWithValue("@part", childPartId);
                        offeringCmd.Parameters.AddWithValue("@vendor", vendorId);
                        offeringCmd.Parameters.AddWithValue("@price", price);
                        offeringCmd.Parameters.AddWithValue("@currency", currency);
                        offeringCmd.Parameters.AddWithValue("@url", (object?)url ?? DBNull.Value);
                        await offeringCmd.ExecuteNonQueryAsync(ct);
                    }
                }
            }

            const string componentUpsertSql = @"INSERT INTO PartComponent (parent_part_id, child_part_id, qty_per_parent)
                                                VALUES (@parent, @child, @qty)
                                                ON DUPLICATE KEY UPDATE qty_per_parent=VALUES(qty_per_parent)";
            await using (var componentCmd = new MySqlCommand(componentUpsertSql, conn, tx))
            {
                componentCmd.Parameters.AddWithValue("@parent", partId);
                componentCmd.Parameters.AddWithValue("@child", childPartId);
                componentCmd.Parameters.AddWithValue("@qty", qty);
                await componentCmd.ExecuteNonQueryAsync(ct);
            }

            await tx.CommitAsync(ct);
            return Results.Json(new { ok = true, child_part_id = childPartId, qty });
        }
        catch
        {
            await tx.RollbackAsync(ct);
            throw;
        }
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Add component failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: bulk add/merge kit components
app.MapPost("/api/admin/kits/{partId:long}/components/bulk", async (HttpContext ctx, long partId, AdminKitComponentBulkRequest body, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    if (body?.Lines is null || body.Lines.Count == 0)
        return Results.BadRequest(new { error = "no_lines" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        if (!await PartExistsAsync(conn, partId, ct))
            return Results.NotFound(new { error = "part_not_found" });

        if (!await PartIsKitAsync(conn, partId, ct))
            return Results.BadRequest(new { error = "not_a_kit" });

        await using var tx = await conn.BeginTransactionAsync(ct);

        var inserted = 0;
        var missing = new List<string>();

        foreach (var line in body.Lines)
        {
            var currentLine = line;
            if (currentLine is null)
                continue;
            var sku = currentLine.ChildSku?.Trim();
            if (string.IsNullOrWhiteSpace(sku) || currentLine.Qty <= 0)
                continue;

            long? childId;
            await using (var lookup = new MySqlCommand("SELECT part_id FROM Part WHERE sku=@sku", conn, tx))
            {
                lookup.Parameters.AddWithValue("@sku", sku);
                var result = await lookup.ExecuteScalarAsync(ct);
                childId = result is null ? null : Convert.ToInt64(result);
            }

            if (childId is null)
            {
                missing.Add(sku);
                continue;
            }

            const string upsert = @"INSERT INTO PartComponent(parent_part_id, child_part_id, qty_per_parent)
                                   VALUES(@parent, @child, @qty)
                                   ON DUPLICATE KEY UPDATE qty_per_parent = VALUES(qty_per_parent)";

            await using var upsertCmd = new MySqlCommand(upsert, conn, tx);
            upsertCmd.Parameters.AddWithValue("@parent", partId);
            upsertCmd.Parameters.AddWithValue("@child", childId.Value);
            upsertCmd.Parameters.AddWithValue("@qty", currentLine.Qty);
            await upsertCmd.ExecuteNonQueryAsync(ct);
            inserted++;
        }

        await tx.CommitAsync(ct);

        return Results.Json(new { ok = true, added = inserted, missing });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Bulk add components failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: delete kit component via kit route
app.MapDelete("/api/admin/kits/{partId:long}/components/{childPartId:long}", async (HttpContext ctx, long partId, long childPartId, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        const string sql = "DELETE FROM PartComponent WHERE parent_part_id=@parent AND child_part_id=@child";
        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@parent", partId);
        cmd.Parameters.AddWithValue("@child", childPartId);
        await cmd.ExecuteNonQueryAsync(ct);

        return Results.Json(new { ok = true });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Delete component failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: roll-up kit pricing summary
app.MapGet("/api/admin/kits/{partId:long}/rollup", async (HttpContext ctx, long partId, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        if (!await PartExistsAsync(conn, partId, ct))
            return Results.NotFound(new { error = "part_not_found" });

        const string sql = @"SELECT pc.child_part_id, p.sku, p.name, pc.qty_per_parent,
                                     bo.best_price
                              FROM PartComponent pc
                              JOIN Part p ON p.part_id = pc.child_part_id
                              LEFT JOIN v_part_best_offering bo ON bo.part_id = pc.child_part_id
                              WHERE pc.parent_part_id = @parent";

        var items = new List<Dictionary<string, object?>>();
        decimal total = 0m;

        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@parent", partId);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var qty = reader.IsDBNull(3) ? 0m : Convert.ToDecimal(reader.GetValue(3));
            var bestPrice = reader.IsDBNull(4) ? (decimal?)null : Convert.ToDecimal(reader.GetValue(4));
            var subtotal = qty * (bestPrice ?? 0m);
            total += subtotal;

            var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
            {
                ["child_part_id"] = reader.GetInt64(0),
                ["sku"] = reader.IsDBNull(1) ? null : reader.GetString(1),
                ["name"] = reader.IsDBNull(2) ? null : reader.GetString(2),
                ["qty_per_parent"] = qty,
                ["best_price"] = bestPrice,
                ["subtotal"] = subtotal
            };
            items.Add(row);
        }

        return Results.Json(new { items, total });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Roll-up pricing failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: sync kit offering from roll-up total
app.MapPost("/api/admin/kits/{partId:long}/price/sync", async (HttpContext ctx, long partId, AdminKitPriceSyncRequest body, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        if (!await PartExistsAsync(conn, partId, ct))
            return Results.NotFound(new { error = "part_not_found" });

        if (!await PartIsKitAsync(conn, partId, ct))
            return Results.BadRequest(new { error = "not_a_kit" });

        const string totalSql = @"SELECT COALESCE(SUM(pc.qty_per_parent * bo.best_price), 0)
                                   FROM PartComponent pc
                                   LEFT JOIN v_part_best_offering bo ON bo.part_id = pc.child_part_id
                                   WHERE pc.parent_part_id = @parent";

        await using var totalCmd = new MySqlCommand(totalSql, conn);
        totalCmd.Parameters.AddWithValue("@parent", partId);
        var totalObj = await totalCmd.ExecuteScalarAsync(ct);
        var total = totalObj is null || totalObj == DBNull.Value ? 0m : Convert.ToDecimal(totalObj);

        var margin = body?.MarginPct ?? 0m;
        var round = body?.Round ?? 0m;
        var vendorName = string.IsNullOrWhiteSpace(body?.VendorName) ? "Bundle (Virtual)" : body!.VendorName!.Trim();

        var price = total * (1m + margin);
        if (round > 0m)
        {
            price = Math.Ceiling(price / round) * round;
        }

        const string vendorUpsert = "INSERT INTO Vendor(name) VALUES(@name) ON DUPLICATE KEY UPDATE name=VALUES(name)";
        await using (var vendorCmd = new MySqlCommand(vendorUpsert, conn))
        {
            vendorCmd.Parameters.AddWithValue("@name", vendorName);
            await vendorCmd.ExecuteNonQueryAsync(ct);
        }

        long vendorId;
        await using (var idCmd = new MySqlCommand("SELECT vendor_id FROM Vendor WHERE name=@name", conn))
        {
            idCmd.Parameters.AddWithValue("@name", vendorName);
            var idObj = await idCmd.ExecuteScalarAsync(ct);
            vendorId = idObj is null ? 0 : Convert.ToInt64(idObj);
        }

        const string insertOffering = @"INSERT INTO PartOffering(part_id, vendor_id, price, currency, url, availability, effective_from)
                                       VALUES(@part, @vendor, @price, 'USD', NULL, 'in_stock', NOW())";

        await using (var offeringCmd = new MySqlCommand(insertOffering, conn))
        {
            offeringCmd.Parameters.AddWithValue("@part", partId);
            offeringCmd.Parameters.AddWithValue("@vendor", vendorId);
            offeringCmd.Parameters.AddWithValue("@price", price);
            await offeringCmd.ExecuteNonQueryAsync(ct);
        }

        return Results.Json(new { rollup = total, synced_price = price, vendor_id = vendorId });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Price sync failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: validate kit structure
app.MapGet("/api/admin/kits/{partId:long}/validate", async (HttpContext ctx, long partId, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        if (!await PartExistsAsync(conn, partId, ct))
            return Results.NotFound(new { error = "part_not_found" });

        var errors = new List<string>();

        const string countSql = "SELECT COUNT(*) FROM PartComponent WHERE parent_part_id=@parent";
        await using (var cntCmd = new MySqlCommand(countSql, conn))
        {
            cntCmd.Parameters.AddWithValue("@parent", partId);
            var cntObj = await cntCmd.ExecuteScalarAsync(ct);
            var count = cntObj is null ? 0 : Convert.ToInt32(cntObj);
            if (count == 0)
            {
                errors.Add("Kit has no components.");
            }
        }

        const string cycleSql = @"WITH RECURSIVE bom(parent, child, depth, path) AS (
                                      SELECT parent_part_id, child_part_id, 1, CONCAT('/', parent_part_id, '/')
                                      FROM PartComponent
                                      WHERE parent_part_id = @root
                                    UNION ALL
                                      SELECT b.child, pc.child_part_id, b.depth + 1, CONCAT(b.path, pc.child_part_id, '/')
                                      FROM bom b
                                      JOIN PartComponent pc ON pc.parent_part_id = b.child
                                      WHERE b.depth < 10 AND b.path NOT LIKE CONCAT('%/', pc.child_part_id, '/%')
                                  )
                                  SELECT COUNT(*)
                                  FROM bom
                                  WHERE child = @root";

        await using (var cycleCmd = new MySqlCommand(cycleSql, conn))
        {
            cycleCmd.Parameters.AddWithValue("@root", partId);
            var cycleObj = await cycleCmd.ExecuteScalarAsync(ct);
            var cycleCount = cycleObj is null ? 0 : Convert.ToInt32(cycleObj);
            if (cycleCount > 0)
            {
                errors.Add("Cycle detected in BOM.");
            }
        }

        const string unmappedSql = @"SELECT p.sku
                                      FROM PartComponent pc
                                      JOIN Part p ON p.part_id = pc.child_part_id
                                      LEFT JOIN PartCategory map ON map.part_id = p.part_id
                                      WHERE pc.parent_part_id = @parent
                                      GROUP BY p.sku
                                      HAVING COUNT(map.category_id) = 0";

        var missingCategories = new List<string>();
        await using (var unmappedCmd = new MySqlCommand(unmappedSql, conn))
        {
            unmappedCmd.Parameters.AddWithValue("@parent", partId);
            await using var reader = await unmappedCmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                if (!reader.IsDBNull(0))
                    missingCategories.Add(reader.GetString(0));
            }
        }

        if (missingCategories.Count > 0)
        {
            errors.Add($"Children missing categories: {string.Join(", ", missingCategories)}");
        }

        return Results.Json(new { ok = errors.Count == 0, errors });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Kit validation failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: check if part can be deleted
app.MapGet("/api/admin/parts/{partId:long}/can-delete", async (HttpContext ctx, long partId, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        if (!await PartExistsAsync(conn, partId, ct))
            return Results.NotFound(new { error = "part_not_found" });

        const string sql = @"SELECT
                                  (SELECT COUNT(*) FROM BuildSelection WHERE part_id = @partId) AS InBuilds,
                                  (SELECT COUNT(*) FROM PartComponent WHERE child_part_id = @partId) AS UsedAsChildInKits,
                                  (SELECT COUNT(*) FROM PartComponent WHERE parent_part_id = @partId) AS BomChildren,
                                  (SELECT COUNT(*) FROM PartCategory WHERE part_id = @partId) AS Categories,
                                  (SELECT COUNT(*) FROM PartFitment WHERE part_id = @partId) AS Fitment,
                                  (SELECT COUNT(*) FROM PartOffering WHERE part_id = @partId) AS Offerings,
                                  (SELECT IFNULL(is_kit, 0) FROM Part WHERE part_id = @partId) AS IsKit";

        var stats = await conn.QuerySingleAsync(sql, new { partId });

        static int ToInt(object? value) => value is null || value is DBNull ? 0 : Convert.ToInt32(value);
        static bool ToBool(object? value) => value is null || value is DBNull ? false : Convert.ToBoolean(value);

        var inBuilds = ToInt(stats.InBuilds);
        var usedAsChild = ToInt(stats.UsedAsChildInKits);
        var response = new AdminPartDeleteProbeResponse
        {
            Deletable = inBuilds == 0 && usedAsChild == 0,
            Blockers = new AdminPartDeleteBlockers
            {
                InBuilds = inBuilds,
                UsedAsChildInKits = usedAsChild
            },
            Info = new AdminPartDeleteInfo
            {
                IsKit = ToBool(stats.IsKit),
                BomChildren = ToInt(stats.BomChildren),
                Categories = ToInt(stats.Categories),
                Fitment = ToInt(stats.Fitment),
                Offerings = ToInt(stats.Offerings)
            }
        };

        return Results.Json(response);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Probe failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: soft delete (mark discontinued)
app.MapPost("/api/admin/parts/{partId:long}/soft-delete", async (HttpContext ctx, long partId, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        if (!await PartExistsAsync(conn, partId, ct))
            return Results.NotFound(new { error = "part_not_found" });

        const string sql = "UPDATE Part SET status='discontinued', updated_at=NOW() WHERE part_id=@id";
        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@id", partId);
        await cmd.ExecuteNonQueryAsync(ct);

        return Results.Json(new { ok = true });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Soft delete failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: hard delete part
app.MapDelete("/api/admin/parts/{partId:long}", async (HttpContext ctx, long partId, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        if (!await PartExistsAsync(conn, partId, ct))
            return Results.NotFound(new { error = "part_not_found" });

        await using var tx = await conn.BeginTransactionAsync(ct);

        async Task<int> CountAsync(string sql)
        {
            await using var cmd = new MySqlCommand(sql, conn, tx);
            cmd.Parameters.AddWithValue("@id", partId);
            var result = await cmd.ExecuteScalarAsync(ct);
            return result is null || result is DBNull ? 0 : Convert.ToInt32(result);
        }

        var blockersInBuilds = await CountAsync("SELECT COUNT(*) FROM BuildSelection WHERE part_id=@id");
        var blockersAsChild = await CountAsync("SELECT COUNT(*) FROM PartComponent WHERE child_part_id=@id");

        if (blockersInBuilds > 0 || blockersAsChild > 0)
        {
            await tx.RollbackAsync(ct);
            return Results.Json(new
            {
                error = "cannot_delete",
                message = $"Part is referenced (in builds: {blockersInBuilds}, used in kits: {blockersAsChild})."
            }, statusCode: StatusCodes.Status409Conflict);
        }

        const string deleteSql = "DELETE FROM Part WHERE part_id=@id";
        await using (var deleteCmd = new MySqlCommand(deleteSql, conn, tx))
        {
            deleteCmd.Parameters.AddWithValue("@id", partId);
            await deleteCmd.ExecuteNonQueryAsync(ct);
        }

        await tx.CommitAsync(ct);
        return Results.Json(new { ok = true });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Delete failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: list categories with optional search
app.MapGet("/api/admin/categories", async (HttpContext ctx, string? q, bool leafOnly = false, int page = 1, int pageSize = 100, CancellationToken ct = default) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    var search = string.IsNullOrWhiteSpace(q) ? null : q.Trim();
    var pageNumber = Math.Max(1, page);
    var limit = Math.Clamp(pageSize, 1, 500);
    var offset = (pageNumber - 1) * limit;

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        const string sql = @"SELECT category_id, name, slug, is_selectable, description
                              FROM Category
                              WHERE (@q IS NULL OR name LIKE CONCAT('%', @q, '%') OR slug LIKE CONCAT('%', @q, '%'))
                                AND (@leaf = 0 OR is_selectable = 1)
                              ORDER BY is_selectable DESC, name
                              LIMIT @limit OFFSET @offset";

        var rows = new List<Dictionary<string, object?>>();
        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@q", (object?)search ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@leaf", leafOnly ? 1 : 0);
        cmd.Parameters.AddWithValue("@limit", limit);
        cmd.Parameters.AddWithValue("@offset", offset);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
            {
                ["category_id"] = reader.GetInt64(0),
                ["name"] = reader.GetString(1),
                ["slug"] = reader.IsDBNull(2) ? null : reader.GetString(2),
                ["is_selectable"] = !reader.IsDBNull(3) && reader.GetBoolean(3),
                ["description"] = reader.IsDBNull(4) ? null : reader.GetString(4)
            };
            rows.Add(row);
        }

        return Results.Json(rows);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Fetch categories failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: create or upsert a category
app.MapPost("/api/admin/categories", async (HttpContext ctx, AdminCategoryCreateRequest body, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    if (body is null)
        return Results.BadRequest(new { error = "invalid_payload" });

    var name = body.Name?.Trim();
    if (string.IsNullOrWhiteSpace(name))
        return Results.BadRequest(new { error = "name_required" });

    var slugSource = string.IsNullOrWhiteSpace(body.Slug) ? name : body.Slug!;
    var slug = Regex.Replace(slugSource.Trim().ToLowerInvariant(), "[^a-z0-9]+", "-").Trim('-');
    if (string.IsNullOrWhiteSpace(slug))
        return Results.BadRequest(new { error = "slug_required" });

    var description = string.IsNullOrWhiteSpace(body.Description) ? null : body.Description!.Trim();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        await using (var insert = new MySqlCommand(@"INSERT INTO Category(name, slug, is_selectable, description)
                                                   VALUES(@name, @slug, @selectable, @desc)
                                                   ON DUPLICATE KEY UPDATE name=VALUES(name), is_selectable=VALUES(is_selectable), description=VALUES(description)", conn))
        {
            insert.Parameters.AddWithValue("@name", name);
            insert.Parameters.AddWithValue("@slug", slug);
            insert.Parameters.AddWithValue("@selectable", body.IsSelectable);
            insert.Parameters.AddWithValue("@desc", (object?)description ?? DBNull.Value);
            await insert.ExecuteNonQueryAsync(ct);
        }

        long categoryId;
        await using (var fetch = new MySqlCommand("SELECT category_id FROM Category WHERE slug=@slug", conn))
        {
            fetch.Parameters.AddWithValue("@slug", slug);
            var result = await fetch.ExecuteScalarAsync(ct);
            categoryId = result is null ? 0 : Convert.ToInt64(result);
        }

        if (categoryId <= 0)
            return Results.Problem(title: "Create category failed", detail: "Could not determine category id", statusCode: 500);

        return Results.Created($"/api/admin/categories/{categoryId}", new { category_id = categoryId });
    }
    catch (MySqlException ex) when (ex.Number == 1062)
    {
        return Results.Conflict(new { error = "slug_exists" });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Create category failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: update category metadata
app.MapPatch("/api/admin/categories/{categoryId:long}", async (long categoryId, HttpContext ctx, AdminCategoryUpdateRequest body, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    if (body is null)
        return Results.BadRequest(new { error = "invalid_payload" });

    var updates = new List<string>();
    var parameters = new Dictionary<string, object?>
    {
        ["@id"] = categoryId
    };

    if (!string.IsNullOrWhiteSpace(body.Name))
    {
        updates.Add("name=@name");
        parameters["@name"] = body.Name.Trim();
    }

    if (!string.IsNullOrWhiteSpace(body.Slug))
    {
        var slug = Regex.Replace(body.Slug.Trim().ToLowerInvariant(), "[^a-z0-9]+", "-").Trim('-');
        if (string.IsNullOrWhiteSpace(slug))
            return Results.BadRequest(new { error = "slug_required" });
        updates.Add("slug=@slug");
        parameters["@slug"] = slug;
    }

    if (body.IsSelectable.HasValue)
    {
        updates.Add("is_selectable=@selectable");
        parameters["@selectable"] = body.IsSelectable.Value;
    }

    if (body.Description is not null)
    {
        updates.Add("description=@description");
        parameters["@description"] = string.IsNullOrWhiteSpace(body.Description) ? (object)DBNull.Value : body.Description.Trim();
    }

    if (updates.Count == 0)
        return Results.BadRequest(new { error = "no_fields" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        await using var cmd = new MySqlCommand($"UPDATE Category SET {string.Join(",", updates)} WHERE category_id=@id", conn);
        foreach (var kvp in parameters)
        {
            cmd.Parameters.AddWithValue(kvp.Key, kvp.Value ?? DBNull.Value);
        }

        var affected = await cmd.ExecuteNonQueryAsync(ct);
        if (affected == 0)
            return Results.NotFound(new { error = "category_not_found" });

        return Results.Json(new { ok = true });
    }
    catch (MySqlException ex) when (ex.Number == 1062)
    {
        return Results.Conflict(new { error = "slug_exists" });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Update category failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: delete a category if unused
app.MapDelete("/api/admin/categories/{categoryId:long}", async (long categoryId, HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        async Task<bool> ExistsAsync(string sql)
        {
            await using var cmd = new MySqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@id", categoryId);
            var result = await cmd.ExecuteScalarAsync(ct);
            return result is not null && Convert.ToInt64(result) > 0;
        }

        if (await ExistsAsync("SELECT EXISTS(SELECT 1 FROM PartCategory WHERE category_id=@id)"))
            return Results.Conflict(new { error = "in_use", message = "Category has parts assigned." });

        if (await ExistsAsync("SELECT EXISTS(SELECT 1 FROM CategoryEdge WHERE parent_category_id=@id OR child_category_id=@id)"))
            return Results.Conflict(new { error = "linked", message = "Remove category from trees before deleting." });

        await using var delete = new MySqlCommand("DELETE FROM Category WHERE category_id=@id", conn);
        delete.Parameters.AddWithValue("@id", categoryId);
        var rows = await delete.ExecuteNonQueryAsync(ct);
        if (rows == 0)
            return Results.NotFound(new { error = "category_not_found" });

        return Results.Json(new { ok = true });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Delete category failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: create a category tree
app.MapPost("/api/admin/trees", async (HttpContext ctx, AdminTreeCreateRequest body, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    if (body is null)
        return Results.BadRequest(new { error = "invalid_payload" });

    var name = body.Name?.Trim();
    if (string.IsNullOrWhiteSpace(name))
        return Results.BadRequest(new { error = "name_required" });

    var description = string.IsNullOrWhiteSpace(body.Description) ? null : body.Description.Trim();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureEngineFamilyTreeSchemaAsync(conn, ct);

        long treeId;
        await using (var cmd = new MySqlCommand("INSERT INTO CategoryTree(name, description) VALUES(@name, @desc); SELECT LAST_INSERT_ID();", conn))
        {
            cmd.Parameters.AddWithValue("@name", name);
            cmd.Parameters.AddWithValue("@desc", (object?)description ?? DBNull.Value);
            try
            {
                var scalar = await cmd.ExecuteScalarAsync(ct);
                treeId = Convert.ToInt64(scalar);
            }
            catch (MySqlException ex) when (ex.Number == 1062)
            {
                return Results.Conflict(new { error = "tree_name_exists" });
            }
        }

        return Results.Json(new { ok = true, tree_id = treeId, name, description });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Create tree failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: list engine families for tree mapping / pickers
app.MapGet("/api/admin/engines", async (HttpContext ctx, string? q = null, int limit = 200, CancellationToken ct = default) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        var search = string.IsNullOrWhiteSpace(q) ? null : q.Trim();
        var take = Math.Clamp(limit, 1, 500);

        const string sql = @"SELECT engine_family_id, code, rotor_count
                              FROM EngineFamily
                              WHERE (@q IS NULL OR code LIKE CONCAT('%', @q, '%'))
                              ORDER BY code
                              LIMIT @limit";

        var rows = new List<Dictionary<string, object?>>();
        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@q", (object?)search ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@limit", take);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
            {
                ["engine_family_id"] = reader.GetInt64(0),
                ["code"] = reader.GetString(1),
                ["rotor_count"] = reader.IsDBNull(2) ? null : reader.GetValue(2)
            };
            rows.Add(row);
        }

        return Results.Json(rows);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Fetch engines failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: current engine mapping status for a tree
app.MapGet("/api/admin/trees/{treeId:long}/engines", async (long treeId, HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureEngineFamilyTreeSchemaAsync(conn, ct);

        await using (var treeCheck = new MySqlCommand("SELECT 1 FROM CategoryTree WHERE tree_id=@tree LIMIT 1", conn))
        {
            treeCheck.Parameters.AddWithValue("@tree", treeId);
            if (await treeCheck.ExecuteScalarAsync(ct) is null)
                return Results.NotFound(new { error = "tree_not_found" });
        }

        const string sql = @"SELECT ef.engine_family_id,
                                     ef.code,
                                     COALESCE(eft.is_default, 0) AS is_default,
                                     CASE WHEN eft.tree_id IS NULL THEN 0 ELSE 1 END AS attached
                              FROM EngineFamily ef
                              LEFT JOIN EngineFamilyTree eft
                                ON eft.engine_family_id = ef.engine_family_id
                               AND eft.tree_id = @tree
                              ORDER BY ef.code";

        var rows = new List<Dictionary<string, object?>>();
        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@tree", treeId);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
            {
                ["engine_family_id"] = reader.GetInt64(0),
                ["code"] = reader.GetString(1),
                ["is_default"] = !reader.IsDBNull(2) && reader.GetBoolean(2),
                ["attached"] = reader.GetInt32(3) != 0
            };
            rows.Add(row);
        }

        return Results.Json(rows);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Fetch tree engines failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: attach or detach an engine family from a tree
app.MapPost("/api/admin/trees/{treeId:long}/engines/toggle", async (long treeId, HttpContext ctx, AdminTreeEngineToggleRequest body, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    if (body is null)
        return Results.BadRequest(new { error = "invalid_payload" });

    if (body.EngineFamilyId <= 0)
        return Results.BadRequest(new { error = "engine_family_id_required" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureEngineFamilyTreeSchemaAsync(conn, ct);

        await using (var treeCheck = new MySqlCommand("SELECT 1 FROM CategoryTree WHERE tree_id=@tree LIMIT 1", conn))
        {
            treeCheck.Parameters.AddWithValue("@tree", treeId);
            if (await treeCheck.ExecuteScalarAsync(ct) is null)
                return Results.NotFound(new { error = "tree_not_found" });
        }

        await using (var engineCheck = new MySqlCommand("SELECT 1 FROM EngineFamily WHERE engine_family_id=@ef LIMIT 1", conn))
        {
            engineCheck.Parameters.AddWithValue("@ef", body.EngineFamilyId);
            if (await engineCheck.ExecuteScalarAsync(ct) is null)
                return Results.NotFound(new { error = "engine_not_found" });
        }

        if (body.Attach)
        {
            await using var insert = new MySqlCommand("INSERT IGNORE INTO EngineFamilyTree (engine_family_id, tree_id, is_default) VALUES (@ef, @tree, FALSE)", conn);
            insert.Parameters.AddWithValue("@ef", body.EngineFamilyId);
            insert.Parameters.AddWithValue("@tree", treeId);
            await insert.ExecuteNonQueryAsync(ct);
        }
        else
        {
            await using var delete = new MySqlCommand("DELETE FROM EngineFamilyTree WHERE engine_family_id=@ef AND tree_id=@tree", conn);
            delete.Parameters.AddWithValue("@ef", body.EngineFamilyId);
            delete.Parameters.AddWithValue("@tree", treeId);
            await delete.ExecuteNonQueryAsync(ct);
        }

        return Results.Json(new { ok = true });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Update engine mapping failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: set default tree for an engine family
app.MapPost("/api/admin/trees/{treeId:long}/engines/default", async (long treeId, HttpContext ctx, AdminTreeEngineDefaultRequest body, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    if (body is null)
        return Results.BadRequest(new { error = "invalid_payload" });

    if (body.EngineFamilyId <= 0)
        return Results.BadRequest(new { error = "engine_family_id_required" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureEngineFamilyTreeSchemaAsync(conn, ct);

        await using (var treeCheck = new MySqlCommand("SELECT 1 FROM CategoryTree WHERE tree_id=@tree LIMIT 1", conn))
        {
            treeCheck.Parameters.AddWithValue("@tree", treeId);
            if (await treeCheck.ExecuteScalarAsync(ct) is null)
                return Results.NotFound(new { error = "tree_not_found" });
        }

        await using (var engineCheck = new MySqlCommand("SELECT 1 FROM EngineFamily WHERE engine_family_id=@ef LIMIT 1", conn))
        {
            engineCheck.Parameters.AddWithValue("@ef", body.EngineFamilyId);
            if (await engineCheck.ExecuteScalarAsync(ct) is null)
                return Results.NotFound(new { error = "engine_not_found" });
        }

        await using var tx = await conn.BeginTransactionAsync(ct);
        try
        {
            await using (var reset = new MySqlCommand("UPDATE EngineFamilyTree SET is_default=FALSE WHERE engine_family_id=@ef", conn, (MySqlTransaction)tx))
            {
                reset.Parameters.AddWithValue("@ef", body.EngineFamilyId);
                await reset.ExecuteNonQueryAsync(ct);
            }

            await using (var upsert = new MySqlCommand(@"INSERT INTO EngineFamilyTree (engine_family_id, tree_id, is_default)
                                                        VALUES (@ef, @tree, TRUE)
                                                        ON DUPLICATE KEY UPDATE is_default=VALUES(is_default)", conn, (MySqlTransaction)tx))
            {
                upsert.Parameters.AddWithValue("@ef", body.EngineFamilyId);
                upsert.Parameters.AddWithValue("@tree", treeId);
                await upsert.ExecuteNonQueryAsync(ct);
            }

            await tx.CommitAsync(ct);
        }
        catch
        {
            await tx.RollbackAsync(ct);
            throw;
        }

        return Results.Json(new { ok = true });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Set default tree failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: batch set defaults for multiple engine families
app.MapPost("/api/admin/trees/{treeId:long}/engines/default/batch", async (long treeId, HttpContext ctx, AdminTreeEngineDefaultBatchRequest body, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    var ids = body?.EngineFamilyIds?.Where(id => id > 0).Distinct().ToArray() ?? Array.Empty<long>();
    if (ids.Length == 0)
        return Results.BadRequest(new { error = "no_engine_ids" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureEngineFamilyTreeSchemaAsync(conn, ct);

        await using (var treeCheck = new MySqlCommand("SELECT 1 FROM CategoryTree WHERE tree_id=@tree LIMIT 1", conn))
        {
            treeCheck.Parameters.AddWithValue("@tree", treeId);
            if (await treeCheck.ExecuteScalarAsync(ct) is null)
                return Results.NotFound(new { error = "tree_not_found" });
        }

        var missing = new List<long>();
        var defaultsSet = 0;

        await using var tx = await conn.BeginTransactionAsync(ct);
        try
        {
            foreach (var engineId in ids)
            {
                await using var engineCheck = new MySqlCommand("SELECT 1 FROM EngineFamily WHERE engine_family_id=@ef LIMIT 1", conn, (MySqlTransaction)tx);
                engineCheck.Parameters.AddWithValue("@ef", engineId);
                if (await engineCheck.ExecuteScalarAsync(ct) is null)
                {
                    missing.Add(engineId);
                    continue;
                }

                await using (var reset = new MySqlCommand("UPDATE EngineFamilyTree SET is_default=FALSE WHERE engine_family_id=@ef", conn, (MySqlTransaction)tx))
                {
                    reset.Parameters.AddWithValue("@ef", engineId);
                    await reset.ExecuteNonQueryAsync(ct);
                }

                await using (var upsert = new MySqlCommand(@"INSERT INTO EngineFamilyTree (engine_family_id, tree_id, is_default)
                                                            VALUES (@ef, @tree, TRUE)
                                                            ON DUPLICATE KEY UPDATE is_default=VALUES(is_default)", conn, (MySqlTransaction)tx))
                {
                    upsert.Parameters.AddWithValue("@ef", engineId);
                    upsert.Parameters.AddWithValue("@tree", treeId);
                    await upsert.ExecuteNonQueryAsync(ct);
                }

                defaultsSet++;
            }

            await tx.CommitAsync(ct);
        }
        catch
        {
            await tx.RollbackAsync(ct);
            throw;
        }

        return Results.Json(new { ok = true, defaults_set = defaultsSet, missing });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Batch set defaults failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: bulk attach existing categories to a tree branch
app.MapPost("/api/admin/trees/{treeId:long}/add-categories", async (long treeId, HttpContext ctx, AdminTreeAddCategoriesRequest body, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    if (body is null)
        return Results.BadRequest(new { error = "invalid_payload" });

    var parentSlug = body.ParentSlug?.Trim();
    var childSlugs = body.ChildSlugs?.Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s.Trim()).ToArray() ?? Array.Empty<string>();
    if (string.IsNullOrWhiteSpace(parentSlug) || childSlugs.Length == 0)
        return Results.BadRequest(new { error = "parent_and_children_required" });

    var overwrite = body.Overwrite ?? true;
    var startPosition = body.StartPosition.HasValue && body.StartPosition.Value > 0 ? body.StartPosition.Value : 1;

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        await using (var treeCheck = new MySqlCommand("SELECT 1 FROM CategoryTree WHERE tree_id=@tree LIMIT 1", conn))
        {
            treeCheck.Parameters.AddWithValue("@tree", treeId);
            if (await treeCheck.ExecuteScalarAsync(ct) is null)
                return Results.NotFound(new { error = "tree_not_found" });
        }

        long? parentId = null;
        await using (var parentCmd = new MySqlCommand("SELECT category_id FROM Category WHERE slug=@slug", conn))
        {
            parentCmd.Parameters.AddWithValue("@slug", parentSlug);
            var scalar = await parentCmd.ExecuteScalarAsync(ct);
            if (scalar is null)
                return Results.BadRequest(new { error = "unknown_parent" });
            parentId = Convert.ToInt64(scalar);
        }

        var missing = new List<string>();
        var created = 0;
        var updated = 0;
        var position = startPosition;

        await using var tx = await conn.BeginTransactionAsync(ct);
        try
        {
            foreach (var slug in childSlugs)
            {
                await using var childCmd = new MySqlCommand("SELECT category_id FROM Category WHERE slug=@slug", conn, (MySqlTransaction)tx);
                childCmd.Parameters.AddWithValue("@slug", slug);
                var childScalar = await childCmd.ExecuteScalarAsync(ct);
                if (childScalar is null)
                {
                    missing.Add(slug);
                    continue;
                }

                var childId = Convert.ToInt64(childScalar);

                if (overwrite)
                {
                    await using var upsert = new MySqlCommand(@"INSERT INTO CategoryEdge(tree_id, parent_category_id, child_category_id, position)
                                                               VALUES(@tree, @parent, @child, @pos)
                                                               ON DUPLICATE KEY UPDATE position=VALUES(position)", conn, (MySqlTransaction)tx);
                    upsert.Parameters.AddWithValue("@tree", treeId);
                    upsert.Parameters.AddWithValue("@parent", parentId);
                    upsert.Parameters.AddWithValue("@child", childId);
                    upsert.Parameters.AddWithValue("@pos", position);
                    var affected = await upsert.ExecuteNonQueryAsync(ct);
                    if (affected == 1)
                    {
                        created++;
                    }
                    else if (affected >= 2)
                    {
                        updated++;
                    }
                }
                else
                {
                    await using var insert = new MySqlCommand(@"INSERT IGNORE INTO CategoryEdge(tree_id, parent_category_id, child_category_id, position)
                                                               VALUES(@tree, @parent, @child, @pos)", conn, (MySqlTransaction)tx);
                    insert.Parameters.AddWithValue("@tree", treeId);
                    insert.Parameters.AddWithValue("@parent", parentId);
                    insert.Parameters.AddWithValue("@child", childId);
                    insert.Parameters.AddWithValue("@pos", position);
                    var affected = await insert.ExecuteNonQueryAsync(ct);
                    if (affected > 0)
                    {
                        created++;
                    }
                }

                position++;
            }

            await tx.CommitAsync(ct);
        }
        catch
        {
            await tx.RollbackAsync(ct);
            throw;
        }

        return Results.Json(new { ok = true, created, updated, missing });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Add categories failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: list category trees
app.MapGet("/api/admin/trees", async (HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        var rows = new List<Dictionary<string, object?>>();
        await using var cmd = new MySqlCommand("SELECT tree_id, name, description FROM CategoryTree ORDER BY name", conn);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
            {
                ["tree_id"] = reader.GetInt64(0),
                ["name"] = reader.GetString(1),
                ["description"] = reader.IsDBNull(2) ? null : reader.GetString(2)
            };
            rows.Add(row);
        }

        return Results.Json(rows);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Fetch trees failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: fetch edges for a tree
app.MapGet("/api/admin/trees/{treeId:long}/edges", async (long treeId, HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        const string sql = @"SELECT ce.tree_id,
                                     ce.parent_category_id,
                                     parent.slug AS parent_slug,
                                     parent.name AS parent_name,
                                     ce.child_category_id,
                                     child.slug AS child_slug,
                                     child.name AS child_name,
                                     ce.position
                              FROM CategoryEdge ce
                              JOIN Category parent ON parent.category_id = ce.parent_category_id
                              JOIN Category child ON child.category_id = ce.child_category_id
                              WHERE ce.tree_id=@tree
                              ORDER BY parent.name, ce.position";

        var rows = new List<Dictionary<string, object?>>();
        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@tree", treeId);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < reader.FieldCount; i++)
                row[reader.GetName(i)] = reader.IsDBNull(i) ? null : reader.GetValue(i);
            rows.Add(row);
        }

        return Results.Json(rows);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Fetch tree edges failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: add or update a tree edge
app.MapPost("/api/admin/trees/{treeId:long}/edges", async (long treeId, HttpContext ctx, AdminTreeEdgeRequest body, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    if (body is null)
        return Results.BadRequest(new { error = "invalid_payload" });

    var parentSlug = body.ParentSlug?.Trim().ToLowerInvariant();
    var childSlug = body.ChildSlug?.Trim().ToLowerInvariant();
    if (string.IsNullOrWhiteSpace(parentSlug) || string.IsNullOrWhiteSpace(childSlug))
        return Results.BadRequest(new { error = "slugs_required" });
    if (string.Equals(parentSlug, childSlug, StringComparison.OrdinalIgnoreCase))
        return Results.BadRequest(new { error = "invalid_edge", message = "Parent and child cannot be the same." });

    var position = body.Position ?? 0;

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        async Task<long?> LookupAsync(string slug)
        {
            await using var cmd = new MySqlCommand("SELECT category_id FROM Category WHERE slug=@slug", conn);
            cmd.Parameters.AddWithValue("@slug", slug);
            var result = await cmd.ExecuteScalarAsync(ct);
            return result is null ? null : Convert.ToInt64(result);
        }

        var parentId = await LookupAsync(parentSlug);
        var childId = await LookupAsync(childSlug);
        if (parentId is null || childId is null)
            return Results.NotFound(new { error = "category_not_found" });

        await using var cmd = new MySqlCommand(@"INSERT INTO CategoryEdge(tree_id, parent_category_id, child_category_id, position)
                                                  VALUES(@tree, @parent, @child, @pos)
                                                  ON DUPLICATE KEY UPDATE position = VALUES(position)", conn);
        cmd.Parameters.AddWithValue("@tree", treeId);
        cmd.Parameters.AddWithValue("@parent", parentId.Value);
        cmd.Parameters.AddWithValue("@child", childId.Value);
        cmd.Parameters.AddWithValue("@pos", position);
        await cmd.ExecuteNonQueryAsync(ct);

        return Results.Json(new { ok = true });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Upsert edge failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: delete a tree edge
app.MapDelete("/api/admin/trees/{treeId:long}/edges", async (long treeId, HttpContext ctx, string parent_slug, string child_slug, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    if (string.IsNullOrWhiteSpace(parent_slug) || string.IsNullOrWhiteSpace(child_slug))
        return Results.BadRequest(new { error = "slugs_required" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        const string sql = @"DELETE ce FROM CategoryEdge ce
                              JOIN Category p ON p.category_id = ce.parent_category_id AND p.slug = @parent
                              JOIN Category c ON c.category_id = ce.child_category_id AND c.slug = @child
                              WHERE ce.tree_id = @tree";

        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@tree", treeId);
        cmd.Parameters.AddWithValue("@parent", parent_slug.Trim().ToLowerInvariant());
        cmd.Parameters.AddWithValue("@child", child_slug.Trim().ToLowerInvariant());
        var rows = await cmd.ExecuteNonQueryAsync(ct);
        if (rows == 0)
            return Results.NotFound(new { error = "edge_not_found" });

        return Results.Json(new { ok = true });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Delete edge failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// List categories for builder filters
app.MapGet("/api/categories", async (HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    var query = ctx.Request.Query;
    long? treeId = query.TryGetValue("tree_id", out var treeVal) && long.TryParse(treeVal, out var t) ? t : (long?)null;

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        const string sql = @"SELECT c.category_id, c.name, c.is_selectable
                              FROM Category c
                              WHERE (@tree IS NULL OR EXISTS (
                                        SELECT 1 FROM CategoryEdge e
                                        WHERE e.child_category_id = c.category_id AND e.tree_id = @tree))
                              ORDER BY c.name";

        var list = new List<Dictionary<string, object?>>();
        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@tree", (object?)treeId ?? DBNull.Value);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
            {
                ["category_id"] = reader.GetInt64(0),
                ["name"] = reader.GetString(1),
                ["is_selectable"] = !reader.IsDBNull(2) && reader.GetBoolean(2)
            };
            list.Add(row);
        }

        return Results.Json(list);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Categories query failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Hierarchical view for a category tree (used by builder UI)
app.MapGet("/api/trees/{treeId:long}/hierarchy", async (long treeId, HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        const string edgeSql = @"SELECT ce.parent_category_id,
                                      ce.child_category_id,
                                      ce.position,
                                      parent.name AS parent_name,
                                      parent.slug AS parent_slug,
                                      parent.is_selectable AS parent_leaf,
                                      child.name AS child_name,
                                      child.slug AS child_slug,
                                      child.is_selectable AS child_leaf
                               FROM CategoryEdge ce
                               JOIN Category parent ON parent.category_id = ce.parent_category_id
                               JOIN Category child  ON child.category_id  = ce.child_category_id
                               WHERE ce.tree_id = @tree";

        var nodes = new Dictionary<long, CategoryTreeNode>();

        CategoryTreeNode GetOrCreate(long id, string name, string slug, bool isSelectable)
        {
            if (!nodes.TryGetValue(id, out var node))
            {
                node = new CategoryTreeNode(id, name, slug, isSelectable);
                nodes[id] = node;
            }
            else
            {
                node.Name = name;
                node.Slug = slug;
                node.IsSelectable = isSelectable;
            }
            return node;
        }

        await using (var cmd = new MySqlCommand(edgeSql, conn))
        {
            cmd.Parameters.AddWithValue("@tree", treeId);
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                var parentId = reader.GetInt64(0);
                var childId = reader.GetInt64(1);
                var position = reader.IsDBNull(2) ? 0 : reader.GetInt32(2);

                var parent = GetOrCreate(parentId,
                    reader.GetString(3),
                    reader.GetString(4),
                    !reader.IsDBNull(5) && reader.GetBoolean(5));

                var child = GetOrCreate(childId,
                    reader.GetString(6),
                    reader.GetString(7),
                    !reader.IsDBNull(8) && reader.GetBoolean(8));

                child.ParentId = parent.Id;
                child.Position = position;

                if (!parent.Children.Contains(child))
                {
                    parent.Children.Add(child);
                }
            }
        }

        if (nodes.Count == 0)
            return Results.Json(Array.Empty<object>());

        var roots = nodes.Values
            .Where(n => n.ParentId is null)
            .OrderBy(n => n.Position)
            .ThenBy(n => n.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var result = new List<object>(nodes.Count);
        var visited = new HashSet<long>();

        void Walk(CategoryTreeNode node, int depth)
        {
            if (!visited.Add(node.Id)) return;

            result.Add(new
            {
                category_id = node.Id,
                name = node.Name,
                slug = node.Slug,
                parent_id = node.ParentId,
                is_selectable = node.IsSelectable,
                depth
            });

            foreach (var child in node.Children
                         .OrderBy(c => c.Position)
                         .ThenBy(c => c.Name, StringComparer.OrdinalIgnoreCase))
            {
                Walk(child, depth + 1);
            }
        }

        foreach (var root in roots)
        {
            Walk(root, 0);
        }

        // Include any disconnected nodes (just in case)
        foreach (var node in nodes.Values)
        {
            if (!visited.Contains(node.Id))
            {
                Walk(node, node.ParentId.HasValue ? 1 : 0);
            }
        }

        return Results.Json(result);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Fetch hierarchy failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Parts for a category (builder)
app.MapGet("/api/categories/{categoryId:long}/parts", async (long categoryId, HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    var query = ctx.Request.Query;
    long? engineFamilyId = query.TryGetValue("engine_family_id", out var engineVal) && long.TryParse(engineVal, out var ef) ? ef : (long?)null;

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsurePartColumnsAsync(conn, ct);

        const string sql = @"SELECT DISTINCT
                                    p.part_id,
                                    p.sku,
                                    p.name,
                                    p.is_kit,
                                    p.pieces_per_unit,
                                    p.status,
                                    p.image_url,
                                    b.name AS brand_name,
                                    v.best_price
                              FROM PartCategory pc
                              JOIN Part p ON p.part_id = pc.part_id
                              LEFT JOIN Brand b ON b.brand_id = p.brand_id
                              LEFT JOIN v_part_best_offering v ON v.part_id = p.part_id
                              WHERE pc.category_id = @cat
                                AND (
                                    @engine IS NULL
                                    OR EXISTS (SELECT 1 FROM PartFitment pf WHERE pf.part_id = p.part_id AND pf.engine_family_id = @engine)
                                    OR NOT EXISTS (SELECT 1 FROM PartFitment pf WHERE pf.part_id = p.part_id)
                                )
                              ORDER BY p.name";

        var list = new List<Dictionary<string, object?>>();
        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@cat", categoryId);
        cmd.Parameters.AddWithValue("@engine", (object?)engineFamilyId ?? DBNull.Value);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < reader.FieldCount; i++)
                row[reader.GetName(i)] = reader.IsDBNull(i) ? null : reader.GetValue(i);
            list.Add(row);
        }

        return Results.Json(list);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Category parts query failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin ingest: create part, map to leaf, and add offering
// Admin: media upload for ingest assets
app.MapPost("/api/admin/media/upload", async (HttpContext ctx, IWebHostEnvironment env, CancellationToken ct) =>
{
    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    var form = await ctx.Request.ReadFormAsync(ct);
    var file = form.Files.FirstOrDefault();
    if (file is null || file.Length == 0)
        return Results.BadRequest(new { error = "no_file" });

    var ext = Path.GetExtension(file.FileName).ToLowerInvariant();
    var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".jpg", ".jpeg", ".png", ".webp" };
    if (!allowed.Contains(ext))
        return Results.BadRequest(new { error = "unsupported_type", allowed });

    var root = env.WebRootPath;
    if (string.IsNullOrWhiteSpace(root))
        root = Path.Combine(AppContext.BaseDirectory, "wwwroot");

    var relativeDir = Path.Combine("uploads", "parts", DateTime.UtcNow.ToString("yyyy"), DateTime.UtcNow.ToString("MM"));
    var absoluteDir = Path.Combine(root, relativeDir);
    Directory.CreateDirectory(absoluteDir);

    var fileName = $"{Guid.NewGuid():N}{ext}";
    var destinationPath = Path.Combine(absoluteDir, fileName);

    await using (var stream = new FileStream(destinationPath, FileMode.Create, FileAccess.Write, FileShare.None))
    {
        await file.CopyToAsync(stream, ct);
    }

    var relativeUrl = "/" + Path.Combine(relativeDir, fileName).Replace('\\', '/');
    return Results.Json(new { url = relativeUrl });
}).RequireAuthorization("IsSignedIn");

app.MapPost("/api/admin/ingest/ai-normalize", async (HttpContext ctx, JsonElement payload, CancellationToken ct) =>
{
    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    var warnings = new List<string>();
    var errors = new List<string>();

    if (payload.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        return Results.BadRequest(new { error = "invalid_payload", detail = "Payload must be a JSON object." });

    if (payload.ValueKind != JsonValueKind.Object)
        return Results.BadRequest(new { error = "invalid_payload", detail = "Payload must be a JSON object." });

    if (payload.TryGetProperty("tree", out _))
        warnings.Add("Removed 'tree' object from AI payload (admin controls category trees).");

    var sku = TryGetStringByPath(payload, "part.sku", "parts[0].sku", "sku", "part.number", "part.part_number");
    var name = TryGetStringByPath(payload, "part.name", "parts[0].name", "name", "title", "product_name");
    var brand = TryGetStringByPath(payload, "part.brand_name", "parts[0].brand_name", "brand", "brand_name", "manufacturer", "maker");
    var status = TryGetStringByPath(payload, "part.status", "status", "part.part_status");
    var uom = TryGetStringByPath(payload, "part.uom", "uom", "part.unit");
    var pieces = TryGetDecimalByPath(payload, "part.pieces_per_unit", "pieces_per_unit", "part.qty", "part.quantity");
    var isKit = TryGetBoolByPath(payload, "part.is_kit", "is_kit");
    var imageUrl = TryGetStringByPath(payload, "part.image_url", "parts[0].image_url", "image_url", "image", "imageUrl");

    var categories = ExtractCategorySlugs(payload);
    var fitment = ExtractFitmentCodes(payload);
    var offerings = ExtractOfferings(payload);

    var initial = new AdminIngestPayloadEnvelope
    {
        Part = new AdminIngestPartPayload
        {
            Sku = sku,
            Name = name,
            BrandName = string.IsNullOrWhiteSpace(brand) ? "Generic" : brand,
            Status = status,
            Uom = string.IsNullOrWhiteSpace(uom) ? "each" : uom,
        PiecesPerUnit = pieces.HasValue && pieces.Value > 0 ? pieces.Value : null,
            IsKit = isKit,
            ImageUrl = string.IsNullOrWhiteSpace(imageUrl) ? null : imageUrl
        },
        Categories = categories,
        Fitment = fitment,
        Offerings = offerings
    };

    var normalized = NormalizeAdminIngestPayload(initial);

    var normalizedPart = normalized.Part ?? new AdminIngestPartPayload();
    var normalizedCategories = normalized.Categories ?? new List<string>();
    var normalizedFitment = normalized.Fitment ?? new List<string>();

    if (string.IsNullOrWhiteSpace(normalizedPart.Sku) || string.IsNullOrWhiteSpace(normalizedPart.Name))
        errors.Add("SKU and Name are required.");

    if (normalizedCategories.Count == 0)
        warnings.Add("No category slugs provided; select categories manually before saving.");

    if (normalizedFitment.Count == 0)
        warnings.Add("No engine codes provided; add fitment manually if needed.");

    if (!string.IsNullOrWhiteSpace(connectionString))
    {
        try
        {
            await using var conn = new MySqlConnection(connectionString);
            await conn.OpenAsync(ct);

            var missingCategories = new List<string>();
            foreach (var slug in normalizedCategories.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                await using var cmd = new MySqlCommand("SELECT category_id FROM Category WHERE slug=@slug AND is_selectable=TRUE LIMIT 1", conn);
                cmd.Parameters.AddWithValue("@slug", slug);
                var existing = await cmd.ExecuteScalarAsync(ct);
                if (existing is null)
                    missingCategories.Add(slug);
            }

            if (missingCategories.Count > 0)
                warnings.Add($"Unknown/non-leaf categories: {string.Join(", ", missingCategories)}");

            var missingEngines = new List<string>();
            foreach (var code in normalizedFitment.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                await using var cmd = new MySqlCommand("SELECT engine_family_id FROM EngineFamily WHERE code=@code LIMIT 1", conn);
                cmd.Parameters.AddWithValue("@code", code);
                var exists = await cmd.ExecuteScalarAsync(ct);
                if (exists is null)
                    missingEngines.Add(code);
            }

            if (missingEngines.Count > 0)
                warnings.Add($"Unknown engine codes: {string.Join(", ", missingEngines)}");
        }
        catch (Exception ex)
        {
            warnings.Add($"Skipped DB validation: {ex.Message}");
        }
    }

    var ok = errors.Count == 0;

    return Results.Json(new
    {
        ok,
        normalized,
        warnings,
        errors
    });
}).RequireAuthorization("IsSignedIn");

app.MapPost("/api/admin/ingest/ai-draft", async (HttpContext ctx, IngestionService svc, AiDraftFromUrlRequest body, CancellationToken ct) =>
{
    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    if (body is null || string.IsNullOrWhiteSpace(body.Url))
        return Results.BadRequest(new { error = "url_required", detail = "Provide a source URL." });

    var errors = new List<string>();
    var warnings = new List<string>();

    var forcedCodes = (body.ForcedEngineCodes ?? new()).Where(code => !string.IsNullOrWhiteSpace(code))
        .Select(code => code!.Trim().ToUpperInvariant())
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToList();

    try
    {
        var payload = await svc.GenerateFromUrlAsync(
            body.Url!,
            string.IsNullOrWhiteSpace(body.EngineCode) ? null : body.EngineCode,
            string.IsNullOrWhiteSpace(body.TreeName) ? null : body.TreeName,
            body.UseDbEngineList,
            body.UseDbCategoryList,
            body.UseDbTreeEdges,
            forcedCodes,
            ct);

        if (body.EnrichParts)
            payload = await svc.EnrichPartsAsync(payload, ct);

        payload = svc.NormalizePayload(payload, forcedCodes);

        var part = payload.Parts.FirstOrDefault();
        if (part is null)
        {
            errors.Add("AI response did not include any parts.");
            return Results.Json(new { ok = false, warnings, errors });
        }

        var categories = payload.PartCategories
            .Where(pc => string.Equals(pc.PartSku, part.Sku, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(pc => pc.IsPrimary ?? false)
            .ThenBy(pc => pc.DisplayOrder ?? 0)
            .Select(pc => pc.CategorySlug)
            .Where(slug => !string.IsNullOrWhiteSpace(slug))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (categories.Count == 0)
        {
            categories = payload.Categories
                .Where(c => c.IsSelectable == true)
                .Select(c => c.Slug)
                .Where(slug => !string.IsNullOrWhiteSpace(slug))
                .Select(slug => slug!)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        var fitmentSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var f in payload.Fitment
                     .Where(f => string.IsNullOrWhiteSpace(f.PartSku) || string.Equals(f.PartSku, part.Sku, StringComparison.OrdinalIgnoreCase)))
        {
            if (!string.IsNullOrWhiteSpace(f.EngineCode))
                fitmentSet.Add(f.EngineCode!.Trim().ToUpperInvariant());
        }

        if (!string.IsNullOrWhiteSpace(payload.Engine?.Code))
            fitmentSet.Add(payload.Engine.Code.Trim().ToUpperInvariant());

        foreach (var code in forcedCodes)
            fitmentSet.Add(code);

        var fitmentCodes = fitmentSet.ToList();

        var offerings = payload.Offerings
            .Where(o => string.Equals(o.PartSku, part.Sku, StringComparison.OrdinalIgnoreCase))
            .Select(o => new AdminIngestOfferingPayload
            {
                VendorName = string.IsNullOrWhiteSpace(o.VendorName) ? null : o.VendorName!.Trim(),
                Price = o.Price,
                Currency = string.IsNullOrWhiteSpace(o.Currency) ? null : o.Currency!.Trim(),
                Url = string.IsNullOrWhiteSpace(o.Url) ? null : o.Url!.Trim(),
                Availability = string.IsNullOrWhiteSpace(o.Availability) ? null : o.Availability!.Trim()
            })
            .Where(o => !string.IsNullOrWhiteSpace(o.VendorName))
            .ToList();

        var normalized = NormalizeAdminIngestPayload(new AdminIngestPayloadEnvelope
        {
            Part = new AdminIngestPartPayload
            {
                Sku = part.Sku,
                Name = part.Name,
                BrandName = part.BrandName,
                IsKit = part.IsKit,
                Uom = part.Uom,
                PiecesPerUnit = part.PiecesPerUnit,
                Status = part.Status,
                ImageUrl = part.ImageUrl
            },
            Categories = categories,
            Fitment = fitmentCodes,
            Offerings = offerings
        });

        if (normalized.Categories is null || normalized.Categories.Count == 0)
            warnings.Add("AI draft did not include category slugs. Set categories manually before saving.");

        if (normalized.Fitment is null || normalized.Fitment.Count == 0)
            warnings.Add("AI draft did not include fitment codes. Add fitment manually if required.");

        if (string.IsNullOrWhiteSpace(normalized.Part?.Sku) || string.IsNullOrWhiteSpace(normalized.Part?.Name))
            errors.Add("Normalized payload missing SKU or Name.");

        var normalizedJson = JsonSerializer.Serialize(normalized, new JsonSerializerOptions { WriteIndented = true });

        return Results.Json(new
        {
            ok = errors.Count == 0,
            warnings,
            errors,
            normalized,
            normalized_json = normalizedJson
        });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "AI draft fetch failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

app.MapPost("/api/admin/ingest/validate", async (HttpContext ctx, JsonElement payload, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    AdminIngestPayloadEnvelope? body;
    try
    {
        body = JsonSerializer.Deserialize<AdminIngestPayloadEnvelope>(payload, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = "invalid_payload", detail = ex.Message });
    }

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        var validation = await ValidateAdminIngestPayloadAsync(conn, body, ct);

        return Results.Json(new
        {
            ok = validation.Errors.Count == 0,
            errors = validation.Errors,
            warnings = validation.Warnings,
            normalized = validation.Normalized,
            existing_part_id = validation.ExistingPartId
        });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Validate ingest payload failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

app.MapPost("/api/admin/ingest/part", async (HttpContext ctx, JsonElement payload, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    AdminIngestPayloadEnvelope? body;
    try
    {
        body = JsonSerializer.Deserialize<AdminIngestPayloadEnvelope>(payload, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = "invalid_payload", detail = ex.Message });
    }

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        await EnsurePartColumnsAsync(conn, ct);
        await EnsurePartCategoryTriggersAsync(conn, ct);

        var validation = await ValidateAdminIngestPayloadAsync(conn, body, ct);
        if (validation.Errors.Count > 0)
        {
            return Results.BadRequest(new
            {
                ok = false,
                errors = validation.Errors,
                warnings = validation.Warnings,
                normalized = validation.Normalized
            });
        }

        var normalized = validation.Normalized;
        var part = normalized.Part ?? new AdminIngestPartPayload();

        await using var tx = await conn.BeginTransactionAsync(ct);
        try
        {
            bool brandInserted;
            await using (var upsertBrand = new MySqlCommand("INSERT INTO Brand(name) VALUES(@name) ON DUPLICATE KEY UPDATE name=VALUES(name)", conn, (MySqlTransaction)tx))
            {
                upsertBrand.Parameters.AddWithValue("@name", part.BrandName ?? string.Empty);
                brandInserted = await upsertBrand.ExecuteNonQueryAsync(ct) == 1;
            }

            long brandId;
            await using (var fetchBrand = new MySqlCommand("SELECT brand_id FROM Brand WHERE name=@name", conn, (MySqlTransaction)tx))
            {
                fetchBrand.Parameters.AddWithValue("@name", part.BrandName ?? string.Empty);
                var brandResult = await fetchBrand.ExecuteScalarAsync(ct);
                brandId = brandResult is null ? 0 : Convert.ToInt64(brandResult);
            }

            if (brandId == 0)
            {
                await tx.RollbackAsync(ct);
                return Results.Problem(title: "Ingest failed", detail: "Unable to resolve brand id", statusCode: 500);
            }

            bool partInserted;
            await using (var upsertPart = new MySqlCommand(@"INSERT INTO Part (sku, name, brand_id, is_kit, uom, pieces_per_unit, status, image_url)
                                                             VALUES(@sku, @name, @brand, @kit, @uom, @ppu, @status, @image)
                                                             ON DUPLICATE KEY UPDATE name=VALUES(name), brand_id=VALUES(brand_id), is_kit=VALUES(is_kit), uom=VALUES(uom), pieces_per_unit=VALUES(pieces_per_unit), status=VALUES(status), image_url=VALUES(image_url)", conn, (MySqlTransaction)tx))
            {
                upsertPart.Parameters.AddWithValue("@sku", part.Sku ?? string.Empty);
                upsertPart.Parameters.AddWithValue("@name", part.Name ?? string.Empty);
                upsertPart.Parameters.AddWithValue("@brand", brandId);
                upsertPart.Parameters.AddWithValue("@kit", part.IsKit ?? false);
                upsertPart.Parameters.AddWithValue("@uom", part.Uom ?? "each");
                upsertPart.Parameters.AddWithValue("@ppu", part.PiecesPerUnit ?? 1m);
                upsertPart.Parameters.AddWithValue("@status", part.Status ?? "active");
                upsertPart.Parameters.AddWithValue("@image", string.IsNullOrWhiteSpace(part.ImageUrl) ? (object)DBNull.Value : part.ImageUrl!);
                partInserted = await upsertPart.ExecuteNonQueryAsync(ct) == 1;
            }

            long partId;
            await using (var fetchPart = new MySqlCommand("SELECT part_id FROM Part WHERE sku=@sku", conn, (MySqlTransaction)tx))
            {
                fetchPart.Parameters.AddWithValue("@sku", part.Sku ?? string.Empty);
                var partResult = await fetchPart.ExecuteScalarAsync(ct);
                partId = partResult is null ? 0 : Convert.ToInt64(partResult);
            }

            if (partId == 0)
            {
                await tx.RollbackAsync(ct);
                return Results.Problem(title: "Ingest failed", detail: "Unable to resolve part id", statusCode: 500);
            }

            await using (var deleteCats = new MySqlCommand("DELETE FROM PartCategory WHERE part_id=@part", conn, (MySqlTransaction)tx))
            {
                deleteCats.Parameters.AddWithValue("@part", partId);
                await deleteCats.ExecuteNonQueryAsync(ct);
            }

            var orderedCategories = validation.Categories.OrderBy(c => c.Order).ToList();
            for (var index = 0; index < orderedCategories.Count; index++)
            {
                var cat = orderedCategories[index];
                await using var insertCat = new MySqlCommand(@"INSERT INTO PartCategory(part_id, category_id, is_primary, coverage_weight, display_order)
                                                              VALUES(@part, @cat, @primary, 1.0, @display)
                                                              ON DUPLICATE KEY UPDATE is_primary=VALUES(is_primary), coverage_weight=VALUES(coverage_weight), display_order=VALUES(display_order)", conn, (MySqlTransaction)tx);
                insertCat.Parameters.AddWithValue("@part", partId);
                insertCat.Parameters.AddWithValue("@cat", cat.CategoryId);
                insertCat.Parameters.AddWithValue("@primary", index == 0 ? 1 : 0);
                insertCat.Parameters.AddWithValue("@display", index + 1);
                await insertCat.ExecuteNonQueryAsync(ct);
            }

            await using (var deleteFitment = new MySqlCommand("DELETE FROM PartFitment WHERE part_id=@part", conn, (MySqlTransaction)tx))
            {
                deleteFitment.Parameters.AddWithValue("@part", partId);
                await deleteFitment.ExecuteNonQueryAsync(ct);
            }

            foreach (var engine in validation.Engines)
            {
                await using var insertFitment = new MySqlCommand(@"INSERT INTO PartFitment(part_id, engine_family_id, years_start, years_end, notes)
                                                                  VALUES(@part, @engine, NULL, NULL, NULL)
                                                                  ON DUPLICATE KEY UPDATE part_id=VALUES(part_id)", conn, (MySqlTransaction)tx);
                insertFitment.Parameters.AddWithValue("@part", partId);
                insertFitment.Parameters.AddWithValue("@engine", engine.EngineFamilyId);
                await insertFitment.ExecuteNonQueryAsync(ct);
            }

            await using (var closeOfferings = new MySqlCommand("UPDATE PartOffering SET effective_to = NOW() WHERE part_id=@part AND effective_to IS NULL", conn, (MySqlTransaction)tx))
            {
                closeOfferings.Parameters.AddWithValue("@part", partId);
                await closeOfferings.ExecuteNonQueryAsync(ct);
            }

            var vendorCreates = 0;
            foreach (var offering in validation.Offerings)
            {
                await using (var upsertVendor = new MySqlCommand("INSERT INTO Vendor(name) VALUES(@name) ON DUPLICATE KEY UPDATE name=VALUES(name)", conn, (MySqlTransaction)tx))
                {
                    upsertVendor.Parameters.AddWithValue("@name", offering.VendorName);
                    if (await upsertVendor.ExecuteNonQueryAsync(ct) == 1)
                        vendorCreates++;
                }

                long vendorId;
                await using (var fetchVendor = new MySqlCommand("SELECT vendor_id FROM Vendor WHERE name=@name", conn, (MySqlTransaction)tx))
                {
                    fetchVendor.Parameters.AddWithValue("@name", offering.VendorName);
                    var vendorResult = await fetchVendor.ExecuteScalarAsync(ct);
                    vendorId = vendorResult is null ? 0 : Convert.ToInt64(vendorResult);
                }

                if (vendorId == 0)
                {
                    await tx.RollbackAsync(ct);
                    return Results.Problem(title: "Ingest failed", detail: $"Unable to resolve vendor id for '{offering.VendorName}'", statusCode: 500);
                }

                await using var insertOffering = new MySqlCommand(@"INSERT INTO PartOffering(part_id, vendor_id, price, currency, url, availability, affiliate_url, effective_from)
                                                                   VALUES(@part, @vendor, @price, @currency, @url, @availability, NULL, NOW())", conn, (MySqlTransaction)tx);
                insertOffering.Parameters.AddWithValue("@part", partId);
                insertOffering.Parameters.AddWithValue("@vendor", vendorId);
                insertOffering.Parameters.AddWithValue("@price", offering.Price);
                insertOffering.Parameters.AddWithValue("@currency", offering.Currency);
                insertOffering.Parameters.AddWithValue("@url", string.IsNullOrWhiteSpace(offering.Url) ? (object)DBNull.Value : offering.Url!);
                insertOffering.Parameters.AddWithValue("@availability", offering.Availability);
                await insertOffering.ExecuteNonQueryAsync(ct);
            }

            await tx.CommitAsync(ct);

            return Results.Json(new
            {
                ok = true,
                part_id = partId,
                sku = part.Sku,
                created = new
                {
                    brand = brandInserted,
                    part = partInserted,
                    vendors = vendorCreates,
                    offerings = validation.Offerings.Count,
                    fitment = validation.Engines.Count,
                    categories = validation.Categories.Count
                },
                warnings = validation.Warnings,
                existing_part_id = validation.ExistingPartId
            });
        }
        catch
        {
            await tx.RollbackAsync(ct);
            throw;
        }
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Upsert ingest payload failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

app.MapPost("/api/admin/ingest", async (HttpContext ctx, AdminIngestRequest body, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    if (body is null || body.Part is null || body.Offering is null)
        return Results.BadRequest(new { error = "invalid_payload" });

    var sku = body.Part.Sku?.Trim();
    var name = body.Part.Name?.Trim();
    var brand = body.Part.BrandName?.Trim();
    var uom = string.IsNullOrWhiteSpace(body.Part.Uom) ? "each" : body.Part.Uom.Trim();
    var status = string.IsNullOrWhiteSpace(body.Part.Status) ? "active" : body.Part.Status.Trim().ToLowerInvariant();
    var piecesPerUnit = body.Part.PiecesPerUnit <= 0 ? 1m : body.Part.PiecesPerUnit;
    var isKit = body.Part.IsKit ?? false;

    var vendor = body.Offering.VendorName?.Trim();
    var currency = string.IsNullOrWhiteSpace(body.Offering.Currency) ? "USD" : body.Offering.Currency!.Trim().ToUpperInvariant();
    var url = string.IsNullOrWhiteSpace(body.Offering.Url) ? null : body.Offering.Url!.Trim();
    var price = body.Offering.Price;

    if (string.IsNullOrWhiteSpace(name))
        return Results.BadRequest(new { error = "name_required" });
    if (string.IsNullOrWhiteSpace(brand))
        return Results.BadRequest(new { error = "brand_required" });
    if (string.IsNullOrWhiteSpace(sku))
        return Results.BadRequest(new { error = "sku_required" });
    if (string.IsNullOrWhiteSpace(vendor))
        return Results.BadRequest(new { error = "vendor_required" });
    if (price <= 0)
        return Results.BadRequest(new { error = "price_invalid" });

    var categorySlugs = (body.CategorySlugs ?? new List<string>())
        .Select(slug => (slug ?? string.Empty).Trim().ToLowerInvariant())
        .Where(slug => !string.IsNullOrWhiteSpace(slug))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToList();

    var fitmentCodes = (body.FitmentCodes ?? new List<string>())
        .Select(code => (code ?? string.Empty).Trim())
        .Where(code => !string.IsNullOrWhiteSpace(code))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToList();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsurePartColumnsAsync(conn, ct);
        await EnsurePartCategoryTriggersAsync(conn, ct);

        await using var tx = await conn.BeginTransactionAsync(ct);
        try
        {
            var categoryIds = new HashSet<long>();
            var categoryOrder = new List<long>();

            async Task<IResult?> EnsureCategoryByIdAsync(long id)
            {
                await using var cmd = new MySqlCommand("SELECT is_selectable FROM Category WHERE category_id=@id", conn, (MySqlTransaction)tx);
                cmd.Parameters.AddWithValue("@id", id);
                var result = await cmd.ExecuteScalarAsync(ct);
                if (result is null)
                {
                    return Results.NotFound(new { error = "category_not_found", category_id = id });
                }

                if (Convert.ToInt32(result) == 0)
                {
                    return Results.BadRequest(new { error = "not_leaf", message = "Pick a leaf category.", category_id = id });
                }

                if (categoryIds.Add(id))
                {
                    categoryOrder.Add(id);
                }
                return null;
            }

            async Task<IResult?> EnsureCategoryBySlugAsync(string slug)
            {
                await using var cmd = new MySqlCommand("SELECT category_id, is_selectable FROM Category WHERE slug=@slug", conn, (MySqlTransaction)tx);
                cmd.Parameters.AddWithValue("@slug", slug);
                await using var reader = await cmd.ExecuteReaderAsync(ct);
                if (!await reader.ReadAsync(ct))
                {
                    return Results.NotFound(new { error = "category_not_found", slug });
                }

                var id = reader.GetInt64(0);
                var isSelectable = reader.GetBoolean(1);
                if (!isSelectable)
                {
                    return Results.BadRequest(new { error = "not_leaf", message = "Pick a leaf category.", slug });
                }

                if (categoryIds.Add(id))
                {
                    categoryOrder.Add(id);
                }
                return null;
            }

            if (body.CategoryId is long directCategoryId && directCategoryId > 0)
            {
                var ensure = await EnsureCategoryByIdAsync(directCategoryId);
                if (ensure is not null)
                {
                    await tx.RollbackAsync(ct);
                    return ensure;
                }
            }

            foreach (var slug in categorySlugs)
            {
                var ensure = await EnsureCategoryBySlugAsync(slug);
                if (ensure is not null)
                {
                    await tx.RollbackAsync(ct);
                    return ensure;
                }
            }

            if (categoryIds.Count == 0)
            {
                await tx.RollbackAsync(ct);
                return Results.BadRequest(new { error = "category_required" });
            }

            // Brand
            await using (var upsertBrand = new MySqlCommand("INSERT INTO Brand(name) VALUES(@name) ON DUPLICATE KEY UPDATE name=VALUES(name)", conn, (MySqlTransaction)tx))
            {
                upsertBrand.Parameters.AddWithValue("@name", brand);
                await upsertBrand.ExecuteNonQueryAsync(ct);
            }

            long brandId;
            await using (var fetchBrand = new MySqlCommand("SELECT brand_id FROM Brand WHERE name=@name", conn, (MySqlTransaction)tx))
            {
                fetchBrand.Parameters.AddWithValue("@name", brand);
                var brandResult = await fetchBrand.ExecuteScalarAsync(ct);
                brandId = brandResult is null ? 0 : Convert.ToInt64(brandResult);
            }

            if (brandId == 0)
            {
                await tx.RollbackAsync(ct);
                return Results.Problem(title: "Ingest failed", detail: "Could not determine brand id", statusCode: 500);
            }

            // Part
            await using (var upsertPart = new MySqlCommand(@"INSERT INTO Part (sku, name, brand_id, is_kit, uom, pieces_per_unit, status)
                                                             VALUES(@sku, @name, @brand, @kit, @uom, @ppu, @status)
                                                             ON DUPLICATE KEY UPDATE name=VALUES(name), brand_id=VALUES(brand_id), is_kit=VALUES(is_kit), uom=VALUES(uom), pieces_per_unit=VALUES(pieces_per_unit), status=VALUES(status)", conn, (MySqlTransaction)tx))
            {
                upsertPart.Parameters.AddWithValue("@sku", sku);
                upsertPart.Parameters.AddWithValue("@name", name);
                upsertPart.Parameters.AddWithValue("@brand", brandId);
                upsertPart.Parameters.AddWithValue("@kit", isKit);
                upsertPart.Parameters.AddWithValue("@uom", uom);
                upsertPart.Parameters.AddWithValue("@ppu", piecesPerUnit);
                upsertPart.Parameters.AddWithValue("@status", status);
                await upsertPart.ExecuteNonQueryAsync(ct);
            }

            long partId;
            await using (var fetchPart = new MySqlCommand("SELECT part_id FROM Part WHERE sku=@sku", conn, (MySqlTransaction)tx))
            {
                fetchPart.Parameters.AddWithValue("@sku", sku);
                var partResult = await fetchPart.ExecuteScalarAsync(ct);
                partId = partResult is null ? 0 : Convert.ToInt64(partResult);
            }

            if (partId == 0)
            {
                await tx.RollbackAsync(ct);
                return Results.Problem(title: "Ingest failed", detail: "Could not determine part id", statusCode: 500);
            }

            for (var index = 0; index < categoryOrder.Count; index++)
            {
                var catId = categoryOrder[index];
                await using var map = new MySqlCommand(@"INSERT INTO PartCategory(part_id, category_id, is_primary, coverage_weight, display_order)
                                                         VALUES(@part, @cat, @primary, 1.0, @order)
                                                         ON DUPLICATE KEY UPDATE is_primary=VALUES(is_primary), coverage_weight=VALUES(coverage_weight), display_order=VALUES(display_order)", conn, (MySqlTransaction)tx);
                map.Parameters.AddWithValue("@part", partId);
                map.Parameters.AddWithValue("@cat", catId);
                map.Parameters.AddWithValue("@primary", index == 0 ? 1 : 0);
                map.Parameters.AddWithValue("@order", index + 1);
                await map.ExecuteNonQueryAsync(ct);
            }

            if (fitmentCodes.Count > 0)
            {
                var engineIds = new HashSet<long>();
                foreach (var code in fitmentCodes)
                {
                    await using var engineCmd = new MySqlCommand("SELECT engine_family_id FROM EngineFamily WHERE code=@code", conn, (MySqlTransaction)tx);
                    engineCmd.Parameters.AddWithValue("@code", code);
                    var engineResult = await engineCmd.ExecuteScalarAsync(ct);
                    if (engineResult is null)
                    {
                        await tx.RollbackAsync(ct);
                        return Results.NotFound(new { error = "engine_not_found", code });
                    }

                    var engineId = Convert.ToInt64(engineResult);
                    if (!engineIds.Add(engineId))
                        continue;

                    await using var fitCmd = new MySqlCommand(@"INSERT IGNORE INTO PartFitment(part_id, engine_family_id, years_start, years_end, notes)
                                                                 VALUES(@part, @engine, NULL, NULL, NULL)", conn, (MySqlTransaction)tx);
                    fitCmd.Parameters.AddWithValue("@part", partId);
                    fitCmd.Parameters.AddWithValue("@engine", engineId);
                    await fitCmd.ExecuteNonQueryAsync(ct);
                }
            }

            // Vendor
            await using (var upsertVendor = new MySqlCommand("INSERT INTO Vendor(name) VALUES(@name) ON DUPLICATE KEY UPDATE name=VALUES(name)", conn, (MySqlTransaction)tx))
            {
                upsertVendor.Parameters.AddWithValue("@name", vendor);
                await upsertVendor.ExecuteNonQueryAsync(ct);
            }

            long vendorId;
            await using (var fetchVendor = new MySqlCommand("SELECT vendor_id FROM Vendor WHERE name=@name", conn, (MySqlTransaction)tx))
            {
                fetchVendor.Parameters.AddWithValue("@name", vendor);
                var vendorResult = await fetchVendor.ExecuteScalarAsync(ct);
                vendorId = vendorResult is null ? 0 : Convert.ToInt64(vendorResult);
            }

            if (vendorId == 0)
            {
                await tx.RollbackAsync(ct);
                return Results.Problem(title: "Ingest failed", detail: "Could not determine vendor id", statusCode: 500);
            }

            await using (var insertOffering = new MySqlCommand(@"INSERT INTO PartOffering(part_id, vendor_id, price, currency, url, availability)
                                                                VALUES(@part, @vendor, @price, @currency, @url, 'in_stock')", conn, (MySqlTransaction)tx))
            {
                insertOffering.Parameters.AddWithValue("@part", partId);
                insertOffering.Parameters.AddWithValue("@vendor", vendorId);
                insertOffering.Parameters.AddWithValue("@price", price);
                insertOffering.Parameters.AddWithValue("@currency", currency);
                insertOffering.Parameters.AddWithValue("@url", (object?)url ?? DBNull.Value);
                await insertOffering.ExecuteNonQueryAsync(ct);
            }

            await tx.CommitAsync(ct);
            return Results.Json(new { part_id = partId });
        }
        catch (MySqlException ex) when (ex.SqlState == "45000")
        {
            await tx.RollbackAsync(ct);
            return Results.BadRequest(new { error = "not_leaf", message = ex.Message });
        }
        catch (Exception)
        {
            await tx.RollbackAsync(ct);
            throw;
        }
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Ingest part failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Dangerous: wipe data to re-ingest (admin-only)
app.MapPost("/api/admin/wipe", async (HttpContext ctx, HttpRequest req) =>
{
    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    var body = await req.ReadFromJsonAsync<Dictionary<string, object?>>();
    var scope = body != null && body.TryGetValue("scope", out var s) ? Convert.ToString(s) : "catalog"; // catalog | all
    var includeEngines = body != null && body.TryGetValue("include_engines", out var ie) && bool.TryParse(Convert.ToString(ie), out var b) ? b : false;
    var confirm = body != null && body.TryGetValue("confirm", out var c) ? Convert.ToString(c) : null;
    if (!string.Equals(confirm, "WIPE", StringComparison.Ordinal))
        return Results.BadRequest(new { error = "Confirmation required. Include { \"confirm\": \"WIPE\" } in body." });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync();
        await using var tx = await conn.BeginTransactionAsync();

        async Task Exec(string sql)
        {
            await using var cmd = new MySqlCommand(sql, conn, (MySqlTransaction)tx);
            await cmd.ExecuteNonQueryAsync();
        }

        if (string.Equals(scope, "all", StringComparison.OrdinalIgnoreCase))
        {
            await Exec("DELETE FROM ClickAttribution");
            await Exec("DELETE FROM OrderItem");
            await Exec("DELETE FROM `Order`");
            await Exec("DELETE FROM CartItem");
            await Exec("DELETE FROM Cart");
            await Exec("DELETE FROM BuildSelection");
            await Exec("DELETE FROM Build");
        }

        // Catalog data
        await Exec("DELETE FROM PartOffering");
        await Exec("DELETE FROM AffiliateProgram");
        await Exec("DELETE FROM PartFitment");
        await Exec("DELETE FROM PartComponent");
        await Exec("DELETE FROM PartCategory");
        await Exec("DELETE FROM Part");
        await Exec("DELETE FROM Vendor");
        await Exec("DELETE FROM Brand");
        await Exec("DELETE FROM CategoryEdge");
        await Exec("DELETE FROM CategoryRequirement");
        await Exec("DELETE FROM Category");
        await Exec("DELETE FROM CategoryTree");
        await Exec("DELETE FROM UserPlan");
        await Exec("DELETE FROM Plan");

        if (includeEngines)
        {
            await Exec("DELETE FROM EngineFamilyVehicle");
            await Exec("DELETE FROM EngineFamily");
        }

        await tx.CommitAsync();
        return Results.Json(new { ok = true, scope, include_engines = includeEngines });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Wipe failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: list click attribution entries with filters and pagination
app.MapGet("/api/admin/clicks", async (
    HttpContext ctx,
    string? from,
    string? to,
    string? q,
    string? vendor,
    string? sku,
    string? buildId,
    int page = 1,
    int pageSize = 50,
    string sort = "recent",
    CancellationToken ct = default) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    if (!TryParseDateQuery(from, out var fromDate))
        return Results.BadRequest(new { error = "invalid_from_date" });
    if (!TryParseDateQuery(to, out var toDate))
        return Results.BadRequest(new { error = "invalid_to_date" });

    var search = string.IsNullOrWhiteSpace(q) ? null : q.Trim();
    var vendorFilter = string.IsNullOrWhiteSpace(vendor) ? null : vendor.Trim();
    var skuFilter = string.IsNullOrWhiteSpace(sku) ? null : sku.Trim();
    long? buildFilter = null;
    if (!string.IsNullOrWhiteSpace(buildId))
    {
        if (!long.TryParse(buildId, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsedBuild))
            return Results.BadRequest(new { error = "invalid_build_id" });
        buildFilter = parsedBuild;
    }
    var pageNumber = Math.Max(1, page);
    var limit = Math.Clamp(pageSize, 1, 200);
    var offset = (pageNumber - 1) * limit;
    var orderClause = sort?.Trim().ToLowerInvariant() switch
    {
        "vendor" => "v.name ASC, ca.clicked_at DESC",
        "part" => "p.name ASC, ca.clicked_at DESC",
        _ => "ca.clicked_at DESC"
    };

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureClickAttributionSchemaAsync(conn, ct);

        const string whereClause = @"
            WHERE (@from IS NULL OR ca.clicked_at >= @from)
              AND (@to   IS NULL OR ca.clicked_at <  @to)
              AND (@vendor IS NULL OR v.name = @vendor)
              AND (@sku    IS NULL OR p.sku  = @sku)
              AND (@build  IS NULL OR ca.build_id = @build)
              AND (@q IS NULL OR p.name LIKE CONCAT('%', @q, '%')
                               OR p.sku LIKE CONCAT('%', @q, '%')
                               OR v.name LIKE CONCAT('%', @q, '%'))";

        var rows = new List<Dictionary<string, object?>>(limit);
        var sql = @"SELECT
                ca.click_id,
                ca.clicked_at,
                p.part_id,
                p.sku,
                p.name AS part_name,
                v.vendor_id,
                v.name AS vendor_name,
                ca.build_id,
                ca.referrer,
                ca.utm_source,
                ca.utm_medium,
                ca.utm_campaign
            FROM ClickAttribution ca
            JOIN Part   p ON p.part_id = ca.part_id
            JOIN Vendor v ON v.vendor_id = ca.vendor_id
            " + whereClause + @"
            ORDER BY " + orderClause + @"
            LIMIT @limit OFFSET @offset";

        await using (var cmd = new MySqlCommand(sql, conn))
        {
            cmd.Parameters.AddWithValue("@from", (object?)fromDate ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@to", (object?)toDate ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@vendor", (object?)vendorFilter ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@sku", (object?)skuFilter ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@build", (object?)buildFilter ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@q", (object?)search ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@limit", limit);
            cmd.Parameters.AddWithValue("@offset", offset);

            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
                {
                    ["click_id"] = reader.GetInt64(0),
                    ["clicked_at"] = reader.GetDateTime(1),
                    ["part_id"] = reader.GetInt64(2),
                    ["sku"] = reader.IsDBNull(3) ? null : reader.GetString(3),
                    ["part_name"] = reader.IsDBNull(4) ? null : reader.GetString(4),
                    ["vendor_id"] = reader.GetInt64(5),
                    ["vendor_name"] = reader.IsDBNull(6) ? null : reader.GetString(6),
                    ["build_id"] = reader.IsDBNull(7) ? null : reader.GetValue(7),
                    ["referrer"] = reader.IsDBNull(8) ? null : reader.GetString(8),
                    ["utm_source"] = reader.IsDBNull(9) ? null : reader.GetString(9),
                    ["utm_medium"] = reader.IsDBNull(10) ? null : reader.GetString(10),
                    ["utm_campaign"] = reader.IsDBNull(11) ? null : reader.GetString(11)
                };
                rows.Add(row);
            }
        }

        var totalSql = @"SELECT COUNT(*)
            FROM ClickAttribution ca
            JOIN Part   p ON p.part_id = ca.part_id
            JOIN Vendor v ON v.vendor_id = ca.vendor_id
            " + whereClause;

        await using var totalCmd = new MySqlCommand(totalSql, conn);
        totalCmd.Parameters.AddWithValue("@from", (object?)fromDate ?? DBNull.Value);
        totalCmd.Parameters.AddWithValue("@to", (object?)toDate ?? DBNull.Value);
        totalCmd.Parameters.AddWithValue("@vendor", (object?)vendorFilter ?? DBNull.Value);
        totalCmd.Parameters.AddWithValue("@sku", (object?)skuFilter ?? DBNull.Value);
        totalCmd.Parameters.AddWithValue("@build", (object?)buildFilter ?? DBNull.Value);
        totalCmd.Parameters.AddWithValue("@q", (object?)search ?? DBNull.Value);

        var totalObj = await totalCmd.ExecuteScalarAsync(ct);
        var total = totalObj is null ? 0 : Convert.ToInt32(totalObj);

        return Results.Json(new { rows, total, page = pageNumber, pageSize = limit });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Fetch click attribution failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: click attribution summary (top vendors/parts and trend)
app.MapGet("/api/admin/clicks/summary", async (
    HttpContext ctx,
    string? from,
    string? to,
    int limit = 10,
    CancellationToken ct = default) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    var top = Math.Clamp(limit, 1, 100);

    if (!TryParseDateQuery(from, out var fromDate))
        return Results.BadRequest(new { error = "invalid_from_date" });
    if (!TryParseDateQuery(to, out var toDate))
        return Results.BadRequest(new { error = "invalid_to_date" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureClickAttributionSchemaAsync(conn, ct);

        var byVendor = new List<object>();
        const string byVendorSql = @"SELECT v.name AS vendor, COUNT(*) AS clicks
            FROM ClickAttribution ca
            JOIN Vendor v ON v.vendor_id = ca.vendor_id
            WHERE (@from IS NULL OR ca.clicked_at >= @from)
              AND (@to   IS NULL OR ca.clicked_at <  @to)
            GROUP BY v.vendor_id
            ORDER BY clicks DESC
            LIMIT @limit";

        await using (var cmd = new MySqlCommand(byVendorSql, conn))
        {
            cmd.Parameters.AddWithValue("@from", (object?)fromDate ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@to", (object?)toDate ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@limit", top);

            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                byVendor.Add(new
                {
                    vendor = reader.IsDBNull(0) ? null : reader.GetString(0),
                    clicks = reader.IsDBNull(1) ? 0 : Convert.ToInt32(reader.GetValue(1))
                });
            }
        }

        var byPart = new List<object>();
        const string byPartSql = @"SELECT p.sku AS sku, p.name AS part_name, COUNT(*) AS clicks
            FROM ClickAttribution ca
            JOIN Part p ON p.part_id = ca.part_id
            WHERE (@from IS NULL OR ca.clicked_at >= @from)
              AND (@to   IS NULL OR ca.clicked_at <  @to)
            GROUP BY p.part_id
            ORDER BY clicks DESC
            LIMIT @limit";

        await using (var cmd = new MySqlCommand(byPartSql, conn))
        {
            cmd.Parameters.AddWithValue("@from", (object?)fromDate ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@to", (object?)toDate ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@limit", top);

            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                byPart.Add(new
                {
                    sku = reader.IsDBNull(0) ? null : reader.GetString(0),
                    name = reader.IsDBNull(1) ? null : reader.GetString(1),
                    clicks = reader.IsDBNull(2) ? 0 : Convert.ToInt32(reader.GetValue(2))
                });
            }
        }

        var byDay = new List<object>();
        const string byDaySql = @"SELECT DATE(ca.clicked_at) AS day, COUNT(*) AS clicks
            FROM ClickAttribution ca
            WHERE (@from IS NULL OR ca.clicked_at >= @from)
              AND (@to   IS NULL OR ca.clicked_at <  @to)
            GROUP BY DATE(ca.clicked_at)
            ORDER BY day ASC";

        await using (var cmd = new MySqlCommand(byDaySql, conn))
        {
            cmd.Parameters.AddWithValue("@from", (object?)fromDate ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@to", (object?)toDate ?? DBNull.Value);

            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                byDay.Add(new
                {
                    day = reader.IsDBNull(0) ? (DateTime?)null : reader.GetDateTime(0),
                    clicks = reader.IsDBNull(1) ? 0 : Convert.ToInt32(reader.GetValue(1))
                });
            }
        }

        const string totalSql = @"SELECT COUNT(*)
            FROM ClickAttribution ca
            WHERE (@from IS NULL OR ca.clicked_at >= @from)
              AND (@to   IS NULL OR ca.clicked_at <  @to)";

        await using var totalCmd = new MySqlCommand(totalSql, conn);
        totalCmd.Parameters.AddWithValue("@from", (object?)fromDate ?? DBNull.Value);
        totalCmd.Parameters.AddWithValue("@to", (object?)toDate ?? DBNull.Value);

        var totalObj = await totalCmd.ExecuteScalarAsync(ct);
        var total = totalObj is null ? 0 : Convert.ToInt32(totalObj);

        return Results.Json(new { total, byVendor, byPart, byDay });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Fetch click attribution summary failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: export click attribution CSV with filters
app.MapGet("/api/admin/clicks/export.csv", async (
    HttpContext ctx,
    string? from,
    string? to,
    string? vendor,
    string? sku,
    string? buildId,
    string? q,
    CancellationToken ct = default) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    if (!TryParseDateQuery(from, out var fromDate))
        return Results.BadRequest(new { error = "invalid_from_date" });
    if (!TryParseDateQuery(to, out var toDate))
        return Results.BadRequest(new { error = "invalid_to_date" });

    var search = string.IsNullOrWhiteSpace(q) ? null : q.Trim();
    var vendorFilter = string.IsNullOrWhiteSpace(vendor) ? null : vendor.Trim();
    var skuFilter = string.IsNullOrWhiteSpace(sku) ? null : sku.Trim();
    long? buildFilter = null;
    if (!string.IsNullOrWhiteSpace(buildId))
    {
        if (!long.TryParse(buildId, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsedBuild))
            return Results.BadRequest(new { error = "invalid_build_id" });
        buildFilter = parsedBuild;
    }

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureClickAttributionSchemaAsync(conn, ct);

        const string sql = @"SELECT
                ca.click_id,
                ca.clicked_at,
                p.sku,
                p.name AS part_name,
                v.name AS vendor_name,
                ca.build_id,
                ca.referrer,
                ca.utm_source,
                ca.utm_medium,
                ca.utm_campaign
            FROM ClickAttribution ca
            JOIN Part   p ON p.part_id = ca.part_id
            JOIN Vendor v ON v.vendor_id = ca.vendor_id
            WHERE (@from IS NULL OR ca.clicked_at >= @from)
              AND (@to   IS NULL OR ca.clicked_at <  @to)
              AND (@vendor IS NULL OR v.name = @vendor)
              AND (@sku    IS NULL OR p.sku  = @sku)
              AND (@build  IS NULL OR ca.build_id = @build)
              AND (@q IS NULL OR p.name LIKE CONCAT('%', @q, '%')
                               OR p.sku LIKE CONCAT('%', @q, '%')
                               OR v.name LIKE CONCAT('%', @q, '%'))
            ORDER BY ca.clicked_at DESC";

        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@from", (object?)fromDate ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@to", (object?)toDate ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@vendor", (object?)vendorFilter ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@sku", (object?)skuFilter ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@build", (object?)buildFilter ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@q", (object?)search ?? DBNull.Value);

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        var sb = new StringBuilder();
        sb.AppendLine("click_id,clicked_at,sku,part_name,vendor_name,build_id,referrer,utm_source,utm_medium,utm_campaign");

        static string EscapeCsv(string? value)
        {
            if (string.IsNullOrEmpty(value))
                return string.Empty;
            var needsQuotes = value.Contains(',') || value.Contains('"') || value.Contains('\n') || value.Contains('\r');
            var escaped = value.Replace("\"", "\"\"");
            return needsQuotes ? $"\"{escaped}\"" : escaped;
        }

        while (await reader.ReadAsync(ct))
        {
            var clickId = reader.GetInt64(0);
            var clickedAt = reader.GetDateTime(1);
            var skuValue = reader.IsDBNull(2) ? null : reader.GetString(2);
            var partName = reader.IsDBNull(3) ? null : reader.GetString(3);
            var vendorName = reader.IsDBNull(4) ? null : reader.GetString(4);
            var buildValue = reader.IsDBNull(5) ? (long?)null : reader.GetInt64(5);
            var referrerValue = reader.IsDBNull(6) ? null : reader.GetString(6);
            var utmSource = reader.IsDBNull(7) ? null : reader.GetString(7);
            var utmMedium = reader.IsDBNull(8) ? null : reader.GetString(8);
            var utmCampaign = reader.IsDBNull(9) ? null : reader.GetString(9);

            sb.Append(clickId);
            sb.Append(',');
            sb.Append(clickedAt.ToUniversalTime().ToString("O"));
            sb.Append(',');
            sb.Append(EscapeCsv(skuValue));
            sb.Append(',');
            sb.Append(EscapeCsv(partName));
            sb.Append(',');
            sb.Append(EscapeCsv(vendorName));
            sb.Append(',');
            sb.Append(buildValue?.ToString() ?? string.Empty);
            sb.Append(',');
            sb.Append(EscapeCsv(referrerValue));
            sb.Append(',');
            sb.Append(EscapeCsv(utmSource));
            sb.Append(',');
            sb.Append(EscapeCsv(utmMedium));
            sb.Append(',');
            sb.Append(EscapeCsv(utmCampaign));
            sb.AppendLine();
        }

        var fileName = $"clicks-{DateTime.UtcNow:yyyyMMddHHmmss}.csv";
        var bytes = Encoding.UTF8.GetBytes(sb.ToString());
        return Results.File(bytes, "text/csv", fileName);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Export click attribution failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: list users with plan and usage details
app.MapGet("/api/admin/users", async (HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.Identity?.IsAuthenticated ?? true)
        return Results.Unauthorized();
    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    var query = ctx.Request.Query;
    var search = query.TryGetValue("q", out var qv) ? qv.ToString()?.Trim() : null;
    var page = query.TryGetValue("page", out var pv) && int.TryParse(pv, out var parsedPage) && parsedPage > 0 ? parsedPage : 1;
    var pageSize = query.TryGetValue("page_size", out var psv) && int.TryParse(psv, out var parsedSize) && parsedSize > 0 ? Math.Min(parsedSize, 200) : 50;
    var offset = (page - 1) * pageSize;

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureUserAccountTableAsync(conn, ct);
        await EnsurePlanTablesAsync(conn, ct);
        await EnsureBuildColumnsAsync(conn, ct);

        const string sql = @"SELECT
                ua.user_id,
                ua.email,
                ua.display_name,
                ua.is_admin,
                ua.is_banned,
                p.code AS plan_code,
                CAST(JSON_UNQUOTE(JSON_EXTRACT(p.features_json, '$.max_active_builds')) AS SIGNED) AS max_active_builds,
                CAST(JSON_UNQUOTE(JSON_EXTRACT(p.features_json, '$.max_total_builds')) AS SIGNED) AS max_total_builds,
                COALESCE(bstats.active_builds, 0) AS active_builds,
                COALESCE(bstats.total_builds, 0) AS total_builds,
                ua.created_at
            FROM UserAccount ua
            LEFT JOIN (
                SELECT user_id, plan_id
                FROM (
                    SELECT up.user_id,
                           up.plan_id,
                           ROW_NUMBER() OVER (
                               PARTITION BY up.user_id
                               ORDER BY CASE up.status WHEN 'active' THEN 0 WHEN 'past_due' THEN 1 ELSE 2 END,
                                        up.current_period_start DESC
                           ) AS rn
                    FROM UserPlan up
                ) ranked
                WHERE rn = 1
            ) active_plan ON active_plan.user_id = ua.user_id
            LEFT JOIN Plan p ON p.plan_id = active_plan.plan_id
            LEFT JOIN (
                SELECT user_id,
                       SUM(CASE WHEN is_archived = FALSE THEN 1 ELSE 0 END) AS active_builds,
                       COUNT(*) AS total_builds
                FROM Build
                GROUP BY user_id
            ) bstats ON bstats.user_id = ua.user_id
            WHERE (@search IS NULL
                   OR ua.email LIKE CONCAT('%', @search, '%')
                   OR ua.display_name LIKE CONCAT('%', @search, '%'))
            ORDER BY ua.created_at DESC
            LIMIT @limit OFFSET @offset";

        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@search", string.IsNullOrWhiteSpace(search) ? DBNull.Value : search);
        cmd.Parameters.AddWithValue("@limit", pageSize);
        cmd.Parameters.AddWithValue("@offset", offset);

        var rows = new List<AdminUserSummary>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                var summary = new AdminUserSummary
                {
                    UserId = reader.GetInt64(0),
                    Email = reader.IsDBNull(1) ? string.Empty : reader.GetString(1),
                    DisplayName = reader.IsDBNull(2) ? null : reader.GetString(2),
                    IsAdmin = !reader.IsDBNull(3) && reader.GetBoolean(3),
                    IsBanned = !reader.IsDBNull(4) && reader.GetBoolean(4),
                    PlanCode = reader.IsDBNull(5) ? null : reader.GetString(5),
                    MaxActiveBuilds = reader.IsDBNull(6) ? (int?)null : Convert.ToInt32(reader.GetValue(6)),
                    MaxTotalBuilds = reader.IsDBNull(7) ? (int?)null : Convert.ToInt32(reader.GetValue(7)),
                    ActiveBuilds = reader.IsDBNull(8) ? 0 : Convert.ToInt32(reader.GetValue(8)),
                    TotalBuilds = reader.IsDBNull(9) ? 0 : Convert.ToInt32(reader.GetValue(9)),
                    CreatedAt = reader.GetDateTime(10)
                };
                rows.Add(summary);
            }

        return Results.Json(rows);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "List admin users failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: update user flags/display name
app.MapPatch("/api/admin/users/{userId:long}", async (long userId, AdminUserPatchRequest body, HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);
    if (!ctx.User.Identity?.IsAuthenticated ?? true)
        return Results.Unauthorized();
    if (!ctx.User.IsAdmin())
        return Results.Forbid();
    if (body is null)
        return Results.BadRequest(new { error = "Invalid JSON" });

    var setClauses = new List<string>();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureUserAccountTableAsync(conn, ct);

        await using var cmd = new MySqlCommand { Connection = conn };

        if (body.IsAdmin.HasValue)
        {
            setClauses.Add("is_admin=@is_admin");
            cmd.Parameters.AddWithValue("@is_admin", body.IsAdmin.Value);
        }

        if (body.IsBanned.HasValue)
        {
            setClauses.Add("is_banned=@is_banned");
            cmd.Parameters.AddWithValue("@is_banned", body.IsBanned.Value);
        }

        if (body.DisplayName is not null)
        {
            var trimmed = string.IsNullOrWhiteSpace(body.DisplayName) ? null : body.DisplayName.Trim();
            setClauses.Add("display_name=@display_name");
            cmd.Parameters.AddWithValue("@display_name", (object?)trimmed ?? DBNull.Value);
        }

        if (setClauses.Count == 0)
            return Results.BadRequest(new { error = "no_fields" });

        setClauses.Add("updated_at = CURRENT_TIMESTAMP");
        cmd.CommandText = $"UPDATE UserAccount SET {string.Join(", ", setClauses)} WHERE user_id=@uid";
        cmd.Parameters.AddWithValue("@uid", userId);

        var rows = await cmd.ExecuteNonQueryAsync(ct);
        if (rows == 0)
            return Results.NotFound(new { error = "user_not_found" });

        return Results.Json(new { ok = true });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Update user failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: assign a plan by code
app.MapPost("/api/admin/users/{userId:long}/plan", async (long userId, AdminAssignPlanRequest body, HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);
    if (!ctx.User.Identity?.IsAuthenticated ?? true)
        return Results.Unauthorized();
    if (!ctx.User.IsAdmin())
        return Results.Forbid();
    if (body is null || string.IsNullOrWhiteSpace(body.PlanCode))
        return Results.BadRequest(new { error = "plan_code_required" });

    var planCode = body.PlanCode.Trim();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureUserAccountTableAsync(conn, ct);
        await EnsurePlanTablesAsync(conn, ct);

        long? planId;
        await using (var planCmd = new MySqlCommand("SELECT plan_id FROM Plan WHERE code=@code", conn))
        {
            planCmd.Parameters.AddWithValue("@code", planCode);
            var result = await planCmd.ExecuteScalarAsync(ct);
            planId = result is null ? null : Convert.ToInt64(result);
        }

        if (planId is null)
            return Results.NotFound(new { error = "plan_not_found" });

        await using var tx = await conn.BeginTransactionAsync(ct);

        await using (var userCheck = new MySqlCommand("SELECT 1 FROM UserAccount WHERE user_id=@uid", conn, (MySqlTransaction)tx))
        {
            userCheck.Parameters.AddWithValue("@uid", userId);
            if (await userCheck.ExecuteScalarAsync(ct) is null)
            {
                await tx.RollbackAsync(ct);
                return Results.NotFound(new { error = "user_not_found" });
            }
        }

        await using (var cancel = new MySqlCommand("UPDATE UserPlan SET status='canceled', current_period_end=NOW() WHERE user_id=@uid AND status='active'", conn, (MySqlTransaction)tx))
        {
            cancel.Parameters.AddWithValue("@uid", userId);
            await cancel.ExecuteNonQueryAsync(ct);
        }

        await using (var insert = new MySqlCommand("INSERT INTO UserPlan(user_id, plan_id, status, current_period_start) VALUES(@uid, @pid, 'active', NOW())", conn, (MySqlTransaction)tx))
        {
            insert.Parameters.AddWithValue("@uid", userId);
            insert.Parameters.AddWithValue("@pid", planId.Value);
            await insert.ExecuteNonQueryAsync(ct);
        }

        await tx.CommitAsync(ct);
        return Results.Json(new { ok = true });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Assign plan failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: delete all builds for a user
app.MapDelete("/api/admin/users/{userId:long}/builds", async (long userId, HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);
    if (!ctx.User.Identity?.IsAuthenticated ?? true)
        return Results.Unauthorized();
    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureUserAccountTableAsync(conn, ct);
        await EnsureBuildColumnsAsync(conn, ct);

        await using (var userCheck = new MySqlCommand("SELECT 1 FROM UserAccount WHERE user_id=@uid", conn))
        {
            userCheck.Parameters.AddWithValue("@uid", userId);
            if (await userCheck.ExecuteScalarAsync(ct) is null)
            {
                return Results.NotFound(new { error = "user_not_found" });
            }
        }

        int deleted;
        await using (var delete = new MySqlCommand("DELETE FROM Build WHERE user_id=@uid", conn))
        {
            delete.Parameters.AddWithValue("@uid", userId);
            deleted = await delete.ExecuteNonQueryAsync(ct);
        }

        return Results.Json(new { deleted });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Delete user builds failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: list plans and limits
app.MapGet("/api/admin/plans", async (HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsurePlanTablesAsync(conn, ct);

        await using var cmd = new MySqlCommand(@"SELECT p.plan_id, p.code, p.name, p.monthly_price, p.currency, p.is_archived,
                                                      COALESCE(pl.max_active_builds, 0) AS max_active_builds,
                                                      COALESCE(pl.max_total_builds, 0)  AS max_total_builds
                                               FROM Plan p
                                               LEFT JOIN PlanLimits pl ON pl.plan_id = p.plan_id
                                               ORDER BY p.is_archived, p.monthly_price, p.plan_id", conn);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        var rows = new List<Dictionary<string, object?>>(8);
        while (await reader.ReadAsync(ct))
        {
            var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
            {
                ["plan_id"] = reader.GetInt64(0),
                ["code"] = reader.GetString(1),
                ["name"] = reader.GetString(2),
                ["monthly_price"] = reader.GetDecimal(3),
                ["currency"] = reader.GetString(4),
                ["is_archived"] = reader.GetBoolean(5),
                ["max_active_builds"] = reader.GetValue(6),
                ["max_total_builds"] = reader.GetValue(7)
            };
            rows.Add(row);
        }

        return Results.Json(rows);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Fetch plans failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: create plan
app.MapPost("/api/admin/plans", async (HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    var body = await ctx.Request.ReadFromJsonAsync<AdminPlanCreateRequest>(cancellationToken: ct);
    if (body is null)
        return Results.BadRequest(new { error = "invalid_payload" });

    var code = body.Code?.Trim();
    var name = body.Name?.Trim();
    if (string.IsNullOrWhiteSpace(code) || string.IsNullOrWhiteSpace(name))
        return Results.BadRequest(new { error = "code_and_name_required" });

    if (code.Length > 60 || name.Length > 120)
        return Results.BadRequest(new { error = "value_too_long" });

    var monthlyPrice = body.MonthlyPrice ?? 0m;
    if (monthlyPrice < 0)
        return Results.BadRequest(new { error = "monthly_price_invalid" });

    var maxActive = body.MaxActiveBuilds ?? 0;
    var maxTotal = body.MaxTotalBuilds ?? 0;
    if (maxActive < 0 || maxTotal < 0)
        return Results.BadRequest(new { error = "limits_must_be_positive" });

    var currency = string.IsNullOrWhiteSpace(body.Currency) ? "USD" : body.Currency.Trim().ToUpperInvariant();
    if (currency.Length != 3)
        return Results.BadRequest(new { error = "currency_invalid" });

    var normalizedCode = code.ToUpperInvariant();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsurePlanTablesAsync(conn, ct);
        await using var tx = await conn.BeginTransactionAsync(ct);

        long planId;
        await using (var planCmd = new MySqlCommand("INSERT INTO Plan(code, name, monthly_price, currency) VALUES(@code,@name,@price,@currency); SELECT LAST_INSERT_ID();", conn, (MySqlTransaction)tx))
        {
            planCmd.Parameters.AddWithValue("@code", normalizedCode);
            planCmd.Parameters.AddWithValue("@name", name);
            planCmd.Parameters.AddWithValue("@price", monthlyPrice);
            planCmd.Parameters.AddWithValue("@currency", currency);
            try
            {
                var result = await planCmd.ExecuteScalarAsync(ct);
                planId = Convert.ToInt64(result);
            }
            catch (MySqlException ex) when (ex.Number == 1062)
            {
                await tx.RollbackAsync(ct);
                return Results.Conflict(new { error = "plan_code_exists" });
            }
        }

        await using (var limitCmd = new MySqlCommand("INSERT INTO PlanLimits (plan_id, max_active_builds, max_total_builds) VALUES(@pid, @active, @total)", conn, (MySqlTransaction)tx))
        {
            limitCmd.Parameters.AddWithValue("@pid", planId);
            limitCmd.Parameters.AddWithValue("@active", maxActive);
            limitCmd.Parameters.AddWithValue("@total", maxTotal);
            await limitCmd.ExecuteNonQueryAsync(ct);
        }

        await tx.CommitAsync(ct);

        var response = new
        {
            plan_id = planId,
            code = normalizedCode,
            name,
            monthly_price = monthlyPrice,
            currency,
            max_active_builds = maxActive,
            max_total_builds = maxTotal
        };

        return Results.Created($"/api/admin/plans/{planId}", response);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Create plan failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: update plan metadata and limits
app.MapPatch("/api/admin/plans/{planId:long}", async (long planId, HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    var body = await ctx.Request.ReadFromJsonAsync<AdminPlanUpdateRequest>(cancellationToken: ct);
    if (body is null)
        return Results.BadRequest(new { error = "invalid_payload" });

    var hasPlanUpdate = body.Name is not null || body.MonthlyPrice.HasValue;
    var hasLimitUpdate = body.MaxActiveBuilds.HasValue || body.MaxTotalBuilds.HasValue;
    if (!hasPlanUpdate && !hasLimitUpdate)
        return Results.BadRequest(new { error = "no_fields" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsurePlanTablesAsync(conn, ct);
        await using var tx = await conn.BeginTransactionAsync(ct);

        if (hasPlanUpdate)
        {
            await using var planCmd = new MySqlCommand("UPDATE Plan SET name = COALESCE(@name, name), monthly_price = COALESCE(@price, monthly_price) WHERE plan_id=@id", conn, (MySqlTransaction)tx);
            planCmd.Parameters.AddWithValue("@name", (object?)body.Name ?? DBNull.Value);
            planCmd.Parameters.AddWithValue("@price", body.MonthlyPrice.HasValue ? body.MonthlyPrice.Value : (object)DBNull.Value);
            planCmd.Parameters.AddWithValue("@id", planId);
            await planCmd.ExecuteNonQueryAsync(ct);
        }

        if (hasLimitUpdate)
        {
            await using var limitCmd = new MySqlCommand(@"INSERT INTO PlanLimits (plan_id, max_active_builds, max_total_builds)
                                                           VALUES (@id, COALESCE(@active, 3), COALESCE(@total, 10))
                                                           ON DUPLICATE KEY UPDATE
                                                               max_active_builds = COALESCE(@active, max_active_builds),
                                                               max_total_builds  = COALESCE(@total, max_total_builds)", conn, (MySqlTransaction)tx);
            limitCmd.Parameters.AddWithValue("@id", planId);
            limitCmd.Parameters.AddWithValue("@active", body.MaxActiveBuilds.HasValue ? body.MaxActiveBuilds.Value : (object)DBNull.Value);
            limitCmd.Parameters.AddWithValue("@total", body.MaxTotalBuilds.HasValue ? body.MaxTotalBuilds.Value : (object)DBNull.Value);
            await limitCmd.ExecuteNonQueryAsync(ct);
        }

        await tx.CommitAsync(ct);
        return Results.Ok(new { ok = true });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Update plan failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");


// Admin: list roles
app.MapGet("/api/admin/roles", async (HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);
    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureRoleTablesAsync(conn, ct);

        var rows = new List<Dictionary<string, object?>>(8);
        await using var cmd = new MySqlCommand("SELECT role_id, code, name, description, is_system FROM AppRole ORDER BY is_system DESC, name", conn);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
            {
                ["role_id"] = reader.GetInt64(0),
                ["code"] = reader.GetString(1),
                ["name"] = reader.GetString(2),
                ["description"] = reader.IsDBNull(3) ? null : reader.GetString(3),
                ["is_system"] = reader.GetBoolean(4)
            };
            rows.Add(row);
        }

        return Results.Json(rows);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Fetch roles failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Admin: create a custom role
app.MapPost("/api/admin/roles", async (HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);
    if (!ctx.User.IsAdmin())
        return Results.Forbid();

    var body = await ctx.Request.ReadFromJsonAsync<AdminRoleCreateRequest>(cancellationToken: ct);
    if (body is null)
        return Results.BadRequest(new { error = "invalid_payload" });

    var code = body.Code?.Trim();
    var name = body.Name?.Trim();
    var description = string.IsNullOrWhiteSpace(body.Description) ? null : body.Description.Trim();

    if (string.IsNullOrWhiteSpace(code) || string.IsNullOrWhiteSpace(name))
        return Results.BadRequest(new { error = "code_and_name_required" });

    if (code.Length > 64 || name.Length > 120)
        return Results.BadRequest(new { error = "value_too_long" });

    var normalizedCode = code.ToLowerInvariant();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureRoleTablesAsync(conn, ct);

        await using var cmd = new MySqlCommand("INSERT INTO AppRole (code, name, description) VALUES (@code, @name, @desc); SELECT LAST_INSERT_ID();", conn);
        cmd.Parameters.AddWithValue("@code", normalizedCode);
        cmd.Parameters.AddWithValue("@name", name);
        cmd.Parameters.AddWithValue("@desc", (object?)description ?? DBNull.Value);

        long roleId;
        try
        {
            var result = await cmd.ExecuteScalarAsync(ct);
            roleId = Convert.ToInt64(result);
        }
        catch (MySqlException ex) when (ex.Number == 1062)
        {
            return Results.Conflict(new { error = "role_code_exists" });
        }

        return Results.Created($"/api/admin/roles/{roleId}", new { role_id = roleId, code = normalizedCode, name, description });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Create role failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");



// Admin: transfer build ownership
app.MapPost("/api/admin/builds/{buildId:long}/transfer", async (long buildId, AdminTransferBuildRequest body, HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);
    if (!ctx.User.Identity?.IsAuthenticated ?? true)
        return Results.Unauthorized();
    if (!ctx.User.IsAdmin())
        return Results.Forbid();
    if (body is null || body.UserId <= 0)
        return Results.BadRequest(new { error = "user_id_required" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureUserAccountTableAsync(conn, ct);
        await EnsureBuildColumnsAsync(conn, ct);
        await EnsurePlanTablesAsync(conn, ct);

        await using var tx = await conn.BeginTransactionAsync(ct);

        long? existingOwner = null;
        await using (var buildCmd = new MySqlCommand("SELECT user_id FROM Build WHERE build_id=@bid", conn, (MySqlTransaction)tx))
        {
            buildCmd.Parameters.AddWithValue("@bid", buildId);
            var ownerResult = await buildCmd.ExecuteScalarAsync(ct);
            if (ownerResult is null)
            {
                await tx.RollbackAsync(ct);
                return Results.NotFound(new { error = "build_not_found" });
            }

            existingOwner = ownerResult is DBNull ? null : Convert.ToInt64(ownerResult);
        }

        await using (var userCheck = new MySqlCommand("SELECT 1 FROM UserAccount WHERE user_id=@uid", conn, (MySqlTransaction)tx))
        {
            userCheck.Parameters.AddWithValue("@uid", body.UserId);
            if (await userCheck.ExecuteScalarAsync(ct) is null)
            {
                await tx.RollbackAsync(ct);
                return Results.NotFound(new { error = "target_user_not_found" });
            }
        }

        await using (var update = new MySqlCommand("UPDATE Build SET user_id=@uid, updated_at=CURRENT_TIMESTAMP WHERE build_id=@bid", conn, (MySqlTransaction)tx))
        {
            update.Parameters.AddWithValue("@uid", body.UserId);
            update.Parameters.AddWithValue("@bid", buildId);
            await update.ExecuteNonQueryAsync(ct);
        }

        await tx.CommitAsync(ct);
        return Results.Json(new { ok = true, previous_owner = existingOwner });
    }
    catch (Exception ex) when (ex is MySqlException sqlEx && sqlEx.SqlState == "45000")
    {
        return Results.Json(new { error = "quota_exceeded", message = ex.Message }, statusCode: 403);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Transfer build failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");


// Users: create account (returns JWT)
app.MapPost("/api/users", async (CreateUserRequest body, IEmailSender emailSender, IConfiguration cfg, HttpContext httpContext, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);
    if (body is null) return Results.BadRequest(new { error = "Invalid JSON" });

    var email = body.Email?.Trim();
    var displayName = string.IsNullOrWhiteSpace(body.DisplayName) ? null : body.DisplayName.Trim();
    if (string.IsNullOrWhiteSpace(email)) return Results.BadRequest(new { error = "email required" });
    if (string.IsNullOrWhiteSpace(body.Password)) return Results.BadRequest(new { error = "password required" });

    email = email.ToLowerInvariant();

    var passwordHash = BCrypt.Net.BCrypt.HashPassword(body.Password);
    var emailOptIn = body.EmailOptIn ?? false;
    var verificationToken = SecureTokenGenerator.CreateToken();
    var verificationExpires = DateTime.UtcNow.AddHours(24);

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureUserAccountTableAsync(conn, ct);
        await EnsurePlanTablesAsync(conn, ct);
        await using var tx = await conn.BeginTransactionAsync(ct);

        await using (var insert = new MySqlCommand("INSERT INTO UserAccount(email, display_name, password_hash, email_opt_in, email_verification_token, email_verification_expires) VALUES(@email, @display, @pwd, @opt, @verifyToken, @verifyExpires)", conn, (MySqlTransaction)tx))
        {
            insert.Parameters.AddWithValue("@email", email);
            insert.Parameters.AddWithValue("@display", (object?)displayName ?? DBNull.Value);
            insert.Parameters.AddWithValue("@pwd", passwordHash);
            insert.Parameters.AddWithValue("@opt", emailOptIn);
            insert.Parameters.AddWithValue("@verifyToken", verificationToken);
            insert.Parameters.AddWithValue("@verifyExpires", verificationExpires);
            try
            {
                await insert.ExecuteNonQueryAsync(ct);
            }
            catch (MySqlException ex) when (ex.Number == 1062)
            {
                await tx.RollbackAsync(ct);
                return Results.Conflict(new { error = "email_exists" });
            }
        }

        long userId;
        string? persistedEmail = null;
        bool isAdmin = false;
        bool isBanned = false;
        bool persistedOptIn = emailOptIn;
        bool emailVerified = false;
        bool emailBounced = false;
        bool emailUnsubscribed = false;
        await using (var fetch = new MySqlCommand("SELECT user_id, email, display_name, is_admin, is_banned, email_opt_in, email_verified_at, email_bounced, email_unsubscribed FROM UserAccount WHERE email=@email", conn, (MySqlTransaction)tx))
        {
            fetch.Parameters.AddWithValue("@email", email);
            await using var reader = await fetch.ExecuteReaderAsync(ct);
            if (!await reader.ReadAsync(ct))
            {
                await tx.RollbackAsync(ct);
                return Results.Problem(title: "Signup failed", detail: "Unable to load created user", statusCode: 500);
            }

            userId = reader.GetInt64(0);
            persistedEmail = reader.IsDBNull(1) ? null : reader.GetString(1);
            displayName = reader.IsDBNull(2) ? null : reader.GetString(2);
            isAdmin = !reader.IsDBNull(3) && reader.GetBoolean(3);
            isBanned = !reader.IsDBNull(4) && reader.GetBoolean(4);
            if (!reader.IsDBNull(5))
            {
                persistedOptIn = reader.GetBoolean(5);
            }
            emailVerified = !reader.IsDBNull(6);
            emailBounced = !reader.IsDBNull(7) && reader.GetBoolean(7);
            emailUnsubscribed = !reader.IsDBNull(8) && reader.GetBoolean(8);
        }

        try
        {
            await using var ensurePlan = new MySqlCommand(@"INSERT INTO UserPlan (user_id, plan_id, status, current_period_start, current_period_end)
                                                            SELECT @uid, p.plan_id, 'active', NOW(), NULL
                                                            FROM Plan p
                                                            WHERE p.code='FREE'
                                                              AND NOT EXISTS (
                                                                SELECT 1 FROM UserPlan up
                                                                WHERE up.user_id = @uid AND up.status='active'
                                                              )", conn, (MySqlTransaction)tx);
            ensurePlan.Parameters.AddWithValue("@uid", userId);
            await ensurePlan.ExecuteNonQueryAsync(ct);
        }
        catch (MySqlException planEx) when (planEx.Number == 1146)
        {
            // Plan/UserPlan tables not present yet; skip seeding for now.
        }

        await tx.CommitAsync(ct);

        var accountEmail = persistedEmail ?? email;
        var token = GenerateJwt(userId, accountEmail!, displayName, isAdmin, emailVerified, isBanned);

        if (!emailVerified && !string.IsNullOrWhiteSpace(accountEmail))
        {
            var baseUrl = ResolveBaseUrl(cfg, httpContext.Request);
            var link = string.IsNullOrWhiteSpace(baseUrl) ? $"/verify-email?token={verificationToken}" : $"{baseUrl}/verify-email?token={verificationToken}";
            var html = $"""
                <p>Welcome to RotorBase!</p>
                <p>Please verify your email address to enable alerts and notifications.</p>
                <p><a href="{link}">Verify your email</a></p>
                <p>This link expires in 24 hours.</p>
            """;
            var text = $"Welcome to RotorBase! Verify your email: {link}";
            try
            {
                await emailSender.SendAsync(new EmailMessage(accountEmail, "Verify your email", html, text), ct);
            }
            catch (Exception ex) when (ex is InvalidOperationException or SmtpException)
            {
                var logger = httpContext.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("SignupEmail");
                logger.LogError(ex, "Signup verification email failed for {Email}", accountEmail);

                try
                {
                    await using var cleanup = new MySqlCommand("DELETE FROM UserAccount WHERE user_id=@uid", conn);
                    cleanup.Parameters.AddWithValue("@uid", userId);
                    await cleanup.ExecuteNonQueryAsync(ct);
                }
                catch (Exception cleanupEx)
                {
                    logger.LogWarning(cleanupEx, "Cleanup failed after signup email error for {Email}", accountEmail);
                }

                return Results.BadRequest(new { error = "email_send_failed" });
            }
        }

        return Results.Json(new
        {
            token,
            user = new
            {
                user_id = userId,
                email = accountEmail,
                display_name = displayName,
                is_admin = isAdmin,
                email_opt_in = persistedOptIn,
                email_verified = emailVerified,
                email_bounced = emailBounced,
                email_unsubscribed = emailUnsubscribed,
                is_banned = isBanned
            }
        });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Create user failed", detail: ex.Message, statusCode: 500);
    }
});

// Users: login
app.MapPost("/api/auth/login", async (LoginRequest body, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);
    if (body is null) return Results.BadRequest(new { error = "Invalid JSON" });

    var email = body.Email?.Trim();
    if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(body.Password))
        return Results.BadRequest(new { error = "email_and_password_required" });

    email = email.ToLowerInvariant();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureUserAccountTableAsync(conn, ct);
        await EnsurePlanTablesAsync(conn, ct);
        await using var cmd = new MySqlCommand("SELECT user_id, email, display_name, password_hash, is_admin, is_banned, email_opt_in, email_verified_at, email_bounced, email_unsubscribed FROM UserAccount WHERE email=@email", conn);
        cmd.Parameters.AddWithValue("@email", email);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct))
            return Results.Unauthorized();

        var userId = reader.GetInt64(0);
        var persistedEmail = reader.IsDBNull(1) ? email : reader.GetString(1);
        var displayName = reader.IsDBNull(2) ? null : reader.GetString(2);
        var passwordHash = reader.IsDBNull(3) ? null : reader.GetString(3);
        var isAdmin = !reader.IsDBNull(4) && reader.GetBoolean(4);
        var isBanned = !reader.IsDBNull(5) && reader.GetBoolean(5);
        var emailOptIn = !reader.IsDBNull(6) && reader.GetBoolean(6);
        var emailVerified = !reader.IsDBNull(7);
        var emailBounced = !reader.IsDBNull(8) && reader.GetBoolean(8);
        var emailUnsubscribed = !reader.IsDBNull(9) && reader.GetBoolean(9);

        if (string.IsNullOrWhiteSpace(passwordHash) || !BCrypt.Net.BCrypt.Verify(body.Password, passwordHash))
            return Results.Unauthorized();

        if (isBanned)
            return Results.Json(new { error = "account_banned" }, statusCode: StatusCodes.Status403Forbidden);

        var token = GenerateJwt(userId, persistedEmail ?? email!, displayName, isAdmin, emailVerified, isBanned);
        return Results.Json(new
        {
            token,
            user = new
            {
                user_id = userId,
                email = persistedEmail ?? email,
                display_name = displayName,
                is_admin = isAdmin,
                email_opt_in = emailOptIn,
                email_verified = emailVerified,
                email_bounced = emailBounced,
                email_unsubscribed = emailUnsubscribed,
                is_banned = isBanned
            }
        });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Login failed", detail: ex.Message, statusCode: 500);
    }
});

app.MapGet("/verify-email", async (HttpContext ctx, IConfiguration cfg, string? token, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (string.IsNullOrWhiteSpace(token))
    {
        return Results.Redirect(BuildAbsoluteUrl(cfg, ctx.Request, "/account/plan?verify=invalid"));
    }

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureUserAccountTableAsync(conn, ct);

        long? userId = null;
        DateTime? expires = null;
        await using (var cmd = new MySqlCommand("SELECT user_id, email_verification_expires FROM UserAccount WHERE email_verification_token=@token", conn))
        {
            cmd.Parameters.AddWithValue("@token", token);
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            if (await reader.ReadAsync(ct))
            {
                userId = reader.GetInt64(0);
                expires = reader.IsDBNull(1) ? null : reader.GetDateTime(1);
            }
        }

        if (userId is null)
        {
            return Results.Redirect(BuildAbsoluteUrl(cfg, ctx.Request, "/account/plan?verify=invalid"));
        }

        if (expires.HasValue && expires.Value < DateTime.UtcNow)
        {
            return Results.Redirect(BuildAbsoluteUrl(cfg, ctx.Request, "/account/plan?verify=expired"));
        }

        await using (var update = new MySqlCommand("UPDATE UserAccount SET email_verified_at=NOW(), email_verification_token=NULL, email_verification_expires=NULL, email_bounced=FALSE WHERE user_id=@uid", conn))
        {
            update.Parameters.AddWithValue("@uid", userId.Value);
            await update.ExecuteNonQueryAsync(ct);
        }

        return Results.Redirect(BuildAbsoluteUrl(cfg, ctx.Request, "/account/plan?verify=ok"));
    }
    catch (Exception ex)
    {
        var logger = ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("VerifyEmail");
        logger.LogError(ex, "Email verification failed for token {Token}", token);
        return Results.Redirect(BuildAbsoluteUrl(cfg, ctx.Request, "/account/plan?verify=error"));
    }
});

app.MapPost("/api/auth/resend-verification", async (HttpContext ctx, IConfiguration cfg, IEmailSender emailSender, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    var userId = ctx.User.TryGetUserId();
    if (userId is null)
        return Results.Unauthorized();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureUserAccountTableAsync(conn, ct);

        string? email = null;
        DateTime? verifiedAt = null;
        DateTime? expires = null;

        await using (var cmd = new MySqlCommand("SELECT email, email_verified_at, email_verification_expires FROM UserAccount WHERE user_id=@uid", conn))
        {
            cmd.Parameters.AddWithValue("@uid", userId.Value);
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            if (!await reader.ReadAsync(ct))
            {
                return Results.NotFound(new { error = "user_not_found" });
            }

            email = reader.IsDBNull(0) ? null : reader.GetString(0);
            verifiedAt = reader.IsDBNull(1) ? null : reader.GetDateTime(1);
            expires = reader.IsDBNull(2) ? null : reader.GetDateTime(2);
        }

        if (verifiedAt.HasValue)
        {
            return Results.BadRequest(new { error = "already_verified" });
        }

        if (string.IsNullOrWhiteSpace(email))
        {
            return Results.BadRequest(new { error = "email_missing" });
        }

        if (expires.HasValue)
        {
            var lastSentAt = expires.Value.AddHours(-24);
            if (lastSentAt > DateTime.UtcNow.AddMinutes(-5))
            {
                return Results.BadRequest(new { error = "too_soon" });
            }
        }

        var newToken = SecureTokenGenerator.CreateToken();
        var newExpires = DateTime.UtcNow.AddHours(24);

        await using (var update = new MySqlCommand("UPDATE UserAccount SET email_verification_token=@token, email_verification_expires=@expires WHERE user_id=@uid", conn))
        {
            update.Parameters.AddWithValue("@token", newToken);
            update.Parameters.AddWithValue("@expires", newExpires);
            update.Parameters.AddWithValue("@uid", userId.Value);
            await update.ExecuteNonQueryAsync(ct);
        }

        var baseUrl = ResolveBaseUrl(cfg, ctx.Request);
        var link = string.IsNullOrWhiteSpace(baseUrl) ? $"/verify-email?token={newToken}" : $"{baseUrl}/verify-email?token={newToken}";
        var html = $"""
            <p>Verify your RotorBase email address.</p>
            <p><a href="{link}">Confirm your email</a> so we can send price alerts and build updates.</p>
            <p>The link expires in 24 hours.</p>
        """;
        var text = $"Confirm your RotorBase email: {link}";
        try
        {
            await emailSender.SendAsync(new EmailMessage(email, "Verify your email", html, text), ct);
        }
        catch (Exception ex) when (ex is InvalidOperationException or SmtpException)
        {
            var logger = ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("ResendVerification");
            logger.LogError(ex, "Resend verification email failed for {Email}", email);
            return Results.BadRequest(new { error = "email_send_failed" });
        }

        return Results.Ok(new { ok = true });
    }
    catch (Exception ex)
    {
        var logger = ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("ResendVerification");
        logger.LogError(ex, "Resend verification failed for user {UserId}", userId);
        return Results.Problem(title: "Resend failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Users: current profile
app.MapGet("/api/me", async (ClaimsPrincipal principal, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    var userId = principal.TryGetUserId();
    if (userId is null) return Results.Unauthorized();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureUserAccountTableAsync(conn, ct);
        await EnsurePlanTablesAsync(conn, ct);
        await using var cmd = new MySqlCommand("SELECT user_id, email, display_name, is_admin, is_banned, email_opt_in, email_verified_at, email_bounced, email_unsubscribed FROM UserAccount WHERE user_id=@id", conn);
        cmd.Parameters.AddWithValue("@id", userId.Value);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct))
            return Results.NotFound(new { error = "user_not_found" });

        var payload = new UserProfileDto
        {
            UserId = reader.GetInt64(0),
            Email = reader.IsDBNull(1) ? null : reader.GetString(1),
            DisplayName = reader.IsDBNull(2) ? null : reader.GetString(2),
            IsAdmin = !reader.IsDBNull(3) && reader.GetBoolean(3),
            IsBanned = !reader.IsDBNull(4) && reader.GetBoolean(4),
            EmailOptIn = !reader.IsDBNull(5) && reader.GetBoolean(5),
            EmailVerified = !reader.IsDBNull(6),
            EmailBounced = !reader.IsDBNull(7) && reader.GetBoolean(7),
            EmailUnsubscribed = !reader.IsDBNull(8) && reader.GetBoolean(8)
        };

        return Results.Json(payload);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Fetch user failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Users: plan limits for current user
app.MapGet("/api/me/limits", async (ClaimsPrincipal principal, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    var userId = principal.TryGetUserId();
    if (userId is null) return Results.Unauthorized();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureUserAccountTableAsync(conn, ct);
        await EnsurePlanTablesAsync(conn, ct);

        await using (var ensurePlan = new MySqlCommand(@"INSERT INTO UserPlan (user_id, plan_id, status, current_period_start, current_period_end)
                                                        SELECT @uid, p.plan_id, 'active', NOW(), NULL
                                                        FROM Plan p
                                                        WHERE p.code='FREE'
                                                          AND NOT EXISTS (
                                                            SELECT 1 FROM UserPlan up
                                                            WHERE up.user_id = @uid AND up.status='active'
                                                          )", conn))
        {
            ensurePlan.Parameters.AddWithValue("@uid", userId.Value);
            await ensurePlan.ExecuteNonQueryAsync(ct);
        }

        Dictionary<string, object?>? planRow = null;
        int? maxActiveFromPlan = null;
        int? maxTotalFromPlan = null;
        await using (var planCmd = new MySqlCommand(@"SELECT p.plan_id, p.code, p.name, p.monthly_price, p.currency, p.features_json
                                                    FROM Plan p
                                                    JOIN UserPlan up ON up.plan_id = p.plan_id
                                                    WHERE up.user_id=@uid AND up.status='active'
                                                    ORDER BY up.current_period_start DESC LIMIT 1", conn))
        {
            planCmd.Parameters.AddWithValue("@uid", userId.Value);
            await using var reader = await planCmd.ExecuteReaderAsync(ct);
            if (await reader.ReadAsync(ct))
            {
                planRow = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
                planRow["plan_id"] = reader.GetInt64(0);
                planRow["plan_code"] = reader.GetString(1);
                planRow["plan_name"] = reader.GetString(2);
                planRow["monthly_price"] = reader.IsDBNull(3) ? null : reader.GetValue(3);
                planRow["currency"] = reader.IsDBNull(4) ? null : reader.GetString(4);

                int? Extract(string key)
                {
                    if (reader.IsDBNull(5)) return null;
                    try
                    {
                        using var doc = JsonDocument.Parse(reader.GetString(5));
                        if (doc.RootElement.TryGetProperty(key, out var prop))
                        {
                            if (prop.ValueKind == JsonValueKind.Number && prop.TryGetInt32(out var val))
                                return val;
                            if (prop.ValueKind == JsonValueKind.String && int.TryParse(prop.GetString(), out var parsed))
                                return parsed;
                        }
                    }
                    catch
                    {
                        // ignore malformed JSON
                    }
                    return null;
                }

                maxActiveFromPlan = Extract("max_active_builds");
                maxTotalFromPlan = Extract("max_total_builds");
                planRow["max_active_builds"] = maxActiveFromPlan;
                planRow["max_total_builds"] = maxTotalFromPlan;
            }
        }

        int activeBuilds = 0;
        int totalBuilds = 0;
        await using (var usageCmd = new MySqlCommand(@"SELECT
                                                        SUM(CASE WHEN is_archived = FALSE THEN 1 ELSE 0 END) AS active_builds,
                                                        COUNT(*) AS total_builds
                                                      FROM Build
                                                      WHERE user_id = @uid", conn))
        {
            usageCmd.Parameters.AddWithValue("@uid", userId.Value);
            await using var usageReader = await usageCmd.ExecuteReaderAsync(ct);
            if (await usageReader.ReadAsync(ct))
            {
                activeBuilds = usageReader.IsDBNull(0) ? 0 : Convert.ToInt32(usageReader.GetValue(0));
                totalBuilds = usageReader.IsDBNull(1) ? 0 : Convert.ToInt32(usageReader.GetValue(1));
            }
        }

        var maxActive = maxActiveFromPlan;
        var maxTotal = maxTotalFromPlan;

        int? remainingActive = maxActive.HasValue && maxActive.Value > 0 ? Math.Max(maxActive.Value - activeBuilds, 0) : null;
        int? remainingTotal = maxTotal.HasValue && maxTotal.Value > 0 ? Math.Max(maxTotal.Value - totalBuilds, 0) : null;

        return Results.Json(new
        {
            plan = planRow,
            usage = new { active_builds = activeBuilds, total_builds = totalBuilds, remaining_active = remainingActive, remaining_total = remainingTotal }
        });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Fetch user limits failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");


// Current plan, usage, and catalog for the signed-in user
app.MapGet("/api/me/plan", async (ClaimsPrincipal principal, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    var userId = principal.TryGetUserId();
    if (userId is null) return Results.Unauthorized();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsurePlanTablesAsync(conn, ct);

        Dictionary<string, object?>? currentPlan = null;
        await using (var cmd = new MySqlCommand(@"SELECT plan_code,
                                                        plan_name,
                                                        max_active_builds,
                                                        max_total_builds
                                                 FROM v_user_limits
                                                 WHERE user_id=@uid
                                                 LIMIT 1", conn))
        {
            cmd.Parameters.AddWithValue("@uid", userId.Value);
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            if (await reader.ReadAsync(ct))
            {
                currentPlan = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
                {
                    ["user_id"] = userId.Value,
                    ["plan_code"] = reader.IsDBNull(0) ? null : reader.GetString(0),
                    ["plan_name"] = reader.IsDBNull(1) ? null : reader.GetString(1),
                    ["max_active_builds"] = reader.IsDBNull(2) ? null : reader.GetValue(2),
                    ["max_total_builds"] = reader.IsDBNull(3) ? null : reader.GetValue(3)
                };
            }
        }

        if (currentPlan is null)
        {
            await using var fallback = new MySqlCommand(@"SELECT p.code,
                                                                p.name,
                                                                COALESCE(pl.max_active_builds, 0) AS max_active_builds,
                                                                COALESCE(pl.max_total_builds, 0)  AS max_total_builds
                                                         FROM Plan p
                                                         LEFT JOIN PlanLimits pl ON pl.plan_id = p.plan_id
                                                         WHERE p.code=@code AND p.is_archived = 0
                                                         LIMIT 1", conn);
            fallback.Parameters.AddWithValue("@code", FreePlanCode);
            await using var reader = await fallback.ExecuteReaderAsync(ct);
            if (await reader.ReadAsync(ct))
            {
                currentPlan = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
                {
                    ["user_id"] = userId.Value,
                    ["plan_code"] = reader.IsDBNull(0) ? null : reader.GetString(0),
                    ["plan_name"] = reader.IsDBNull(1) ? null : reader.GetString(1),
                    ["max_active_builds"] = reader.IsDBNull(2) ? null : reader.GetValue(2),
                    ["max_total_builds"] = reader.IsDBNull(3) ? null : reader.GetValue(3)
                };
            }
        }

        int activeBuilds = 0;
        int totalBuilds = 0;
        await using (var usageCmd = new MySqlCommand(@"SELECT SUM(is_archived = FALSE) AS active_builds,
                                                              COUNT(*) AS total_builds
                                                       FROM Build
                                                       WHERE user_id=@uid", conn))
        {
            usageCmd.Parameters.AddWithValue("@uid", userId.Value);
            await using var reader = await usageCmd.ExecuteReaderAsync(ct);
            if (await reader.ReadAsync(ct))
            {
                activeBuilds = reader.IsDBNull(0) ? 0 : Convert.ToInt32(reader.GetValue(0));
                totalBuilds = reader.IsDBNull(1) ? 0 : Convert.ToInt32(reader.GetValue(1));
            }
        }

        var catalog = new List<Dictionary<string, object?>>(8);
        await using (var plansCmd = new MySqlCommand(@"SELECT p.code, p.name, p.monthly_price, p.currency,
                                                             COALESCE(pl.max_active_builds, 0) AS max_active_builds,
                                                             COALESCE(pl.max_total_builds, 0)  AS max_total_builds
                                                      FROM Plan p
                                                      LEFT JOIN PlanLimits pl ON pl.plan_id = p.plan_id
                                                      WHERE p.is_archived = 0
                                                      ORDER BY p.monthly_price, p.plan_id", conn))
        {
            await using var reader = await plansCmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
                {
                    ["plan_code"] = reader.IsDBNull(0) ? null : reader.GetString(0),
                    ["plan_name"] = reader.IsDBNull(1) ? null : reader.GetString(1),
                    ["monthly_price"] = reader.IsDBNull(2) ? 0m : reader.GetDecimal(2),
                    ["currency"] = reader.IsDBNull(3) ? "USD" : reader.GetString(3),
                    ["max_active_builds"] = reader.IsDBNull(4) ? null : reader.GetValue(4),
                    ["max_total_builds"] = reader.IsDBNull(5) ? null : reader.GetValue(5)
                };
                catalog.Add(row);
            }
        }

        var usage = new Dictionary<string, object?>
        {
            ["active_builds"] = activeBuilds,
            ["total_builds"] = totalBuilds
        };

        return Results.Json(new { current = currentPlan, usage, catalog });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Fetch plan failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Change the signed-in user's plan
app.MapPost("/api/me/plan", async (HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    var userId = ctx.User.TryGetUserId();
    if (userId is null) return Results.Unauthorized();

    var payload = await ctx.Request.ReadFromJsonAsync<UserPlanChangeRequest>(cancellationToken: ct);
    if (payload is null || string.IsNullOrWhiteSpace(payload.PlanCode))
        return Results.BadRequest(new { error = "plan_code_required" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsurePlanTablesAsync(conn, ct);
        await using var tx = await conn.BeginTransactionAsync(ct);

        var requestedCode = payload.PlanCode.Trim();
        long? planId = null;
        decimal? monthlyPrice = null;
        decimal currentMonthlyPrice = 0m;
        await using (var find = new MySqlCommand("SELECT plan_id, monthly_price FROM Plan WHERE code=@code", conn, (MySqlTransaction)tx))
        {
            find.Parameters.AddWithValue("@code", requestedCode);
            await using var reader = await find.ExecuteReaderAsync(ct);
            if (await reader.ReadAsync(ct))
            {
                planId = reader.IsDBNull(0) ? null : reader.GetInt64(0);
                if (!reader.IsDBNull(1))
                {
                    monthlyPrice = reader.GetDecimal(1);
                }
            }
            else
            {
                planId = null;
            }
        }

        await using (var currentCmd = new MySqlCommand(@"SELECT p.code, p.monthly_price
                                                        FROM UserPlan up
                                                        JOIN Plan p ON p.plan_id = up.plan_id
                                                        WHERE up.user_id=@uid AND up.status='active'
                                                        ORDER BY up.current_period_start DESC
                                                        LIMIT 1", conn, (MySqlTransaction)tx))
        {
            currentCmd.Parameters.AddWithValue("@uid", userId.Value);
            await using var reader = await currentCmd.ExecuteReaderAsync(ct);
            if (await reader.ReadAsync(ct))
            {
                if (!reader.IsDBNull(1))
                    currentMonthlyPrice = reader.GetDecimal(1);
            }
        }

        if (monthlyPrice.HasValue && monthlyPrice.Value > 0m)
        {
            await tx.RollbackAsync(ct);
            return Results.BadRequest(new { error = "upgrade_requires_checkout" });
        }

        if (monthlyPrice.HasValue && monthlyPrice.Value == 0m && currentMonthlyPrice > 0m)
        {
            await tx.RollbackAsync(ct);
            return Results.BadRequest(new { error = "paid_plan_requires_cancel" });
        }

        if (planId is null)
        {
            await tx.RollbackAsync(ct);
            return Results.NotFound(new { error = "plan_not_found" });
        }

        await using (var cancel = new MySqlCommand("UPDATE UserPlan SET status='canceled', current_period_end=NOW() WHERE user_id=@uid AND status='active'", conn, (MySqlTransaction)tx))
        {
            cancel.Parameters.AddWithValue("@uid", userId.Value);
            await cancel.ExecuteNonQueryAsync(ct);
        }

        await using (var insert = new MySqlCommand("INSERT INTO UserPlan (user_id, plan_id, status, current_period_start) VALUES (@uid, @pid, 'active', NOW())", conn, (MySqlTransaction)tx))
        {
            insert.Parameters.AddWithValue("@uid", userId.Value);
            insert.Parameters.AddWithValue("@pid", planId.Value);
            await insert.ExecuteNonQueryAsync(ct);
        }

        await tx.CommitAsync(ct);
        return Results.Ok(new { ok = true });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Plan change failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Stripe Checkout session for upgrading to Premium
app.MapPost("/api/billing/checkout", async (HttpContext ctx, IConfiguration cfg, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(StripeConfiguration.ApiKey))
        return Results.Problem(title: "Stripe not configured", detail: "Stripe:ApiKey is missing", statusCode: 500);

    var userId = ctx.User.TryGetUserId();
    if (userId is null)
        return Results.Unauthorized();

    var payload = await ctx.Request.ReadFromJsonAsync<CheckoutSessionRequest>(cancellationToken: ct);
    var normalizedCode = NormalizePlanCode(payload?.PlanCode);

    var priceId = cfg[$"Stripe:Prices:{normalizedCode}"];

    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    decimal monthlyPrice = 0m;
    string? stripePriceIdFromPlan = null;
    string? customerId = null;

    await using (var conn = new MySqlConnection(connectionString))
    {
        await conn.OpenAsync(ct);
        await EnsurePlanTablesAsync(conn, ct);
        await EnsureBillingTablesAsync(conn, ct);

        await using (var priceCmd = new MySqlCommand("SELECT monthly_price, features_json FROM Plan WHERE code=@code AND is_archived = 0", conn))
        {
            priceCmd.Parameters.AddWithValue("@code", normalizedCode);
            await using var reader = await priceCmd.ExecuteReaderAsync(ct);
            if (!await reader.ReadAsync(ct))
                return Results.BadRequest(new { error = "plan_not_found" });

            if (!reader.IsDBNull(0))
            {
                monthlyPrice = reader.GetDecimal(0);
            }

            if (string.IsNullOrWhiteSpace(priceId) && !reader.IsDBNull(1))
            {
                try
                {
                    using var doc = JsonDocument.Parse(reader.GetString(1));
                    if (doc.RootElement.TryGetProperty("stripe_price_id", out var token) &&
                        token.ValueKind == JsonValueKind.String)
                    {
                        var raw = token.GetString();
                        if (!string.IsNullOrWhiteSpace(raw))
                        {
                            stripePriceIdFromPlan = raw;
                        }
                    }
                }
                catch (JsonException ex)
                {
                    app.Logger.LogWarning(ex, "Unable to parse features_json for plan {PlanCode}", normalizedCode);
                }
            }
        }

        if (string.IsNullOrWhiteSpace(priceId) && !string.IsNullOrWhiteSpace(stripePriceIdFromPlan))
        {
            priceId = stripePriceIdFromPlan;
        }

        await using (var customerCmd = new MySqlCommand("SELECT stripe_customer_id FROM BillingCustomer WHERE user_id=@uid", conn))
        {
            customerCmd.Parameters.AddWithValue("@uid", userId.Value);
            var existing = await customerCmd.ExecuteScalarAsync(ct);
            customerId = existing?.ToString();
        }
    }

    if (string.IsNullOrWhiteSpace(priceId))
        return Results.BadRequest(new { error = "plan_missing_stripe_price" });

    if (monthlyPrice <= 0m)
        return Results.BadRequest(new { error = "plan_is_free" });

    var baseUrl = cfg["App:BaseUrl"];
    if (string.IsNullOrWhiteSpace(baseUrl))
    {
        var request = ctx.Request;
        baseUrl = $"{request.Scheme}://{request.Host}";
    }

    var email = ctx.User.FindFirst(ClaimTypes.Email)?.Value;

    var customerService = new CustomerService();

    if (string.IsNullOrWhiteSpace(customerId))
    {
        var createOptions = new CustomerCreateOptions
        {
            Email = string.IsNullOrWhiteSpace(email) ? null : email,
            Metadata = new Dictionary<string, string>
            {
                ["user_id"] = userId.Value.ToString()
            }
        };

        var customer = await customerService.CreateAsync(createOptions, cancellationToken: ct);
        customerId = customer.Id;
        await SaveBillingCustomerAsync(connectionString, userId.Value, customerId, ct);
    }
    else
    {
        if (!string.IsNullOrWhiteSpace(email))
        {
            try
            {
                var updateOptions = new CustomerUpdateOptions { Email = email };
                await customerService.UpdateAsync(customerId, updateOptions, cancellationToken: ct);
            }
            catch (StripeException ex)
            {
                app.Logger.LogDebug(ex, "Stripe customer update failed for {CustomerId}", customerId);
            }
        }
        await SaveBillingCustomerAsync(connectionString, userId.Value, customerId, ct);
    }

    var options = new CheckoutSessionCreateOptions
    {
        Mode = "subscription",
        SuccessUrl = string.Concat(baseUrl, "/account/plan?success=1"),
        CancelUrl = string.Concat(baseUrl, "/account/plan?canceled=1"),
        LineItems = new List<CheckoutSessionLineItemOptions>
        {
            new()
            {
                Price = priceId,
                Quantity = 1
            }
        },
        Metadata = new Dictionary<string, string>
        {
            ["user_id"] = userId.Value.ToString(),
            ["plan_code"] = normalizedCode
        },
        SubscriptionData = new CheckoutSubscriptionDataOptions
        {
            Metadata = new Dictionary<string, string>
            {
                ["user_id"] = userId.Value.ToString(),
                ["plan_code"] = normalizedCode
            }
        }
    };

    if (!string.IsNullOrWhiteSpace(customerId))
    {
        options.Customer = customerId;
    }

    try
    {
        var service = new CheckoutSessionService();
        var session = await service.CreateAsync(options, cancellationToken: ct);
        return Results.Ok(new { url = session.Url });
    }
    catch (StripeException ex)
    {
        ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("Stripe").LogError(ex, "Failed to create Stripe checkout session");
        return Results.Problem(title: "Checkout session failed", detail: ex.Message, statusCode: 502);
    }
}).RequireAuthorization("IsSignedIn");

// Stripe webhook handler to activate/downgrade plans
app.MapPost("/webhooks/stripe", async (HttpRequest req, IConfiguration cfg, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(StripeConfiguration.ApiKey))
        return Results.Problem(title: "Stripe not configured", detail: "Stripe:ApiKey is missing", statusCode: 500);

    var webhookSecret = cfg["Stripe:WebhookSecret"];
    if (string.IsNullOrWhiteSpace(webhookSecret))
        return Results.Problem(title: "Stripe not configured", detail: "Stripe:WebhookSecret is missing", statusCode: 500);

    string payload;
    using (var reader = new StreamReader(req.Body))
    {
        payload = await reader.ReadToEndAsync(ct);
    }

    var signature = req.Headers["Stripe-Signature"].ToString();
    Event stripeEvent;
    try
    {
        stripeEvent = EventUtility.ConstructEvent(payload, signature, webhookSecret, throwOnApiVersionMismatch: false);
        if (!string.Equals(stripeEvent.ApiVersion, StripeConfiguration.ApiVersion, StringComparison.OrdinalIgnoreCase))
        {
            app.Logger.LogDebug("Stripe webhook received API version {IncomingVersion} (configured {ConfiguredVersion})", stripeEvent.ApiVersion, StripeConfiguration.ApiVersion ?? "default");
        }
    }
    catch (Exception ex)
    {
        app.Logger.LogWarning(ex, "Stripe webhook signature verification failed");
        return Results.BadRequest();
    }

    try
    {
        switch (stripeEvent.Type)
        {
            case Events.CheckoutSessionCompleted:
            {
                if (stripeEvent.Data.Object is CheckoutSession session && TryGetSubscriptionContext(session.Metadata, out var userId, out var planCode))
                {
                    var lineItem = session.LineItems?.Data?.FirstOrDefault();
                    var priceId = lineItem?.Price?.Id;
                    var normalizedPlan = ResolveEffectivePlanCode(cfg, planCode, priceId);
                    var success = await ActivateUserPlanAsync(connectionString, userId, normalizedPlan, ct);
                    if (!success)
                        app.Logger.LogWarning("Stripe webhook: plan {PlanCode} not present when activating user {UserId}", normalizedPlan, userId);

                    if (!string.IsNullOrWhiteSpace(session.CustomerId))
                    {
                        await SaveBillingCustomerAsync(connectionString, userId, session.CustomerId, ct);
                    }

                    if (!string.IsNullOrWhiteSpace(session.SubscriptionId))
                    {
                        await SaveBillingSubscriptionAsync(connectionString, userId, session.SubscriptionId, normalizedPlan, "active", null, ct);
                    }
                }
                else
                {
                    app.Logger.LogWarning("Stripe webhook: checkout.session.completed without user_id metadata");
                }
                break;
            }

            case Events.CustomerSubscriptionDeleted:
            {
                var subscription = stripeEvent.Data.Object as Subscription;
                if (subscription is null)
                {
                    app.Logger.LogWarning("Stripe webhook: subscription.deleted without subscription object");
                    break;
                }

                if (TryGetSubscriptionContext(subscription.Metadata, out var userId, out _))
                {
                    await ActivateUserPlanAsync(connectionString, userId, FreePlanCode, ct);
                    await SaveBillingSubscriptionAsync(connectionString, userId, subscription.Id, FreePlanCode, subscription.Status ?? "canceled", subscription.CurrentPeriodEnd, ct);
                }
                else
                {
                    var mappedUserId = await FindUserIdByCustomerAsync(connectionString, subscription.CustomerId, ct);
                    if (mappedUserId is not null)
                    {
                        await ActivateUserPlanAsync(connectionString, mappedUserId.Value, FreePlanCode, ct);
                        await SaveBillingSubscriptionAsync(connectionString, mappedUserId.Value, subscription.Id, FreePlanCode, subscription.Status ?? "canceled", subscription.CurrentPeriodEnd, ct);
                    }
                    else
                    {
                        app.Logger.LogWarning("Stripe webhook: subscription.deleted without user mapping");
                    }
                }
                break;
            }

            case Events.CustomerSubscriptionUpdated:
            {
                var subscription = stripeEvent.Data.Object as Subscription;
                if (subscription is null)
                {
                    app.Logger.LogWarning("Stripe webhook: subscription.updated without subscription object");
                    break;
                }

                var activePriceId = subscription.Items?.Data?.FirstOrDefault()?.Price?.Id;

                if (TryGetSubscriptionContext(subscription.Metadata, out var userId, out var planCode))
                {
                    var normalizedPlan = ResolveEffectivePlanCode(cfg, planCode, activePriceId);
                    if (string.Equals(subscription.Status, "active", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(subscription.Status, "trialing", StringComparison.OrdinalIgnoreCase))
                    {
                        var success = await ActivateUserPlanAsync(connectionString, userId, normalizedPlan, ct);
                        if (!success)
                            app.Logger.LogWarning("Stripe webhook: plan {PlanCode} not present when activating user {UserId}", normalizedPlan, userId);
                    }
                    else if (string.Equals(subscription.Status, "past_due", StringComparison.OrdinalIgnoreCase) ||
                             string.Equals(subscription.Status, "canceled", StringComparison.OrdinalIgnoreCase) ||
                             string.Equals(subscription.Status, "unpaid", StringComparison.OrdinalIgnoreCase) ||
                             string.Equals(subscription.Status, "incomplete", StringComparison.OrdinalIgnoreCase) ||
                             string.Equals(subscription.Status, "incomplete_expired", StringComparison.OrdinalIgnoreCase))
                    {
                        await ActivateUserPlanAsync(connectionString, userId, FreePlanCode, ct);
                    }

                    await SaveBillingCustomerAsync(connectionString, userId, subscription.CustomerId, ct);
                    await SaveBillingSubscriptionAsync(connectionString, userId, subscription.Id, normalizedPlan, subscription.Status ?? string.Empty, subscription.CurrentPeriodEnd, ct);
                }
                else
                {
                    var mappedUserId = await FindUserIdByCustomerAsync(connectionString, subscription.CustomerId, ct);
                    if (mappedUserId is not null)
                    {
                        string? metadataPlan = null;
                        if (subscription.Metadata is not null && subscription.Metadata.TryGetValue("plan_code", out var metaPlan))
                        {
                            metadataPlan = metaPlan;
                        }
                        var normalizedPlan = ResolveEffectivePlanCode(cfg, metadataPlan, activePriceId);
                        if (string.Equals(subscription.Status, "active", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(subscription.Status, "trialing", StringComparison.OrdinalIgnoreCase))
                        {
                            var success = await ActivateUserPlanAsync(connectionString, mappedUserId.Value, normalizedPlan, ct);
                            if (!success)
                                app.Logger.LogWarning("Stripe webhook (mapped): plan {PlanCode} missing when activating user {UserId}", normalizedPlan, mappedUserId.Value);
                        }
                        else if (string.Equals(subscription.Status, "past_due", StringComparison.OrdinalIgnoreCase) ||
                                 string.Equals(subscription.Status, "canceled", StringComparison.OrdinalIgnoreCase) ||
                                 string.Equals(subscription.Status, "unpaid", StringComparison.OrdinalIgnoreCase) ||
                                 string.Equals(subscription.Status, "incomplete", StringComparison.OrdinalIgnoreCase) ||
                                 string.Equals(subscription.Status, "incomplete_expired", StringComparison.OrdinalIgnoreCase))
                        {
                            await ActivateUserPlanAsync(connectionString, mappedUserId.Value, FreePlanCode, ct);
                        }

                        await SaveBillingCustomerAsync(connectionString, mappedUserId.Value, subscription.CustomerId, ct);
                        await SaveBillingSubscriptionAsync(connectionString, mappedUserId.Value, subscription.Id, normalizedPlan, subscription.Status ?? string.Empty, subscription.CurrentPeriodEnd, ct);
                    }
                    else
                    {
                        app.Logger.LogWarning("Stripe webhook: subscription.updated without user mapping");
                    }
                }
                break;
            }
        }
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "Stripe webhook processing failed for event {EventId}", stripeEvent.Id);
        return Results.Problem(title: "Webhook processing failed", detail: ex.Message, statusCode: 500);
    }

    return Results.Ok();
});

// Stripe Billing Portal session for existing subscribers
app.MapPost("/api/billing/portal", async (HttpContext ctx, IConfiguration cfg, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(StripeConfiguration.ApiKey))
        return Results.Problem(title: "Stripe not configured", detail: "Stripe:ApiKey is missing", statusCode: 500);

    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    var userId = ctx.User.TryGetUserId();
    if (userId is null)
        return Results.Unauthorized();

    string? customerId = null;
    await using (var conn = new MySqlConnection(connectionString))
    {
        await conn.OpenAsync(ct);
        await EnsureBillingTablesAsync(conn, ct);

        await using var cmd = new MySqlCommand("SELECT stripe_customer_id FROM BillingCustomer WHERE user_id=@uid", conn);
        cmd.Parameters.AddWithValue("@uid", userId.Value);
        customerId = (await cmd.ExecuteScalarAsync(ct))?.ToString();
    }

    if (string.IsNullOrWhiteSpace(customerId))
        return Results.BadRequest(new { error = "no_billing_customer" });

    var baseUrl = cfg["App:BaseUrl"];
    if (string.IsNullOrWhiteSpace(baseUrl))
    {
        var request = ctx.Request;
        baseUrl = $"{request.Scheme}://{request.Host}";
    }

    try
    {
        var service = new BillingPortalSessionService();
        var portal = await service.CreateAsync(new BillingPortalSessionCreateOptions
        {
            Customer = customerId,
            ReturnUrl = string.Concat(baseUrl, "/account/plan")
        }, cancellationToken: ct);

        return Results.Ok(new { url = portal.Url });
    }
    catch (StripeException ex)
    {
        ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("Stripe").LogError(ex, "Failed to create Stripe billing portal session");
        return Results.Problem(title: "Billing portal failed", detail: ex.Message, statusCode: 502);
    }
}).RequireAuthorization("IsSignedIn");

// Cancel Stripe subscription for current user (at period end)
app.MapPost("/api/billing/cancel", async (HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(StripeConfiguration.ApiKey))
        return Results.Problem(title: "Stripe not configured", detail: "Stripe:ApiKey is missing", statusCode: 500);

    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    var userId = ctx.User.TryGetUserId();
    if (userId is null)
        return Results.Unauthorized();

    string? subscriptionId = null;
    string? planCode = null;

    await using (var conn = new MySqlConnection(connectionString))
    {
        await conn.OpenAsync(ct);
        await EnsureBillingTablesAsync(conn, ct);

        await using var cmd = new MySqlCommand("SELECT stripe_subscription_id, plan_code FROM BillingSubscription WHERE user_id=@uid", conn);
        cmd.Parameters.AddWithValue("@uid", userId.Value);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        if (await reader.ReadAsync(ct))
        {
            subscriptionId = reader.IsDBNull(0) ? null : reader.GetString(0);
            planCode = reader.IsDBNull(1) ? null : reader.GetString(1);
        }
    }

    if (string.IsNullOrWhiteSpace(subscriptionId))
        return Results.BadRequest(new { error = "no_active_subscription" });

    try
    {
        bool cancelAtPeriodEnd = true;
        if ((ctx.Request.ContentLength ?? 0) > 0)
        {
            try
            {
                var payload = await ctx.Request.ReadFromJsonAsync<CancelSubscriptionRequestDto>(cancellationToken: ct);
                if (payload?.AtPeriodEnd is bool flag)
                {
                    cancelAtPeriodEnd = flag;
                }
            }
            catch (JsonException ex)
            {
                app.Logger.LogWarning(ex, "Invalid payload for /api/billing/cancel");
            }
        }

        var normalizedPlanCode = NormalizePlanCode(planCode);

        var subscriptionService = new SubscriptionService();
        Subscription subscription;
        if (cancelAtPeriodEnd)
        {
            subscription = await subscriptionService.UpdateAsync(subscriptionId, new SubscriptionUpdateOptions
            {
                CancelAtPeriodEnd = true
            }, cancellationToken: ct);
        }
        else
        {
            subscription = await subscriptionService.CancelAsync(subscriptionId, cancellationToken: ct);
        }

        await SaveBillingSubscriptionAsync(connectionString, userId.Value, subscription.Id, normalizedPlanCode, subscription.Status ?? string.Empty, subscription.CurrentPeriodEnd, ct);

        return Results.Ok(new
        {
            status = subscription.Status,
            cancel_at_period_end = subscription.CancelAtPeriodEnd,
            current_period_end = subscription.CurrentPeriodEnd,
            cancel_at = subscription.CancelAt
        });
    }
    catch (StripeException ex)
    {
        ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("Stripe").LogError(ex, "Failed to cancel Stripe subscription");
        return Results.Problem(title: "Subscription cancel failed", detail: ex.Message, statusCode: 502);
    }
}).RequireAuthorization("IsSignedIn");

// Create a build
app.MapPost("/api/builds", async (HttpContext ctx, IGamification gamification, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    var userId = ctx.User.TryGetUserId();
    if (userId is null) return Results.Unauthorized();

    var request = await ctx.Request.ReadFromJsonAsync<CreateBuildRequest>(cancellationToken: ct);
    if (request is null) return Results.BadRequest(new { error = "Invalid JSON" });

    var engineFamilyId = request.EngineFamilyId;
    if (engineFamilyId <= 0) return Results.BadRequest(new { error = "engine_family_id required" });

    var name = string.IsNullOrWhiteSpace(request.Name)
        ? $"Build {DateTime.UtcNow:yyyyMMdd-HHmmss}"
        : request.Name.Trim();

    var isArchived = request.IsArchived ?? false;
    var isShared = request.IsShared ?? false;

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureBuildColumnsAsync(conn, ct);
        await EnsurePlanTablesAsync(conn, ct);

        var resolvedTree = await ResolveDefaultTreeForEngineAsync(conn, engineFamilyId, ct);
        if (!resolvedTree.EngineExists)
            return Results.BadRequest(new { error = "engine_family_id not found" });

        if (!resolvedTree.TreeId.HasValue)
        {
            var engineLabel = string.IsNullOrWhiteSpace(resolvedTree.EngineCode)
                ? engineFamilyId.ToString()
                : resolvedTree.EngineCode;

            return Results.Json(new
            {
                error = "no_default_tree",
                message = $"No default category tree configured for engine family {engineLabel}."
            }, statusCode: 409);
        }

        var treeId = resolvedTree.TreeId.Value;

        try
        {
            await using var cmd = new MySqlCommand("INSERT INTO Build(user_id, engine_family_id, tree_id, name, is_archived, is_shared) VALUES (@user, @ef, @tree, @name, @archived, @shared); SELECT LAST_INSERT_ID();", conn);
            cmd.Parameters.AddWithValue("@user", userId.Value);
            cmd.Parameters.AddWithValue("@ef", engineFamilyId);
            cmd.Parameters.AddWithValue("@tree", treeId);
            cmd.Parameters.AddWithValue("@name", name);
            cmd.Parameters.AddWithValue("@archived", isArchived);
            cmd.Parameters.AddWithValue("@shared", isShared);
            var id = Convert.ToInt64(await cmd.ExecuteScalarAsync(ct));

            try
            {
                var now = DateTime.UtcNow;
                var inserted = await gamification.AwardAsync(userId.Value, 50, "build_created", id, $"build_created:{id}");
                if (inserted)
                {
                    await gamification.GrantBadgeAsync(userId.Value, "FIRST_BUILD", id);
                }
                await gamification.TickStreakAsync(userId.Value, now);
            }
            catch (Exception hookEx)
            {
                app.Logger.LogError(hookEx, "Gamification build_created hook failed for build {BuildId}", id);
            }

            return Results.Json(new
            {
                build_id = id,
                user_id = userId.Value,
                engine_family_id = engineFamilyId,
                tree_id = treeId,
                name,
                is_archived = isArchived,
                is_shared = isShared
            });
        }
        catch (MySqlException ex) when (ex.SqlState == "45000")
        {
            return Results.Json(new { error = "quota_exceeded", message = ex.Message }, statusCode: 403);
        }
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Create build failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Duplicate an existing build into the current user's account
app.MapPost("/api/builds/{id:long}/duplicate", async (long id, HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    var userId = ctx.User.TryGetUserId();
    if (userId is null) return Results.Unauthorized();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureBuildColumnsAsync(conn, ct);
        await EnsurePlanTablesAsync(conn, ct);

        long? sourceOwnerId = null;
        long engineFamilyId;
        long? treeId = null;
        string sourceName;

        await using (var fetch = new MySqlCommand("SELECT user_id, engine_family_id, tree_id, name FROM Build WHERE build_id=@id", conn))
        {
            fetch.Parameters.AddWithValue("@id", id);
            await using var reader = await fetch.ExecuteReaderAsync(ct);
            if (!await reader.ReadAsync(ct))
                return Results.NotFound(new { error = "build_not_found" });

            sourceOwnerId = reader.IsDBNull(0) ? null : reader.GetInt64(0);
            engineFamilyId = reader.GetInt64(1);
            treeId = reader.IsDBNull(2) ? null : reader.GetInt64(2);
            sourceName = reader.IsDBNull(3) ? "Untitled Build" : reader.GetString(3);
        }

        var role = await GetBuildRoleAsync(conn, id, userId.Value, ct);
        if (role is null)
            return Results.Forbid();

        await using var tx = await conn.BeginTransactionAsync(ct);

        try
        {
            var newName = string.IsNullOrWhiteSpace(sourceName) ? "Copied Build" : $"{sourceName} (copy)";

            long newBuildId;
            await using (var insert = new MySqlCommand("INSERT INTO Build(user_id, engine_family_id, tree_id, name, is_archived, is_shared) VALUES(@user, @engine, @tree, @name, FALSE, FALSE); SELECT LAST_INSERT_ID();", conn, (MySqlTransaction)tx))
            {
                insert.Parameters.AddWithValue("@user", userId.Value);
                insert.Parameters.AddWithValue("@engine", engineFamilyId);
                insert.Parameters.AddWithValue("@tree", (object?)treeId ?? DBNull.Value);
                insert.Parameters.AddWithValue("@name", newName);
                newBuildId = Convert.ToInt64(await insert.ExecuteScalarAsync(ct));
            }

            await using (var cloneSelections = new MySqlCommand("INSERT INTO BuildSelection(build_id, category_id, part_id, qty) SELECT @dest, category_id, part_id, qty FROM BuildSelection WHERE build_id=@src", conn, (MySqlTransaction)tx))
            {
                cloneSelections.Parameters.AddWithValue("@dest", newBuildId);
                cloneSelections.Parameters.AddWithValue("@src", id);
                await cloneSelections.ExecuteNonQueryAsync(ct);
            }

            await tx.CommitAsync(ct);
            return Results.Json(new DuplicateBuildResponse { BuildId = newBuildId });
        }
        catch (MySqlException ex) when (ex.SqlState == "45000")
        {
            await tx.RollbackAsync(ct);
            return Results.Json(new { error = "quota_exceeded", message = ex.Message }, statusCode: 403);
        }
        catch
        {
            await tx.RollbackAsync(ct);
            throw;
        }
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Duplicate build failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("BuildOwnerOrEditor");

// Admin: Engines, subsystems, slots & sockets console
app.MapGet("/api/admin/engine/{engineId:long}/slots-matrix", async (long engineId, HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync(ct);

    const string slotsSql = @"
SELECT CAST(s.slot_id AS SIGNED)        AS SlotId,
       s.`key`                          AS SlotKey,
       s.`name`                         AS SlotName,
       s.gltf_node_path                 AS GltfNodePath,
       s.min_required                   AS MinRequired,
       s.capacity                       AS Capacity,
       sub.`name`                       AS SubsystemName
  FROM Slot s
  JOIN Subsystem sub ON sub.subsystem_id = s.subsystem_id
 WHERE s.engine_family_id = @engineId
 ORDER BY sub.sort_order, s.`key`;";

    var slots = (await conn.QueryAsync<SlotMatrixSlot>(
        new CommandDefinition(slotsSql, new { engineId }, cancellationToken: ct))).ToList();

    if (slots.Count == 0)
    {
        return Results.Ok(Array.Empty<object>());
    }

    var slotIds = slots.Select(s => s.SlotId).ToArray();

    List<SlotMatrixCategory> catRows = new();
    List<SlotMatrixPart> partRows = new();

    if (slotIds.Length > 0)
    {
        const string categoriesSql = @"
SELECT CAST(ps.slot_id AS SIGNED)      AS SlotId,
       CAST(c.category_id AS SIGNED)   AS CategoryId,
       COALESCE(c.slug, CONCAT('cat:', c.category_id)) AS CategoryKey,
       c.`name`                        AS CategoryName
  FROM PartSlot ps
  JOIN Category c ON c.category_id = ps.category_id
 WHERE ps.slot_id IN @slotIds
 ORDER BY c.`name`;";

        const string partsSql = @"
SELECT CAST(ps.slot_id AS SIGNED)    AS SlotId,
       CAST(p.part_id AS SIGNED)     AS PartId,
       p.`name`                      AS PartName
  FROM PartSlot ps
  JOIN Part p ON p.part_id = ps.part_id
 WHERE ps.slot_id IN @slotIds
 ORDER BY p.`name`;";

        catRows = (await conn.QueryAsync<SlotMatrixCategory>(
            new CommandDefinition(categoriesSql, new { slotIds }, cancellationToken: ct))).ToList();

        partRows = (await conn.QueryAsync<SlotMatrixPart>(
            new CommandDefinition(partsSql, new { slotIds }, cancellationToken: ct))).ToList();
    }

    var catLookup = catRows.GroupBy(x => x.SlotId).ToDictionary(g => g.Key, g => g.ToList());
    var partLookup = partRows.GroupBy(x => x.SlotId).ToDictionary(g => g.Key, g => g.ToList());

    var matrix = slots.Select(slot =>
    {
        var cats = catLookup.TryGetValue(slot.SlotId, out var catList)
            ? (IReadOnlyList<SlotMatrixCategory>)catList
            : Array.Empty<SlotMatrixCategory>();
        var parts = partLookup.TryGetValue(slot.SlotId, out var partList)
            ? (IReadOnlyList<SlotMatrixPart>)partList
            : Array.Empty<SlotMatrixPart>();

        var hasMapping = cats.Count > 0 || parts.Count > 0;
        var hasSocketName = !string.IsNullOrWhiteSpace(slot.GltfNodePath) &&
                            slot.GltfNodePath.Contains("Socket_", StringComparison.Ordinal);

        return new
        {
            slot.SlotId,
            slot.SlotKey,
            slot.SlotName,
            slot.SubsystemName,
            slot.GltfNodePath,
            slot.MinRequired,
            slot.Capacity,
            AllowedCategoryCount = cats.Count,
            AllowedPartCount = parts.Count,
            Categories = cats.Take(3)
                .Select(c => new { c.CategoryId, c.CategoryKey, c.CategoryName })
                .ToList(),
            Parts = parts.Take(3)
                .Select(p => new { p.PartId, p.PartName })
                .ToList(),
            Validations = new
            {
                HasMapping = hasMapping,
                HasSocketName = hasSocketName
            }
        };
    }).ToList();

    return Results.Ok(matrix);
}).RequireAuthorization("IsSignedIn");

app.MapGet("/api/admin/categories/lookup", async (string q, HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    q = q?.Trim() ?? string.Empty;
    if (q.Length < 2)
        return Results.Ok(Array.Empty<object>());

    const string sql = @"
SELECT CAST(c.category_id AS SIGNED)                               AS Id,
       COALESCE(c.slug, CONCAT('cat:', c.category_id))              AS `Key`,
       c.name                                                       AS Name
  FROM Category c
 WHERE c.name LIKE CONCAT('%', @term, '%')
    OR COALESCE(c.slug, '') LIKE CONCAT('%', @term, '%')
 ORDER BY c.name
 LIMIT 50;";

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync(ct);
    var rows = await conn.QueryAsync(new CommandDefinition(sql, new { term = q }, cancellationToken: ct));
    return Results.Ok(rows);
}).RequireAuthorization("IsSignedIn");

app.MapGet("/api/admin/parts/lookup", async (string? q, long? categoryId, HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    q = q?.Trim();

    const string sql = @"
SELECT CAST(p.part_id AS SIGNED)                     AS Id,
       p.name                                        AS Name,
       p.sku                                         AS Sku,
       CAST(pc.category_id AS SIGNED)                AS CategoryId
  FROM Part p
  LEFT JOIN PartCategory pc
         ON pc.part_id = p.part_id
        AND (pc.is_primary = 1 OR pc.is_primary IS NULL)
 WHERE (@term IS NULL OR @term = '' OR p.name LIKE CONCAT('%', @term, '%') OR p.sku LIKE CONCAT('%', @term, '%'))
   AND (@categoryId IS NULL OR EXISTS (
           SELECT 1 FROM PartCategory pc2
            WHERE pc2.part_id = p.part_id AND pc2.category_id = @categoryId))
 ORDER BY p.name
 LIMIT 50;";

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync(ct);
    var rows = await conn.QueryAsync(new CommandDefinition(sql, new { term = q, categoryId }, cancellationToken: ct));
    return Results.Ok(rows);
}).RequireAuthorization("IsSignedIn");

app.MapGet("/api/admin/engine/{engineId:long}/slots/by-category/{categoryId:long}", async (long engineId, long categoryId, HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    const string sql = @"
SELECT CAST(s.slot_id AS SIGNED)                                AS SlotId,
       s.`key`                                                  AS SlotKey,
       s.`name`                                                 AS SlotName,
       s.gltf_node_path                                         AS GltfNodePath,
       sub.`name`                                               AS SubsystemName,
       CASE WHEN EXISTS (
           SELECT 1 FROM PartSlot ps
            WHERE ps.slot_id = s.slot_id
              AND ps.category_id = @categoryId
              AND (ps.allow IS NULL OR ps.allow <> 0)
       ) THEN TRUE ELSE FALSE END                               AS IsMapped
  FROM Slot s
  JOIN Subsystem sub ON sub.subsystem_id = s.subsystem_id
 WHERE s.engine_family_id = @engineId
 ORDER BY sub.sort_order, s.`key`;";

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync(ct);
    var rows = await conn.QueryAsync<SlotMappingRow>(new CommandDefinition(sql, new { engineId, categoryId }, cancellationToken: ct));
    return Results.Ok(rows);
}).RequireAuthorization("IsSignedIn");

app.MapGet("/api/admin/engine/{engineId:long}/slots/by-part/{partId:long}", async (long engineId, long partId, HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    const string sql = @"
SELECT CAST(s.slot_id AS SIGNED)                                AS SlotId,
       s.`key`                                                  AS SlotKey,
       s.`name`                                                 AS SlotName,
       s.gltf_node_path                                         AS GltfNodePath,
       sub.`name`                                               AS SubsystemName,
       CASE WHEN EXISTS (
           SELECT 1 FROM PartSlot ps
            WHERE ps.slot_id = s.slot_id
              AND ps.part_id = @partId
              AND (ps.allow IS NULL OR ps.allow <> 0)
       ) THEN TRUE ELSE FALSE END                               AS IsMapped
  FROM Slot s
  JOIN Subsystem sub ON sub.subsystem_id = s.subsystem_id
 WHERE s.engine_family_id = @engineId
 ORDER BY sub.sort_order, s.`key`;";

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync(ct);
    var rows = await conn.QueryAsync<SlotMappingRow>(new CommandDefinition(sql, new { engineId, partId }, cancellationToken: ct));
    return Results.Ok(rows);
}).RequireAuthorization("IsSignedIn");

app.MapPost("/api/admin/slot/map-category", async ([FromBody] SlotCategoryMap map, HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    const string sql = @"
INSERT INTO PartSlot (slot_id, category_id, part_id, allow)
VALUES (@SlotId, @CategoryId, NULL, TRUE)
ON DUPLICATE KEY UPDATE allow = VALUES(allow);";

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync(ct);
    await conn.ExecuteAsync(new CommandDefinition(sql, map, cancellationToken: ct));
    return Results.Ok(new { ok = true });
}).RequireAuthorization("IsSignedIn");

app.MapDelete("/api/admin/slot/map-category", async ([FromBody] SlotCategoryMap map, HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    const string sql = "DELETE FROM PartSlot WHERE slot_id=@SlotId AND category_id=@CategoryId";

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync(ct);
    await conn.ExecuteAsync(new CommandDefinition(sql, map, cancellationToken: ct));
    return Results.Ok(new { ok = true });
}).RequireAuthorization("IsSignedIn");

app.MapPost("/api/admin/slot/map-part", async ([FromBody] SlotPartMap map, HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    const string sql = @"
INSERT INTO PartSlot (slot_id, category_id, part_id, allow)
VALUES (@SlotId, NULL, @PartId, TRUE)
ON DUPLICATE KEY UPDATE allow = VALUES(allow);";

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync(ct);
    await conn.ExecuteAsync(new CommandDefinition(sql, map, cancellationToken: ct));
    return Results.Ok(new { ok = true });
}).RequireAuthorization("IsSignedIn");

app.MapDelete("/api/admin/slot/map-part", async ([FromBody] SlotPartMap map, HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    const string sql = "DELETE FROM PartSlot WHERE slot_id=@SlotId AND part_id=@PartId";

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync(ct);
    await conn.ExecuteAsync(new CommandDefinition(sql, map, cancellationToken: ct));
    return Results.Ok(new { ok = true });
}).RequireAuthorization("IsSignedIn");

app.MapGet("/api/admin/sockets/engines", async (HttpContext ctx, IConfiguration cfg) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync();
    var rows = await conn.QueryAsync("SELECT engine_family_id AS id, code AS `key`, COALESCE(notes, code) AS `name`, NULL AS gltf_uri, NULL AS revision, created_at FROM EngineFamily ORDER BY engine_family_id DESC");
    return Results.Ok(rows);
}).RequireAuthorization("IsSignedIn");

app.MapPost("/api/admin/sockets/engines/upsert", async (UpsertEngine dto, HttpContext ctx, IConfiguration cfg) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync();

    if (dto.Id is null)
    {
        var id = (long)(await conn.ExecuteScalarAsync<decimal>(@"
INSERT INTO EngineFamily(code, notes) VALUES (@k, @n);
SELECT LAST_INSERT_ID();", new { k = dto.Key, n = dto.Name }));
        return Results.Ok(new { id });
    }

    await conn.ExecuteAsync("UPDATE EngineFamily SET code=@k, notes=@n WHERE engine_family_id=@id",
        new { id = dto.Id, k = dto.Key, n = dto.Name });
    return Results.Ok(new { id = dto.Id });
}).RequireAuthorization("IsSignedIn");

app.MapDelete("/api/admin/sockets/engines/{id:long}", async (long id, HttpContext ctx, IConfiguration cfg) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    await using var conn = new MySqlConnection(connectionString);
    await conn.ExecuteAsync("DELETE FROM EngineFamily WHERE engine_family_id=@id", new { id });
    return Results.Ok();
}).RequireAuthorization("IsSignedIn");

app.MapGet("/api/admin/subsystems", async (long engineId, HttpContext ctx) =>
{
    if (engineId <= 0)
        return Results.BadRequest(new { error = "invalid_engine_id" });

    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync();
    var rows = await conn.QueryAsync(@"
SELECT CAST(subsystem_id AS SIGNED) AS id,
       CAST(engine_family_id AS SIGNED) AS engine_id,
       `key`,
       `name`,
       gltf_node_path,
       sort_order
FROM Subsystem
WHERE engine_family_id = @engineId
ORDER BY sort_order, `name`;", new { engineId });
    return Results.Ok(rows);
}).RequireAuthorization("IsSignedIn");

app.MapPost("/api/admin/subsystems", async (CreateSubsystemRequest body, HttpContext ctx) =>
{
    if (body is null)
        return Results.BadRequest(new { error = "invalid_body" });

    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync();
    var id = (long)(await conn.ExecuteScalarAsync<decimal>(@"
INSERT INTO Subsystem(engine_family_id, `key`, `name`, gltf_node_path, sort_order)
VALUES (@EngineId, @Key, @Name, @GltfNodePath, @SortOrder);
SELECT LAST_INSERT_ID();", new
    {
        body.EngineId,
        body.Key,
        body.Name,
        GltfNodePath = string.IsNullOrWhiteSpace(body.GltfNodePath) ? null : body.GltfNodePath,
        body.SortOrder
    }));
    return Results.Ok(new { id });
}).RequireAuthorization("IsSignedIn");

app.MapPut("/api/admin/subsystems/{id:long}", async (long id, UpdateSubsystemRequest body, HttpContext ctx) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync();
    await conn.ExecuteAsync(@"
UPDATE Subsystem
SET `key`=@Key,
    `name`=@Name,
    gltf_node_path=@GltfNodePath,
    sort_order=@SortOrder
WHERE subsystem_id=@Id;", new
    {
        Id = id,
        body.Key,
        body.Name,
        GltfNodePath = string.IsNullOrWhiteSpace(body.GltfNodePath) ? null : body.GltfNodePath,
        body.SortOrder
    });
    return Results.Ok(new { ok = true });
}).RequireAuthorization("IsSignedIn");

app.MapDelete("/api/admin/subsystems/{id:long}", async (long id, HttpContext ctx) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync();
    await conn.ExecuteAsync("DELETE FROM Subsystem WHERE subsystem_id=@Id;", new { Id = id });
    return Results.Ok(new { ok = true });
}).RequireAuthorization("IsSignedIn");

app.MapGet("/api/admin/slots", async (long engineId, HttpContext ctx) =>
{
    if (engineId <= 0)
        return Results.BadRequest(new { error = "invalid_engine_id" });

    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync();
    var rows = await conn.QueryAsync(@"
SELECT CAST(slot_id AS SIGNED) AS id,
       CAST(engine_family_id AS SIGNED) AS engine_id,
       CAST(subsystem_id AS SIGNED) AS subsystem_id,
       `key`,
       `name`,
       gltf_node_path,
       min_required,
       capacity
FROM Slot
WHERE engine_family_id = @engineId
ORDER BY `key`;", new { engineId });
    return Results.Ok(rows);
}).RequireAuthorization("IsSignedIn");

app.MapPost("/api/admin/slots", async (CreateSlotRequest body, HttpContext ctx) =>
{
    if (body is null)
        return Results.BadRequest(new { error = "invalid_body" });

    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync();
    var id = (long)(await conn.ExecuteScalarAsync<decimal>(@"
INSERT INTO Slot(engine_family_id, subsystem_id, `key`, `name`, gltf_node_path, min_required, capacity)
VALUES (@EngineId, @SubsystemId, @Key, @Name, @GltfNodePath, @MinRequired, @Capacity);
SELECT LAST_INSERT_ID();", new
    {
        body.EngineId,
        body.SubsystemId,
        body.Key,
        body.Name,
        GltfNodePath = string.IsNullOrWhiteSpace(body.GltfNodePath) ? null : body.GltfNodePath,
        body.MinRequired,
        body.Capacity
    }));
    return Results.Ok(new { id });
}).RequireAuthorization("IsSignedIn");

app.MapPut("/api/admin/slots/{id:long}", async (long id, UpdateSlotRequest body, HttpContext ctx) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync();
    await conn.ExecuteAsync(@"
UPDATE Slot
SET `key`=@Key,
    `name`=@Name,
    gltf_node_path=@GltfNodePath,
    min_required=@MinRequired,
    capacity=@Capacity
WHERE slot_id=@Id;", new
    {
        Id = id,
        body.Key,
        body.Name,
        GltfNodePath = string.IsNullOrWhiteSpace(body.GltfNodePath) ? null : body.GltfNodePath,
        body.MinRequired,
        body.Capacity
    });
    return Results.Ok(new { ok = true });
}).RequireAuthorization("IsSignedIn");

app.MapDelete("/api/admin/slots/{id:long}", async (long id, HttpContext ctx) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync();
    await conn.ExecuteAsync("DELETE FROM Slot WHERE slot_id=@Id;", new { Id = id });
    return Results.Ok(new { ok = true });
}).RequireAuthorization("IsSignedIn");

app.MapPost("/api/admin/slot/alias", async (SlotAliasRequest body, HttpContext ctx) =>
{
    if (body is null)
        return Results.BadRequest(new { error = "invalid_body" });

    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync();
    await conn.ExecuteAsync(@"
INSERT IGNORE INTO slot_socket_alias(slot_id, alias) VALUES(@SlotId, @Alias);", new
    {
        body.SlotId,
        Alias = body.Alias?.Trim()
    });
    return Results.Ok(new { ok = true });
}).RequireAuthorization("IsSignedIn");

app.MapDelete("/api/admin/slot/alias", async ([FromBody] SlotAliasRequest body, HttpContext ctx) =>
{
    if (body is null)
        return Results.BadRequest(new { error = "invalid_body" });

    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync();
    await conn.ExecuteAsync(@"
DELETE FROM slot_socket_alias WHERE slot_id=@SlotId AND alias=@Alias;", new
    {
        body.SlotId,
        Alias = body.Alias?.Trim()
    });
    return Results.Ok(new { ok = true });
}).RequireAuthorization("IsSignedIn");

app.MapPost("/api/admin/slot-edges", async (EdgeUpsertRequest body, HttpContext ctx) =>
{
    if (body is null)
        return Results.BadRequest(new { error = "invalid_body" });

    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    var attributeKey = string.IsNullOrWhiteSpace(body.AttributeKey) ? null : body.AttributeKey;

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync();
    await conn.ExecuteAsync(@"
INSERT INTO SlotEdge(engine_family_id, from_slot_id, to_slot_id, edge, min_required, description, fix_hint, rule)
VALUES(@EngineId, @FromSlotId, @ToSlotId, @Edge, @MinRequired, @Description, @FixHint,
       CASE WHEN @AttributeKey IS NULL THEN '{}' ELSE JSON_OBJECT('attribute_key', @AttributeKey) END)
ON DUPLICATE KEY UPDATE
    min_required = VALUES(min_required),
    description = VALUES(description),
    fix_hint = VALUES(fix_hint),
    rule = VALUES(rule);", new
    {
        body.EngineId,
        body.FromSlotId,
        body.ToSlotId,
        body.Edge,
        body.MinRequired,
        body.Description,
        body.FixHint,
        AttributeKey = attributeKey
    });
    return Results.Ok(new { ok = true });
}).RequireAuthorization("IsSignedIn");

app.MapDelete("/api/admin/slot-edges", async (long fromSlotId, long toSlotId, string edge, HttpContext ctx) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync();
    await conn.ExecuteAsync(@"
DELETE FROM SlotEdge WHERE from_slot_id=@FromSlotId AND to_slot_id=@ToSlotId AND edge=@Edge;", new
    {
        FromSlotId = fromSlotId,
        ToSlotId = toSlotId,
        Edge = edge
    });
    return Results.Ok(new { ok = true });
}).RequireAuthorization("IsSignedIn");

app.MapPost("/api/admin/slots/bulk-from-sockets", async (BulkSocketRequest body, HttpContext ctx) =>
{
    if (body is null)
        return Results.BadRequest(new { error = "invalid_body" });

    if (body.SocketNames is null || body.SocketNames.Length == 0)
        return Results.BadRequest(new { error = "no_socket_names" });

    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    static string NormalizeKey(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return string.Empty;

        var span = input.Trim();
        var builder = new StringBuilder(span.Length);
        char? last = null;

        foreach (var ch in span)
        {
            char mapped;
            if (char.IsLetterOrDigit(ch))
            {
                mapped = char.ToLowerInvariant(ch);
            }
            else if (ch == '_')
            {
                mapped = '_';
            }
            else
            {
                mapped = '_';
            }

            if (mapped == '_' && (builder.Length == 0 || last == '_'))
                continue;

            builder.Append(mapped);
            last = mapped;
        }

        while (builder.Length > 0 && builder[^1] == '_')
        {
            builder.Length--;
        }

        var start = 0;
        while (start < builder.Length && builder[start] == '_')
        {
            start++;
        }

        return start >= builder.Length ? string.Empty : builder.ToString(start, builder.Length - start);
    }

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync();

    foreach (var raw in body.SocketNames.Distinct(StringComparer.OrdinalIgnoreCase))
    {
        if (string.IsNullOrWhiteSpace(raw))
            continue;

        var trimmed = raw.Trim();
        var keySource = trimmed.StartsWith("Socket_", StringComparison.OrdinalIgnoreCase)
            ? trimmed.Substring(7)
            : trimmed;

        var slotKey = NormalizeKey(keySource);
        if (string.IsNullOrEmpty(slotKey))
            continue;

        var displayName = keySource.Replace('_', ' ').Replace('-', ' ').Trim();
        if (string.IsNullOrEmpty(displayName))
            displayName = keySource;

        await conn.ExecuteAsync(@"
INSERT IGNORE INTO Slot(engine_family_id, subsystem_id, `key`, `name`, gltf_node_path, min_required, capacity)
VALUES(@EngineId, @SubsystemId, @Key, @Name, @GltfNodePath, 1, 1);",
            new
            {
                body.EngineId,
                body.SubsystemId,
                Key = slotKey,
                Name = displayName,
                GltfNodePath = trimmed
            });

        var slotId = await conn.ExecuteScalarAsync<long?>(@"
SELECT slot_id FROM Slot WHERE engine_family_id=@EngineId AND `key`=@Key LIMIT 1;",
            new { body.EngineId, Key = slotKey });

        if (slotId is not null)
        {
            await conn.ExecuteAsync("INSERT IGNORE INTO slot_socket_alias(slot_id, alias) VALUES(@SlotId, @Alias);",
                new { SlotId = slotId.Value, Alias = trimmed });
        }
    }

    return Results.Ok(new { ok = true });
}).RequireAuthorization("IsSignedIn");

app.MapGet("/api/admin/sockets/subsystems", async (long engine_id, HttpContext ctx, IConfiguration cfg) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync();
    var rows = await conn.QueryAsync(@"SELECT subsystem_id AS id,
                                              engine_family_id AS engine_id,
                                              `key`,
                                              `name`,
                                              gltf_node_path,
                                              sort_order
                                       FROM Subsystem
                                       WHERE engine_family_id = @e
                                       ORDER BY sort_order, subsystem_id", new { e = engine_id });
    return Results.Ok(rows);
}).RequireAuthorization("IsSignedIn");

app.MapPost("/api/admin/sockets/subsystems/upsert", async (UpsertSubsystem dto, HttpContext ctx, IConfiguration cfg) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync();

    if (dto.Id is null)
    {
        var id = (long)(await conn.ExecuteScalarAsync<decimal>(@"
INSERT INTO Subsystem(engine_family_id,`key`,`name`,gltf_node_path,sort_order) VALUES (@e,@k,@n,@g,@o);
SELECT LAST_INSERT_ID();", new { e = dto.EngineId, k = dto.Key, n = dto.Name, g = dto.GltfNodePath, o = dto.SortOrder }));
        return Results.Ok(new { id });
    }

    await conn.ExecuteAsync(@"UPDATE Subsystem SET engine_family_id=@e, `key`=@k, `name`=@n, gltf_node_path=@g, sort_order=@o WHERE subsystem_id=@id",
        new { id = dto.Id, e = dto.EngineId, k = dto.Key, n = dto.Name, g = dto.GltfNodePath, o = dto.SortOrder });
    return Results.Ok(new { id = dto.Id });
}).RequireAuthorization("IsSignedIn");

app.MapDelete("/api/admin/sockets/subsystems/{id:long}", async (long id, HttpContext ctx, IConfiguration cfg) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    await using var conn = new MySqlConnection(connectionString);
    await conn.ExecuteAsync("DELETE FROM Subsystem WHERE subsystem_id=@id", new { id });
    return Results.Ok();
}).RequireAuthorization("IsSignedIn");

app.MapGet("/api/admin/sockets/slots", async (long engine_id, long? subsystem_id, HttpContext ctx, IConfiguration cfg) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync();
    var rows = await conn.QueryAsync(@"
SELECT s.slot_id      AS id,
       s.engine_family_id AS engine_id,
       s.subsystem_id,
       s.`key`,
       s.`name`,
       s.gltf_node_path,
       s.min_required,
       s.capacity,
       s.notes,
       sub.`name`      AS subsystem_name
FROM Slot s
LEFT JOIN Subsystem sub ON sub.subsystem_id = s.subsystem_id
WHERE s.engine_family_id=@e AND (@sub IS NULL OR s.subsystem_id=@sub)
ORDER BY s.slot_id", new { e = engine_id, sub = subsystem_id });
    return Results.Ok(rows);
}).RequireAuthorization("IsSignedIn");

app.MapPost("/api/admin/sockets/slots/upsert", async (UpsertSlot dto, HttpContext ctx, IConfiguration cfg) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync();

    if (dto.Id is null)
    {
        var id = (long)(await conn.ExecuteScalarAsync<decimal>(@"
INSERT INTO Slot(engine_family_id,subsystem_id,`key`,`name`,gltf_node_path,min_required,capacity,notes)
VALUES (@e,@s,@k,@n,@g,@m,@c,@no);
SELECT LAST_INSERT_ID();", new
        {
            e = dto.EngineId,
            s = dto.SubsystemId,
            k = dto.Key,
            n = dto.Name,
            g = dto.GltfNodePath,
            m = dto.MinRequired,
            c = dto.Capacity,
            no = dto.Notes
        }));
        return Results.Ok(new { id });
    }

    await conn.ExecuteAsync(@"UPDATE Slot SET engine_family_id=@e, subsystem_id=@s, `key`=@k, `name`=@n, gltf_node_path=@g,
    min_required=@m, capacity=@c, notes=@no WHERE slot_id=@id",
        new
        {
            id = dto.Id,
            e = dto.EngineId,
            s = dto.SubsystemId,
            k = dto.Key,
            n = dto.Name,
            g = dto.GltfNodePath,
            m = dto.MinRequired,
            c = dto.Capacity,
            no = dto.Notes
        });
    return Results.Ok(new { id = dto.Id });
}).RequireAuthorization("IsSignedIn");

app.MapDelete("/api/admin/sockets/slots/{id:long}", async (long id, HttpContext ctx, IConfiguration cfg) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    await using var conn = new MySqlConnection(connectionString);
    await conn.ExecuteAsync("DELETE FROM Slot WHERE slot_id=@id", new { id });
    return Results.Ok();
}).RequireAuthorization("IsSignedIn");

app.MapGet("/api/admin/sockets/edges", async (long engine_id, HttpContext ctx, IConfiguration cfg) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync();
    var rows = await conn.QueryAsync(@"
SELECT e.slot_edge_id AS id,
       e.engine_family_id AS engine_id,
       e.from_slot_id,
       e.to_slot_id,
       e.edge,
       e.min_required,
       CASE WHEN e.rule IS NULL THEN NULL ELSE JSON_PRETTY(e.rule) END AS rule,
       sf.`key` AS from_key,
       st.`key` AS to_key
FROM SlotEdge e
JOIN Slot sf ON sf.slot_id = e.from_slot_id
JOIN Slot st ON st.slot_id = e.to_slot_id
WHERE e.engine_family_id=@e
ORDER BY e.slot_edge_id", new { e = engine_id });
    return Results.Ok(rows);
}).RequireAuthorization("IsSignedIn");

app.MapPost("/api/admin/sockets/edges/upsert", async (UpsertEdge dto, HttpContext ctx, IConfiguration cfg) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync();
    var rule = string.IsNullOrWhiteSpace(dto.RuleJson) ? null : dto.RuleJson?.Trim();

    static bool NeedsAttribute(string edge)
        => string.Equals(edge, "MATCH_ATTR", StringComparison.OrdinalIgnoreCase) ||
           string.Equals(edge, "ENABLED_IF", StringComparison.OrdinalIgnoreCase);

    if (!string.IsNullOrWhiteSpace(rule))
    {
        try
        {
            using var doc = JsonDocument.Parse(rule);
            if (NeedsAttribute(dto.Edge) && !doc.RootElement.TryGetProperty("attribute_key", out _))
            {
                return Results.BadRequest(new { error = "missing_attribute_key", field = "ruleJson" });
            }
        }
        catch (JsonException)
        {
            return Results.BadRequest(new { error = "invalid_json", field = "ruleJson" });
        }
    }
    else if (NeedsAttribute(dto.Edge))
    {
        return Results.BadRequest(new { error = "missing_attribute_key", field = "ruleJson" });
    }

    if (dto.Id is null)
    {
        var id = (long)(await conn.ExecuteScalarAsync<decimal>(@"
INSERT INTO SlotEdge(engine_family_id,from_slot_id,to_slot_id,edge,min_required,rule)
VALUES (@e,@f,@t,@edge,@m,CAST(@rule AS JSON));
SELECT LAST_INSERT_ID();",
            new { e = dto.EngineId, f = dto.FromSlotId, t = dto.ToSlotId, edge = dto.Edge, m = dto.MinRequired, rule }));
        return Results.Ok(new { id });
    }

    await conn.ExecuteAsync(@"UPDATE SlotEdge SET engine_family_id=@e, from_slot_id=@f, to_slot_id=@t, edge=@edge, min_required=@m, rule=CAST(@rule AS JSON)
WHERE slot_edge_id=@id",
        new { id = dto.Id, e = dto.EngineId, f = dto.FromSlotId, t = dto.ToSlotId, edge = dto.Edge, m = dto.MinRequired, rule });
    return Results.Ok(new { id = dto.Id });
}).RequireAuthorization("IsSignedIn");

app.MapDelete("/api/admin/sockets/edges/{id:long}", async (long id, HttpContext ctx, IConfiguration cfg) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    await using var conn = new MySqlConnection(connectionString);
    await conn.ExecuteAsync("DELETE FROM SlotEdge WHERE slot_edge_id=@id", new { id });
    return Results.Ok();
}).RequireAuthorization("IsSignedIn");

app.MapGet("/api/admin/socket-map", async (long familyId, HttpContext ctx) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync();
    var rows = await conn.QueryAsync(@"
SELECT *
FROM v_admin_socket_map
WHERE engine_family_id = @f
ORDER BY subsystem_key, slot_key, part_slot_id", new { f = familyId });
    return Results.Ok(rows);
}).RequireAuthorization("IsSignedIn");

app.MapGet("/api/admin/socket-health", async (long familyId, long? buildId, HttpContext ctx) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync();

    const string sql = @"
WITH fam_slots AS (
  SELECT s.slot_id, s.`key` AS slot_key, s.`name` AS slot_name, s.gltf_node_path
  FROM Slot s WHERE s.engine_family_id=@fam
),
ps_rows AS (
  SELECT ps.part_slot_id, ps.slot_id, ps.category_id, ps.part_id, ps.allow
  FROM PartSlot ps
  JOIN fam_slots fs ON fs.slot_id = ps.slot_id
),
wh AS (
  SELECT slot_id, COUNT(*) AS whitelist_rows
  FROM ps_rows
  WHERE allow = 1
  GROUP BY slot_id
),
candidate_parts AS (
  SELECT ps.slot_id, ps.part_id
  FROM ps_rows ps
  WHERE ps.allow = 1 AND ps.part_id IS NOT NULL
  UNION
  SELECT ps.slot_id, pc.part_id
  FROM ps_rows ps
  JOIN PartCategory pc ON ps.allow = 1 AND ps.category_id IS NOT NULL AND pc.category_id = ps.category_id
),
raw_cand AS (
  SELECT slot_id, COUNT(DISTINCT part_id) AS raw_candidates
  FROM candidate_parts
  GROUP BY slot_id
),
direct_part_glb AS (
  SELECT ps.slot_id,
         COUNT(*) AS direct_count,
         SUM(CASE WHEN p.gltf_uri IS NOT NULL AND p.gltf_uri <> '' THEN 1 ELSE 0 END) AS direct_glb_count
  FROM ps_rows ps
  JOIN Part p ON ps.part_id = p.part_id
  WHERE ps.allow = 1 AND ps.part_id IS NOT NULL
  GROUP BY ps.slot_id
),
category_part_glb AS (
  SELECT ps.slot_id,
         COUNT(DISTINCT pc.part_id) AS category_part_count,
         COUNT(DISTINCT CASE WHEN p.gltf_uri IS NOT NULL AND p.gltf_uri <> '' THEN pc.part_id END) AS category_glb_count
  FROM ps_rows ps
  LEFT JOIN PartCategory pc ON ps.allow = 1 AND ps.category_id IS NOT NULL AND pc.category_id = ps.category_id
  LEFT JOIN Part p ON pc.part_id = p.part_id
  WHERE ps.category_id IS NOT NULL AND ps.allow = 1
  GROUP BY ps.slot_id
),
slot_glb_coverage AS (
  SELECT fs.slot_id,
         CASE
           WHEN COALESCE(dp.direct_count,0) > 0
             THEN CASE WHEN COALESCE(dp.direct_glb_count,0) = COALESCE(dp.direct_count,0) THEN 1 ELSE 0 END
           WHEN COALESCE(cp.category_part_count,0) > 0
             THEN CASE WHEN COALESCE(cp.category_glb_count,0) > 0 THEN 1 ELSE 0 END
           ELSE 0
         END AS whitelist_glb_ok
  FROM fam_slots fs
  LEFT JOIN direct_part_glb dp ON dp.slot_id = fs.slot_id
  LEFT JOIN category_part_glb cp ON cp.slot_id = fs.slot_id
),
en AS (
  SELECT v.slot_id, v.enabled FROM v_build_slot_enabled v WHERE @build IS NOT NULL AND v.build_id=@build
)
SELECT
  CAST(fs.slot_id AS SIGNED) AS slot_id,
  fs.slot_key,
  fs.slot_name,
  fs.gltf_node_path,
  COALESCE(CAST(wh.whitelist_rows AS SIGNED),0) AS whitelist_rows,
  COALESCE(CAST(rc.raw_candidates AS SIGNED),0) AS raw_candidates,
  CASE WHEN COALESCE(sgc.whitelist_glb_ok,0) = 1 THEN TRUE ELSE FALSE END AS whitelist_glb_ok,
  CASE WHEN fs.gltf_node_path IS NULL OR fs.gltf_node_path='' THEN FALSE ELSE TRUE END AS node_path_ok,
  CASE WHEN COALESCE(en.enabled,1) = 1 THEN TRUE ELSE FALSE END AS enabled_for_build
FROM fam_slots fs
LEFT JOIN wh  ON wh.slot_id  = fs.slot_id
LEFT JOIN raw_cand rc ON rc.slot_id = fs.slot_id
LEFT JOIN slot_glb_coverage sgc ON sgc.slot_id=fs.slot_id
LEFT JOIN en ON en.slot_id = fs.slot_id
ORDER BY fs.slot_id;";

    var rows = await conn.QueryAsync(sql, new { fam = familyId, build = buildId });
    return Results.Ok(rows);
}).RequireAuthorization("IsSignedIn");

app.MapPatch("/api/admin/slots", async (PatchSlotDto dto, HttpContext ctx) =>
{
    if (dto is null)
        return Results.BadRequest(new { error = "invalid_body" });

    if (dto.slot_id <= 0)
        return Results.BadRequest(new { error = "invalid_slot_id" });

    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    var setClauses = new List<string>();
    var parameters = new DynamicParameters();
    parameters.Add("@id", dto.slot_id);

    if (!string.IsNullOrWhiteSpace(dto.gltf_node_path))
    {
        setClauses.Add("gltf_node_path=@node");
        parameters.Add("@node", dto.gltf_node_path);
    }

    if (!string.IsNullOrWhiteSpace(dto.name))
    {
        setClauses.Add("`name`=@nm");
        parameters.Add("@nm", dto.name);
    }

    if (dto.min_required is not null)
    {
        setClauses.Add("min_required=@min");
        parameters.Add("@min", dto.min_required);
    }

    if (dto.capacity is not null)
    {
        setClauses.Add("capacity=@cap");
        parameters.Add("@cap", dto.capacity);
    }

    if (setClauses.Count == 0)
        return Results.BadRequest(new { error = "no_fields" });

    var sql = $"UPDATE Slot SET {string.Join(", ", setClauses)} WHERE slot_id=@id";

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync();
    await conn.ExecuteAsync(sql, parameters);
    return Results.Ok(new { ok = true });
}).RequireAuthorization("IsSignedIn");

app.MapPatch("/api/admin/slots/mate", async (PatchMateDto dto, HttpContext ctx) =>
{
    if (dto is null || dto.slot_id <= 0)
        return Results.BadRequest(new { error = "invalid_body" });

    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    var setClauses = new List<string>();
    var parameters = new DynamicParameters();
    parameters.Add("@id", dto.slot_id);

    void AddColumn(string column, double? value)
    {
        if (value is null)
            return;
        setClauses.Add($"{column}=@{column}");
        parameters.Add($"@{column}", value);
    }

    AddColumn("mate_tx", dto.mate_tx);
    AddColumn("mate_ty", dto.mate_ty);
    AddColumn("mate_tz", dto.mate_tz);
    AddColumn("mate_rx", dto.mate_rx);
    AddColumn("mate_ry", dto.mate_ry);
    AddColumn("mate_rz", dto.mate_rz);
    AddColumn("mate_scale", dto.mate_scale);

    if (setClauses.Count == 0)
        return Results.BadRequest(new { error = "no_fields" });

    var sql = $"UPDATE Slot SET {string.Join(", ", setClauses)} WHERE slot_id=@id";

    await using var conn = new MySqlConnection(connectionString);
    await conn.ExecuteAsync(sql, parameters);
    return Results.Ok(new { ok = true, updated = setClauses.Count });
}).RequireAuthorization("IsSignedIn");

app.MapPatch("/api/admin/parts", async (PatchPartDto dto, HttpContext ctx) =>
{
    if (dto is null)
        return Results.BadRequest(new { error = "invalid_body" });

    if (dto.part_id <= 0)
        return Results.BadRequest(new { error = "invalid_part_id" });

    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    var setClauses = new List<string>();
    var parameters = new DynamicParameters();
    parameters.Add("@id", dto.part_id);

    if (!string.IsNullOrWhiteSpace(dto.gltf_uri))
    {
        setClauses.Add("gltf_uri=@uri");
        parameters.Add("@uri", dto.gltf_uri);
    }

    if (!string.IsNullOrWhiteSpace(dto.gltf_attach_node))
    {
        setClauses.Add("gltf_attach_node=@an");
        parameters.Add("@an", dto.gltf_attach_node);
    }

    if (!string.IsNullOrWhiteSpace(dto.name))
    {
        setClauses.Add("`name`=@nm");
        parameters.Add("@nm", dto.name);
    }

    if (setClauses.Count == 0)
        return Results.BadRequest(new { error = "no_fields" });

    var sql = $"UPDATE Part SET {string.Join(", ", setClauses)} WHERE part_id=@id";

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync();
    await conn.ExecuteAsync(sql, parameters);
    return Results.Ok(new { ok = true });
}).RequireAuthorization("IsSignedIn");

app.MapPost("/api/admin/partslot", async (AddWhitelistDto dto, HttpContext ctx) =>
{
    if (dto is null)
        return Results.BadRequest(new { error = "invalid_body" });

    if (dto.slot_id <= 0)
        return Results.BadRequest(new { error = "invalid_slot_id" });

    var hasCategory = dto.category_id is not null;
    var hasPart = dto.part_id is not null;
    if (hasCategory == hasPart)
        return Results.BadRequest(new { error = "provide_exactly_one_of_category_or_part" });

    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync();
    var id = (long)(await conn.ExecuteScalarAsync<decimal>(@"
INSERT INTO PartSlot(slot_id, category_id, part_id, allow)
VALUES (@s,@c,@p,@a);
SELECT LAST_INSERT_ID();",
        new { s = dto.slot_id, c = dto.category_id, p = dto.part_id, a = dto.allow ? 1 : 0 }));
    return Results.Ok(new { ok = true, part_slot_id = id });
}).RequireAuthorization("IsSignedIn");

app.MapDelete("/api/admin/partslot/{partSlotId:long}", async (long partSlotId, HttpContext ctx) =>
{
    if (partSlotId <= 0)
        return Results.BadRequest(new { error = "invalid_part_slot_id" });

    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync();
    await conn.ExecuteAsync("DELETE FROM PartSlot WHERE part_slot_id=@id", new { id = partSlotId });
    return Results.Ok(new { ok = true });
}).RequireAuthorization("IsSignedIn");

app.MapPost("/api/admin/edges/upsert-typed", async (UpsertEdgeTyped dto, HttpContext ctx) =>
{
    if (dto is null)
        return Results.BadRequest(new { error = "invalid_body" });

    if (dto.engine_family_id <= 0 || dto.from_slot_id <= 0 || dto.to_slot_id <= 0)
        return Results.BadRequest(new { error = "invalid_ids" });

    if (string.IsNullOrWhiteSpace(dto.edge))
        return Results.BadRequest(new { error = "missing_edge" });

    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    string? ruleJson = null;
    var needsAttribute = string.Equals(dto.edge, "MATCH_ATTR", StringComparison.OrdinalIgnoreCase)
        || string.Equals(dto.edge, "ENABLED_IF", StringComparison.OrdinalIgnoreCase);

    if (needsAttribute)
    {
        if (string.IsNullOrWhiteSpace(dto.attribute_key))
            return Results.BadRequest(new { error = "missing_attribute_key" });

        var rule = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
        {
            ["attribute_key"] = dto.attribute_key
        };

        if (!string.IsNullOrWhiteSpace(dto.op))
            rule["op"] = dto.op;
        if (!string.IsNullOrWhiteSpace(dto.value_text))
            rule["value_text"] = dto.value_text;
        if (dto.value_num is not null)
            rule["value_num"] = dto.value_num;
        if (dto.value_bool is not null)
            rule["value_bool"] = dto.value_bool;

        ruleJson = JsonSerializer.Serialize(rule);
    }

    try
    {
        if (ruleJson is not null)
            JsonDocument.Parse(ruleJson);
    }
    catch (JsonException)
    {
        return Results.BadRequest(new { error = "invalid_rule_json" });
    }

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync();

    if (dto.slot_edge_id is null)
    {
        var id = (long)(await conn.ExecuteScalarAsync<decimal>(@"
INSERT INTO SlotEdge(engine_family_id, from_slot_id, to_slot_id, edge, min_required, rule)
VALUES (@e,@f,@t,@edge,@m,CAST(@rule AS JSON));
SELECT LAST_INSERT_ID();",
            new { e = dto.engine_family_id, f = dto.from_slot_id, t = dto.to_slot_id, edge = dto.edge, m = dto.min_required, rule = ruleJson }));
        return Results.Ok(new { slot_edge_id = id });
    }

    await conn.ExecuteAsync(@"
UPDATE SlotEdge SET engine_family_id=@e, from_slot_id=@f, to_slot_id=@t, edge=@edge, min_required=@m, rule=CAST(@rule AS JSON)
WHERE slot_edge_id=@id",
        new { id = dto.slot_edge_id, e = dto.engine_family_id, f = dto.from_slot_id, t = dto.to_slot_id, edge = dto.edge, m = dto.min_required, rule = ruleJson });
    return Results.Ok(new { slot_edge_id = dto.slot_edge_id });
}).RequireAuthorization("IsSignedIn");

app.MapGet("/api/admin/sockets/partslot", async (long slot_id, HttpContext ctx, IConfiguration cfg) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync();
    var rows = await conn.QueryAsync(@"
SELECT ps.part_slot_id AS id,
       ps.slot_id,
       ps.category_id,
       ps.part_id,
       ps.allow = 1 AS allow,
       c.name AS category_name,
       p.name AS part_name
FROM PartSlot ps
LEFT JOIN Category c ON c.category_id = ps.category_id
LEFT JOIN Part p ON p.part_id = ps.part_id
WHERE ps.slot_id=@s
ORDER BY ps.part_slot_id", new { s = slot_id });
    return Results.Ok(rows);
}).RequireAuthorization("IsSignedIn");

app.MapPost("/api/admin/sockets/partslot/upsert", async (UpsertPartSlot dto, HttpContext ctx, IConfiguration cfg) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    var hasCategory = dto.CategoryId.HasValue;
    var hasPart = dto.PartId.HasValue;
    if (hasCategory == hasPart)
        return Results.BadRequest(new { error = "provide_exactly_one" });

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync();

    if (dto.Id is null)
    {
        var id = (long)(await conn.ExecuteScalarAsync<decimal>(@"
INSERT INTO PartSlot(slot_id, category_id, part_id, allow) VALUES (@s,@c,@p,@a);
SELECT LAST_INSERT_ID();",
            new { s = dto.SlotId, c = dto.CategoryId, p = dto.PartId, a = dto.Allow ? 1 : 0 }));
        return Results.Ok(new { id });
    }

    await conn.ExecuteAsync("UPDATE PartSlot SET slot_id=@s, category_id=@c, part_id=@p, allow=@a WHERE part_slot_id=@id",
        new { id = dto.Id, s = dto.SlotId, c = dto.CategoryId, p = dto.PartId, a = dto.Allow ? 1 : 0 });
    return Results.Ok(new { id = dto.Id });
}).RequireAuthorization("IsSignedIn");

app.MapDelete("/api/admin/sockets/partslot/{id:long}", async (long id, HttpContext ctx, IConfiguration cfg) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    await using var conn = new MySqlConnection(connectionString);
    await conn.ExecuteAsync("DELETE FROM PartSlot WHERE part_slot_id=@id", new { id });
    return Results.Ok();
}).RequireAuthorization("IsSignedIn");

app.MapGet("/api/admin/sockets/attributes", async (HttpContext ctx, IConfiguration cfg) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync();
    var rows = await conn.QueryAsync("SELECT attribute_id AS id, `key`, `name`, `type` FROM Attribute ORDER BY `key`");
    return Results.Ok(rows);
}).RequireAuthorization("IsSignedIn");

app.MapPost("/api/admin/sockets/attributes/upsert", async (UpsertAttribute dto, HttpContext ctx, IConfiguration cfg) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync();

    if (dto.Id is null)
    {
        var id = (long)(await conn.ExecuteScalarAsync<decimal>(@"
INSERT INTO Attribute(`key`,`name`,`type`) VALUES (@k,@n,@t);
SELECT LAST_INSERT_ID();",
            new { k = dto.Key, n = dto.Name, t = dto.Type }));
        return Results.Ok(new { id });
    }

    await conn.ExecuteAsync("UPDATE Attribute SET `key`=@k, `name`=@n, `type`=@t WHERE attribute_id=@id",
        new { id = dto.Id, k = dto.Key, n = dto.Name, t = dto.Type });
    return Results.Ok(new { id = dto.Id });
}).RequireAuthorization("IsSignedIn");

app.MapGet("/api/admin/sockets/part-attributes", async (long part_id, HttpContext ctx, IConfiguration cfg) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync();
    var rows = await conn.QueryAsync(@"
SELECT pa.part_id, pa.attribute_id, a.`key` AS attribute_key, a.`type`, pa.value_num, pa.value_text, pa.value_bool
FROM PartAttribute pa
JOIN Attribute a ON a.attribute_id = pa.attribute_id
WHERE pa.part_id=@p
ORDER BY a.`key`", new { p = part_id });
    return Results.Ok(rows);
}).RequireAuthorization("IsSignedIn");

app.MapPost("/api/admin/sockets/part-attributes/upsert", async (UpsertPartAttribute dto, HttpContext ctx, IConfiguration cfg) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    var setCount = (dto.ValueNum.HasValue ? 1 : 0) + (!string.IsNullOrWhiteSpace(dto.ValueText) ? 1 : 0) + (dto.ValueBool.HasValue ? 1 : 0);
    if (setCount != 1)
        return Results.BadRequest(new { error = "set_exactly_one_value" });

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync();
    await conn.ExecuteAsync(@"
INSERT INTO PartAttribute(part_id, attribute_id, value_num, value_text, value_bool)
VALUES (@p,@a,@vn,@vt,@vb)
ON DUPLICATE KEY UPDATE value_num=VALUES(value_num), value_text=VALUES(value_text), value_bool=VALUES(value_bool)",
        new { p = dto.PartId, a = dto.AttributeId, vn = dto.ValueNum, vt = dto.ValueText, vb = dto.ValueBool });
    return Results.Ok();
}).RequireAuthorization("IsSignedIn");

app.MapDelete("/api/admin/sockets/part-attributes", async (long part_id, long attribute_id, HttpContext ctx, IConfiguration cfg) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync();
    await conn.ExecuteAsync("DELETE FROM PartAttribute WHERE part_id=@p AND attribute_id=@a", new { p = part_id, a = attribute_id });
    return Results.Ok();
}).RequireAuthorization("IsSignedIn");

app.MapGet("/api/admin/search/categories", async (string q, HttpContext ctx, IConfiguration cfg) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    q = q?.Trim() ?? string.Empty;
    if (q.Length < 2)
        return Results.Ok(Array.Empty<object>());

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync();
    var rows = await conn.QueryAsync("SELECT category_id AS id, slug AS `key`, name FROM Category WHERE slug LIKE CONCAT('%',@term,'%') OR name LIKE CONCAT('%',@term,'%') ORDER BY name LIMIT 25", new { term = q });
    return Results.Ok(rows);
}).RequireAuthorization("IsSignedIn");

app.MapGet("/api/admin/search/parts", async (string? q, long? category_id, HttpContext ctx, IConfiguration cfg) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    q = q?.Trim();

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync();
    var rows = await conn.QueryAsync(@"
SELECT
  p.part_id       AS id,
  p.sku           AS `key`,
  p.name,
  pc1.category_id AS category_id
FROM Part p
LEFT JOIN PartCategory pc1
  ON pc1.part_id = p.part_id
  AND (pc1.is_primary = 1 OR pc1.is_primary IS NULL)
WHERE
  (@term IS NULL OR @term = '' OR p.sku LIKE CONCAT('%',@term,'%') OR p.name LIKE CONCAT('%',@term,'%'))
  AND (@cid IS NULL OR EXISTS (
        SELECT 1 FROM PartCategory pc2
        WHERE pc2.part_id = p.part_id AND pc2.category_id = @cid
      ))
ORDER BY p.sku
LIMIT 50", new { term = q, cid = category_id });
    return Results.Ok(rows);
}).RequireAuthorization("IsSignedIn");

app.MapPost("/api/admin/engine-families/{id:long}/autogen-slots", async (long id, HttpContext ctx, IConfiguration cfg) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync();
    await conn.ExecuteAsync("CALL sp_autogen_slots_from_requirements(@e,'auto','Auto-generated subsystem')", new { e = id });
    return Results.Ok(new { ok = true });
}).RequireAuthorization("IsSignedIn");

app.MapPost("/api/admin/engine-families/{id:long}/autogen-edges", async (long id, HttpContext ctx, IConfiguration cfg) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (!EnsureAdmin(ctx))
        return Results.Forbid();

    await using var conn = new MySqlConnection(connectionString);
    await conn.OpenAsync();
    await conn.ExecuteAsync("CALL sp_autogen_edges_from_rules(@e)", new { e = id });
    return Results.Ok(new { ok = true });
}).RequireAuthorization("IsSignedIn");

// Resolve or create a build for the socket preview flow
app.MapPost("/api/builds/route-to-sockets", async (RouteToSocketsRequest? payload, HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    var userId = ctx.User.TryGetUserId();
    if (userId is null)
        return Results.Unauthorized();

    payload ??= new RouteToSocketsRequest();

    static bool IsPositive(long? value) => value.HasValue && value.Value > 0;

    async Task<RouteToSocketsResult?> CreateBlankAsync(MySqlConnection conn, long user, long? engineId, long? treeId, string? engineKey, bool fromExisting, CancellationToken token)
    {
        long? engine = IsPositive(engineId) ? engineId : null;
        if (engine is null && !string.IsNullOrWhiteSpace(engineKey))
        {
            engine = await conn.ExecuteScalarAsync<long?>(new CommandDefinition(
                "SELECT engine_family_id FROM EngineFamily WHERE code=@code ORDER BY engine_family_id LIMIT 1",
                new { code = engineKey }, cancellationToken: token));
        }

        if (engine is null)
        {
            engine = await conn.ExecuteScalarAsync<long?>(new CommandDefinition(
                "SELECT engine_family_id FROM EngineFamily ORDER BY engine_family_id LIMIT 1",
                cancellationToken: token));
            if (engine is null)
            {
                return null;
            }
        }

        long? resolvedTree = IsPositive(treeId) ? treeId : null;
        if (!resolvedTree.HasValue)
        {
            var resolved = await ResolveDefaultTreeForEngineAsync(conn, engine.Value, token);
            if (!resolved.EngineExists)
            {
                return null;
            }

            resolvedTree = resolved.TreeId;
        }

        var name = $"Socket Build {DateTime.UtcNow:yyyyMMdd-HHmmss}";

        await using var insert = new MySqlCommand("INSERT INTO Build(user_id, engine_family_id, tree_id, name, is_archived, is_shared) VALUES(@user, @engine, @tree, @name, FALSE, FALSE); SELECT LAST_INSERT_ID();", conn);
        insert.Parameters.AddWithValue("@user", user);
        insert.Parameters.AddWithValue("@engine", engine.Value);
        insert.Parameters.AddWithValue("@tree", resolvedTree.HasValue ? resolvedTree.Value : (object)DBNull.Value);
        insert.Parameters.AddWithValue("@name", name);

        var id = Convert.ToInt64(await insert.ExecuteScalarAsync(token));

        var reason = fromExisting ? "new_on_same_engine" : "new_build";

        return new RouteToSocketsResult
        {
            TargetBuildId = id,
            Created = true,
            Forked = false,
            Reason = reason
        };
    }

    async Task<RouteToSocketsResult?> DuplicateAsync(MySqlConnection conn, long sourceBuildId, long user, CancellationToken token)
    {
        long engineFamilyId;
        long? treeId = null;
        string sourceName = "Socket Build";

        await using (var fetch = new MySqlCommand("SELECT engine_family_id, tree_id, name FROM Build WHERE build_id=@id", conn))
        {
            fetch.Parameters.AddWithValue("@id", sourceBuildId);
            await using var reader = await fetch.ExecuteReaderAsync(token);
            if (!await reader.ReadAsync(token))
            {
                return null;
            }

            engineFamilyId = reader.GetInt64(0);
            treeId = reader.IsDBNull(1) ? null : reader.GetInt64(1);
            sourceName = reader.IsDBNull(2) ? sourceName : reader.GetString(2);
        }

        await using var tx = await conn.BeginTransactionAsync(token);
        try
        {
            var cloneName = string.IsNullOrWhiteSpace(sourceName) ? "Socket Build" : $"{sourceName} (preview)";

            long newBuildId;
            await using (var insert = new MySqlCommand("INSERT INTO Build(user_id, engine_family_id, tree_id, name, is_archived, is_shared) VALUES(@user, @engine, @tree, @name, FALSE, FALSE); SELECT LAST_INSERT_ID();", conn, (MySqlTransaction)tx))
            {
                insert.Parameters.AddWithValue("@user", user);
                insert.Parameters.AddWithValue("@engine", engineFamilyId);
                insert.Parameters.AddWithValue("@tree", (object?)treeId ?? DBNull.Value);
                insert.Parameters.AddWithValue("@name", cloneName);
                newBuildId = Convert.ToInt64(await insert.ExecuteScalarAsync(token));
            }

            await using (var cloneSelections = new MySqlCommand("INSERT INTO BuildSelection(build_id, category_id, part_id, qty) SELECT @dest, category_id, part_id, qty FROM BuildSelection WHERE build_id=@src", conn, (MySqlTransaction)tx))
            {
                cloneSelections.Parameters.AddWithValue("@dest", newBuildId);
                cloneSelections.Parameters.AddWithValue("@src", sourceBuildId);
                await cloneSelections.ExecuteNonQueryAsync(token);
            }

            try
            {
                await using var cloneSlots = new MySqlCommand(
                    @"INSERT INTO BuildSlotSelection(build_id, slot_id, part_id, quantity)
                      SELECT @dest, slot_id, part_id, quantity
                      FROM BuildSlotSelection
                      WHERE build_id=@src
                      ON DUPLICATE KEY UPDATE part_id = VALUES(part_id), quantity = VALUES(quantity), added_at = CURRENT_TIMESTAMP;",
                    conn, (MySqlTransaction)tx);
                cloneSlots.Parameters.AddWithValue("@dest", newBuildId);
                cloneSlots.Parameters.AddWithValue("@src", sourceBuildId);
                await cloneSlots.ExecuteNonQueryAsync(token);
            }
            catch (MySqlException cloneEx) when (cloneEx.Number == 1146)
            {
                // BuildSlotSelection table not present; ignore to keep the flow resilient.
            }

            await tx.CommitAsync(token);

            return new RouteToSocketsResult
            {
                TargetBuildId = newBuildId,
                Created = true,
                Forked = true,
                Reason = "forked_copy"
            };
        }
        catch
        {
            await tx.RollbackAsync(token);
            throw;
        }
    }

    void LogResult(RouteToSocketsResult result)
    {
        app.Logger.LogInformation(
            "route-to-sockets user={User} build={Build} -> target={Target} created={Created} forked={Forked} reason={Reason}",
            userId.Value,
            payload.BuildId,
            result.TargetBuildId,
            result.Created,
            result.Forked,
            result.Reason);
    }

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureBuildColumnsAsync(conn, ct);
        await EnsurePlanTablesAsync(conn, ct);

        long? existingEngineId = null;
        long? existingTreeId = null;

        if (IsPositive(payload.BuildId))
        {
            await using var buildFetch = new MySqlCommand("SELECT engine_family_id, tree_id FROM Build WHERE build_id=@id", conn);
            buildFetch.Parameters.AddWithValue("@id", payload.BuildId!.Value);
            await using var buildReader = await buildFetch.ExecuteReaderAsync(ct);
            if (!await buildReader.ReadAsync(ct))
            {
                app.Logger.LogInformation("route-to-sockets missing build user={User} build={Build}", userId.Value, payload.BuildId);
                return Results.NotFound(new { error = "build_not_found" });
            }

            existingEngineId = buildReader.IsDBNull(0) ? null : buildReader.GetInt64(0);
            existingTreeId = buildReader.IsDBNull(1) ? null : buildReader.GetInt64(1);
        }

        if (IsPositive(payload.BuildId))
        {
            var buildId = payload.BuildId!.Value;
            var role = await GetBuildRoleAsync(conn, buildId, userId.Value, ct);

            if (!string.IsNullOrWhiteSpace(role))
            {
                if (string.Equals(role, "owner", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(role, "editor", StringComparison.OrdinalIgnoreCase))
                {
                    var authorized = new RouteToSocketsResult
                    {
                        TargetBuildId = buildId,
                        Created = false,
                        Forked = false,
                        Reason = "authorized"
                    };
                    LogResult(authorized);
                    return Results.Ok(authorized);
                }

                var forked = await DuplicateAsync(conn, buildId, userId.Value, ct);
                if (forked is not null)
                {
                    LogResult(forked);
                    return Results.Ok(forked);
                }
            }

            var hasEngineContext = existingEngineId.HasValue || payload.EngineFamilyId.HasValue || !string.IsNullOrWhiteSpace(payload.EngineKey);

            var createdFromExisting = await CreateBlankAsync(
                conn,
                userId.Value,
                existingEngineId ?? payload.EngineFamilyId,
                existingTreeId ?? payload.TreeId,
                payload.EngineKey,
                fromExisting: hasEngineContext,
                ct);

            if (createdFromExisting is not null)
            {
                LogResult(createdFromExisting);
                return Results.Ok(createdFromExisting);
            }

            return Results.Json(new { error = "engine_required", message = "Select an engine family before opening the socket preview." }, statusCode: 400);
        }

        var created = await CreateBlankAsync(conn, userId.Value, payload.EngineFamilyId, payload.TreeId, payload.EngineKey, fromExisting: false, ct);
        if (created is null)
        {
            return Results.Json(new { error = "engine_required", message = "Select an engine family before opening the socket preview." }, statusCode: 400);
        }

        LogResult(created);
        return Results.Ok(created);
    }
    catch (MySqlException ex) when (ex.SqlState == "45000")
    {
        return Results.Json(new { error = "quota_exceeded", message = ex.Message }, statusCode: 403);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Route to sockets failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Publish or unpublish a build to the public gallery (owner only)
app.MapPatch("/api/builds/{id:long}/publish", async (long id, BuildPublishRequest body, HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (body is null || body.IsPublic is null)
        return Results.BadRequest(new { error = "is_public required" });

    var userId = ctx.User.TryGetUserId();
    if (userId is null) return Results.Unauthorized();

    var desiredPublic = body.IsPublic.Value;
    var requestedSlug = string.IsNullOrWhiteSpace(body.Slug) ? null : body.Slug.Trim();
    if (!string.IsNullOrWhiteSpace(requestedSlug))
    {
        requestedSlug = requestedSlug.ToLowerInvariant();
        if (!PublicSlugRegex.IsMatch(requestedSlug))
            return Results.BadRequest(new { error = "invalid_slug", message = "Use 3-40 lowercase letters, numbers, or hyphens." });
    }

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureBuildColumnsAsync(conn, ct);

        long? ownerId = null;
        string? existingSlug = null;
        bool isArchived = false;

        await using (var fetch = new MySqlCommand("SELECT user_id, public_slug, is_archived FROM Build WHERE build_id=@id", conn))
        {
            fetch.Parameters.AddWithValue("@id", id);
            await using var reader = await fetch.ExecuteReaderAsync(ct);
            if (!await reader.ReadAsync(ct))
                return Results.NotFound(new { error = "build_not_found" });

            ownerId = reader.IsDBNull(0) ? null : reader.GetInt64(0);
            existingSlug = reader.IsDBNull(1) ? null : reader.GetString(1);
            isArchived = !reader.IsDBNull(2) && reader.GetBoolean(2);
        }

        if (ownerId != userId.Value)
            return Results.Forbid();

        string? nextSlug = existingSlug;

        if (desiredPublic)
        {
            if (isArchived)
                return Results.Conflict(new { error = "build_archived", message = "Unarchive this build before publishing it." });

            if (!string.IsNullOrWhiteSpace(requestedSlug))
            {
                await using var slugCheck = new MySqlCommand("SELECT build_id FROM Build WHERE public_slug=@slug AND build_id<>@id LIMIT 1", conn);
                slugCheck.Parameters.AddWithValue("@slug", requestedSlug);
                slugCheck.Parameters.AddWithValue("@id", id);
                if (await slugCheck.ExecuteScalarAsync(ct) is not null)
                    return Results.Conflict(new { error = "slug_in_use" });

                nextSlug = requestedSlug;
            }
            else if (string.IsNullOrWhiteSpace(nextSlug))
            {
                nextSlug = await GenerateUniquePublicSlugAsync(conn, ct);
            }
        }
        else
        {
            nextSlug = null;
        }

        await using var update = new MySqlCommand("UPDATE Build SET is_public=@pub, public_slug=@slug WHERE build_id=@id", conn);
        update.Parameters.AddWithValue("@pub", desiredPublic);
        update.Parameters.AddWithValue("@slug", desiredPublic ? (object?)nextSlug ?? DBNull.Value : DBNull.Value);
        update.Parameters.AddWithValue("@id", id);
        await update.ExecuteNonQueryAsync(ct);

        return Results.Ok(new { build_id = id, is_public = desiredPublic, public_slug = desiredPublic ? nextSlug : null });
    }
    catch (MySqlException ex) when (ex.Number == 1062)
    {
        return Results.Conflict(new { error = "slug_in_use" });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Publish build failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Claim an unowned build
app.MapPost("/api/builds/{id:long}/claim", async (long id, HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    var userId = ctx.User.TryGetUserId();
    if (userId is null) return Results.Unauthorized();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureBuildSummaryViewsAsync(conn, ct);
        await EnsurePlanTablesAsync(conn, ct);

        await using var cmd = new MySqlCommand("UPDATE Build SET user_id=@uid WHERE build_id=@id AND user_id IS NULL", conn);
        cmd.Parameters.AddWithValue("@uid", userId.Value);
        cmd.Parameters.AddWithValue("@id", id);
        var rows = await cmd.ExecuteNonQueryAsync(ct);
        if (rows == 0)
        {
            // Determine whether the build exists
            await using var check = new MySqlCommand("SELECT user_id FROM Build WHERE build_id=@id", conn);
            check.Parameters.AddWithValue("@id", id);
            var existingOwner = await check.ExecuteScalarAsync(ct);
            if (existingOwner is null)
                return Results.NotFound(new { error = "Build not found" });
            if (existingOwner is DBNull)
                return Results.Conflict(new { error = "claim_failed" });
            return Results.Conflict(new { error = "already_claimed" });
        }

        return Results.Json(new { build_id = id, user_id = userId.Value });
    }
    catch (MySqlException ex) when (ex.SqlState == "45000")
    {
        return Results.Json(new { error = "quota_exceeded", message = ex.Message }, statusCode: 403);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Claim build failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Delete a build (owner only, must be archived)
app.MapDelete("/api/builds/{id:long}", async (long id, HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    var userId = ctx.User.TryGetUserId();
    if (userId is null) return Results.Unauthorized();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureBuildColumnsAsync(conn, ct);

        long? ownerId = null;
        bool isArchived;

        await using (var fetch = new MySqlCommand("SELECT user_id, is_archived FROM Build WHERE build_id=@id", conn))
        {
            fetch.Parameters.AddWithValue("@id", id);
            await using var reader = await fetch.ExecuteReaderAsync(ct);
            if (!await reader.ReadAsync(ct))
                return Results.NotFound(new { error = "build_not_found" });

            ownerId = reader.IsDBNull(0) ? null : reader.GetInt64(0);
            isArchived = !reader.IsDBNull(1) && reader.GetBoolean(1);
        }

        if (ownerId != userId.Value)
            return Results.Forbid();

        if (!isArchived)
            return Results.Conflict(new { error = "not_deletable", message = "Archive this build before deleting it." });

        await using (var delete = new MySqlCommand("DELETE FROM Build WHERE build_id=@id AND user_id=@uid", conn))
        {
            delete.Parameters.AddWithValue("@id", id);
            delete.Parameters.AddWithValue("@uid", userId.Value);
            var rows = await delete.ExecuteNonQueryAsync(ct);
            if (rows == 0)
                return Results.Conflict(new { error = "delete_failed", message = "Build could not be deleted." });
        }

        return Results.Json(new { ok = true });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Delete build failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Update build tree
app.MapPut("/api/builds/{id:long}/tree", async (long id, HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    var userId = ctx.User.TryGetUserId();
    if (userId is null) return Results.Unauthorized();

    var payload = await ctx.Request.ReadFromJsonAsync<Dictionary<string, long?>>(cancellationToken: ct) ?? new();
    if (!payload.TryGetValue("tree_id", out var treeId))
        return Results.BadRequest(new { error = "tree_id required" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureBuildColumnsAsync(conn, ct);

        var role = await GetBuildRoleAsync(conn, id, userId.Value, ct);
        if (role is null) return Results.Forbid();
        if (role == "viewer") return Results.Forbid();

        await using var cmd = new MySqlCommand("UPDATE Build SET tree_id=@tree WHERE build_id=@id", conn);
        cmd.Parameters.AddWithValue("@tree", (object?)treeId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@id", id);
        var rows = await cmd.ExecuteNonQueryAsync(ct);
        if (rows == 0) return Results.NotFound(new { error = "Build not found" });
        return Results.Json(new { build_id = id, tree_id = treeId });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Update build tree failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("BuildOwnerOrEditor");

// Update build engine family
app.MapPut("/api/builds/{id:long}/engine", async (long id, HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    var userId = ctx.User.TryGetUserId();
    if (userId is null) return Results.Unauthorized();

    var payload = await ctx.Request.ReadFromJsonAsync<Dictionary<string, long?>>(cancellationToken: ct) ?? new();
    if (!payload.TryGetValue("engine_family_id", out var engineFamilyId) || !engineFamilyId.HasValue || engineFamilyId.Value <= 0)
        return Results.BadRequest(new { error = "engine_family_id required" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsurePlanTablesAsync(conn, ct);

        var role = await GetBuildRoleAsync(conn, id, userId.Value, ct);
        if (role is null) return Results.Forbid();
        if (role == "viewer") return Results.Forbid();

        await using (var check = new MySqlCommand("SELECT COUNT(*) FROM EngineFamily WHERE engine_family_id=@ef", conn))
        {
            check.Parameters.AddWithValue("@ef", engineFamilyId.Value);
            var exists = Convert.ToInt32(await check.ExecuteScalarAsync(ct)) > 0;
            if (!exists) return Results.BadRequest(new { error = "engine_family_id not found" });
        }

        await using var cmd = new MySqlCommand("UPDATE Build SET engine_family_id=@ef WHERE build_id=@id", conn);
        cmd.Parameters.AddWithValue("@ef", engineFamilyId.Value);
        cmd.Parameters.AddWithValue("@id", id);
        var rows = await cmd.ExecuteNonQueryAsync(ct);
        if (rows == 0) return Results.NotFound(new { error = "Build not found" });
        return Results.Json(new { build_id = id, engine_family_id = engineFamilyId.Value });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Update build engine failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("BuildOwnerOrEditor");

// Rename / update build metadata
app.MapPatch("/api/builds/{id:long}", async (long id, HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    var userId = ctx.User.TryGetUserId();
    if (userId is null) return Results.Unauthorized();

    var body = await ctx.Request.ReadFromJsonAsync<UpdateBuildRequest>(cancellationToken: ct);
    if (body is null) return Results.BadRequest(new { error = "Invalid JSON" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        var role = await GetBuildRoleAsync(conn, id, userId.Value, ct);
        if (role is null) return Results.Forbid();
        if (role == "viewer") return Results.Forbid();

        var setClauses = new List<string>();
        await using var cmd = new MySqlCommand();
        cmd.Connection = conn;

        if (!string.IsNullOrWhiteSpace(body.Name))
        {
            setClauses.Add("name=@name");
            cmd.Parameters.AddWithValue("@name", body.Name.Trim());
        }

        if (body.IsArchived.HasValue)
        {
            setClauses.Add("is_archived=@archived");
            cmd.Parameters.AddWithValue("@archived", body.IsArchived.Value);
        }

        if (body.IsShared.HasValue)
        {
            setClauses.Add("is_shared=@shared");
            cmd.Parameters.AddWithValue("@shared", body.IsShared.Value);
        }

        if (setClauses.Count == 0)
            return Results.BadRequest(new { error = "No fields provided" });

        cmd.CommandText = $"UPDATE Build SET {string.Join(",", setClauses)} WHERE build_id=@id";
        cmd.Parameters.AddWithValue("@id", id);
        var rows = await cmd.ExecuteNonQueryAsync(ct);
        if (rows == 0) return Results.NotFound(new { error = "Build not found" });

        return Results.Json(new
        {
            build_id = id,
            name = body.Name,
            is_archived = body.IsArchived,
            is_shared = body.IsShared
        });
    }
    catch (MySqlException ex) when (ex.SqlState == "45000")
    {
        return Results.Json(new { error = "quota_exceeded", message = ex.Message }, statusCode: 403);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Update build failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("BuildOwnerOrEditor");

// List builds with lightweight summary
app.MapGet("/api/builds", async (HttpContext ctx, ILogger<Program> logger, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    var userId = ctx.User.TryGetUserId();
    if (userId is null) return Results.Unauthorized();

    var query = ctx.Request.Query;
    var includeArchived = query.TryGetValue("include_archived", out var ia) && bool.TryParse(ia, out var includeArchivedParsed) && includeArchivedParsed;
    var includeShared = query.TryGetValue("include_shared", out var ish) && bool.TryParse(ish, out var includeSharedParsed) && includeSharedParsed;
    var search = query.TryGetValue("q", out var qv) ? qv.ToString()?.Trim() : null;
    var page = query.TryGetValue("page", out var pv) && int.TryParse(pv, out var parsedPage) && parsedPage > 0 ? parsedPage : 1;
    var pageSize = query.TryGetValue("page_size", out var psv) && int.TryParse(psv, out var parsedSize) && parsedSize > 0 ? Math.Min(parsedSize, 200) : 100;
    var offset = (page - 1) * pageSize;

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        // Ensure supporting tables exist (older installs may lack BuildShare)
        await EnsureShareTablesAsync(conn, ct);

        var hasSummary = await ViewExistsAsync(conn, "v_build_summary", ct);

        var summaryColumns = hasSummary
            ? "COALESCE(summary.completion_pct, 0) AS completion_pct, COALESCE(summary.categories_complete, 0) AS categories_complete, COALESCE(summary.categories_total, 0) AS categories_total, summary.estimated_cost_lowest"
            : "0 AS completion_pct, 0 AS categories_complete, 0 AS categories_total, NULL AS estimated_cost_lowest";

        var summaryJoin = hasSummary ? "LEFT JOIN v_build_summary summary ON summary.build_id = b.build_id" : string.Empty;

        var sql = $@"
SELECT
    b.build_id,
    b.name,
    b.is_archived,
    b.updated_at,
    ef.code AS engine_code,
    {summaryColumns},
    b.is_public,
    b.public_slug,
    (b.user_id = @uid) AS is_owner,
    CASE
        WHEN b.user_id = @uid THEN 'owner'
        WHEN share.role IS NOT NULL THEN share.role
        ELSE NULL
    END AS access_role
FROM Build b
JOIN EngineFamily ef ON ef.engine_family_id = b.engine_family_id
{summaryJoin}
LEFT JOIN BuildShare share ON share.build_id = b.build_id AND share.user_id = @uid
WHERE
    (b.user_id = @uid OR (@include_shared = TRUE AND share.role IS NOT NULL))
    AND (@include_archived = TRUE OR b.is_archived = FALSE)
    AND (@search IS NULL OR b.name LIKE CONCAT('%', @search, '%'))
ORDER BY b.is_archived, b.updated_at DESC
LIMIT @take OFFSET @skip";

        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@uid", userId.Value);
        cmd.Parameters.AddWithValue("@include_shared", includeShared);
        cmd.Parameters.AddWithValue("@include_archived", includeArchived);
        cmd.Parameters.AddWithValue("@search", string.IsNullOrWhiteSpace(search) ? DBNull.Value : search);
        cmd.Parameters.AddWithValue("@take", pageSize);
        cmd.Parameters.AddWithValue("@skip", offset);

        var rows = new List<Dictionary<string, object?>>(pageSize);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
            {
                ["build_id"] = reader.GetInt64(0),
                ["name"] = reader.IsDBNull(1) ? null : reader.GetString(1),
                ["is_archived"] = !reader.IsDBNull(2) && reader.GetBoolean(2),
                ["updated_at"] = reader.GetDateTime(3),
                ["engine_code"] = reader.IsDBNull(4) ? null : reader.GetString(4),
                ["completion_pct"] = reader.IsDBNull(5) ? 0m : Convert.ToDecimal(reader.GetValue(5)),
                ["categories_complete"] = reader.IsDBNull(6) ? 0 : Convert.ToInt32(reader.GetValue(6)),
                ["categories_total"] = reader.IsDBNull(7) ? 0 : Convert.ToInt32(reader.GetValue(7)),
                ["estimated_cost_lowest"] = reader.IsDBNull(8) ? null : reader.GetValue(8),
                ["is_public"] = !reader.IsDBNull(9) && reader.GetBoolean(9),
                ["public_slug"] = reader.IsDBNull(10) ? null : reader.GetString(10),
                ["is_owner"] = !reader.IsDBNull(11) && reader.GetBoolean(11),
                ["access_role"] = reader.IsDBNull(12) ? null : reader.GetString(12)
            };

            rows.Add(row);
        }

        return Results.Json(rows);
    }
    catch (MySqlException sqlEx)
    {
        logger.LogError(sqlEx, "MySQL error while loading builds for user {UserId}", userId);
        return Results.Problem(title: "Database error", detail: sqlEx.Message, statusCode: 500);
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Unhandled error while loading builds for user {UserId}", userId);
        return Results.Problem(title: "Fetch builds failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Get build details with access role
app.MapGet("/api/builds/{id:long}", async (long id, HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    var userId = ctx.User.TryGetUserId();
    if (userId is null) return Results.Unauthorized();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        var role = await GetBuildRoleAsync(conn, id, userId.Value, ct);
        if (role is null) return Results.Forbid();

        await using var cmd = new MySqlCommand("SELECT build_id, user_id, engine_family_id, tree_id, name, is_archived, is_shared, is_public, public_slug, created_at, updated_at FROM Build WHERE build_id=@id", conn);
        cmd.Parameters.AddWithValue("@id", id);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct)) return Results.NotFound(new { error = "Build not found" });
        var payload = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
        {
            ["build_id"] = reader.GetInt64(0),
            ["user_id"] = reader.IsDBNull(1) ? null : reader.GetValue(1),
            ["engine_family_id"] = reader.GetInt64(2),
            ["tree_id"] = reader.IsDBNull(3) ? null : reader.GetValue(3),
            ["name"] = reader.IsDBNull(4) ? null : reader.GetString(4),
            ["is_archived"] = !reader.IsDBNull(5) && reader.GetBoolean(5),
            ["is_shared"] = !reader.IsDBNull(6) && reader.GetBoolean(6),
            ["is_public"] = !reader.IsDBNull(7) && reader.GetBoolean(7),
            ["public_slug"] = reader.IsDBNull(8) ? null : reader.GetString(8),
            ["created_at"] = reader.GetDateTime(9),
            ["updated_at"] = reader.GetDateTime(10)
        };

        return Results.Json(new { build = payload, role });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Query failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("BuildOwnerOrEditor");

// Build completion view
app.MapGet("/api/builds/{id:long}/completion", async (long id, HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings:Default not set", statusCode: 500);

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        var rows = await ReadBuildCompletionAsync(conn, id, ct);
        ApplyNoStoreCacheHeaders(ctx);
        return Results.Json(rows);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Query failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("BuildOwnerOrEditor");

// Build selections (read)
app.MapGet("/api/builds/{id:long}/selections", async (long id, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);
    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        const string sql = @"SELECT bs.build_id, bs.category_id, c.name AS category_name, bs.part_id, p.name AS part_name, p.sku, bs.qty
                              FROM BuildSelection bs JOIN Part p ON p.part_id=bs.part_id JOIN Category c ON c.category_id=bs.category_id
                              WHERE bs.build_id=@id ORDER BY c.name, p.name";
        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@id", id);
        var list = new List<Dictionary<string, object?>>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < reader.FieldCount; i++) row[reader.GetName(i)] = reader.IsDBNull(i) ? null : reader.GetValue(i);
            list.Add(row);
        }
        return Results.Json(list);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Query failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("BuildOwnerOrEditor");

// Slot candidate list (EFT-style picker support)
app.MapGet("/api/builds/{id:long}/slots/{slotId:long}/candidates", async (long id, long slotId, IConfiguration cfg) =>
{
    var connString = cfg.GetConnectionString("DefaultConnection");
    if (string.IsNullOrWhiteSpace(connString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    await using var conn = new MySqlConnection(connString);
    await conn.OpenAsync();

    var rows = new List<(long PartId, string PartName, long? CategoryId, bool Allowed, string Reason, string? GltfUri, string? GltfAttachNode)>();

    async Task<Dictionary<long, (string? Uri, string? Attach)>> LoadPartMetadataAsync(IEnumerable<long> ids)
    {
        var distinctIds = ids.Distinct().ToArray();
        var meta = new Dictionary<long, (string? Uri, string? Attach)>();

        if (distinctIds.Length == 0)
            return meta;

        var placeholders = string.Join(",", distinctIds.Select((_, i) => $"@p{i}"));
        var sql = $"SELECT part_id, gltf_uri, gltf_attach_node FROM Part WHERE part_id IN ({placeholders})";

        await using var cmd = new MySqlCommand(sql, conn);
        for (var i = 0; i < distinctIds.Length; i++)
        {
            cmd.Parameters.AddWithValue($"@p{i}", distinctIds[i]);
        }

        await using var rdr = await cmd.ExecuteReaderAsync();
        while (await rdr.ReadAsync())
        {
            var partId = rdr.GetInt64(0);
            var uri = rdr.IsDBNull(1) ? null : rdr.GetString(1);
            var attach = rdr.IsDBNull(2) ? null : rdr.GetString(2);
            meta[partId] = (uri, attach);
        }

        return meta;
    }

    async Task<List<(long PartId, string PartName, long? CategoryId, bool Allowed, string Reason, string? GltfUri, string? GltfAttachNode)>> QueryStoredProcedureAsync()
    {
        var results = new List<(long PartId, string PartName, long? CategoryId, bool Allowed, string Reason, string? GltfUri, string? GltfAttachNode)>();

        await using var cmd = new MySqlCommand("CALL sp_compatible_parts(@b,@s);", conn);
        cmd.Parameters.AddWithValue("@b", id);
        cmd.Parameters.AddWithValue("@s", slotId);

        await using var rdr = await cmd.ExecuteReaderAsync();
        while (await rdr.ReadAsync())
        {
            results.Add((
                rdr.GetInt64(0),
                rdr.GetString(1),
                rdr.IsDBNull(2) ? (long?)null : rdr.GetInt64(2),
                rdr.GetBoolean(3),
                rdr.GetString(4),
                (string?)null,
                (string?)null
            ));
        }

        while (await rdr.NextResultAsync()) { }
        return results;
    }

    async Task<List<(long PartId, string PartName, long? CategoryId, bool Allowed, string Reason, string? GltfUri, string? GltfAttachNode)>> QueryFallbackAsync()
    {
        const string fallbackSql = @"
WITH enabled AS (
  SELECT COALESCE(e.enabled, TRUE) AS enabled
  FROM v_build_slot_enabled e
  WHERE e.build_id = @b AND e.slot_id = @s
),
candidate_parts AS (
  SELECT DISTINCT ps.slot_id, p.part_id, p.name AS part_name, ps.category_id
  FROM PartSlot ps
  JOIN Part p ON p.part_id = ps.part_id
  WHERE ps.slot_id = @s AND ps.allow = 1 AND ps.part_id IS NOT NULL
  UNION
  SELECT DISTINCT ps.slot_id, p.part_id, p.name AS part_name, ps.category_id
  FROM PartSlot ps
  JOIN PartCategory pc ON pc.category_id = ps.category_id
  JOIN Part p ON p.part_id = pc.part_id
  WHERE ps.slot_id = @s AND ps.allow = 1 AND ps.category_id IS NOT NULL
),
candidates AS (
  SELECT cp.part_id, cp.part_name, cp.category_id
  FROM candidate_parts cp
),
selected AS (
  SELECT slot_id, part_id
  FROM BuildSlotSelection
  WHERE build_id = @b
),
others AS (
  SELECT *
  FROM SlotEdge
  WHERE (from_slot_id = @s OR to_slot_id = @s)
    AND edge IN ('MATCH_ATTR','EXCLUDES')
),
paired AS (
  SELECT
    slot_edge_id,
    CASE WHEN from_slot_id = @s THEN to_slot_id ELSE from_slot_id END AS other_slot_id,
    edge AS kind,
    rule
  FROM others
),
excl_hits AS (
  SELECT 1
  FROM paired pr
  JOIN selected s ON s.slot_id = pr.other_slot_id
  WHERE pr.kind = 'EXCLUDES'
  LIMIT 1
),
attr_mismatch AS (
  SELECT c.part_id
  FROM candidates c
  JOIN paired pr ON pr.kind = 'MATCH_ATTR'
  JOIN selected s_to ON s_to.slot_id = pr.other_slot_id
  JOIN Attribute a ON a.`key` = JSON_UNQUOTE(JSON_EXTRACT(pr.rule, '$.attribute_key'))
  JOIN PartAttribute pa_cand ON pa_cand.part_id = c.part_id AND pa_cand.attribute_id = a.attribute_id
  JOIN PartAttribute pa_sel  ON pa_sel.part_id  = s_to.part_id AND pa_sel.attribute_id  = a.attribute_id
  WHERE
    (a.`type`='TEXT'   AND (pa_cand.value_text <> pa_sel.value_text OR pa_cand.value_text IS NULL OR pa_sel.value_text IS NULL)) OR
    (a.`type`='NUMBER' AND (pa_cand.value_num  <> pa_sel.value_num  OR pa_cand.value_num  IS NULL OR pa_sel.value_num  IS NULL)) OR
    (a.`type`='BOOL'   AND (pa_cand.value_bool <> pa_sel.value_bool OR pa_cand.value_bool IS NULL OR pa_sel.value_bool IS NULL))
)
SELECT
  c.part_id,
  c.part_name,
  c.category_id,
  CASE
    WHEN NOT COALESCE((SELECT enabled FROM enabled LIMIT 1), TRUE) THEN 0
    WHEN EXISTS (SELECT 1 FROM excl_hits) THEN 0
    WHEN EXISTS (SELECT 1 FROM attr_mismatch am WHERE am.part_id = c.part_id) THEN 0
    ELSE 1
  END AS allowed,
  CASE
    WHEN NOT COALESCE((SELECT enabled FROM enabled LIMIT 1), TRUE) THEN 'socket_disabled'
    WHEN EXISTS (SELECT 1 FROM excl_hits) THEN 'excluded_by_rule'
    WHEN EXISTS (SELECT 1 FROM attr_mismatch am WHERE am.part_id = c.part_id) THEN 'attr_mismatch'
    ELSE 'ok'
  END AS reason,
  p.gltf_uri,
  p.gltf_attach_node
FROM candidates c
JOIN Part p ON p.part_id = c.part_id
ORDER BY c.part_name;";

        var results = new List<(long PartId, string PartName, long? CategoryId, bool Allowed, string Reason, string? GltfUri, string? GltfAttachNode)>();

        await using var fallback = new MySqlCommand(fallbackSql, conn);
        fallback.Parameters.AddWithValue("@b", id);
        fallback.Parameters.AddWithValue("@s", slotId);
        await using var rdr = await fallback.ExecuteReaderAsync();
        while (await rdr.ReadAsync())
        {
            results.Add((
                rdr.GetInt64(0),
                rdr.GetString(1),
                rdr.IsDBNull(2) ? (long?)null : rdr.GetInt64(2),
                rdr.GetBoolean(3),
                rdr.GetString(4),
                rdr.IsDBNull(5) ? null : rdr.GetString(5),
                rdr.IsDBNull(6) ? null : rdr.GetString(6)
            ));
        }

        return results;
    }

    async Task<SlotMateDto?> LoadSlotMateAsync(long slotId)
    {
        const string mateSql = @"
SELECT
  mate_tx   AS MateTx,
  mate_ty   AS MateTy,
  mate_tz   AS MateTz,
  mate_rx   AS MateRx,
  mate_ry   AS MateRy,
  mate_rz   AS MateRz,
  mate_scale AS MateScale
FROM Slot
WHERE slot_id = @slotId
LIMIT 1;";

        var mate = await conn.QuerySingleOrDefaultAsync<SlotMateDto>(mateSql, new { slotId });
        if (mate.Equals(default(SlotMateDto)))
            return null;
        return mate;
    }

    try
    {
        rows = await QueryStoredProcedureAsync();
    }
    catch (MySqlException ex) when (ex.Number == 1305)
    {
        rows = await QueryFallbackAsync();
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Slot candidate lookup failed", detail: ex.Message, statusCode: 500);
    }

    try
    {
        if (rows.Count == 0)
            return Results.Ok(Array.Empty<object>());

        var missingMeta = rows.Where(r => r.GltfUri is null && r.GltfAttachNode is null)
            .Select(r => r.PartId);
        var meta = await LoadPartMetadataAsync(missingMeta);
        var mate = await LoadSlotMateAsync(slotId);
        object? matePayload = mate is null || mate.Value.IsEmpty
            ? null
            : new
            {
                tx = mate.Value.MateTx,
                ty = mate.Value.MateTy,
                tz = mate.Value.MateTz,
                rx = mate.Value.MateRx,
                ry = mate.Value.MateRy,
                rz = mate.Value.MateRz,
                scale = mate.Value.MateScale
            };

        var payload = rows.Select(r =>
        {
            var resolvedUri = r.GltfUri;
            var resolvedAttach = r.GltfAttachNode;
            if (meta.TryGetValue(r.PartId, out var m))
            {
                resolvedUri ??= m.Uri;
                resolvedAttach ??= m.Attach;
            }
            resolvedAttach ??= "Attach_Main";

            return new
            {
                part_id = r.PartId,
                part_name = r.PartName,
                category_id = r.CategoryId,
                allowed = r.Allowed,
                reason = r.Reason,
                gltf_uri = resolvedUri,
                gltf_attach_node = resolvedAttach,
                mate = matePayload
            };
        }).ToList<object>();

        return Results.Ok(payload);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Slot candidate lookup failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("BuildOwnerOrEditor");

app.MapGet("/api/builds/{buildId:long}/slots/{slotId:long}/current", async (long buildId, long slotId, IConfiguration cfg) =>
{
    var connString = cfg.GetConnectionString("DefaultConnection");
    if (string.IsNullOrWhiteSpace(connString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    await using var conn = new MySqlConnection(connString);
    await conn.OpenAsync();

    var row = await conn.QuerySingleOrDefaultAsync<SlotCurrentRow>(@"
SELECT s.slot_id AS SlotId,
       bs.part_id AS PartId,
       p.gltf_uri AS GltfUri,
       COALESCE(p.gltf_attach_node,'Attach_Main') AS GltfAttachNode,
       s.mate_tx AS MateTx,
       s.mate_ty AS MateTy,
       s.mate_tz AS MateTz,
       s.mate_rx AS MateRx,
       s.mate_ry AS MateRy,
       s.mate_rz AS MateRz,
       s.mate_scale AS MateScale
FROM Build b
JOIN Slot s ON s.engine_family_id = b.engine_family_id AND s.slot_id = @slotId
LEFT JOIN BuildSlotSelection bs ON bs.build_id = @b AND bs.slot_id = s.slot_id
LEFT JOIN Part p ON p.part_id = bs.part_id
WHERE b.build_id = @b
LIMIT 1;", new { b = buildId, slotId });

    if (row.Equals(default(SlotCurrentRow)) || string.IsNullOrWhiteSpace(row.GltfUri))
        return Results.NotFound();

    var hasMate = row.MateTx is not null || row.MateTy is not null || row.MateTz is not null ||
                  row.MateRx is not null || row.MateRy is not null || row.MateRz is not null || row.MateScale is not null;

    object? mate = hasMate
        ? new
        {
            tx = row.MateTx,
            ty = row.MateTy,
            tz = row.MateTz,
            rx = row.MateRx,
            ry = row.MateRy,
            rz = row.MateRz,
            scale = row.MateScale
        }
        : null;

    return Results.Ok(new
    {
        slot_id = row.SlotId,
        gltf_uri = row.GltfUri,
        gltf_attach_node = row.GltfAttachNode ?? "Attach_Main",
        mate
    });
}).RequireAuthorization("BuildOwnerOrEditor");

app.MapGet("/api/builds/{buildId:long}/export", async (long buildId, string? by, bool includeMates, IConfiguration cfg) =>
{
    var connString = cfg.GetConnectionString("DefaultConnection");
    if (string.IsNullOrWhiteSpace(connString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    var useSku = string.Equals(by, "sku", StringComparison.OrdinalIgnoreCase) || string.IsNullOrWhiteSpace(by);

    await using var conn = new MySqlConnection(connString);
    await conn.OpenAsync();

    var head = await conn.QuerySingleOrDefaultAsync<(long Id, string Code)?>(@"SELECT ef.engine_family_id AS Id, ef.code
FROM Build b
JOIN EngineFamily ef ON ef.engine_family_id = b.engine_family_id
WHERE b.build_id = @b", new { b = buildId });

    if (head is null)
        return Results.NotFound(new { error = "build_not_found" });

    var rows = await conn.QueryAsync<ExportSlotRow>(@"
SELECT s.slot_id     AS SlotId,
       s.`key`       AS SlotKey,
       bs.part_id    AS PartId,
       p.sku         AS PartSku,
       bs.quantity   AS Quantity,
       s.mate_tx     AS MateTx,
       s.mate_ty     AS MateTy,
       s.mate_tz     AS MateTz,
       s.mate_rx     AS MateRx,
       s.mate_ry     AS MateRy,
       s.mate_rz     AS MateRz,
       s.mate_scale  AS MateScale
FROM Slot s
JOIN Build b ON b.engine_family_id = s.engine_family_id AND b.build_id = @b
LEFT JOIN BuildSlotSelection bs ON bs.build_id = b.build_id AND bs.slot_id = s.slot_id
LEFT JOIN Part p ON p.part_id = bs.part_id
ORDER BY s.slot_id" , new { b = buildId });

    var slots = rows
        .Where(r => r.PartId is not null)
        .Select(r =>
        {
            object? mate = null;
            if (includeMates && (r.MateTx is not null || r.MateTy is not null || r.MateTz is not null ||
                                 r.MateRx is not null || r.MateRy is not null || r.MateRz is not null || r.MateScale is not null))
            {
                mate = new
                {
                    tx = r.MateTx,
                    ty = r.MateTy,
                    tz = r.MateTz,
                    rx = r.MateRx,
                    ry = r.MateRy,
                    rz = r.MateRz,
                    scale = r.MateScale
                };
            }

            return new
            {
                slot_id = useSku ? null : (long?)r.SlotId,
                slot_key = useSku ? r.SlotKey : null,
                part_id = useSku ? null : r.PartId,
                part_sku = useSku ? r.PartSku : null,
                quantity = r.Quantity ?? 1,
                mate_override = mate
            };
        })
        .ToList();

    var payload = new
    {
        version = 1,
        engine_family = new { id = head.Value.Id, code = head.Value.Code },
        build_meta = new { exported_at = DateTime.UtcNow },
        slots
    };

    return Results.Json(payload, new JsonSerializerOptions { WriteIndented = true });
}).RequireAuthorization("BuildOwnerOrEditor");

app.MapPost("/api/builds/{buildId:long}/import", async (long buildId, ImportPresetDto dto, IConfiguration cfg) =>
{
    if (dto is null)
        return Results.BadRequest(new { error = "invalid_body" });
    if (dto.Version != 1)
        return Results.BadRequest(new { error = "unsupported_version" });
    if (dto.Slots is null || dto.Slots.Count == 0)
        return Results.BadRequest(new { error = "no_slots" });

    var connString = cfg.GetConnectionString("DefaultConnection");
    if (string.IsNullOrWhiteSpace(connString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    await using var conn = new MySqlConnection(connString);
    await conn.OpenAsync();

    var buildFamilyId = await conn.ExecuteScalarAsync<long?>("SELECT engine_family_id FROM Build WHERE build_id=@b", new { b = buildId });
    if (buildFamilyId is null)
        return Results.NotFound(new { error = "build_not_found" });

    if (dto.EngineFamily.Id != buildFamilyId.Value)
        return Results.UnprocessableEntity(new { error = "engine_family_mismatch" });

    var slotMap = (await conn.QueryAsync<(long SlotId, string SlotKey)>(
        "SELECT slot_id AS SlotId, `key` AS SlotKey FROM Slot WHERE engine_family_id=@f",
        new { f = buildFamilyId.Value }))
        .ToDictionary(t => t.SlotKey, t => t.SlotId, StringComparer.OrdinalIgnoreCase);

    var skuToId = (await conn.QueryAsync<(long PartId, string Sku)>(
        "SELECT part_id AS PartId, sku AS Sku FROM Part WHERE sku IS NOT NULL"))
        .ToDictionary(t => t.Sku, t => t.PartId, StringComparer.OrdinalIgnoreCase);

    const string validationSql = @"
WITH enabled AS (
  SELECT COALESCE(e.enabled, TRUE) AS enabled
  FROM v_build_slot_enabled e
  WHERE e.build_id = @b AND e.slot_id = @s
),
candidates AS (
  SELECT DISTINCT p.part_id
  FROM PartSlot ps
  JOIN Part p ON p.part_id = @p
  LEFT JOIN PartCategory pc ON pc.part_id = p.part_id
  WHERE ps.slot_id = @s
    AND ps.allow = 1
    AND (
      (ps.part_id IS NOT NULL AND ps.part_id = p.part_id)
      OR (ps.category_id IS NOT NULL AND EXISTS(
            SELECT 1 FROM PartCategory pc2
            WHERE pc2.part_id = p.part_id AND pc2.category_id = ps.category_id))
    )
),
selected AS (
  SELECT slot_id, part_id
  FROM BuildSlotSelection
  WHERE build_id = @b
),
others AS (
  SELECT *
  FROM SlotEdge
  WHERE (from_slot_id = @s OR to_slot_id = @s)
    AND edge IN ('MATCH_ATTR','EXCLUDES')
),
paired AS (
  SELECT
    slot_edge_id,
    CASE WHEN from_slot_id = @s THEN to_slot_id ELSE from_slot_id END AS other_slot_id,
    edge AS kind,
    rule
  FROM others
),
excl_hits AS (
  SELECT 1
  FROM paired pr
  JOIN selected s ON s.slot_id = pr.other_slot_id
  WHERE pr.kind = 'EXCLUDES'
  LIMIT 1
),
attr_mismatch AS (
  SELECT 1
  FROM paired pr
  JOIN selected s_to ON s_to.slot_id = pr.other_slot_id
  JOIN Attribute a ON a.`key` = JSON_UNQUOTE(JSON_EXTRACT(pr.rule, '$.attribute_key'))
  JOIN PartAttribute pa_cand ON pa_cand.part_id = @p AND pa_cand.attribute_id = a.attribute_id
  JOIN PartAttribute pa_sel  ON pa_sel.part_id  = s_to.part_id AND pa_sel.attribute_id  = a.attribute_id
  WHERE pr.kind = 'MATCH_ATTR'
    AND (
      (a.`type`='TEXT'   AND (pa_cand.value_text <> pa_sel.value_text OR pa_cand.value_text IS NULL OR pa_sel.value_text IS NULL)) OR
      (a.`type`='NUMBER' AND (pa_cand.value_num  <> pa_sel.value_num  OR pa_cand.value_num  IS NULL OR pa_sel.value_num  IS NULL)) OR
      (a.`type`='BOOL'   AND (pa_cand.value_bool <> pa_sel.value_bool OR pa_cand.value_bool IS NULL OR pa_sel.value_bool IS NULL))
    )
  LIMIT 1
)
SELECT
  CASE
    WHEN NOT EXISTS (SELECT 1 FROM candidates) THEN 0
    WHEN NOT COALESCE((SELECT enabled FROM enabled LIMIT 1), TRUE) THEN 0
    WHEN EXISTS (SELECT 1 FROM excl_hits) THEN 0
    WHEN EXISTS (SELECT 1 FROM attr_mismatch) THEN 0
    ELSE 1
  END AS allowed,
  CASE
    WHEN NOT EXISTS (SELECT 1 FROM candidates) THEN 'not_candidate'
    WHEN NOT COALESCE((SELECT enabled FROM enabled LIMIT 1), TRUE) THEN 'socket_disabled'
    WHEN EXISTS (SELECT 1 FROM excl_hits) THEN 'excluded_by_rule'
    WHEN EXISTS (SELECT 1 FROM attr_mismatch) THEN 'attr_mismatch'
    ELSE 'ok'
  END AS reason;";

    var applied = 0;
    var matesUpdated = 0;
    var errors = new List<object>();

    foreach (var slot in dto.Slots)
    {
        long slotId;
        if (slot.SlotId is not null)
        {
            slotId = slot.SlotId.Value;
        }
        else if (!string.IsNullOrWhiteSpace(slot.SlotKey) && slotMap.TryGetValue(slot.SlotKey, out var resolvedSlot))
        {
            slotId = resolvedSlot;
        }
        else
        {
            errors.Add(new { slot = slot.SlotKey ?? slot.SlotId?.ToString() ?? "?", error = "slot_not_found" });
            continue;
        }

        long partId;
        if (slot.PartId is not null)
        {
            partId = slot.PartId.Value;
        }
        else if (!string.IsNullOrWhiteSpace(slot.PartSku) && skuToId.TryGetValue(slot.PartSku, out var resolvedPart))
        {
            partId = resolvedPart;
        }
        else
        {
            errors.Add(new { slot = slotId, error = "part_not_found" });
            continue;
        }

        bool allowed;
        string reason;
        await using (var check = new MySqlCommand(validationSql, conn))
        {
            check.Parameters.AddWithValue("@b", buildId);
            check.Parameters.AddWithValue("@s", slotId);
            check.Parameters.AddWithValue("@p", partId);
            await using var reader = await check.ExecuteReaderAsync();
            if (!await reader.ReadAsync())
            {
                errors.Add(new { slot = slotId, part = partId, error = "validation_failed" });
                continue;
            }

            allowed = reader.GetBoolean(0);
            reason = reader.GetString(1);
        }

        if (!allowed)
        {
            errors.Add(new { slot = slotId, part = partId, error = reason });
            continue;
        }

        await conn.ExecuteAsync(@"
INSERT INTO BuildSlotSelection (build_id, slot_id, part_id, quantity)
VALUES (@b,@s,@p, COALESCE(@q,1))
ON DUPLICATE KEY UPDATE part_id = VALUES(part_id), quantity = VALUES(quantity), added_at = CURRENT_TIMESTAMP;",
            new { b = buildId, s = slotId, p = partId, q = slot.Quantity });
        applied++;

        if (slot.MateOverride is not null)
        {
            await conn.ExecuteAsync(@"
UPDATE Slot SET
  mate_tx = COALESCE(@tx, mate_tx),
  mate_ty = COALESCE(@ty, mate_ty),
  mate_tz = COALESCE(@tz, mate_tz),
  mate_rx = COALESCE(@rx, mate_rx),
  mate_ry = COALESCE(@ry, mate_ry),
  mate_rz = COALESCE(@rz, mate_rz),
  mate_scale = COALESCE(@scale, mate_scale)
WHERE slot_id = @s;",
                new
                {
                    s = slotId,
                    tx = (double?)slot.MateOverride.Tx,
                    ty = (double?)slot.MateOverride.Ty,
                    tz = (double?)slot.MateOverride.Tz,
                    rx = (double?)slot.MateOverride.Rx,
                    ry = (double?)slot.MateOverride.Ry,
                    rz = (double?)slot.MateOverride.Rz,
                    scale = (double?)slot.MateOverride.Scale
                });
            matesUpdated++;
        }
    }

    return Results.Ok(new { applied, mates_updated = matesUpdated, errors });
}).RequireAuthorization("BuildOwnerOrEditor");

app.MapGet("/api/builds/{id:long}/scene", async (long id, IConfiguration cfg) =>
{
    var connString = cfg.GetConnectionString("DefaultConnection");
    if (string.IsNullOrWhiteSpace(connString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    await using var conn = new MySqlConnection(connString);
    await conn.OpenAsync();

    var engineMeta = await conn.QuerySingleOrDefaultAsync<(string? SceneUri, long EngineFamilyId)>(@"
SELECT ef.scene_gltf_uri AS SceneUri,
       ef.engine_family_id AS EngineFamilyId
FROM Build b
JOIN EngineFamily ef ON ef.engine_family_id = b.engine_family_id
WHERE b.build_id = @b", new { b = id });

    if (engineMeta == default)
        return Results.NotFound(new { error = "build_not_found" });

    var slots = await conn.QueryAsync<BuildSceneSlotDto>(@"
SELECT s.slot_id        AS SlotId,
       s.`key`          AS SlotKey,
       s.gltf_node_path AS GltfNodePath,
       s.mate_tx        AS MateTx,
       s.mate_ty        AS MateTy,
       s.mate_tz        AS MateTz,
       s.mate_rx        AS MateRx,
       s.mate_ry        AS MateRy,
       s.mate_rz        AS MateRz,
       s.mate_scale     AS MateScale,
       p.part_id        AS PartId,
       p.sku            AS Sku,
       p.gltf_uri       AS GltfUri,
       p.gltf_attach_node AS GltfAttachNode
FROM Build b
JOIN Slot s ON s.engine_family_id = b.engine_family_id
LEFT JOIN BuildSlotSelection bs ON bs.build_id = b.build_id AND bs.slot_id = s.slot_id
LEFT JOIN Part p ON p.part_id = bs.part_id
WHERE b.build_id = @b
ORDER BY s.slot_id", new { b = id });

    var slotPayload = slots.Select(s =>
    {
        object? mate = s.HasMate
            ? new
            {
                tx = s.MateTx,
                ty = s.MateTy,
                tz = s.MateTz,
                rx = s.MateRx,
                ry = s.MateRy,
                rz = s.MateRz,
                scale = s.MateScale
            }
            : null;

        return new
        {
            slot_id = s.SlotId,
            slot_key = s.SlotKey,
            gltf_node_path = s.GltfNodePath,
            part_id = s.PartId,
            sku = s.Sku,
            gltf_uri = s.GltfUri,
            gltf_attach_node = s.GltfAttachNode,
            mate
        };
    }).ToList();

    return Results.Ok(new { engine_gltf_uri = engineMeta.SceneUri, engine_family_id = engineMeta.EngineFamilyId, slots = slotPayload });
}).RequireAuthorization("BuildOwnerOrEditor");

app.MapGet("/api/builds/{id:long}/stats", async (long id, IConfiguration cfg) =>
{
    var connString = cfg.GetConnectionString("DefaultConnection");
    if (string.IsNullOrWhiteSpace(connString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    await using var conn = new MySqlConnection(connString);
    await conn.OpenAsync();

    var rows = await conn.QueryAsync<BuildStatRow>(@"
SELECT stat_key AS StatKey, stat_name AS StatName, value AS Value
FROM v_build_stats
WHERE build_id = @b", new { b = id });
    return Results.Ok(rows);
}).RequireAuthorization("BuildOwnerOrEditor");

// Slot selection with validation
app.MapPost("/api/builds/{id:long}/select", async (long id, SlotSelectDto dto, IConfiguration cfg) =>
{
    var connString = cfg.GetConnectionString("DefaultConnection");
    if (string.IsNullOrWhiteSpace(connString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (dto is null || dto.SlotId <= 0 || dto.PartId <= 0)
        return Results.BadRequest(new { error = "slot_id and part_id are required" });

    await using var conn = new MySqlConnection(connString);
    await conn.OpenAsync();

    const string checkSql = @"
WITH enabled AS (
  SELECT COALESCE(e.enabled, TRUE) AS enabled
  FROM v_build_slot_enabled e
  WHERE e.build_id = @b AND e.slot_id = @s
),
candidates AS (
  SELECT DISTINCT p.part_id
  FROM PartSlot ps
  JOIN Part p ON p.part_id = @p
  LEFT JOIN PartCategory pc ON pc.part_id = p.part_id
  WHERE ps.slot_id = @s
    AND ps.allow = 1
    AND (
      (ps.part_id IS NOT NULL AND ps.part_id = p.part_id)
      OR (ps.category_id IS NOT NULL AND pc.category_id = ps.category_id)
    )
),
selected AS (
  SELECT slot_id, part_id
  FROM BuildSlotSelection
  WHERE build_id = @b
),
others AS (
  SELECT *
  FROM SlotEdge
  WHERE (from_slot_id = @s OR to_slot_id = @s)
    AND edge IN ('MATCH_ATTR','EXCLUDES')
),
paired AS (
  SELECT
    slot_edge_id,
    CASE WHEN from_slot_id = @s THEN to_slot_id ELSE from_slot_id END AS other_slot_id,
    edge AS kind,
    rule
  FROM others
),
excl_hits AS (
  SELECT 1
  FROM paired pr
  JOIN selected s ON s.slot_id = pr.other_slot_id
  WHERE pr.kind = 'EXCLUDES'
  LIMIT 1
),
attr_mismatch AS (
  SELECT 1
  FROM paired pr
  JOIN selected s_to ON s_to.slot_id = pr.other_slot_id
  JOIN Attribute a ON a.`key` = JSON_UNQUOTE(JSON_EXTRACT(pr.rule, '$.attribute_key'))
  JOIN PartAttribute pa_cand ON pa_cand.part_id = @p AND pa_cand.attribute_id = a.attribute_id
  JOIN PartAttribute pa_sel  ON pa_sel.part_id  = s_to.part_id AND pa_sel.attribute_id  = a.attribute_id
  WHERE pr.kind = 'MATCH_ATTR'
    AND (
      (a.`type`='TEXT'   AND (pa_cand.value_text <> pa_sel.value_text OR pa_cand.value_text IS NULL OR pa_sel.value_text IS NULL)) OR
      (a.`type`='NUMBER' AND (pa_cand.value_num  <> pa_sel.value_num  OR pa_cand.value_num  IS NULL OR pa_sel.value_num  IS NULL)) OR
      (a.`type`='BOOL'   AND (pa_cand.value_bool <> pa_sel.value_bool OR pa_cand.value_bool IS NULL OR pa_sel.value_bool IS NULL))
    )
  LIMIT 1
)
SELECT
  CASE
    WHEN NOT EXISTS (SELECT 1 FROM candidates) THEN 0
    WHEN NOT COALESCE((SELECT enabled FROM enabled LIMIT 1), TRUE) THEN 0
    WHEN EXISTS (SELECT 1 FROM excl_hits) THEN 0
    WHEN EXISTS (SELECT 1 FROM attr_mismatch) THEN 0
    ELSE 1
  END AS allowed,
  CASE
    WHEN NOT EXISTS (SELECT 1 FROM candidates) THEN 'not_candidate'
    WHEN NOT COALESCE((SELECT enabled FROM enabled LIMIT 1), TRUE) THEN 'socket_disabled'
    WHEN EXISTS (SELECT 1 FROM excl_hits) THEN 'excluded_by_rule'
    WHEN EXISTS (SELECT 1 FROM attr_mismatch) THEN 'attr_mismatch'
    ELSE 'ok'
  END AS reason;";

    bool allowed;
    string reason;

    await using (var check = new MySqlCommand(checkSql, conn))
    {
        check.Parameters.AddWithValue("@b", id);
        check.Parameters.AddWithValue("@s", dto.SlotId);
        check.Parameters.AddWithValue("@p", dto.PartId);
        await using var reader = await check.ExecuteReaderAsync();
        if (!await reader.ReadAsync())
            return Results.UnprocessableEntity(new { error = "not_candidate" });

        allowed = reader.GetBoolean(0);
        reason = reader.GetString(1);
    }

    if (!allowed)
        return Results.UnprocessableEntity(new { error = reason });

    const string upsertSql = @"
INSERT INTO BuildSlotSelection (build_id, slot_id, part_id, quantity)
VALUES (@b,@s,@p, COALESCE(@q,1))
ON DUPLICATE KEY UPDATE part_id = VALUES(part_id), quantity = VALUES(quantity), added_at = CURRENT_TIMESTAMP;";

    await using (var upsert = new MySqlCommand(upsertSql, conn))
    {
        upsert.Parameters.AddWithValue("@b", id);
        upsert.Parameters.AddWithValue("@s", dto.SlotId);
        upsert.Parameters.AddWithValue("@p", dto.PartId);
        upsert.Parameters.AddWithValue("@q", dto.Quantity.HasValue ? dto.Quantity.Value : 1);
        await upsert.ExecuteNonQueryAsync();
    }

    await using var fetch = new MySqlCommand("SELECT build_id, slot_id, part_id, quantity FROM BuildSlotSelection WHERE build_id=@b AND slot_id=@s", conn);
    fetch.Parameters.AddWithValue("@b", id);
    fetch.Parameters.AddWithValue("@s", dto.SlotId);
    await using var resultReader = await fetch.ExecuteReaderAsync();
    if (!await resultReader.ReadAsync())
        return Results.Problem(title: "Selection save failed", detail: "build_slot_selection_missing", statusCode: 500);

    return Results.Ok(new
    {
        build_id = resultReader.GetInt64(0),
        slot_id = resultReader.GetInt64(1),
        part_id = resultReader.GetInt64(2),
        quantity = resultReader.GetInt32(3)
    });
}).RequireAuthorization("BuildOwnerOrEditor");

app.MapPost("/api/builds/{id:long}/clear", async (long id, SlotClearDto dto, IConfiguration cfg) =>
{
    if (dto is null || dto.SlotId <= 0)
        return Results.BadRequest(new { error = "invalid_body" });

    var connString = cfg.GetConnectionString("DefaultConnection");
    if (string.IsNullOrWhiteSpace(connString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    await using var conn = new MySqlConnection(connString);
    await conn.OpenAsync();
    await conn.ExecuteAsync("DELETE FROM BuildSlotSelection WHERE build_id=@b AND slot_id=@s", new { b = id, s = dto.SlotId });
    return Results.Ok(new { ok = true });
}).RequireAuthorization("BuildOwnerOrEditor");

// Combined slot summary view (status + badge)
app.MapGet("/api/builds/{id:long}/slots", async (long id, HttpContext ctx, IConfiguration cfg, CancellationToken ct) =>
{
    var connString = cfg.GetConnectionString("DefaultConnection");
    if (string.IsNullOrWhiteSpace(connString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    var userId = ctx.User.TryGetUserId();
    if (userId is null)
        return Results.Unauthorized();

    try
    {
        await using var conn = new MySqlConnection(connString);
        await conn.OpenAsync(ct);

        var role = await GetBuildRoleAsync(conn, id, userId.Value, ct);
        if (role is null || string.Equals(role, "viewer", StringComparison.OrdinalIgnoreCase))
            return Results.Forbid();

        var rows = await conn.QueryAsync(new CommandDefinition(
            @"SELECT build_id, slot_id, slot_key, slot_name, subsystem_id,
                     part_id, part_name, enabled, local_complete, rules_ok,
                     status_code, badge
              FROM v_build_slot_summary
              WHERE build_id = @build
              ORDER BY slot_key",
            new { build = id }, cancellationToken: ct));

        var shaped = rows.Select(row => new
        {
            build_id = (long)row.build_id,
            slot_id = (long)row.slot_id,
            slot_key = (string)row.slot_key,
            slot_name = (string)row.slot_name,
            subsystem_id = row.subsystem_id == null ? (long?)null : (long)row.subsystem_id,
            part_id = row.part_id == null ? (long?)null : (long)row.part_id,
            part_name = row.part_name as string,
            enabled = CoerceToBool(row.enabled),
            local_complete = CoerceToBool(row.local_complete),
            rules_ok = CoerceToBool(row.rules_ok),
            status_code = row.status_code as string,
            badge = row.badge as string
        });

        return Results.Ok(shaped);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Slot summary query failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("BuildOwnerOrEditor");

// Subsystem badge rollup
app.MapGet("/api/builds/{id:long}/subsystems", async (long id, HttpContext ctx, IConfiguration cfg, CancellationToken ct) =>
{
    var connString = cfg.GetConnectionString("DefaultConnection");
    if (string.IsNullOrWhiteSpace(connString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    var userId = ctx.User.TryGetUserId();
    if (userId is null)
        return Results.Unauthorized();

    try
    {
        await using var conn = new MySqlConnection(connString);
        await conn.OpenAsync(ct);

        var role = await GetBuildRoleAsync(conn, id, userId.Value, ct);
        if (role is null || string.Equals(role, "viewer", StringComparison.OrdinalIgnoreCase))
            return Results.Forbid();

        var rows = await conn.QueryAsync(new CommandDefinition(
            @"SELECT build_id, subsystem_id, subsystem_name, ok_slots, total_slots, badge
              FROM v_build_subsystem_summary
              WHERE build_id = @build
              ORDER BY subsystem_name",
            new { build = id }, cancellationToken: ct));

        return Results.Ok(rows);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Subsystem summary failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("BuildOwnerOrEditor");

// Create preset from current build selection
app.MapPost("/api/builds/{buildId:long}/presets", async (long buildId, SavePresetDto dto, HttpContext ctx, IConfiguration cfg, CancellationToken ct) =>
{
    var connString = cfg.GetConnectionString("DefaultConnection");
    if (string.IsNullOrWhiteSpace(connString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    if (dto is null || string.IsNullOrWhiteSpace(dto.Name))
        return Results.BadRequest(new { error = "name_required" });

    var userId = ctx.User.TryGetUserId();
    if (userId is null)
        return Results.Unauthorized();

    await using var conn = new MySqlConnection(connString);
    await conn.OpenAsync(ct);

    var role = await GetBuildRoleAsync(conn, buildId, userId.Value, ct);
    if (role is null || string.Equals(role, "viewer", StringComparison.OrdinalIgnoreCase))
        return Results.Forbid();

    await using var tx = await conn.BeginTransactionAsync(ct);

    var engineId = await conn.ExecuteScalarAsync<long?>(new CommandDefinition(
        "SELECT engine_family_id FROM Build WHERE build_id=@build LIMIT 1",
        new { build = buildId }, tx, cancellationToken: ct));
    if (engineId is null)
    {
        await tx.RollbackAsync(ct);
        return Results.NotFound(new { error = "build_not_found" });
    }

    var presetName = dto.Name.Trim();
    try
    {
        await conn.ExecuteAsync(new CommandDefinition(
            "INSERT INTO Preset(engine_family_id, name, owner_user, is_public) VALUES (@engine, @name, @owner, @pub)",
            new { engine = engineId.Value, name = presetName, owner = userId.Value, pub = dto.IsPublic ? 1 : 0 },
            tx, cancellationToken: ct));
    }
    catch (MySqlException ex) when (ex.Number == 1062)
    {
        await tx.RollbackAsync(ct);
        return Results.BadRequest(new { error = "preset_exists", message = "Preset name already exists for this engine." });
    }

    var presetId = await conn.ExecuteScalarAsync<long>(new CommandDefinition(
        "SELECT LAST_INSERT_ID();", transaction: tx, cancellationToken: ct));

    await conn.ExecuteAsync(new CommandDefinition(
        @"INSERT INTO PresetSelection(preset_id, slot_id, part_id, quantity)
          SELECT @preset, slot_id, part_id, quantity
          FROM BuildSlotSelection
          WHERE build_id = @build
          ON DUPLICATE KEY UPDATE part_id=VALUES(part_id), quantity=VALUES(quantity);",
        new { preset = presetId, build = buildId }, tx, cancellationToken: ct));

    await tx.CommitAsync(ct);
    return Results.Ok(new { preset_id = presetId });
}).RequireAuthorization("BuildOwnerOrEditor");

// List presets (optionally filtered by engine family)
app.MapGet("/api/presets", async (long? engineFamilyId, IConfiguration cfg, CancellationToken ct) =>
{
    var connString = cfg.GetConnectionString("DefaultConnection");
    if (string.IsNullOrWhiteSpace(connString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    await using var conn = new MySqlConnection(connString);
    var presets = await conn.QueryAsync(new CommandDefinition(
        @"SELECT preset_id, engine_family_id, name, owner_user, is_public, created_at, updated_at
          FROM Preset
          WHERE (@engineId IS NULL OR engine_family_id = @engineId)
          ORDER BY created_at DESC",
        new { engineId = engineFamilyId }, cancellationToken: ct));

    return Results.Ok(presets);
});

// Validate a preset against slot rules
app.MapGet("/api/presets/{presetId:long}/validate", async (long presetId, IConfiguration cfg, CancellationToken ct) =>
{
    var connString = cfg.GetConnectionString("DefaultConnection");
    if (string.IsNullOrWhiteSpace(connString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    await using var conn = new MySqlConnection(connString);
    var rows = await conn.QueryAsync(new CommandDefinition(
        @"SELECT preset_id, slot_id, slot_key, slot_name, part_id, part_name, socket_enabled, status_code
          FROM v_preset_slot_validation
          WHERE preset_id = @preset
          ORDER BY slot_id",
        new { preset = presetId }, cancellationToken: ct));

    return Results.Ok(rows);
});

// Apply a preset to an existing build (non-destructive upsert)
app.MapPost("/api/builds/{buildId:long}/apply-preset/{presetId:long}", async (long buildId, long presetId, HttpContext ctx, IConfiguration cfg, CancellationToken ct) =>
{
    var connString = cfg.GetConnectionString("DefaultConnection");
    if (string.IsNullOrWhiteSpace(connString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    var userId = ctx.User.TryGetUserId();
    if (userId is null)
        return Results.Unauthorized();

    await using var conn = new MySqlConnection(connString);
    await conn.OpenAsync(ct);

    var role = await GetBuildRoleAsync(conn, buildId, userId.Value, ct);
    if (role is null || string.Equals(role, "viewer", StringComparison.OrdinalIgnoreCase))
        return Results.Forbid();

    await using var tx = await conn.BeginTransactionAsync(ct);

    var buildEngine = await conn.ExecuteScalarAsync<long?>(new CommandDefinition(
        "SELECT engine_family_id FROM Build WHERE build_id=@build LIMIT 1",
        new { build = buildId }, tx, cancellationToken: ct));
    var presetEngine = await conn.ExecuteScalarAsync<long?>(new CommandDefinition(
        "SELECT engine_family_id FROM Preset WHERE preset_id=@preset LIMIT 1",
        new { preset = presetId }, tx, cancellationToken: ct));

    if (buildEngine is null || presetEngine is null)
    {
        await tx.RollbackAsync(ct);
        return Results.NotFound(new { error = "build_or_preset_missing" });
    }

    if (buildEngine.Value != presetEngine.Value)
    {
        await tx.RollbackAsync(ct);
        return Results.UnprocessableEntity(new { error = "engine_mismatch" });
    }

    var selections = (await conn.QueryAsync<(long SlotId, long PartId, int Quantity)>(new CommandDefinition(
        "SELECT slot_id AS SlotId, part_id AS PartId, quantity AS Quantity FROM PresetSelection WHERE preset_id=@preset",
        new { preset = presetId }, tx, cancellationToken: ct))).ToList();

    const string checkSql = @"
WITH enabled AS (
  SELECT COALESCE(e.enabled, TRUE) AS enabled
  FROM v_build_slot_enabled e
  WHERE e.build_id = @b AND e.slot_id = @s
),
candidates AS (
  SELECT ps.part_id
  FROM PartSlot ps
  WHERE ps.slot_id = @s AND ps.allow = 1 AND ps.part_id = @p
  UNION
  SELECT pc.part_id
  FROM PartSlot ps
  JOIN PartCategory pc ON pc.category_id = ps.category_id
  WHERE ps.slot_id = @s AND ps.allow = 1 AND ps.category_id IS NOT NULL AND pc.part_id = @p
),
selected AS (
  SELECT slot_id, part_id
  FROM BuildSlotSelection
  WHERE build_id = @b
),
others AS (
  SELECT *
  FROM SlotEdge
  WHERE (from_slot_id = @s OR to_slot_id = @s)
    AND edge IN ('MATCH_ATTR','EXCLUDES')
),
paired AS (
  SELECT
    slot_edge_id,
    CASE WHEN from_slot_id = @s THEN to_slot_id ELSE from_slot_id END AS other_slot_id,
    edge AS kind,
    rule
  FROM others
),
excl_hits AS (
  SELECT 1
  FROM paired pr
  JOIN selected sel ON sel.slot_id = pr.other_slot_id
  WHERE pr.kind = 'EXCLUDES'
  LIMIT 1
),
attr_mismatch AS (
  SELECT 1
  FROM paired pr
  JOIN selected sel ON sel.slot_id = pr.other_slot_id
  JOIN Attribute a ON a.`key` = JSON_UNQUOTE(JSON_EXTRACT(pr.rule,'$.attribute_key'))
  JOIN PartAttribute pa_sel ON pa_sel.part_id = sel.part_id AND pa_sel.attribute_id = a.attribute_id
  JOIN PartAttribute pa_new ON pa_new.part_id = @p AND pa_new.attribute_id = a.attribute_id
  WHERE pr.kind = 'MATCH_ATTR'
    AND (
      (a.`type`='TEXT'   AND (pa_sel.value_text <> pa_new.value_text OR pa_sel.value_text IS NULL OR pa_new.value_text IS NULL)) OR
      (a.`type`='NUMBER' AND (pa_sel.value_num  <> pa_new.value_num  OR pa_sel.value_num  IS NULL OR pa_new.value_num  IS NULL)) OR
      (a.`type`='BOOL'   AND (pa_sel.value_bool <> pa_new.value_bool OR pa_sel.value_bool IS NULL OR pa_new.value_bool IS NULL))
    )
)
SELECT
  CASE
    WHEN NOT COALESCE((SELECT enabled FROM enabled LIMIT 1), TRUE) THEN 0
    WHEN NOT EXISTS (SELECT 1 FROM candidates) THEN 0
    WHEN EXISTS (SELECT 1 FROM excl_hits) THEN 0
    WHEN EXISTS (SELECT 1 FROM attr_mismatch) THEN 0
    ELSE 1
  END AS allowed;";

    var upserts = 0;
    foreach (var selection in selections)
    {
        var allowed = await conn.ExecuteScalarAsync<int>(new CommandDefinition(
            checkSql,
            new { b = buildId, s = selection.SlotId, p = selection.PartId },
            tx, cancellationToken: ct));

        if (allowed == 1)
        {
            await conn.ExecuteAsync(new CommandDefinition(
                @"INSERT INTO BuildSlotSelection(build_id, slot_id, part_id, quantity)
                  VALUES (@b,@s,@p,@q)
                  ON DUPLICATE KEY UPDATE part_id = VALUES(part_id), quantity = VALUES(quantity), added_at = CURRENT_TIMESTAMP;",
                new { b = buildId, s = selection.SlotId, p = selection.PartId, q = selection.Quantity },
                tx, cancellationToken: ct));
            upserts++;
        }
    }

    await tx.CommitAsync(ct);
    return Results.Ok(new ApplyPresetResultDto(buildId, presetId, upserts));
}).RequireAuthorization("BuildOwnerOrEditor");

// Build selection: add part (auto-resolve primary category when missing)
app.MapPost("/api/builds/{buildId:long}/add-part", async (HttpContext ctx, long buildId, BuildAddPartRequest body, IGamification gamification, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    var userId = ctx.User.TryGetUserId();
    if (userId is null)
        return Results.Unauthorized();

    if (body is null || body.PartId <= 0)
        return Results.BadRequest(new { error = "invalid_payload", message = "part_id is required." });

    var qty = body.Qty ?? 1m;
    if (qty <= 0)
        return Results.BadRequest(new { error = "invalid_qty", message = "Quantity must be greater than zero." });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        var role = await GetBuildRoleAsync(conn, buildId, userId.Value, ct);
        if (string.IsNullOrWhiteSpace(role) || string.Equals(role, "viewer", StringComparison.OrdinalIgnoreCase))
            return Results.Forbid();

        await using (var partCheck = new MySqlCommand("SELECT 1 FROM Part WHERE part_id=@p LIMIT 1", conn))
        {
            partCheck.Parameters.AddWithValue("@p", body.PartId);
            if (await partCheck.ExecuteScalarAsync(ct) is null)
                return Results.NotFound(new { error = "part_not_found", message = "Part was not found." });
        }

        var categoryId = body.CategoryId;
        if (!categoryId.HasValue)
        {
            const string categorySql = @"SELECT pc.category_id
                                          FROM PartCategory pc
                                          WHERE pc.part_id=@part
                                          ORDER BY pc.is_primary DESC, pc.display_order ASC
                                          LIMIT 1";
            await using var catCmd = new MySqlCommand(categorySql, conn);
            catCmd.Parameters.AddWithValue("@part", body.PartId);
            var result = await catCmd.ExecuteScalarAsync(ct);
            categoryId = result is null ? null : Convert.ToInt64(result);
        }

        if (!categoryId.HasValue)
            return Results.BadRequest(new { error = "no_category_mapping", message = "This part is not linked to any categories." });

        await EnsureBuildSummaryViewsAsync(conn, ct);

        var selectionCountBefore = await conn.ExecuteScalarAsync<long>(new CommandDefinition(
            "SELECT COUNT(*) FROM BuildSelection WHERE build_id=@build",
            new { build = buildId },
            cancellationToken: ct));
        var wasFirstSelection = selectionCountBefore == 0;

        var categoriesBefore = await LoadCategoryStatusesAsync(conn, buildId, ct);
        var summaryBefore = await LoadSummarySnapshotAsync(conn, buildId, ct);

        const string insertSql = @"INSERT INTO BuildSelection(build_id, category_id, part_id, qty)
                                   VALUES(@build, @category, @part, @qty)
                                   ON DUPLICATE KEY UPDATE qty = qty + VALUES(qty)";

        try
        {
            await using var insertCmd = new MySqlCommand(insertSql, conn);
            insertCmd.Parameters.AddWithValue("@build", buildId);
            insertCmd.Parameters.AddWithValue("@category", categoryId.Value);
            insertCmd.Parameters.AddWithValue("@part", body.PartId);
            insertCmd.Parameters.AddWithValue("@qty", qty);
            await insertCmd.ExecuteNonQueryAsync(ct);
        }
        catch (MySqlException ex) when (ex.SqlState == "45000")
        {
            return Results.Json(new { error = "blocked", message = ex.Message }, statusCode: StatusCodes.Status403Forbidden);
        }

        Dictionary<long, string>? categoriesAfter = null;
        SummarySnapshot summaryAfter = default;

        try
        {
            categoriesAfter = await LoadCategoryStatusesAsync(conn, buildId, ct);
            summaryAfter = await LoadSummarySnapshotAsync(conn, buildId, ct);

            await TrackGamificationAsync(
                gamification,
                conn,
                userId.Value,
                buildId,
                wasFirstSelection,
                categoriesBefore,
                categoriesAfter,
                summaryBefore,
                summaryAfter,
                ct);
        }
        catch (Exception hookEx)
        {
            app.Logger.LogError(hookEx, "Gamification add-part hook failed for build {BuildId}", buildId);
        }

        return Results.Ok(new
        {
            ok = true,
            build_id = buildId,
            part_id = body.PartId,
            category_id = categoryId.Value,
            qty_added = qty
        });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Add part failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("BuildOwnerOrEditor");

// Build selections (upsert)
app.MapPost("/api/builds/{id:long}/selections/increment", async (long id, HttpContext ctx, IGamification gamification, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    var userId = ctx.User.TryGetUserId();
    if (userId is null) return Results.Unauthorized();

    var body = await ctx.Request.ReadFromJsonAsync<SelectionAdjustRequest>(cancellationToken: ct);
    if (body is null) return Results.BadRequest(new { error = "Invalid JSON" });

    var categoryId = body.CategoryId;
    var partId = body.PartId;
    var delta = body.Delta ?? 1m;
    if (delta == 0)
    {
        return Results.BadRequest(new { error = "delta must not be zero" });
    }

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        var role = await GetBuildRoleAsync(conn, id, userId.Value, ct);
        if (role is null || role == "viewer") return Results.Forbid();

        await EnsureBuildSummaryViewsAsync(conn, ct);

        var selectionCountBefore = await conn.ExecuteScalarAsync<long>(new CommandDefinition(
            "SELECT COUNT(*) FROM BuildSelection WHERE build_id=@build",
            new { build = id },
            cancellationToken: ct));
        var wasFirstSelection = selectionCountBefore == 0;

        var categoriesBefore = await LoadCategoryStatusesAsync(conn, id, ct);
        var summaryBefore = await LoadSummarySnapshotAsync(conn, id, ct);

        await using var tx = await conn.BeginTransactionAsync(ct);
        try
        {
            // Read current qty (if any)
            var currentQty = await conn.ExecuteScalarAsync<decimal?>(new CommandDefinition(
                "SELECT qty FROM BuildSelection WHERE build_id=@b AND category_id=@c AND part_id=@p",
                new { b = id, c = categoryId, p = partId },
                transaction: tx,
                cancellationToken: ct)) ?? 0m;

            var newQty = currentQty + delta;

            if (newQty <= 0)
            {
                const string delSql = "DELETE FROM BuildSelection WHERE build_id=@b AND category_id=@c AND part_id=@p";
                await conn.ExecuteAsync(new CommandDefinition(
                    delSql,
                    new { b = id, c = categoryId, p = partId },
                    transaction: tx,
                    cancellationToken: ct));
            }
            else
            {
                const string sql = @"INSERT INTO BuildSelection(build_id, category_id, part_id, qty) VALUES(@b,@c,@p,@q)
                                     ON DUPLICATE KEY UPDATE qty = VALUES(qty)";
                await using var cmd = new MySqlCommand(sql, conn, (MySqlTransaction)tx);
                cmd.Parameters.AddWithValue("@b", id);
                cmd.Parameters.AddWithValue("@c", categoryId);
                cmd.Parameters.AddWithValue("@p", partId);
                cmd.Parameters.AddWithValue("@q", newQty);
                await cmd.ExecuteNonQueryAsync(ct);
            }

            await tx.CommitAsync(ct);
        }
        catch
        {
            await tx.RollbackAsync(ct);
            throw;
        }

        var completion = await ReadBuildCompletionAsync(conn, id, ct);
        var summaryRaw = await ReadBuildSummaryAsync(conn, id, app.Logger, ct);
        var summary = ComposeSummaryFromCompletion(completion, summaryRaw, id);
        var selections = await ReadBuildSelectionsAsync(conn, id, ct);
        var cost = BuildCostPayloadFromSummary(summaryRaw, id);

        try
        {
            await TrackGamificationAsync(
                gamification,
                conn,
                userId.Value,
                id,
                wasFirstSelection,
                categoriesBefore,
                BuildCategoryStatusMap(completion),
                summaryBefore,
                ExtractSummarySnapshot(summaryRaw),
                ct);
        }
        catch (Exception hookEx)
        {
            app.Logger.LogError(hookEx, "Gamification selection increment hook failed for build {BuildId}", id);
        }

        return Results.Json(new { ok = true, summary, completion, cost, selections });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Increment failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("BuildOwnerOrEditor");

app.MapPost("/api/builds/{id:long}/selections", async (long id, HttpContext ctx, IGamification gamification, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    var userId = ctx.User.TryGetUserId();
    if (userId is null) return Results.Unauthorized();

    var body = await ctx.Request.ReadFromJsonAsync<SelectionUpsertRequest>(cancellationToken: ct);
    if (body is null) return Results.BadRequest(new { error = "Invalid JSON" });

    var categoryId = body.CategoryId;
    var partId = body.PartId;
    var qty = body.Qty ?? 1m;

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        var role = await GetBuildRoleAsync(conn, id, userId.Value, ct);
        if (role is null || role == "viewer") return Results.Forbid();

        await EnsureBuildSummaryViewsAsync(conn, ct);

        var selectionCountBefore = await conn.ExecuteScalarAsync<long>(new CommandDefinition(
            "SELECT COUNT(*) FROM BuildSelection WHERE build_id=@build",
            new { build = id },
            cancellationToken: ct));
        var wasFirstSelection = selectionCountBefore == 0;

        var categoriesBefore = await LoadCategoryStatusesAsync(conn, id, ct);
        var summaryBefore = await LoadSummarySnapshotAsync(conn, id, ct);

        await using var tx = await conn.BeginTransactionAsync(ct);
        try
        {
            const string sql = @"INSERT INTO BuildSelection(build_id, category_id, part_id, qty) VALUES(@b,@c,@p,@q)
                                 ON DUPLICATE KEY UPDATE qty = VALUES(qty)";
            await using var cmd = new MySqlCommand(sql, conn, (MySqlTransaction)tx);
            cmd.Parameters.AddWithValue("@b", id);
            cmd.Parameters.AddWithValue("@c", categoryId);
            cmd.Parameters.AddWithValue("@p", partId);
            cmd.Parameters.AddWithValue("@q", qty);
            await cmd.ExecuteNonQueryAsync(ct);
            await tx.CommitAsync(ct);
        }
        catch
        {
            await tx.RollbackAsync(ct);
            throw;
        }

        var completion = await ReadBuildCompletionAsync(conn, id, ct);
        var summaryRaw = await ReadBuildSummaryAsync(conn, id, app.Logger, ct);
        var summary = ComposeSummaryFromCompletion(completion, summaryRaw, id);
        var selections = await ReadBuildSelectionsAsync(conn, id, ct);
        var cost = BuildCostPayloadFromSummary(summaryRaw, id);

        try
        {
            await TrackGamificationAsync(
                gamification,
                conn,
                userId.Value,
                id,
                wasFirstSelection,
                categoriesBefore,
                BuildCategoryStatusMap(completion),
                summaryBefore,
                ExtractSummarySnapshot(summaryRaw),
                ct);
        }
        catch (Exception hookEx)
        {
            app.Logger.LogError(hookEx, "Gamification selection update hook failed for build {BuildId}", id);
        }

        return Results.Json(new { ok = true, summary, completion, cost, selections });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Upsert failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("BuildOwnerOrEditor");

// Build selections (remove)
app.MapDelete("/api/builds/{id:long}/selections", async (long id, long category_id, long part_id, HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    var userId = ctx.User.TryGetUserId();
    if (userId is null) return Results.Unauthorized();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);

        var role = await GetBuildRoleAsync(conn, id, userId.Value, ct);
        if (role is null || role == "viewer") return Results.Forbid();

        await using var tx = await conn.BeginTransactionAsync(ct);
        try
        {
            await using var cmd = new MySqlCommand("DELETE FROM BuildSelection WHERE build_id=@b AND category_id=@c AND part_id=@p", conn, (MySqlTransaction)tx);
            cmd.Parameters.AddWithValue("@b", id);
            cmd.Parameters.AddWithValue("@c", category_id);
            cmd.Parameters.AddWithValue("@p", part_id);
            await cmd.ExecuteNonQueryAsync(ct);
            await tx.CommitAsync(ct);
        }
        catch
        {
            await tx.RollbackAsync(ct);
            throw;
        }

        var completion = await ReadBuildCompletionAsync(conn, id, ct);
        var summaryRaw = await ReadBuildSummaryAsync(conn, id, app.Logger, ct);
        var summary = ComposeSummaryFromCompletion(completion, summaryRaw, id);
        var selections = await ReadBuildSelectionsAsync(conn, id, ct);
        var cost = BuildCostPayloadFromSummary(summaryRaw, id);

        return Results.Json(new { ok = true, summary, completion, cost, selections });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Delete failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("BuildOwnerOrEditor");

// List shares for a build
app.MapGet("/api/builds/{id:long}/shares", async (long id, HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    var userId = ctx.User.TryGetUserId();
    if (userId is null) return Results.Unauthorized();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureShareTablesAsync(conn, ct);

        var role = await GetBuildRoleAsync(conn, id, userId.Value, ct);
        if (!string.Equals(role, "owner", StringComparison.OrdinalIgnoreCase))
            return Results.Forbid();

        const string sql = @"SELECT bs.build_id, bs.user_id, bs.role, ua.email, ua.display_name
                             FROM BuildShare bs JOIN UserAccount ua ON ua.user_id = bs.user_id
                             WHERE bs.build_id = @id ORDER BY ua.email";
        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@id", id);
        var list = new List<Dictionary<string, object?>>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < reader.FieldCount; i++) row[reader.GetName(i)] = reader.IsDBNull(i) ? null : reader.GetValue(i);
            list.Add(row);
        }
        return Results.Json(list);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "List build shares failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("BuildOwnerOrEditor");

// Share build directly with an existing user
app.MapPost("/api/builds/{id:long}/shares", async (long id, ShareBuildRequest body, HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);
    if (body is null) return Results.BadRequest(new { error = "Invalid JSON" });

    var userId = ctx.User.TryGetUserId();
    if (userId is null) return Results.Unauthorized();

    var role = (body.Role ?? "viewer").Trim().ToLowerInvariant();
    if (role is not ("viewer" or "editor")) return Results.BadRequest(new { error = "role_invalid" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureShareTablesAsync(conn, ct);

        var callerRole = await GetBuildRoleAsync(conn, id, userId.Value, ct);
        if (!string.Equals(callerRole, "owner", StringComparison.OrdinalIgnoreCase))
            return Results.Forbid();

        long? targetUserId = body.UserId;
        string? email = body.Email?.Trim();

        if (targetUserId is null && !string.IsNullOrWhiteSpace(email))
        {
            await using var lookup = new MySqlCommand("SELECT user_id FROM UserAccount WHERE email=@mail", conn);
            lookup.Parameters.AddWithValue("@mail", email);
            var existingUser = await lookup.ExecuteScalarAsync(ct);
            if (existingUser is not null)
            {
                targetUserId = Convert.ToInt64(existingUser);
            }
            else
            {
                // No existing user, create invite instead
                var token = Guid.NewGuid().ToString();
                var expiresAt = DateTime.UtcNow.AddDays(7);
                await using var inviteCmd = new MySqlCommand(@"INSERT INTO BuildInvite(build_id, email, role, token, expires_at)
                                                              VALUES(@build, @mail, @role, @token, @expires)
                                                              ON DUPLICATE KEY UPDATE role=VALUES(role), token=VALUES(token), expires_at=VALUES(expires_at), accepted_by=NULL", conn);
                inviteCmd.Parameters.AddWithValue("@build", id);
                inviteCmd.Parameters.AddWithValue("@mail", email);
                inviteCmd.Parameters.AddWithValue("@role", role);
                inviteCmd.Parameters.AddWithValue("@token", token);
                inviteCmd.Parameters.AddWithValue("@expires", expiresAt);
                await inviteCmd.ExecuteNonQueryAsync(ct);
                return Results.Json(new { added = "invite", token, expires_at = expiresAt });
            }
        }

        if (targetUserId is null)
            return Results.BadRequest(new { error = "user_required" });

        await using (var userCheck = new MySqlCommand("SELECT user_id FROM UserAccount WHERE user_id=@uid", conn))
        {
            userCheck.Parameters.AddWithValue("@uid", targetUserId.Value);
            if (await userCheck.ExecuteScalarAsync(ct) is null)
                return Results.BadRequest(new { error = "user_not_found" });
        }

        await using (var upsert = new MySqlCommand(@"INSERT INTO BuildShare(build_id, user_id, role)
                                                    VALUES(@build, @user, @role)
                                                    ON DUPLICATE KEY UPDATE role = VALUES(role)", conn))
        {
            upsert.Parameters.AddWithValue("@build", id);
            upsert.Parameters.AddWithValue("@user", targetUserId.Value);
            upsert.Parameters.AddWithValue("@role", role);
            await upsert.ExecuteNonQueryAsync(ct);
        }

        return Results.Ok(new { added = "direct", build_id = id, user_id = targetUserId.Value, role });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Share build failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("BuildOwnerOrEditor");

// Invite a user by email
app.MapPost("/api/builds/{id:long}/shares/invite", async (long id, ShareInviteRequest body, HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);
    if (body is null) return Results.BadRequest(new { error = "Invalid JSON" });

    var userId = ctx.User.TryGetUserId();
    if (userId is null) return Results.Unauthorized();

    var email = body.Email?.Trim();
    if (string.IsNullOrWhiteSpace(email)) return Results.BadRequest(new { error = "email_required" });
    var role = (body.Role ?? "viewer").Trim().ToLowerInvariant();
    if (role is not ("viewer" or "editor")) return Results.BadRequest(new { error = "role_invalid" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureShareTablesAsync(conn, ct);

        var callerRole = await GetBuildRoleAsync(conn, id, userId.Value, ct);
        if (!string.Equals(callerRole, "owner", StringComparison.OrdinalIgnoreCase))
            return Results.Forbid();

        var token = Guid.NewGuid().ToString();
        var expiresAt = DateTime.UtcNow.AddDays(7);

        await using var cmd = new MySqlCommand(@"INSERT INTO BuildInvite(build_id, email, role, token, expires_at)
                                                VALUES(@build, @mail, @role, @token, @expires)
                                                ON DUPLICATE KEY UPDATE role=VALUES(role), token=VALUES(token), expires_at=VALUES(expires_at), accepted_by=NULL", conn);
        cmd.Parameters.AddWithValue("@build", id);
        cmd.Parameters.AddWithValue("@mail", email);
        cmd.Parameters.AddWithValue("@role", role);
        cmd.Parameters.AddWithValue("@token", token);
        cmd.Parameters.AddWithValue("@expires", expiresAt);
        await cmd.ExecuteNonQueryAsync(ct);

        return Results.Json(new { token, expires_at = expiresAt });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Invite failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("BuildOwnerOrEditor");

// List pending invites for a build (owner only)
app.MapGet("/api/builds/{id:long}/invites", async (long id, HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    var callerId = ctx.User.TryGetUserId();
    if (callerId is null) return Results.Unauthorized();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureShareTablesAsync(conn, ct);

        var callerRole = await GetBuildRoleAsync(conn, id, callerId.Value, ct);
        if (!string.Equals(callerRole, "owner", StringComparison.OrdinalIgnoreCase))
            return Results.Forbid();

        const string sql = @"SELECT invite_id, email, role, token, expires_at, accepted_by
                             FROM BuildInvite
                             WHERE build_id=@build
                             ORDER BY created_at DESC";

        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@build", id);
        var list = new List<Dictionary<string, object?>>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < reader.FieldCount; i++)
                row[reader.GetName(i)] = reader.IsDBNull(i) ? null : reader.GetValue(i);
            list.Add(row);
        }

        return Results.Json(list);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "List invites failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("BuildOwnerOrEditor");

// Revoke an invite (owner only)
app.MapDelete("/api/builds/{id:long}/invites/{inviteId:long}", async (long id, long inviteId, HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    var callerId = ctx.User.TryGetUserId();
    if (callerId is null) return Results.Unauthorized();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureShareTablesAsync(conn, ct);

        var callerRole = await GetBuildRoleAsync(conn, id, callerId.Value, ct);
        if (!string.Equals(callerRole, "owner", StringComparison.OrdinalIgnoreCase))
            return Results.Forbid();

        await using var cmd = new MySqlCommand("DELETE FROM BuildInvite WHERE invite_id=@invite AND build_id=@build", conn);
        cmd.Parameters.AddWithValue("@invite", inviteId);
        cmd.Parameters.AddWithValue("@build", id);
        var removed = await cmd.ExecuteNonQueryAsync(ct);
        return removed > 0 ? Results.Ok(new { removed = inviteId }) : Results.NotFound();
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Delete invite failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("BuildOwnerOrEditor");

// Accept an invite (must be signed in)
app.MapPost("/api/builds/invites/accept", async (AcceptInviteRequest body, HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);
    if (body is null || string.IsNullOrWhiteSpace(body.Token))
        return Results.BadRequest(new { error = "token_required" });

    var userId = ctx.User.TryGetUserId();
    if (userId is null) return Results.Unauthorized();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureShareTablesAsync(conn, ct);
        await using var tx = await conn.BeginTransactionAsync(ct);

        long buildId;
        string role;
        await using (var fetch = new MySqlCommand("SELECT invite_id, build_id, role, email, expires_at FROM BuildInvite WHERE token=@tok", conn, (MySqlTransaction)tx))
        {
            fetch.Parameters.AddWithValue("@tok", body.Token.Trim());
            await using var reader = await fetch.ExecuteReaderAsync(ct);
            if (!await reader.ReadAsync(ct))
            {
                await tx.RollbackAsync(ct);
                return Results.NotFound(new { error = "invite_not_found" });
            }
            var inviteId = reader.GetInt64(0);
            buildId = reader.GetInt64(1);
            role = reader.GetString(2);
            var expires = reader.GetDateTime(4);
            if (expires < DateTime.UtcNow)
            {
                await reader.CloseAsync();
                await tx.RollbackAsync(ct);
                return Results.BadRequest(new { error = "invite_expired" });
            }
        }

        await using (var upsert = new MySqlCommand(@"INSERT INTO BuildShare(build_id, user_id, role)
                                                    VALUES(@build, @user, @role)
                                                    ON DUPLICATE KEY UPDATE role = VALUES(role)", conn, (MySqlTransaction)tx))
        {
            upsert.Parameters.AddWithValue("@build", buildId);
            upsert.Parameters.AddWithValue("@user", userId.Value);
            upsert.Parameters.AddWithValue("@role", role);
            await upsert.ExecuteNonQueryAsync(ct);
        }

        await using (var updateInvite = new MySqlCommand("UPDATE BuildInvite SET accepted_by=@uid WHERE token=@tok", conn, (MySqlTransaction)tx))
        {
            updateInvite.Parameters.AddWithValue("@uid", userId.Value);
            updateInvite.Parameters.AddWithValue("@tok", body.Token.Trim());
            await updateInvite.ExecuteNonQueryAsync(ct);
        }

        await tx.CommitAsync(ct);

        return Results.Ok(new { build_id = buildId, role });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Accept invite failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Remove a share (owner only)
app.MapDelete("/api/builds/{id:long}/shares/{userId:long}", async (long id, long userId, HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    var callerId = ctx.User.TryGetUserId();
    if (callerId is null) return Results.Unauthorized();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureShareTablesAsync(conn, ct);

        var callerRole = await GetBuildRoleAsync(conn, id, callerId.Value, ct);
        if (!string.Equals(callerRole, "owner", StringComparison.OrdinalIgnoreCase))
            return Results.Forbid();

        await using var cmd = new MySqlCommand("DELETE FROM BuildShare WHERE build_id=@build AND user_id=@user", conn);
        cmd.Parameters.AddWithValue("@build", id);
        cmd.Parameters.AddWithValue("@user", userId);
        var rows = await cmd.ExecuteNonQueryAsync(ct);
        if (rows == 0) return Results.NotFound(new { error = "Share not found" });
        return Results.Ok(new { build_id = id, user_id = userId, removed = true });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Remove build share failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("BuildOwnerOrEditor");

// Build cost summary
app.MapGet("/api/builds/{id:long}/summary", async (long id, Func<MySqlConnection> dbFactory, CancellationToken ct) =>
{
    await using var conn = dbFactory();
    await conn.OpenAsync(ct);

    var slots = await conn.QueryAsync<(int MinRequired, int Capacity, int Selected)>(new CommandDefinition(
        @"WITH counts AS (
              SELECT slot_id, COUNT(*) AS cnt
                FROM BuildSlotSelection
               WHERE build_id = @buildId
               GROUP BY slot_id
           )
           SELECT
             COALESCE(s.min_required, 0) AS MinRequired,
             COALESCE(s.capacity, 2147483647) AS Capacity,
             COALESCE(c.cnt, 0) AS Selected
           FROM Build b
           JOIN Slot s ON s.engine_family_id = b.engine_family_id
           LEFT JOIN counts c ON c.slot_id = s.slot_id
          WHERE b.build_id = @buildId;",
        new { buildId = id },
        cancellationToken: ct));

    var list = slots.ToList();
    var total = list.Count;
    var complete = list.Count(r => r.Selected >= r.MinRequired && r.Selected <= r.Capacity);
    var incomplete = total - complete;
    var missing = list.Sum(r => Math.Max(0, r.MinRequired - r.Selected));
    var pct = total == 0
        ? 0m
        : Math.Round(100m * complete / total, 1, MidpointRounding.AwayFromZero);

    return Results.Ok(new
    {
        build_id = id,
        categories_total = total,
        categories_complete = complete,
        categories_incomplete = incomplete,
        completion_pct = pct,
        total_pieces_missing = (decimal)missing,
        estimated_cost_lowest = (decimal?)null
    });
}).RequireAuthorization("BuildOwnerOrEditor");

app.MapGet("/api/builds/{id:long}/brand-mix", async (long id, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);
    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await using var cmd = new MySqlCommand(@"SELECT build_id, brand_name, total_qty, est_spend FROM v_build_brand_vendor_mix WHERE build_id=@b ORDER BY est_spend DESC, brand_name", conn);
        cmd.Parameters.AddWithValue("@b", id);
        var list = new List<Dictionary<string, object?>>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < reader.FieldCount; i++) row[reader.GetName(i)] = reader.IsDBNull(i) ? null : reader.GetValue(i);
            list.Add(row);
        }
        return Results.Json(list);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Query failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("BuildOwnerOrEditor");

app.MapGet("/api/builds/{id:long}/cost", async (long id, Func<MySqlConnection> dbFactory, CancellationToken ct) =>
{
    await using var conn = dbFactory();
    await conn.OpenAsync(ct);

    var selected = await conn.QueryAsync<(decimal? BestPrice, decimal Qty)>(new CommandDefinition(
        @"SELECT MIN(po.price) AS BestPrice,
                 SUM(bs.qty)   AS Qty
            FROM BuildSelection bs
            JOIN PartOffering po ON po.part_id = bs.part_id
           WHERE bs.build_id = @buildId
             AND (po.effective_to IS NULL OR po.effective_to > NOW())
             AND po.availability IN ('in_stock','backorder')
           GROUP BY bs.part_id;",
        new { buildId = id },
        cancellationToken: ct));

    var selectedTotal = selected.Sum(x =>
    {
        if (!x.BestPrice.HasValue)
            return 0m;
        return x.BestPrice.Value * (x.Qty <= 0 ? 1 : x.Qty);
    });

    var lowest = await conn.QueryAsync<decimal?>(new CommandDefinition(
        @"SELECT MIN(po.price) AS best_for_slot
            FROM Build b
            JOIN Slot s ON s.engine_family_id = b.engine_family_id
            JOIN PartSlot ps ON ps.slot_id = s.slot_id AND ps.allow = 1
            LEFT JOIN PartCategory pc ON pc.category_id = ps.category_id
            LEFT JOIN PartOffering po
                   ON po.part_id = COALESCE(ps.part_id, pc.part_id)
                  AND (po.effective_to IS NULL OR po.effective_to > NOW())
                  AND po.availability IN ('in_stock','backorder')
           WHERE b.build_id = @buildId
           GROUP BY s.slot_id;",
        new { buildId = id },
        cancellationToken: ct));

    var lowestValues = lowest.Where(x => x.HasValue).Select(x => x!.Value).ToList();
    decimal? lowestMix = lowestValues.Count > 0 ? lowestValues.Sum() : (decimal?)null;

    return Results.Ok(new
    {
        selected_total = selectedTotal,
        lowest_mix_total = lowestMix
    });
}).RequireAuthorization("BuildOwnerOrEditor");

// Public builds gallery listing
app.MapGet("/api/public/builds", async (string? engine, string? q, string sort, int page, int pageSize, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);

    var normalizedSort = string.IsNullOrWhiteSpace(sort) ? "recent" : sort.Trim().ToLowerInvariant();
    page = Math.Max(1, page);
    pageSize = Math.Clamp(pageSize, 1, 60);
    var offset = (page - 1) * pageSize;

    var engineFilter = string.IsNullOrWhiteSpace(engine) ? null : engine.Trim();
    var searchFilter = string.IsNullOrWhiteSpace(q) ? null : q.Trim();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureBuildColumnsAsync(conn, ct);
        bool hasSummaryView;
        try
        {
            await EnsureBuildSummaryViewsAsync(conn, ct);
            hasSummaryView = await ViewExistsAsync(conn, "v_build_summary", ct);
        }
        catch (Exception)
        {
            hasSummaryView = await ViewExistsAsync(conn, "v_build_summary", ct);
        }

        var summarySelect = hasSummaryView
            ? "s.completion_pct        AS CompletionPct, s.estimated_cost_lowest AS EstimatedCostLowest"
            : "NULL AS CompletionPct, NULL AS EstimatedCostLowest";
        var summaryJoin = hasSummaryView ? "LEFT JOIN v_build_summary s ON s.build_id = b.build_id" : string.Empty;

        var orderClause = normalizedSort switch
        {
            "complete" when hasSummaryView => "CompletionPct DESC, b.updated_at DESC",
            "popular" => "b.updated_at DESC",
            _ => "b.updated_at DESC"
        };

        var sql = @"SELECT b.build_id   AS BuildId,
                           b.public_slug AS PublicSlug,
                           b.name        AS Name,
                           ef.code       AS EngineCode,
                           " + summarySelect + @",
                           b.updated_at            AS UpdatedAt
                    FROM Build b
                    JOIN EngineFamily ef ON ef.engine_family_id = b.engine_family_id
                    " + summaryJoin + @"
                    WHERE b.is_public = TRUE
                      AND b.public_slug IS NOT NULL
                      AND (@engine IS NULL OR ef.code = @engine)
                      AND (@search IS NULL OR b.name LIKE CONCAT('%', @search, '%'))
                    ORDER BY " + orderClause + @"
                    LIMIT @take OFFSET @skip";

        var items = (await conn.QueryAsync<PublicBuildListItem>(sql, new
        {
            engine = engineFilter,
            search = searchFilter,
            take = pageSize,
            skip = offset
        })).ToList();

        const string countSql = @"SELECT COUNT(*)
                                  FROM Build b
                                  JOIN EngineFamily ef ON ef.engine_family_id = b.engine_family_id
                                  WHERE b.is_public = TRUE
                                    AND b.public_slug IS NOT NULL
                                    AND (@engine IS NULL OR ef.code = @engine)
                                    AND (@search IS NULL OR b.name LIKE CONCAT('%', @search, '%'))";

        var total = await conn.ExecuteScalarAsync<long>(countSql, new { engine = engineFilter, search = searchFilter });

        return Results.Ok(new { items, page, page_size = pageSize, total });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "List public builds failed", detail: ex.Message, statusCode: 500);
    }
});

// Public build detail by slug
app.MapGet("/api/public/builds/{slug}", async (string slug, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);
    if (string.IsNullOrWhiteSpace(slug))
        return Results.BadRequest(new { error = "slug_required" });

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureBuildColumnsAsync(conn, ct);
        bool hasSummaryView;
        try
        {
            await EnsureBuildSummaryViewsAsync(conn, ct);
            hasSummaryView = await ViewExistsAsync(conn, "v_build_summary", ct);
        }
        catch (Exception)
        {
            hasSummaryView = await ViewExistsAsync(conn, "v_build_summary", ct);
        }

        var hasCategoryView = await ViewExistsAsync(conn, "v_build_category_completion", ct);

        var normalizedSlug = slug.Trim().ToLowerInvariant();

        var build = await conn.QuerySingleOrDefaultAsync<PublicBuildDetailDto>(@"
            SELECT b.build_id   AS BuildId,
                   b.public_slug AS PublicSlug,
                   b.name        AS Name,
                   ef.code       AS EngineCode,
                   b.updated_at  AS UpdatedAt
            FROM Build b
            JOIN EngineFamily ef ON ef.engine_family_id = b.engine_family_id
            WHERE b.is_public = TRUE AND b.public_slug=@slug", new { slug = normalizedSlug });

        if (build is null)
            return Results.NotFound(new { error = "build_not_found" });

        PublicBuildSummaryDto? summary = null;
        if (hasSummaryView)
        {
            summary = await conn.QuerySingleOrDefaultAsync<PublicBuildSummaryDto>(@"
                SELECT build_id      AS BuildId,
                       categories_total      AS CategoriesTotal,
                       categories_complete   AS CategoriesComplete,
                       categories_incomplete AS CategoriesIncomplete,
                       completion_pct        AS CompletionPct,
                       total_pieces_missing  AS TotalPiecesMissing,
                       estimated_cost_lowest AS EstimatedCostLowest
                FROM v_build_summary
                WHERE build_id=@id", new { id = build.BuildId });
        }

        var categories = new List<PublicBuildCategoryDto>();
        if (hasCategoryView)
        {
            categories = (await conn.QueryAsync<PublicBuildCategoryDto>(@"
                SELECT category_name    AS CategoryName,
                       required_qty     AS RequiredQty,
                       pieces_supplied  AS PiecesSupplied,
                       pieces_missing   AS PiecesMissing,
                       status           AS Status
                FROM v_build_category_completion
                WHERE build_id=@id
                ORDER BY category_name", new { id = build.BuildId })).ToList();
        }

        return Results.Ok(new { build, summary, categories });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Load public build failed", detail: ex.Message, statusCode: 500);
    }
});

// Clone a public build into the signed-in user's workspace
app.MapPost("/api/public/builds/{slug}/clone", async (string slug, HttpContext ctx, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);
    if (string.IsNullOrWhiteSpace(slug))
        return Results.BadRequest(new { error = "slug_required" });

    var userId = ctx.User.TryGetUserId();
    if (userId is null) return Results.Unauthorized();

    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await EnsureBuildColumnsAsync(conn, ct);
        await EnsurePlanTablesAsync(conn, ct);

        await using var tx = await conn.BeginTransactionAsync(ct);

        long sourceBuildId;
        long engineFamilyId;
        long? treeId;
        string sourceName;

        var normalizedSlug = slug.Trim().ToLowerInvariant();

        await using (var fetch = new MySqlCommand("SELECT build_id, engine_family_id, tree_id, name FROM Build WHERE public_slug=@slug AND is_public=TRUE", conn, (MySqlTransaction)tx))
        {
            fetch.Parameters.AddWithValue("@slug", normalizedSlug);
            await using var reader = await fetch.ExecuteReaderAsync(ct);
            if (!await reader.ReadAsync(ct))
            {
                await reader.CloseAsync();
                await tx.RollbackAsync(ct);
                return Results.NotFound(new { error = "build_not_found" });
            }

            sourceBuildId = reader.GetInt64(0);
            engineFamilyId = reader.GetInt64(1);
            treeId = reader.IsDBNull(2) ? null : reader.GetInt64(2);
            sourceName = reader.IsDBNull(3) ? "Community Build" : reader.GetString(3);
        }

        try
        {
            var newName = string.IsNullOrWhiteSpace(sourceName) ? "Community Build" : $"{sourceName} (clone)";

            long newBuildId;
            await using (var insert = new MySqlCommand("INSERT INTO Build(user_id, engine_family_id, tree_id, name, is_archived, is_shared, is_public, public_slug) VALUES(@user, @engine, @tree, @name, FALSE, FALSE, FALSE, NULL); SELECT LAST_INSERT_ID();", conn, (MySqlTransaction)tx))
            {
                insert.Parameters.AddWithValue("@user", userId.Value);
                insert.Parameters.AddWithValue("@engine", engineFamilyId);
                insert.Parameters.AddWithValue("@tree", (object?)treeId ?? DBNull.Value);
                insert.Parameters.AddWithValue("@name", newName);
                newBuildId = Convert.ToInt64(await insert.ExecuteScalarAsync(ct));
            }

            await using (var cloneSelections = new MySqlCommand("INSERT INTO BuildSelection(build_id, category_id, part_id, qty) SELECT @dest, category_id, part_id, qty FROM BuildSelection WHERE build_id=@src", conn, (MySqlTransaction)tx))
            {
                cloneSelections.Parameters.AddWithValue("@dest", newBuildId);
                cloneSelections.Parameters.AddWithValue("@src", sourceBuildId);
                await cloneSelections.ExecuteNonQueryAsync(ct);
            }

            await tx.CommitAsync(ct);
            return Results.Ok(new { build_id = newBuildId });
        }
        catch (MySqlException ex) when (ex.SqlState == "45000")
        {
            await tx.RollbackAsync(ct);
            return Results.Json(new { error = "quota_exceeded", message = ex.Message }, statusCode: 403);
        }
        catch
        {
            await tx.RollbackAsync(ct);
            throw;
        }
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Clone public build failed", detail: ex.Message, statusCode: 500);
    }
}).RequireAuthorization("IsSignedIn");

// Public buy plan endpoint resolves slug then reuses core generator
app.MapPost("/api/public/builds/{slug}/buyplan", async (string slug, string mode, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);
    if (string.IsNullOrWhiteSpace(slug))
        return Results.BadRequest(new { error = "slug_required" });

    try
    {
        long buildId;
        await using (var conn = new MySqlConnection(connectionString))
        {
            await conn.OpenAsync(ct);
            await EnsureBuildColumnsAsync(conn, ct);
            var normalizedSlug = slug.Trim().ToLowerInvariant();
            await using var cmd = new MySqlCommand("SELECT build_id FROM Build WHERE public_slug=@slug AND is_public=TRUE", conn);
            cmd.Parameters.AddWithValue("@slug", normalizedSlug);
            var val = await cmd.ExecuteScalarAsync(ct);
            if (val is null)
                return Results.NotFound(new { error = "build_not_found" });
            buildId = Convert.ToInt64(val);
        }

        return await GenerateBuyPlanAsync(connectionString, buildId, mode, ct);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Public buy plan failed", detail: ex.Message, statusCode: 500);
    }
});

// Click tracking + redirect to affiliate/product URL
app.MapGet("/api/click/redirect", async (long build_id, long part_id, long? offering_id, long? user_id) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);
    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync();
        await EnsureClickAttributionSchemaAsync(conn, CancellationToken.None);
        long? vendorId = null;
        string? targetUrl = null;
        decimal? price = null;

        if (offering_id.HasValue)
        {
            await using var cmd1 = new MySqlCommand("SELECT vendor_id, COALESCE(affiliate_url, url), price FROM PartOffering WHERE offering_id=@o", conn);
            cmd1.Parameters.AddWithValue("@o", offering_id.Value);
            await using var r = await cmd1.ExecuteReaderAsync();
            if (await r.ReadAsync())
            {
                vendorId = r.IsDBNull(0) ? null : r.GetInt64(0);
                targetUrl = r.IsDBNull(1) ? null : r.GetString(1);
                price = r.IsDBNull(2) ? null : r.GetDecimal(2);
            }
        }
        if (targetUrl is null)
        {
            await using var fallback = new MySqlCommand("SELECT po.offering_id, po.vendor_id, COALESCE(po.affiliate_url, po.url) AS u, po.price FROM PartOffering po WHERE po.part_id=@p AND (po.effective_to IS NULL OR po.effective_to > NOW()) ORDER BY po.price LIMIT 1", conn);
            fallback.Parameters.AddWithValue("@p", part_id);
            await using var r2 = await fallback.ExecuteReaderAsync();
            if (await r2.ReadAsync())
            {
                offering_id = r2.GetInt64(0);
                vendorId = r2.IsDBNull(1) ? null : r2.GetInt64(1);
                targetUrl = r2.IsDBNull(2) ? null : r2.GetString(2);
                var fallbackPrice = r2.IsDBNull(3) ? (decimal?)null : r2.GetDecimal(3);
                if (!price.HasValue) price = fallbackPrice;
            }
        }
        if (vendorId is null || string.IsNullOrWhiteSpace(targetUrl))
            return Results.NotFound(new { error = "No offering/URL found" });

        decimal? commissionPct = null;
        decimal? expectedCommission = null;

        await using (var commissionCmd = new MySqlCommand("SELECT base_commission_pct FROM AffiliateProgram WHERE vendor_id=@v", conn))
        {
            commissionCmd.Parameters.AddWithValue("@v", vendorId.Value);
            var val = await commissionCmd.ExecuteScalarAsync();
            if (val is not null && val is not DBNull)
            {
                commissionPct = Convert.ToDecimal(val);
            }
        }

        if (commissionPct.HasValue && price.HasValue)
        {
            expectedCommission = Math.Round(price.Value * commissionPct.Value / 100m, 2, MidpointRounding.AwayFromZero);
        }

        await using var ins = new MySqlCommand("INSERT INTO ClickAttribution(build_id, part_id, vendor_id, offering_id, user_id, commission_pct_at_click, expected_commission) VALUES(@b,@p,@v,@o,@u,@cp,@ec)", conn);
        ins.Parameters.AddWithValue("@b", build_id);
        ins.Parameters.AddWithValue("@p", part_id);
        ins.Parameters.AddWithValue("@v", vendorId);
        ins.Parameters.AddWithValue("@o", (object?)offering_id ?? DBNull.Value);
        ins.Parameters.AddWithValue("@u", (object?)user_id ?? DBNull.Value);
        ins.Parameters.AddWithValue("@cp", (object?)commissionPct ?? DBNull.Value);
        ins.Parameters.AddWithValue("@ec", (object?)expectedCommission ?? DBNull.Value);
        await ins.ExecuteNonQueryAsync();

        return Results.Redirect(targetUrl);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Click failed", detail: ex.Message, statusCode: 500);
    }
});

// Cart from BuildSelection
app.MapPost("/api/carts/from-build/{build_id:long}", async (long build_id, long? user_id) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);
    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync();
        long cartId;
        await using (var cmd = new MySqlCommand("INSERT INTO Cart(user_id) VALUES(@u); SELECT LAST_INSERT_ID();", conn))
        {
            cmd.Parameters.AddWithValue("@u", (object?)user_id ?? DBNull.Value);
            cartId = Convert.ToInt64(await cmd.ExecuteScalarAsync());
        }
        const string copySql = @"INSERT INTO CartItem(cart_id, part_id, qty)
                                 SELECT @cart, part_id, qty FROM BuildSelection WHERE build_id=@b
                                 ON DUPLICATE KEY UPDATE qty = VALUES(qty)";
        await using (var copy = new MySqlCommand(copySql, conn))
        {
            copy.Parameters.AddWithValue("@cart", cartId);
            copy.Parameters.AddWithValue("@b", build_id);
            await copy.ExecuteNonQueryAsync();
        }
        return Results.Json(new { cart_id = cartId });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Create cart failed", detail: ex.Message, statusCode: 500);
    }
});

// List subscription plans
app.MapGet("/api/plans", async () =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);
    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync();
        await using var cmd = new MySqlCommand("SELECT plan_id, code, name, monthly_price, currency FROM Plan ORDER BY monthly_price", conn);
        var list = new List<Dictionary<string, object?>>();
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < reader.FieldCount; i++) row[reader.GetName(i)] = reader.IsDBNull(i) ? null : reader.GetValue(i);
            list.Add(row);
        }
        return Results.Json(list);
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Query failed", detail: ex.Message, statusCode: 500);
    }
});

// Seed: default engine families
app.MapPost("/api/seed/engines", async () =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);
    var data = new (string code, int? ys, int? ye, int rotors, int hpMin, int hpMax)[]
    {
        ("10A-L10A", 1965, 1967, 2, 110, 110),
        ("10A-L10B", 1968, 1973, 2, 100, 128),
        ("12A", 1970, 1978, 2, 100, 130),
        ("12A-6P", 1979, 1985, 2, 135, 150),
        ("12A-Turbo", 1982, 1985, 2, 160, 165),
        ("13A", 1969, 1972, 2, 126, 126),
        ("20A", 1974, 1976, 2, 135, 135),
        ("13B-4P", 1973, 1980, 2, 110, 130),
        ("13B-S3", 1981, 1985, 2, 135, 135),
        ("13B-S4-NA", 1986, 1988, 2, 146, 160),
        ("13B-S4T", 1986, 1988, 2, 182, 190),
        ("13B-S5-NA", 1989, 1991, 2, 160, 165),
        ("13B-S5T", 1989, 1991, 2, 200, 210),
        ("13B-RE-NA", 1990, 1995, 2, 180, 180),
        ("13B-RE-Turbo", 1990, 1995, 2, 230, 230),
        ("13B-REW-S6", 1992, 1995, 2, 255, 255),
        ("13B-REW-S7", 1996, 1998, 2, 265, 265),
        ("13B-REW-S8", 1999, 2002, 2, 280, 280),
        ("20B-REW", 1990, 1995, 3, 280, 300),
        ("RENESIS-4P", 2003, 2012, 2, 192, 192),
        ("RENESIS-6P", 2003, 2012, 2, 238, 238)
    };
    try
    {
        await using var conn = new MySqlConnector.MySqlConnection(connectionString);
        await conn.OpenAsync();
        var sql = @"INSERT INTO EngineFamily (code, years_start, years_end, rotor_count, hp_min, hp_max)
                    VALUES(@code,@ys,@ye,@rotors,@hpmin,@hpmax)
                    ON DUPLICATE KEY UPDATE years_start=VALUES(years_start), years_end=VALUES(years_end), rotor_count=VALUES(rotor_count), hp_min=VALUES(hp_min), hp_max=VALUES(hp_max)";
        var count = 0;
        foreach (var e in data)
        {
            await using var cmd = new MySqlConnector.MySqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@code", e.code);
            cmd.Parameters.AddWithValue("@ys", (object?)e.ys ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@ye", (object?)e.ye ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@rotors", e.rotors);
            cmd.Parameters.AddWithValue("@hpmin", e.hpMin);
            cmd.Parameters.AddWithValue("@hpmax", e.hpMax);
            count += await cmd.ExecuteNonQueryAsync();
        }
        return Results.Json(new { ok = true, upserts = data.Length });
    }
    catch (Exception ex)
    {
        return Results.Problem(title: "Seed failed", detail: ex.Message, statusCode: 500);
    }
});

// Brand detail (with parts)
app.MapGet("/api/brands/{id:long}", async (long id) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);
    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync();
        await using var bcmd = new MySqlCommand("SELECT brand_id, name, website FROM Brand WHERE brand_id=@id", conn);
        bcmd.Parameters.AddWithValue("@id", id);
        await using var br = await bcmd.ExecuteReaderAsync();
        if (!await br.ReadAsync()) return Results.NotFound();
        var brand = new Dictionary<string, object?>
        {
            ["brand_id"] = br.GetInt64(0),
            ["name"] = br.GetString(1),
            ["website"] = br.IsDBNull(2) ? null : br.GetString(2)
        };
        await br.CloseAsync();
        const string psql = @"SELECT p.part_id, p.sku, p.name, p.image_url, p.status, v.best_price
                              FROM Part p
                              LEFT JOIN v_part_best_offering v ON v.part_id=p.part_id
                              WHERE p.brand_id=@id ORDER BY p.name";
        var parts = new List<Dictionary<string, object?>>();
        await using var pcmd = new MySqlCommand(psql, conn);
        pcmd.Parameters.AddWithValue("@id", id);
        await using var pr = await pcmd.ExecuteReaderAsync();
        while (await pr.ReadAsync())
        {
            var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < pr.FieldCount; i++) row[pr.GetName(i)] = pr.IsDBNull(i) ? null : pr.GetValue(i);
            parts.Add(row);
        }
        return Results.Json(new { brand, parts });
    }
    catch (Exception ex) { return Results.Problem(title: "Query failed", detail: ex.Message, statusCode: 500); }
});

// Vendors list
app.MapGet("/api/vendors", async () =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);
    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync();
        const string sql = @"SELECT v.vendor_id, v.name, v.website,
                                    COUNT(po.offering_id) AS offering_count,
                                    COUNT(DISTINCT po.part_id) AS parts_count
                             FROM Vendor v
                             LEFT JOIN PartOffering po ON po.vendor_id=v.vendor_id
                             GROUP BY v.vendor_id ORDER BY v.name";
        var list = new List<Dictionary<string, object?>>();
        await using var cmd = new MySqlCommand(sql, conn);
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < reader.FieldCount; i++) row[reader.GetName(i)] = reader.IsDBNull(i) ? null : reader.GetValue(i);
            list.Add(row);
        }
        return Results.Json(list);
    }
    catch (Exception ex) { return Results.Problem(title: "Query failed", detail: ex.Message, statusCode: 500); }
});

// Vendor detail
app.MapGet("/api/vendors/{id:long}", async (long id) =>
{
    if (string.IsNullOrWhiteSpace(connectionString))
        return Results.Problem(title: "Missing connection string", detail: "ConnectionStrings not set", statusCode: 500);
    try
    {
        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync();
        await using var bcmd = new MySqlCommand("SELECT vendor_id, name, website FROM Vendor WHERE vendor_id=@id", conn);
        bcmd.Parameters.AddWithValue("@id", id);
        await using var br = await bcmd.ExecuteReaderAsync();
        if (!await br.ReadAsync()) return Results.NotFound();
        var vendor = new Dictionary<string, object?>
        {
            ["vendor_id"] = br.GetInt64(0),
            ["name"] = br.GetString(1),
            ["website"] = br.IsDBNull(2) ? null : br.GetString(2)
        };
        await br.CloseAsync();
        const string sql = @"SELECT po.offering_id, po.part_id, p.name AS part_name, p.sku, po.price, po.currency, po.availability, po.url, po.affiliate_url,
                                    po.effective_from, po.effective_to
                             FROM PartOffering po JOIN Part p ON p.part_id=po.part_id
                             WHERE po.vendor_id=@id AND (po.effective_to IS NULL OR po.effective_to>NOW())
                             ORDER BY po.price";
        var offs = new List<Dictionary<string, object?>>();
        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@id", id);
        await using var r = await cmd.ExecuteReaderAsync();
        while (await r.ReadAsync())
        {
            var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < r.FieldCount; i++) row[r.GetName(i)] = r.IsDBNull(i) ? null : r.GetValue(i);
            offs.Add(row);
        }
        return Results.Json(new { vendor, offerings = offs });
    }
    catch (Exception ex) { return Results.Problem(title: "Query failed", detail: ex.Message, statusCode: 500); }
});

app.Run();

readonly record struct SummarySnapshot(int Total, int Incomplete);

record UserPrefsDto(bool ShowPoints, bool ShowBadges, bool EmailOptIn, int StreakGraceDays, string? Timezone);

public sealed record UpsertEngine(long? Id, string Key, string Name, string? GltfUri, string? Revision);
public sealed record UpsertSubsystem(long? Id, long EngineId, string Key, string Name, string? GltfNodePath, int SortOrder);
public sealed record UpsertSlot(long? Id, long EngineId, long SubsystemId, string Key, string Name, string GltfNodePath, int MinRequired, int Capacity, string? Notes);
public sealed record UpsertEdge(long? Id, long EngineId, long FromSlotId, long ToSlotId, string Edge, int MinRequired, string? RuleJson);
public sealed record PatchSlotDto(long slot_id, string? gltf_node_path, string? name, int? min_required, int? capacity);
public sealed record PatchMateDto(long slot_id, double? mate_tx, double? mate_ty, double? mate_tz,
    double? mate_rx, double? mate_ry, double? mate_rz, double? mate_scale);
public sealed record PatchPartDto(long part_id, string? gltf_uri, string? gltf_attach_node, string? name);
public sealed record AddWhitelistDto(long slot_id, long? category_id, long? part_id, bool allow);
public sealed record UpsertEdgeTyped(long? slot_edge_id, long engine_family_id, long from_slot_id, long to_slot_id,
    string edge, int min_required, string? attribute_key, string? op, string? value_text, decimal? value_num, bool? value_bool);
public sealed record SocketHealthRow(long slot_id, string slot_key, string slot_name, string? gltf_node_path,
    long whitelist_rows, long raw_candidates, bool whitelist_glb_ok, bool node_path_ok, bool enabled_for_build);
public sealed record SlotClearDto([property: JsonPropertyName("slot_id")] long SlotId);
public readonly record struct BuildSceneSlotDto(
    long SlotId,
    string SlotKey,
    string? GltfNodePath,
    double? MateTx,
    double? MateTy,
    double? MateTz,
    double? MateRx,
    double? MateRy,
    double? MateRz,
    double? MateScale,
    long? PartId,
    string? Sku,
    string? GltfUri,
    string? GltfAttachNode)
{
    public bool HasMate =>
        MateTx is not null ||
        MateTy is not null ||
        MateTz is not null ||
        MateRx is not null ||
        MateRy is not null ||
        MateRz is not null ||
        MateScale is not null;
}

public readonly record struct SlotMateDto(
    double? MateTx,
    double? MateTy,
    double? MateTz,
    double? MateRx,
    double? MateRy,
    double? MateRz,
    double? MateScale)
{
    public bool IsEmpty =>
        MateTx is null &&
        MateTy is null &&
        MateTz is null &&
        MateRx is null &&
        MateRy is null &&
        MateRz is null &&
        MateScale is null;
}

public readonly record struct SlotCurrentRow(
    long SlotId,
    long? PartId,
    string? GltfUri,
    string? GltfAttachNode,
    double? MateTx,
    double? MateTy,
    double? MateTz,
    double? MateRx,
    double? MateRy,
    double? MateRz,
    double? MateScale);

public readonly record struct ExportSlotRow(
    long SlotId,
    string SlotKey,
    long? PartId,
    string? PartSku,
    int? Quantity,
    double? MateTx,
    double? MateTy,
    double? MateTz,
    double? MateRx,
    double? MateRy,
    double? MateRz,
    double? MateScale);

public sealed record ImportMateDto(
    [property: JsonPropertyName("tx")] float? Tx,
    [property: JsonPropertyName("ty")] float? Ty,
    [property: JsonPropertyName("tz")] float? Tz,
    [property: JsonPropertyName("rx")] float? Rx,
    [property: JsonPropertyName("ry")] float? Ry,
    [property: JsonPropertyName("rz")] float? Rz,
    [property: JsonPropertyName("scale")] float? Scale);

public sealed record ImportSlotItem(
    [property: JsonPropertyName("slot_id")] long? SlotId,
    [property: JsonPropertyName("slot_key")] string? SlotKey,
    [property: JsonPropertyName("part_id")] long? PartId,
    [property: JsonPropertyName("part_sku")] string? PartSku,
    [property: JsonPropertyName("quantity")] int? Quantity,
    [property: JsonPropertyName("mate_override")] ImportMateDto? MateOverride);

public sealed record ImportEngineFamily(
    [property: JsonPropertyName("id")] long Id,
    [property: JsonPropertyName("code")] string? Code);

public sealed record ImportPresetDto(
    [property: JsonPropertyName("version")] int Version,
    [property: JsonPropertyName("engine_family")] ImportEngineFamily EngineFamily,
    [property: JsonPropertyName("slots")] List<ImportSlotItem> Slots);

public readonly record struct BuildStatRow(
    string StatKey,
    string StatName,
    double? Value);
public sealed record CreateSubsystemRequest(long EngineId, string Key, string Name, int SortOrder, string? GltfNodePath);
public sealed record UpdateSubsystemRequest(string Key, string Name, int SortOrder, string? GltfNodePath);
public sealed record CreateSlotRequest(long EngineId, long SubsystemId, string Key, string Name, string? GltfNodePath, int MinRequired = 1, int Capacity = 1);
public sealed record UpdateSlotRequest(string Key, string Name, string? GltfNodePath, int MinRequired, int Capacity);
public sealed record SlotAliasRequest(long SlotId, string Alias);
public sealed record EdgeUpsertRequest(long EngineId, long FromSlotId, long ToSlotId, string Edge, int MinRequired = 1, string? Description = null, string? FixHint = null, string? AttributeKey = null);
public sealed record BulkSocketRequest(long EngineId, long SubsystemId, string[] SocketNames);
public sealed record UpsertPartSlot(long? Id, long SlotId, long? CategoryId, long? PartId, bool Allow);
public sealed record UpsertAttribute(long? Id, string Key, string Name, string Type);
public sealed record UpsertPartAttribute(long PartId, long AttributeId, decimal? ValueNum, string? ValueText, bool? ValueBool);

record IngestPreviewRequest(
    string? url,
    string? engine_code,
    string? tree_name,
    bool? use_db_engines,
    bool? use_db_categories,
    bool? use_db_tree_edges,
    bool? enrich_parts,
    List<string>? engine_codes
);

sealed class AdminIngestValidationResult
{
    public AdminIngestValidationResult(AdminIngestPayloadEnvelope normalized)
    {
        Normalized = normalized;
    }

    public AdminIngestPayloadEnvelope Normalized { get; }
    public List<string> Errors { get; } = new();
    public List<string> Warnings { get; } = new();
    public List<AdminIngestCategoryResult> Categories { get; } = new();
    public List<AdminIngestEngineResult> Engines { get; } = new();
    public List<AdminIngestOfferingNormalized> Offerings { get; } = new();
    public long? ExistingPartId { get; set; }
}

sealed record AdminIngestCategoryResult(long CategoryId, string Slug, int Order);

sealed record AdminIngestEngineResult(long EngineFamilyId, string Code);

sealed record AdminIngestOfferingNormalized(string VendorName, decimal Price, string Currency, string? Url, string Availability);

sealed class AdminEngineFamilyRow
{
    [JsonPropertyName("engine_family_id")] public long EngineFamilyId { get; set; }
    [JsonPropertyName("code")] public string Code { get; set; } = string.Empty;
    [JsonPropertyName("rotor_count")] public int? RotorCount { get; set; }
    [JsonPropertyName("years_start")] public int? YearsStart { get; set; }
    [JsonPropertyName("years_end")] public int? YearsEnd { get; set; }
    [JsonPropertyName("hp_min")] public int? HpMin { get; set; }
    [JsonPropertyName("hp_max")] public int? HpMax { get; set; }
    [JsonPropertyName("induction")] public string? Induction { get; set; }
    [JsonPropertyName("injection")] public string? Injection { get; set; }
    [JsonPropertyName("omp_type")] public string? OmpType { get; set; }
    [JsonPropertyName("ignition_layout")] public string? IgnitionLayout { get; set; }
    [JsonPropertyName("intake_arch")] public string? IntakeArch { get; set; }
    [JsonPropertyName("port_family")] public string? PortFamily { get; set; }
    [JsonPropertyName("egt_sensors")] public int? EgtSensors { get; set; }
    [JsonPropertyName("o2_sensors")] public int? O2Sensors { get; set; }
    [JsonPropertyName("ecu_type")] public string? EcuType { get; set; }
    [JsonPropertyName("turbo_system")] public string? TurboSystem { get; set; }
    [JsonPropertyName("intercooler")] public bool? Intercooler { get; set; }
    [JsonPropertyName("apex_seal_thickness_mm")] public decimal? ApexSealThicknessMm { get; set; }
    [JsonPropertyName("rotor_mass_g")] public int? RotorMassG { get; set; }
    [JsonPropertyName("housing_step")] public string? HousingStep { get; set; }
    [JsonPropertyName("exhaust_port_type")] public string? ExhaustPortType { get; set; }
    [JsonPropertyName("emissions_pkg")] public string? EmissionsPkg { get; set; }
    [JsonPropertyName("compression_min_psi")] public int? CompressionMinPsi { get; set; }
    [JsonPropertyName("compression_max_psi")] public int? CompressionMaxPsi { get; set; }
    [JsonPropertyName("notes")] public string? Notes { get; set; }
    [JsonPropertyName("created_at")] public DateTime CreatedAt { get; set; }
    [JsonPropertyName("updated_at")] public DateTime UpdatedAt { get; set; }
    [JsonPropertyName("default_tree_id")] public long? DefaultTreeId { get; set; }
    [JsonPropertyName("default_tree_name")] public string? DefaultTreeName { get; set; }
}

sealed class AdminEngineAttributeDefRow
{
    [JsonPropertyName("engine_attr_id")] public long EngineAttrId { get; set; }
    [JsonPropertyName("code")] public string Code { get; set; } = string.Empty;
    [JsonPropertyName("name")] public string Name { get; set; } = string.Empty;
    [JsonPropertyName("data_type")] public string DataType { get; set; } = string.Empty;
    [JsonPropertyName("unit")] public string? Unit { get; set; }
}

sealed class AdminEngineAttributeDefCreateRequest
{
    [JsonPropertyName("code")] public string? Code { get; set; }
    [JsonPropertyName("name")] public string? Name { get; set; }
    [JsonPropertyName("data_type")] public string? DataType { get; set; }
    [JsonPropertyName("unit")] public string? Unit { get; set; }
}

sealed class AdminEngineAttributeDefUpdateRequest
{
    [JsonPropertyName("name")] public string? Name { get; set; }
    [JsonPropertyName("data_type")] public string? DataType { get; set; }
    [JsonPropertyName("unit")] public string? Unit { get; set; }
}

sealed class AdminEngineAttributeValueRow
{
    [JsonPropertyName("engine_attr_id")] public long EngineAttrId { get; set; }
    [JsonPropertyName("code")] public string Code { get; set; } = string.Empty;
    [JsonPropertyName("name")] public string Name { get; set; } = string.Empty;
    [JsonPropertyName("data_type")] public string DataType { get; set; } = string.Empty;
    [JsonPropertyName("unit")] public string? Unit { get; set; }
    [JsonPropertyName("val_int")] public long? ValInt { get; set; }
    [JsonPropertyName("val_decimal")] public decimal? ValDecimal { get; set; }
    [JsonPropertyName("val_bool")] public bool? ValBool { get; set; }
    [JsonPropertyName("val_text")] public string? ValText { get; set; }
}

sealed class AdminEngineFamilyCreateRequest
{
    [JsonPropertyName("code")] public string? Code { get; set; }
    [JsonPropertyName("rotor_count")] public int? RotorCount { get; set; }
    [JsonPropertyName("years_start")] public int? YearsStart { get; set; }
    [JsonPropertyName("years_end")] public int? YearsEnd { get; set; }
    [JsonPropertyName("hp_min")] public int? HpMin { get; set; }
    [JsonPropertyName("hp_max")] public int? HpMax { get; set; }
    [JsonPropertyName("induction")] public string? Induction { get; set; }
    [JsonPropertyName("injection")] public string? Injection { get; set; }
    [JsonPropertyName("omp_type")] public string? OmpType { get; set; }
    [JsonPropertyName("ignition_layout")] public string? IgnitionLayout { get; set; }
    [JsonPropertyName("intake_arch")] public string? IntakeArch { get; set; }
    [JsonPropertyName("port_family")] public string? PortFamily { get; set; }
    [JsonPropertyName("egt_sensors")] public int? EgtSensors { get; set; }
    [JsonPropertyName("o2_sensors")] public int? O2Sensors { get; set; }
    [JsonPropertyName("ecu_type")] public string? EcuType { get; set; }
    [JsonPropertyName("turbo_system")] public string? TurboSystem { get; set; }
    [JsonPropertyName("intercooler")] public bool? Intercooler { get; set; }
    [JsonPropertyName("apex_seal_thickness_mm")] public decimal? ApexSealThicknessMm { get; set; }
    [JsonPropertyName("rotor_mass_g")] public int? RotorMassG { get; set; }
    [JsonPropertyName("housing_step")] public string? HousingStep { get; set; }
    [JsonPropertyName("exhaust_port_type")] public string? ExhaustPortType { get; set; }
    [JsonPropertyName("emissions_pkg")] public string? EmissionsPkg { get; set; }
    [JsonPropertyName("compression_min_psi")] public int? CompressionMinPsi { get; set; }
    [JsonPropertyName("compression_max_psi")] public int? CompressionMaxPsi { get; set; }
    [JsonPropertyName("notes")] public string? Notes { get; set; }
    [JsonPropertyName("default_tree_id")] public long? DefaultTreeId { get; set; }
}

sealed class AdminEngineFamilyMergeRequest
{
    [JsonPropertyName("from_id")] public long FromId { get; set; }
    [JsonPropertyName("to_id")] public long ToId { get; set; }
}

sealed class CompareRequest
{
    [JsonPropertyName("skus")] public List<string> Skus { get; set; } = new();
}

sealed class AdminEngineFamilyUsageRow
{
    public int Builds { get; set; }
    public int Fitments { get; set; }
    public int Mappings { get; set; }
}

sealed class AiDraftFromUrlRequest
{
    public string? Url { get; set; }
    public string? EngineCode { get; set; }
    public string? TreeName { get; set; }
    public bool UseDbEngineList { get; set; } = true;
    public bool UseDbCategoryList { get; set; } = true;
    public bool UseDbTreeEdges { get; set; } = false;
    public bool EnrichParts { get; set; } = true;
    public List<string>? ForcedEngineCodes { get; set; }
}

sealed class CategoryTreeNode
{
    public CategoryTreeNode(long id, string name, string slug, bool selectable)
    {
        Id = id;
        Name = name;
        Slug = slug;
        IsSelectable = selectable;
    }

    public long Id { get; }
    public string Name { get; set; }
    public string Slug { get; set; }
    public bool IsSelectable { get; set; }
    public long? ParentId { get; set; }
    public int Position { get; set; }
    public List<CategoryTreeNode> Children { get; } = new();
}
