using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using MySqlConnector;

namespace RotorBase.Security;

public sealed class BuildAccessRequirement : IAuthorizationRequirement
{
    public static readonly BuildAccessRequirement Instance = new();
}

public sealed class BuildAccessHandler : AuthorizationHandler<BuildAccessRequirement>
{
    private readonly IConfiguration _configuration;

    public BuildAccessHandler(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, BuildAccessRequirement requirement)
    {
        var httpContext = context.Resource switch
        {
            HttpContext http => http,
            Endpoint endpoint => endpoint.Metadata.GetMetadata<IHttpContextAccessor>()?.HttpContext,
            _ => null
        };

        httpContext ??= (context.Resource as HttpContext);

        if (httpContext is null)
            return;

        var userIdClaim = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!long.TryParse(userIdClaim, out var userId))
            return;

        if (!TryResolveBuildId(httpContext, out var buildId))
            return;

        var connectionString = _configuration.GetConnectionString("Default")
            ?? _configuration.GetConnectionString("DefaultConnection")
            ?? _configuration["ConnectionStrings:Default"]
            ?? _configuration["ConnectionStrings:DefaultConnection"];

        if (string.IsNullOrWhiteSpace(connectionString))
            return;

        await using var conn = new MySqlConnection(connectionString);
        await conn.OpenAsync(httpContext.RequestAborted);

        // Owner shortcut
        await using (var ownerCmd = new MySqlCommand("SELECT 1 FROM Build WHERE build_id=@b AND user_id=@u LIMIT 1", conn))
        {
            ownerCmd.Parameters.AddWithValue("@b", buildId);
            ownerCmd.Parameters.AddWithValue("@u", userId);
            if (await ownerCmd.ExecuteScalarAsync(httpContext.RequestAborted) is not null)
            {
                context.Succeed(requirement);
                return;
            }
        }

        // Shared access (viewer/editor)
        await using (var shareCmd = new MySqlCommand("SELECT role FROM BuildShare WHERE build_id=@b AND user_id=@u LIMIT 1", conn))
        {
            shareCmd.Parameters.AddWithValue("@b", buildId);
            shareCmd.Parameters.AddWithValue("@u", userId);
            if (await shareCmd.ExecuteScalarAsync(httpContext.RequestAborted) is not null)
            {
                context.Succeed(requirement);
            }
        }
    }

    private static bool TryResolveBuildId(HttpContext httpContext, out long buildId)
    {
        buildId = 0;
        if (httpContext.Request.RouteValues.TryGetValue("buildId", out var explicitId) && TryParse(explicitId, out buildId))
            return true;
        if (httpContext.Request.RouteValues.TryGetValue("id", out var routeId) && TryParse(routeId, out buildId))
            return true;
        return false;
    }

    private static bool TryParse(object? value, out long parsed)
    {
        parsed = 0;
        return value is not null && long.TryParse(value.ToString(), out parsed);
    }
}
