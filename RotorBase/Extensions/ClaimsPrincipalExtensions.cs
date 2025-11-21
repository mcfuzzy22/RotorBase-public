using System.Security.Claims;

namespace RotorBase.Extensions;

public static class ClaimsPrincipalExtensions
{
    public static long? TryGetUserId(this ClaimsPrincipal principal)
    {
        var value = principal.FindFirstValue(ClaimTypes.NameIdentifier);
        return long.TryParse(value, out var parsed) ? parsed : (long?)null;
    }

    public static long RequireUserId(this ClaimsPrincipal principal)
        => TryGetUserId(principal) ?? throw new InvalidOperationException("Missing user id claim.");

    public static bool IsAdmin(this ClaimsPrincipal principal)
    {
        if (principal is null) return false;

        var adminClaim = principal.FindFirst("is_admin");
        if (adminClaim is not null && bool.TryParse(adminClaim.Value, out var parsed))
        {
            return parsed;
        }

        var roleClaim = principal.FindFirst(ClaimTypes.Role);
        return roleClaim is not null && string.Equals(roleClaim.Value, "admin", StringComparison.OrdinalIgnoreCase);
    }
}
