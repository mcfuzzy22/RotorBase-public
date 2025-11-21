using System;

namespace RotorBase;

public static class SocketRouteMessages
{
    public static string GetToastMessage(string? reason)
        => reason?.Trim().ToLowerInvariant() switch
        {
            "authorized" => "Opening your build...",
            "forked_copy" => "You don't have edit access - opening a copy you can edit.",
            "new_on_same_engine" => "You don't have access - opening a fresh build on the same engine.",
            "new_build" => "Creating a new build...",
            _ => "Opening socket builder..."
        };

    public static string GetToastMessage(RouteToSocketsResult? result)
        => GetToastMessage(result?.Reason);
}
