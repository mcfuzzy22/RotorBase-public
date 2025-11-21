using System;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;
using Microsoft.JSInterop;

namespace RotorBase.Services;

public static class Analytics
{
    public static async Task<string> SessionId(IJSRuntime js)
        => await js.InvokeAsync<string>("rb.sessionId");

    public static async Task Track(
        IJSRuntime js,
        HttpClient http,
        string name,
        object? extra = null,
        long? userId = null,
        long? buildId = null,
        long? engineFamilyId = null,
        long? categoryId = null,
        long? partId = null,
        long? ruleId = null,
        string? severity = null,
        string? source = null,
        decimal? numericValue = null)
    {
        var sessionId = await SessionId(js);
        var payload = new
        {
            EventName = name,
            EventUuid = Guid.NewGuid().ToString(),
            OccurredAtUtc = DateTime.UtcNow,
            SessionId = sessionId,
            UserId = userId,
            BuildId = buildId,
            EngineFamilyId = engineFamilyId,
            CategoryId = categoryId,
            PartId = partId,
            RuleId = ruleId,
            Severity = severity,
            Source = source,
            NumericValue = numericValue,
            Extra = extra
        };

        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/analytics/ingest")
        {
            Content = JsonContent.Create(payload)
        };

        var key = Environment.GetEnvironmentVariable("Analytics__IngestKey")
                  ?? "dev_da56214d0a5f7c76375b10d3660fc0ca52cfdee379932833c0412b0272f5b1e0";
        request.Headers.Add("X-Analytics-Key", key);

        using var response = await http.SendAsync(request);
        response.EnsureSuccessStatusCode();
    }

    public static async Task TrackOnce(
        IJSRuntime js,
        HttpClient http,
        string onceKey,
        string name,
        object? extra = null,
        long? userId = null,
        long? buildId = null,
        long? engineFamilyId = null,
        long? categoryId = null,
        long? partId = null,
        long? ruleId = null,
        string? severity = null,
        string? source = null,
        decimal? numericValue = null)
    {
        if (string.IsNullOrWhiteSpace(onceKey))
        {
            return;
        }

        bool shouldSend;
        try
        {
            shouldSend = await js.InvokeAsync<bool>("rb.once", onceKey);
        }
        catch
        {
            shouldSend = false;
        }

        if (!shouldSend)
        {
            return;
        }

        await Track(
            js,
            http,
            name,
            extra,
            userId,
            buildId,
            engineFamilyId,
            categoryId,
            partId,
            ruleId,
            severity,
            source,
            numericValue);
    }
}
