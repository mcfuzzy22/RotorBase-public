using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace RotorBase.Services;

public class PerplexityClient
{
    private readonly HttpClient _http;
    private readonly PerplexityOptions _opts;

    public PerplexityClient(HttpClient http, IOptions<PerplexityOptions> opts)
    {
        _http = http;
        _opts = opts.Value;
        if (!string.IsNullOrWhiteSpace(_opts.ApiKey))
        {
            _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _opts.ApiKey);
        }
        if (!string.IsNullOrWhiteSpace(_opts.BaseUrl))
        {
            _http.BaseAddress = new Uri(_opts.BaseUrl);
        }
    }

    public async Task<JsonDocument?> ChatJsonAsync(string system, string userPrompt, CancellationToken ct)
    {
        var payload = new
        {
            model = _opts.Model,
            messages = new object[]
            {
                new { role = "system", content = system },
                new { role = "user", content = userPrompt }
            },
            temperature = 0.2,
            top_p = 0.9
        };

        using var resp = await _http.PostAsJsonAsync("/chat/completions", payload, cancellationToken: ct);
        if (!resp.IsSuccessStatusCode)
        {
            var text = await resp.Content.ReadAsStringAsync(ct);
            throw new InvalidOperationException($"Perplexity error {(int)resp.StatusCode}: {text}");
        }

        using var root = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
        // Expect OpenAI-like structure: choices[0].message.content is a string
        var content = root.RootElement.GetProperty("choices")[0].GetProperty("message").GetProperty("content").GetString();
        if (string.IsNullOrWhiteSpace(content)) return null;

        // Normalize content: strip markdown fences if present
        string normalized = content.Trim();
        if (normalized.StartsWith("```"))
        {
            // Remove opening fence line (``` or ```json)
            var firstNl = normalized.IndexOf('\n');
            if (firstNl > 0) normalized = normalized[(firstNl + 1)..];
            // Remove trailing fence
            var lastFence = normalized.LastIndexOf("```", StringComparison.Ordinal);
            if (lastFence >= 0) normalized = normalized[..lastFence];
            normalized = normalized.Trim();
        }

        // Try to parse directly; if it fails, try to salvage the innermost JSON object
        try { return JsonDocument.Parse(normalized); }
        catch
        {
            int start = normalized.IndexOf('{');
            int end = normalized.LastIndexOf('}');
            if (start >= 0 && end > start)
            {
                var slice = normalized.Substring(start, end - start + 1);
                try { return JsonDocument.Parse(slice); } catch { /* fallthrough */ }
            }
            throw new InvalidOperationException("Perplexity returned non-JSON content. First 120 chars: " + normalized.Substring(0, Math.Min(120, normalized.Length)));
        }
    }
}
