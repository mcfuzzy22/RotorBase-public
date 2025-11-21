using System.Net.Http.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;

namespace RotorBase.Services;

public sealed class CompareTrayService
{
    private const string StorageKey = "compareSkus";
    private readonly ProtectedLocalStorage _storage;
    private readonly HttpClient _http;
    private readonly ILogger<CompareTrayService> _logger;
    private readonly List<string> _skus = new();
    private bool _initialized;
    private bool _clientReady;

    public event Action? Changed;

    public IReadOnlyList<string> Skus => _skus;

    public CompareTrayService(HttpClient http, ProtectedLocalStorage storage, ILogger<CompareTrayService> logger)
    {
        _http = http;
        _storage = storage;
        _logger = logger;
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        if (!_clientReady) return;
        if (_initialized) return;
        _initialized = true;

        try
        {
            var stored = await _storage.GetAsync<List<string>>(StorageKey);
            if (stored.Success && stored.Value is { Count: > 0 })
            {
                _skus.Clear();
                foreach (var sku in stored.Value)
                {
                    var normalized = NormalizeSku(sku);
                    if (normalized is null)
                        continue;

                    if (_skus.Any(s => string.Equals(s, normalized, StringComparison.OrdinalIgnoreCase)))
                        continue;

                    _skus.Add(normalized);
                    if (_skus.Count >= 4)
                        break;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to load compare tray from storage");
        }

        NotifyChanged();
    }

    public void MarkClientReady()
    {
        if (_clientReady) return;
        _clientReady = true;
        _initialized = false;
    }

    public async Task<bool> AddAsync(string sku, CancellationToken cancellationToken = default)
    {
        await InitializeAsync(cancellationToken);
        var normalized = NormalizeSku(sku);
        if (normalized is null)
            return false;

        if (_skus.Any(s => string.Equals(s, normalized, StringComparison.OrdinalIgnoreCase)))
            return false;

        if (_skus.Count >= 4)
        {
            _skus.RemoveAt(0);
        }

        _skus.Add(normalized);
        await PersistAsync(cancellationToken);
        NotifyChanged();
        return true;
    }

    public async Task RemoveAsync(string sku, CancellationToken cancellationToken = default)
    {
        await InitializeAsync(cancellationToken);
        var normalized = NormalizeSku(sku);
        if (normalized is null)
            return;

        var removed = _skus.RemoveAll(s => string.Equals(s, normalized, StringComparison.OrdinalIgnoreCase));
        if (removed > 0)
        {
            await PersistAsync(cancellationToken);
            NotifyChanged();
        }
    }

    public async Task ClearAsync(CancellationToken cancellationToken = default)
    {
        await InitializeAsync(cancellationToken);
        if (_skus.Count == 0)
            return;

        _skus.Clear();
        await PersistAsync(cancellationToken);
        NotifyChanged();
    }

    public async Task<CompareResult?> FetchAsync(CancellationToken cancellationToken = default)
    {
        await InitializeAsync(cancellationToken);

        var skus = _skus
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .Select(s => s.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(16)
            .ToList();

        if (skus.Count < 2)
            return null;

        try
        {
            var payload = new { skus };
            using var response = await _http.PostAsJsonAsync("/api/compare", payload, cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                var body = await response.Content.ReadAsStringAsync(cancellationToken);
                _logger.LogWarning("Compare POST failed: {Status} {Body}", response.StatusCode, body);
                return null;
            }

            var result = await response.Content.ReadFromJsonAsync<CompareResult>(cancellationToken: cancellationToken);
            if (result is null)
            {
                _logger.LogWarning("Compare POST returned an empty response body");
            }

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to fetch compare data");
            return null;
        }
    }

    private async Task PersistAsync(CancellationToken cancellationToken)
    {
        if (!_clientReady) return;
        try
        {
            await _storage.SetAsync(StorageKey, _skus.ToList());
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to persist compare tray items");
        }
    }

    private static string? NormalizeSku(string? sku)
    {
        if (string.IsNullOrWhiteSpace(sku))
            return null;
        return sku.Trim();
    }

    private void NotifyChanged() => Changed?.Invoke();

    public sealed class CompareResult
    {
        [JsonPropertyName("items")] public List<CompareItem> Items { get; set; } = new();
        [JsonPropertyName("attributes")] public List<CompareAttribute> Attributes { get; set; } = new();
    }

    public sealed class CompareItem
    {
        [JsonPropertyName("part_id")] public long PartId { get; set; }
        [JsonPropertyName("sku")] public string Sku { get; set; } = string.Empty;
        [JsonPropertyName("name")] public string Name { get; set; } = string.Empty;
        [JsonPropertyName("brand")] public string Brand { get; set; } = string.Empty;
        [JsonPropertyName("best_price")] public decimal? BestPrice { get; set; }
        [JsonPropertyName("status")] public string? Status { get; set; }
    }

    public sealed class CompareAttribute
    {
        [JsonPropertyName("part_id")] public long PartId { get; set; }
        [JsonPropertyName("code")] public string Code { get; set; } = string.Empty;
        [JsonPropertyName("val")] public string? Value { get; set; }
    }
}
