using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;

namespace RotorBase.Services;

public sealed class UserSession
{
    private const string TokenStorageKey = "authToken";

    private readonly HttpClient _http;
    private readonly ProtectedLocalStorage _storage;
    private readonly ILogger<UserSession> _logger;
    private readonly SemaphoreSlim _hydrateLock = new(1, 1);

    private bool _hydrated;
    private bool _clientReady;

    public event Action? Changed;

    public long? UserId { get; private set; }
    public string? Email { get; private set; }
    public string? DisplayName { get; private set; }
    public bool IsAdmin { get; private set; }
    public bool IsBanned { get; private set; }
    public bool EmailOptIn { get; private set; }
    public bool EmailVerified { get; private set; }
    public bool EmailBounced { get; private set; }
    public bool EmailUnsubscribed { get; private set; }
    public string? Token { get; private set; }
    public bool IsSignedIn => UserId.HasValue;

    public UserSession(HttpClient http, ProtectedLocalStorage storage, ILogger<UserSession> logger)
    {
        _http = http;
        _storage = storage;
        _logger = logger;
    }

    public async Task HydrateAsync(CancellationToken cancellationToken = default)
    {
        if (_hydrated || !_clientReady) return;

        await _hydrateLock.WaitAsync(cancellationToken);
        try
        {
            if (_hydrated || !_clientReady) return;
            await HydrateInternalAsync(cancellationToken);
            _hydrated = true;
        }
        finally
        {
            _hydrateLock.Release();
        }
    }

    public async Task<bool> SignInAsync(string email, string password, CancellationToken cancellationToken = default)
    {
        var response = await _http.PostAsJsonAsync("/api/auth/login", new { email, password }, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            if (response.StatusCode == HttpStatusCode.Forbidden)
            {
                ApiError? apiError = null;
                try
                {
                    apiError = await response.Content.ReadFromJsonAsync<ApiError>(cancellationToken: cancellationToken);
                }
                catch (Exception ex) when (ex is NotSupportedException or JsonException)
                {
                    _logger.LogDebug(ex, "Failed to parse login error payload");
                }

                if (string.Equals(apiError?.Error, "account_banned", StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException("This account has been banned.");
                }
            }

            _logger.LogWarning("Sign-in failed with status code {StatusCode}", response.StatusCode);
            return false;
        }

        var payload = await response.Content.ReadFromJsonAsync<AuthResponse>(cancellationToken: cancellationToken);
        if (payload is null || string.IsNullOrWhiteSpace(payload.Token))
        {
            _logger.LogWarning("Auth payload missing token");
            return false;
        }

        await SetTokenAsync(payload.Token, cancellationToken);
        ApplyUser(payload.User);
        NotifyChanged();
        await RefreshLimitsAsync(cancellationToken);
        return true;
    }

    public async Task SignOutAsync(CancellationToken cancellationToken = default)
    {
        ClearUser();

        try
        {
            await _storage.DeleteAsync(TokenStorageKey);
        }
        catch (InvalidOperationException)
        {
            // No existing token to clear – safe to ignore.
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to clear auth token from storage");
        }

        _http.DefaultRequestHeaders.Authorization = null;
        Token = null;
        Limits = null;

        _hydrated = false;
        NotifyChanged();
    }

    public void MarkClientReady()
    {
        if (_clientReady)
        {
            return;
        }

        _clientReady = true;
        _hydrated = false;
    }

    private async Task HydrateInternalAsync(CancellationToken cancellationToken)
    {
        string? storedToken = null;
        try
        {
            var result = await _storage.GetAsync<string>(TokenStorageKey);
            if (result.Success)
            {
                storedToken = result.Value;
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Unable to retrieve auth token from storage");
        }

        if (string.IsNullOrWhiteSpace(storedToken))
        {
            ClearUser();
            return;
        }

        Token = storedToken;
        _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", storedToken);

        try
        {
            var profile = await _http.GetFromJsonAsync<UserProfileDto>("/api/me", cancellationToken);
            if (profile is null)
            {
                await SignOutAsync(cancellationToken);
                return;
            }

            if (profile.IsBanned)
            {
                _logger.LogInformation("Banned account {Email} rejected during hydration", profile.Email);
                await SignOutAsync(cancellationToken);
                return;
            }

            UserId = profile.UserId;
            Email = profile.Email;
            DisplayName = profile.DisplayName;
            IsAdmin = profile.IsAdmin;
            IsBanned = profile.IsBanned;
            EmailOptIn = profile.EmailOptIn;
            EmailVerified = profile.EmailVerified;
            EmailBounced = profile.EmailBounced;
            EmailUnsubscribed = profile.EmailUnsubscribed;
            NotifyChanged();
        }
        catch (HttpRequestException ex) when (ex.StatusCode == HttpStatusCode.Unauthorized)
        {
            _logger.LogInformation("Stored token rejected – signing out");
            await SignOutAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to hydrate user profile");
        }
    }

    private async Task SetTokenAsync(string token, CancellationToken cancellationToken)
    {
        Token = token;
        _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        try
        {
            await _storage.SetAsync(TokenStorageKey, token);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to persist auth token");
        }
    }

    private void ApplyUser(AuthUser user)
    {
        UserId = user.UserId;
        Email = user.Email;
        DisplayName = user.DisplayName;
        IsAdmin = user.IsAdmin;
        IsBanned = user.IsBanned;
        EmailOptIn = user.EmailOptIn;
        EmailVerified = user.EmailVerified;
        EmailBounced = user.EmailBounced;
        EmailUnsubscribed = user.EmailUnsubscribed;
    }

    public void UpdateEmailOptIn(bool value)
    {
        EmailOptIn = value;
        NotifyChanged();
    }

    private void ClearUser()
    {
        UserId = null;
        Email = null;
        DisplayName = null;
        IsAdmin = false;
        IsBanned = false;
        EmailOptIn = false;
        EmailVerified = false;
        EmailBounced = false;
        EmailUnsubscribed = false;
        Limits = null;
    }
    public LimitsUsageDto? Limits { get; private set; }

    public async Task RefreshLimitsAsync(CancellationToken cancellationToken = default)
    {
        if (!IsSignedIn)
        {
            Limits = null;
            NotifyChanged();
            return;
        }

        try
        {
            Limits = await _http.GetFromJsonAsync<LimitsUsageDto>("/api/me/limits", cancellationToken);
            NotifyChanged();
        }
        catch (HttpRequestException ex) when (ex.StatusCode == HttpStatusCode.Unauthorized)
        {
            await SignOutAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to refresh usage limits");
        }
    }

    public sealed class LimitsUsageDto
    {
        [JsonPropertyName("plan")] public Dictionary<string, object?>? Plan { get; set; }
        [JsonPropertyName("usage")] public UsageDto? Usage { get; set; }

        public sealed class UsageDto
        {
            [JsonPropertyName("active_builds")] public int ActiveBuilds { get; set; }
            [JsonPropertyName("total_builds")] public int TotalBuilds { get; set; }
            [JsonPropertyName("remaining_active")] public int? RemainingActive { get; set; }
            [JsonPropertyName("remaining_total")] public int? RemainingTotal { get; set; }
        }
    }

    private void NotifyChanged() => Changed?.Invoke();

    private sealed record AuthResponse(
        [property: JsonPropertyName("token")] string Token,
        [property: JsonPropertyName("user")] AuthUser User);

        private sealed record AuthUser(
            [property: JsonPropertyName("user_id")] long UserId,
            [property: JsonPropertyName("email")] string Email,
            [property: JsonPropertyName("display_name")] string? DisplayName,
            [property: JsonPropertyName("is_admin")] bool IsAdmin,
            [property: JsonPropertyName("is_banned")] bool IsBanned,
            [property: JsonPropertyName("email_opt_in")] bool EmailOptIn,
            [property: JsonPropertyName("email_verified")] bool EmailVerified,
            [property: JsonPropertyName("email_bounced")] bool EmailBounced,
            [property: JsonPropertyName("email_unsubscribed")] bool EmailUnsubscribed);

    private sealed record ApiError([property: JsonPropertyName("error")] string? Error);
}
