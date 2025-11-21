using System;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;
using Dapper;
using MySqlConnector;

namespace RotorBase.Services;

public interface IGamification
{
    Task<bool> AwardAsync(long userId, int points, string reason,
                          long? buildId = null, string? uniqKey = null);
    Task<bool> GrantBadgeAsync(long userId, string badgeCode, long? buildId = null);
    Task TickStreakAsync(long userId, DateTime utcNow);
    Task<(int points, int streak, int best, IReadOnlyList<string> badges)> GetSummaryAsync(long userId);
}

public sealed class Gamification : IGamification
{
    private readonly Func<MySqlConnection> _dbFactory;

    public Gamification(Func<MySqlConnection> dbFactory) => _dbFactory = dbFactory;

    public async Task<bool> AwardAsync(long userId, int points, string reason, long? buildId = null, string? uniqKey = null)
    {
        if (points == 0) return false;
        await using var db = _dbFactory();
        await db.OpenAsync();
        await using var tx = await db.BeginTransactionAsync();

        var inserted = await db.ExecuteAsync(
            @"INSERT INTO UserPointsLedger(user_id, points, reason, build_id, uniq_key)
              VALUES(@userId, @points, @reason, @buildId, @uniqKey)
              ON DUPLICATE KEY UPDATE user_id = user_id",
            new { userId, points, reason, buildId, uniqKey }, tx) == 1;

        if (inserted)
        {
            // keep header fast
            await db.ExecuteAsync(
              @"INSERT INTO UserPointsSummary(user_id, points_total)
                VALUES(@userId, @points)
                ON DUPLICATE KEY UPDATE points_total = points_total + VALUES(points_total)",
              new { userId, points }, tx);
        }

        await tx.CommitAsync();
        return inserted;
    }

    public async Task<bool> GrantBadgeAsync(long userId, string badgeCode, long? buildId = null)
    {
        await using var db = _dbFactory();
        var badgeId = await db.ExecuteScalarAsync<long?>(
            "SELECT badge_id FROM Badge WHERE code=@badgeCode", new { badgeCode });
        if (badgeId is null) return false;

        var changed = await db.ExecuteAsync(
            "INSERT IGNORE INTO UserBadge(user_id, badge_id, build_id) VALUES(@userId, @badgeId, @buildId)",
            new { userId, badgeId, buildId }) == 1;

        return changed;
    }

    public async Task TickStreakAsync(long userId, DateTime utcNow)
    {
        await using var db = _dbFactory();

        // Read prefs (timezone + grace)
        var pref = await db.QuerySingleOrDefaultAsync<(string tz, int grace)>(
            @"SELECT timezone, streak_grace_days FROM UserGamificationPrefs WHERE user_id=@userId",
            new { userId });

        var tz = pref.tz ?? "UTC";
        var grace = pref.grace <= 0 ? 0 : pref.grace;

        var userToday = ConvertToLocalDate(utcNow, tz);

        var row = await db.QuerySingleOrDefaultAsync<(int current, int best, DateTime last)?>(
            @"SELECT current_length, best_length, last_day FROM UserStreak WHERE user_id=@userId",
            new { userId });

        if (row is null)
        {
            await db.ExecuteAsync(
              "INSERT INTO UserStreak(user_id, current_length, best_length, last_day) VALUES(@userId,1,1,@day)",
              new { userId, day = userToday });
            return;
        }

        var (cur, best, lastDay) = row.Value;
        if (lastDay == userToday) return; // already counted today

        var isConsecutive = lastDay == userToday.AddDays(-1);
        var withinGrace   = lastDay >= userToday.AddDays(-(1 + grace));

        var next = (isConsecutive || withinGrace) ? cur + 1 : 1;
        var newBest = Math.Max(best, next);

        await db.ExecuteAsync(
          "UPDATE UserStreak SET current_length=@next, best_length=@newBest, last_day=@day WHERE user_id=@userId",
          new { next, newBest, day = userToday, userId });
    }

    public async Task<(int points, int streak, int best, IReadOnlyList<string> badges)> GetSummaryAsync(long userId)
    {
        await using var db = _dbFactory();

        var pts = await db.ExecuteScalarAsync<long?>(
            "SELECT points_total FROM UserPointsSummary WHERE user_id=@userId", new { userId })
            ?? await db.ExecuteScalarAsync<long>(
                 "SELECT COALESCE(SUM(points),0) FROM UserPointsLedger WHERE user_id=@userId", new { userId });

        var streak = await db.QuerySingleOrDefaultAsync<(int current, int best)>(
            "SELECT current_length, best_length FROM UserStreak WHERE user_id=@userId", new { userId });

        var badges = (await db.QueryAsync<string>(
            @"SELECT b.code
                FROM UserBadge ub
                JOIN Badge b ON b.badge_id=ub.badge_id
               WHERE ub.user_id=@userId
               ORDER BY ub.earned_at DESC", new { userId }))
            .ToList();

        return ((int)pts, streak.current, streak.best, badges);
    }

    private static DateTime ConvertToLocalDate(DateTime utcNow, string timeZoneId)
    {
        // If you're on Linux with IANA TZ IDs (e.g., "America/New_York"), this works.
        // On Windows you may need a mapping (e.g., TimeZoneConverter).
        var tz = TimeZoneInfo.FindSystemTimeZoneById(timeZoneId);
        var local = TimeZoneInfo.ConvertTimeFromUtc(utcNow, tz);
        return local.Date;
    }
}
