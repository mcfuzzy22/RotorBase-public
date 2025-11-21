using System.Text.Json;
using System.Text.Json.Serialization;
using MySqlConnector;

var arguments = ParseArgs(args);
var outputPath = ResolveOutputPath(arguments);
var verbose = arguments.ContainsKey("verbose");
Action<string>? logger = verbose ? Console.WriteLine : null;

var connectionString = await ResolveConnectionStringAsync(arguments, logger);

if (string.IsNullOrWhiteSpace(connectionString))
{
    Console.Error.WriteLine("Unable to locate a connection string. Provide one via --connection, ROTORBASE_CONNECTION_STRING, or a config file.");
    return 1;
}

var dump = new Dictionary<string, object?>();
await using var connection = new MySqlConnection(connectionString);
await connection.OpenAsync();

var tables = await GetTableNamesAsync(connection);

foreach (var table in tables)
{
    var rows = await ReadTableAsync(connection, table);
    dump[table] = rows;
    Console.WriteLine($"Dumped {rows.Count} rows from {table}");
}

var serializerOptions = new JsonSerializerOptions
{
    WriteIndented = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.Never
};

await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(dump, serializerOptions));
Console.WriteLine($"Database dump written to {outputPath}");
return 0;

static Dictionary<string, string> ParseArgs(string[] rawArgs)
{
    var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    for (var i = 0; i < rawArgs.Length; i++)
    {
        var arg = rawArgs[i];

        if (!arg.StartsWith("--", StringComparison.Ordinal))
        {
            continue;
        }

        var trimmed = arg[2..];
        var splitIndex = trimmed.IndexOf('=');
        if (splitIndex >= 0)
        {
            result[trimmed[..splitIndex]] = trimmed[(splitIndex + 1)..];
        }
        else if (i + 1 < rawArgs.Length && !rawArgs[i + 1].StartsWith("--", StringComparison.Ordinal))
        {
            result[trimmed] = rawArgs[++i];
        }
        else
        {
            result[trimmed] = "true";
        }
    }

    return result;
}

static string ResolveOutputPath(Dictionary<string, string> arguments)
{
    if (arguments.TryGetValue("output", out var custom) && !string.IsNullOrWhiteSpace(custom))
    {
        var normalized = Path.GetFullPath(custom);
        var directory = Path.GetDirectoryName(normalized);
        if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
        {
            Directory.CreateDirectory(directory);
        }

        return normalized;
    }

    var defaultDirectory = Path.Combine(Directory.GetCurrentDirectory(), "exports");
    Directory.CreateDirectory(defaultDirectory);
    return Path.Combine(defaultDirectory, "db_dump.json");
}

static async Task<string?> ResolveConnectionStringAsync(Dictionary<string, string> arguments, Action<string>? log = null)
{
    if (arguments.TryGetValue("connection", out var provided) && !string.IsNullOrWhiteSpace(provided))
    {
        log?.Invoke("Using connection string from --connection argument.");
        return provided;
    }

    var envConnection = Environment.GetEnvironmentVariable("ROTORBASE_CONNECTION_STRING");
    if (!string.IsNullOrWhiteSpace(envConnection))
    {
        log?.Invoke("Using connection string from ROTORBASE_CONNECTION_STRING environment variable.");
        return envConnection;
    }

    var configPaths = new List<string>();
    if (arguments.TryGetValue("config", out var customConfig) && !string.IsNullOrWhiteSpace(customConfig))
    {
        configPaths.Add(Path.GetFullPath(customConfig));
    }
    else
    {
        configPaths.AddRange(DiscoverConfigPaths());
    }

    if (configPaths.Count == 0)
    {
        log?.Invoke("No configuration file found.");
        return null;
    }

    foreach (var configPath in configPaths.Distinct(StringComparer.OrdinalIgnoreCase))
    {
        if (!File.Exists(configPath))
        {
            continue;
        }

        log?.Invoke($"Checking configuration file {configPath}");
        await using var stream = File.OpenRead(configPath);
        var document = await JsonDocument.ParseAsync(stream);
        if (document.RootElement.TryGetProperty("ConnectionStrings", out var connectionStrings) &&
            connectionStrings.TryGetProperty("DefaultConnection", out var defaultConnection))
        {
            var value = defaultConnection.GetString();
            if (!string.IsNullOrWhiteSpace(value))
            {
                log?.Invoke("Found DefaultConnection in configuration.");
                return value;
            }
        }
    }

    log?.Invoke("DefaultConnection not found in configuration.");
    return null;
}

static IEnumerable<string> DiscoverConfigPaths()
{
    var searched = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    var current = Directory.GetCurrentDirectory();
    var candidates = new[] { "appsettings.Development.json", "appsettings.json" };

    while (!string.IsNullOrEmpty(current) && searched.Add(current))
    {
        foreach (var candidate in candidates)
        {
            var direct = Path.Combine(current, candidate);
            if (File.Exists(direct))
            {
                yield return direct;
            }

            var nested = Path.Combine(current, "RotorBase", candidate);
            if (File.Exists(nested))
            {
                yield return nested;
            }
        }

        var parent = Directory.GetParent(current);
        if (parent is null)
        {
            break;
        }

        current = parent.FullName;
    }

    var appContextBase = AppContext.BaseDirectory;
    foreach (var candidate in candidates)
    {
        var nested = Path.Combine(appContextBase, "..", "..", "..", "..", candidate);
        if (File.Exists(nested))
        {
            yield return Path.GetFullPath(nested);
        }

        var rootNested = Path.Combine(appContextBase, "..", "..", "..", "..", "RotorBase", candidate);
        if (File.Exists(rootNested))
        {
            yield return Path.GetFullPath(rootNested);
        }
    }
}

static async Task<List<string>> GetTableNamesAsync(MySqlConnection connection)
{
    const string sql = @"SELECT TABLE_NAME
                         FROM INFORMATION_SCHEMA.TABLES
                         WHERE TABLE_SCHEMA = DATABASE()
                         ORDER BY TABLE_NAME";
    var names = new List<string>();
    await using var command = new MySqlCommand(sql, connection);
    await using var reader = await command.ExecuteReaderAsync();
    while (await reader.ReadAsync())
    {
        names.Add(reader.GetString(0));
    }

    return names;
}

static async Task<List<Dictionary<string, object?>>> ReadTableAsync(MySqlConnection connection, string tableName)
{
    var rows = new List<Dictionary<string, object?>>();
    var sql = $"SELECT * FROM `{tableName}`";
    await using var command = new MySqlCommand(sql, connection);
    await using var reader = await command.ExecuteReaderAsync();

    while (await reader.ReadAsync())
    {
        var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < reader.FieldCount; i++)
        {
            var value = reader.IsDBNull(i) ? null : reader.GetValue(i);
            row[reader.GetName(i)] = NormalizeValue(value);
        }

        rows.Add(row);
    }

    return rows;
}

static object? NormalizeValue(object? value)
{
    switch (value)
    {
        case null:
            return null;
        case byte[] bytes:
            return Convert.ToBase64String(bytes);
        case MySqlDateTime mySqlDateTime:
            try
            {
                return mySqlDateTime.GetDateTime();
            }
            catch
            {
                return mySqlDateTime.ToString();
            }
        default:
            return value;
    }
}
