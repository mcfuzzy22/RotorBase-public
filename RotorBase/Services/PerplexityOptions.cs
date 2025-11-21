namespace RotorBase.Services;

public class PerplexityOptions
{
    public string? ApiKey { get; set; }
    public string BaseUrl { get; set; } = "https://api.perplexity.ai";
    public string Model { get; set; } = "sonar-large-online";
}

