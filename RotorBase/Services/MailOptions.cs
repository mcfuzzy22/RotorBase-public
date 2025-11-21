namespace RotorBase.Services;

public sealed class MailOptions
{
    public string? Provider { get; set; }
    public string? FromEmail { get; set; }
    public string? FromName { get; set; }
    public string? BaseUrl { get; set; }
    public string? SendGridApiKey { get; set; }
    public SmtpOptions Smtp { get; set; } = new();
    public MailgunOptions Mailgun { get; set; } = new();

    public sealed class SmtpOptions
    {
        public string? Host { get; set; }
        public int? Port { get; set; }
        public string? User { get; set; }
        public string? Pass { get; set; }
        public bool? UseTls { get; set; }
    }

    public sealed class MailgunOptions
    {
        public string? Domain { get; set; }
        public string? ApiKey { get; set; }
        public string? BaseUrl { get; set; }
    }
}
