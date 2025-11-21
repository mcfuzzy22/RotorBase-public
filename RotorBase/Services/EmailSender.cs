using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Mail;
using System.Net.Mime;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SendGrid;
using SendGrid.Helpers.Mail;

namespace RotorBase.Services;

public interface IEmailSender
{
    Task SendAsync(EmailMessage message, CancellationToken cancellationToken = default);
}

public sealed record EmailMessage(string To, string Subject, string HtmlBody, string? TextBody = null);

public sealed class SendGridEmailSender : IEmailSender
{
    private readonly MailOptions _options;
    private readonly ILogger<SendGridEmailSender> _logger;

    public SendGridEmailSender(IOptions<MailOptions> options, ILogger<SendGridEmailSender> logger)
    {
        _options = options.Value;
        _logger = logger;
    }

    public async Task SendAsync(EmailMessage message, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(_options.SendGridApiKey) || string.IsNullOrWhiteSpace(_options.FromEmail))
        {
            _logger.LogWarning("SendGrid not configured; skipping email to {Recipient}", message.To);
            return;
        }

        var client = new SendGridClient(_options.SendGridApiKey);
        var mailMessage = new SendGridMessage
        {
            From = new EmailAddress(_options.FromEmail, _options.FromName),
            Subject = message.Subject,
            HtmlContent = message.HtmlBody,
            PlainTextContent = EmailContentFormatter.ToPlainText(message)
        };
        mailMessage.AddTo(new EmailAddress(message.To));
        mailMessage.SetClickTracking(false, false);
        mailMessage.SetOpenTracking(false);

        try
        {
            var response = await client.SendEmailAsync(mailMessage, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("SendGrid returned status {StatusCode} for {Recipient}", response.StatusCode, message.To);
                throw new InvalidOperationException($"SendGrid returned status {response.StatusCode}");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "SendGrid send failed for {Recipient}", message.To);
            throw;
        }
    }

}

public sealed class SmtpEmailSender : IEmailSender
{
    private readonly MailOptions _options;
    private readonly ILogger<SmtpEmailSender> _logger;

    public SmtpEmailSender(IOptions<MailOptions> options, ILogger<SmtpEmailSender> logger)
    {
        _options = options.Value;
        _logger = logger;
    }

    public async Task SendAsync(EmailMessage message, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(_options.Smtp.Host) || string.IsNullOrWhiteSpace(_options.FromEmail))
        {
            _logger.LogWarning("SMTP not configured; skipping email to {Recipient}", message.To);
            return;
        }

        using var mailMessage = new MailMessage
        {
            From = new MailAddress(_options.FromEmail!, _options.FromName),
            Subject = message.Subject,
            Body = message.HtmlBody,
            IsBodyHtml = true
        };
        mailMessage.To.Add(message.To);

        var plainText = EmailContentFormatter.ToPlainText(message);
        if (!string.IsNullOrWhiteSpace(plainText))
        {
            var textView = AlternateView.CreateAlternateViewFromString(plainText, Encoding.UTF8, MediaTypeNames.Text.Plain);
            mailMessage.AlternateViews.Add(textView);
        }

        using var client = _options.Smtp.Port.HasValue
            ? new SmtpClient(_options.Smtp.Host!, _options.Smtp.Port.Value)
            : new SmtpClient(_options.Smtp.Host!);

        client.EnableSsl = _options.Smtp.UseTls ?? true;
        if (!string.IsNullOrWhiteSpace(_options.Smtp.User))
        {
            client.Credentials = new NetworkCredential(_options.Smtp.User, _options.Smtp.Pass);
        }

        try
        {
            await client.SendMailAsync(mailMessage);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "SMTP send failed for {Recipient}", message.To);
            throw;
        }
    }
}

public sealed class NoOpEmailSender : IEmailSender
{
    private readonly ILogger<NoOpEmailSender> _logger;

    public NoOpEmailSender(ILogger<NoOpEmailSender> logger)
    {
        _logger = logger;
    }

    public Task SendAsync(EmailMessage message, CancellationToken cancellationToken = default)
    {
        _logger.LogDebug("Email sender disabled; dropping message to {Recipient}", message.To);
        return Task.CompletedTask;
    }
}

public static class EmailSenderFactory
{
    public static IEmailSender Create(IServiceProvider services)
    {
        var options = services.GetRequiredService<IOptions<MailOptions>>();
        var provider = options.Value.Provider;
        var loggerFactory = services.GetRequiredService<ILoggerFactory>();

        if (string.Equals(provider, "sendgrid", StringComparison.OrdinalIgnoreCase))
        {
            return new SendGridEmailSender(options, loggerFactory.CreateLogger<SendGridEmailSender>());
        }

        if (string.Equals(provider, "smtp", StringComparison.OrdinalIgnoreCase))
        {
            return new SmtpEmailSender(options, loggerFactory.CreateLogger<SmtpEmailSender>());
        }

        if (string.Equals(provider, "mailgun", StringComparison.OrdinalIgnoreCase))
        {
            var factory = services.GetRequiredService<IHttpClientFactory>();
            var httpClient = factory.CreateClient("mailgun");
            return new MailgunEmailSender(httpClient, options, loggerFactory.CreateLogger<MailgunEmailSender>());
        }

        return new NoOpEmailSender(loggerFactory.CreateLogger<NoOpEmailSender>());
    }
}

internal static class EmailContentFormatter
{
    private static readonly Regex HtmlStripRegex = new("<[^>]+>", RegexOptions.Compiled);

    public static string ToPlainText(EmailMessage message)
    {
        if (!string.IsNullOrWhiteSpace(message.TextBody))
        {
            return message.TextBody;
        }

        return StripHtml(message.HtmlBody);
    }

    public static string StripHtml(string html)
    {
        if (string.IsNullOrWhiteSpace(html))
        {
            return string.Empty;
        }

        return HtmlStripRegex.Replace(html, string.Empty).Trim();
    }
}

public sealed class MailgunEmailSender : IEmailSender
{
    private readonly HttpClient _httpClient;
    private readonly MailOptions _options;
    private readonly ILogger<MailgunEmailSender> _logger;

    public MailgunEmailSender(HttpClient httpClient, IOptions<MailOptions> options, ILogger<MailgunEmailSender> logger)
    {
        _httpClient = httpClient;
        _options = options.Value;
        _logger = logger;
    }

    public async Task SendAsync(EmailMessage message, CancellationToken cancellationToken = default)
    {
        var mgOptions = _options.Mailgun;
        if (string.IsNullOrWhiteSpace(mgOptions.Domain) || string.IsNullOrWhiteSpace(mgOptions.ApiKey) || string.IsNullOrWhiteSpace(_options.FromEmail))
        {
            _logger.LogWarning("Mailgun not configured; skipping email to {Recipient}", message.To);
            return;
        }

        var baseUrl = string.IsNullOrWhiteSpace(mgOptions.BaseUrl) ? "https://api.mailgun.net" : mgOptions.BaseUrl;
        var requestUri = new Uri(new Uri(baseUrl, UriKind.Absolute), $"/v3/{mgOptions.Domain}/messages");

        using var request = new HttpRequestMessage(HttpMethod.Post, requestUri);
        var authValue = Convert.ToBase64String(Encoding.ASCII.GetBytes($"api:{mgOptions.ApiKey}"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", authValue);

        var htmlBody = message.HtmlBody;
        var textBody = EmailContentFormatter.ToPlainText(message);

        using var content = new MultipartFormDataContent
        {
            { new StringContent(string.IsNullOrWhiteSpace(_options.FromName) ? _options.FromEmail! : $"{_options.FromName} <{_options.FromEmail}>"), "from" },
            { new StringContent(message.To), "to" },
            { new StringContent(message.Subject ?? string.Empty), "subject" },
            { new StringContent(textBody), "text" }
        };

        if (!string.IsNullOrWhiteSpace(htmlBody))
        {
            content.Add(new StringContent(htmlBody, Encoding.UTF8, MediaTypeNames.Text.Html), "html");
        }

        request.Content = content;

        try
        {
            var response = await _httpClient.SendAsync(request, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                var body = await response.Content.ReadAsStringAsync(cancellationToken);
                _logger.LogError("Mailgun returned {StatusCode} for {Recipient}: {Body}", response.StatusCode, message.To, body);
                throw new InvalidOperationException($"Mailgun returned {(int)response.StatusCode}");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Mailgun send failed for {Recipient}", message.To);
            throw;
        }
    }
}
