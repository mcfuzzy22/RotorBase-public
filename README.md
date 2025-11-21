# RotorBase

RotorBase is a .NET 8 + Blazor application for browsing rotary engine parts, builds, and admin tooling.  
This repo is now scrubbed for public release – all API keys, passwords, and tenant‑specific URLs were replaced with placeholders so nothing sensitive is in source control.

## Prerequisites

- .NET 8 SDK
- Node.js 18+ (for the Tailwind/JS pipeline)
- MySQL 8.x

## Local configuration

The committed `appsettings.json` / `appsettings.Development.json` only contain safe placeholders.  
Provide your own values either via `appsettings.Development.local.json` (ignored by Git) or via `dotnet user-secrets` / environment variables.

Required settings:

- `ConnectionStrings:DefaultConnection`
- `Mail:FromEmail`
- `Mail:Mailgun:Domain`
- `Mail:Mailgun:ApiKey`
- `Stripe:ApiKey`
- `Stripe:WebhookSecret`
- `Stripe:Prices:PREMIUM`
- `Stripe:Prices:STANDARD`
- `Analytics:IngestKey`
- `Analytics:IpSalt`

Example (user-secrets):

```bash
cd RotorBase
dotnet user-secrets init
dotnet user-secrets set "ConnectionStrings:DefaultConnection" "Server=localhost;Port=3306;Database=rotorbase;User Id=root;Password=yourPassword;"
dotnet user-secrets set "Mail:Mailgun:ApiKey" "key-..."
dotnet user-secrets set "Stripe:ApiKey" "sk_live_..."
dotnet user-secrets set "Stripe:WebhookSecret" "whsec_..."
```

## Running locally

```bash
dotnet restore
npm install --prefix RotorBase
dotnet run --project RotorBase/RotorBase.csproj
```

The site serves on `http://localhost:5048` by default.

## Before pushing to GitHub

- Keep real secrets out of Git by relying on the `.local` config or user-secrets.
- Double-check future contributions with tools such as `git diff --cached` or `git secrets`.
- Remove any environment-specific dumps/export files before pushing if they contain proprietary data.

Happy hacking!
