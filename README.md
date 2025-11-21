# RotorBase

RotorBase is a .NET 8 + Blazor application for browsing rotary engine parts, builds, and admin tooling.  
This repo is now scrubbed for public release – all API keys, passwords, and tenant‑specific URLs were replaced with placeholders so nothing sensitive is in source control.

## Prerequisites

- .NET 8 SDK
- Node.js 18+ (for the Tailwind/JS pipeline)
- MySQL 8.x

## Local configuration

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

## Running locally

```bash
dotnet restore
npm install --prefix RotorBase
dotnet run --project RotorBase/RotorBase.csproj
```

The site serves on `http://localhost:5048` by default.
