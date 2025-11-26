# RotorBase

RotorBase is a full-stack .NET 8 application for researching rotary-engine builds, managing curated parts, and handling paid feature upgrades.  
The project is deployed on a Vultr Ubuntu 24.04 box behind nginx + systemd (`rotorbase.service`). This README walks through the system architecture and the relational data model to make future changes straightforward.

---

## 1. Technology Overview

| Layer | Technology | Notes |
| --- | --- | --- |
| UI | Blazor Server (Razor components) + Tailwind + small JS helpers | Components live under `RotorBase/Components`. |
| API | .NET 8 Minimal APIs (`Program.cs`) | Endpoints cover auth, builds, shop, billing, admin, etc. |
| Database | MySQL 8 | Schema managed at runtime through the `Ensure*` helpers in `Program.cs`. |
| Messaging | Mailgun (verification, alerts) | Configured through `Mail:*` settings. |
| Payments | Stripe Checkout + Billing portal | Plans map to Stripe Price IDs. |
| Hosting | nginx → Kestrel (.NET) behind systemd | Config in `/etc/nginx/sites-available/rotorbase`. |

The Kestrel process listens on `127.0.0.1:5048` and nginx proxies HTTP/HTTPS traffic to it.  
System service lives at `/etc/systemd/system/rotorbase.service`.

---

## 2. Repository Layout

```
RotorBase-public/
├─ RotorBase/                 # Main .NET project
│  ├─ Components/             # Blazor UI (pages, layouts, shared widgets)
│  ├─ Services/               # Client-side services (sessions, toasts, theme, etc.)
│  ├─ Security/, Extensions/  # Server helpers (auth, claims helpers, formatting)
│  ├─ Program.cs              # All minimal API endpoints + DI setup + schema guards
│  ├─ appsettings*.json       # Default config (production secrets kept off repo)
│  └─ wwwroot/                # Static assets, CSS, JS (theme loader, etc.)
├─ RotorBase.Tests/           # Placeholder for unit tests
├─ publish/                   # Output folder for `dotnet publish`
└─ README.md                  # (this document)
```

Notable client-side building blocks:

- `Components/Layout` contains application shell (`MainLayout`, `AuthControls`, `SidebarApp`, etc.).
- `Components/Pages` contains Blazor pages (Builder, Shop, Account/Plan, Admin sections).
- `Services/UserSession` keeps JWT + profile state hydrated for components.

---

## 3. Runtime Architecture

`Program.cs` wires up the entire backend:

1. **Configuration / DI**  
   - Loads `appsettings*.json` + environment-specific overrides.  
   - Registers `HttpClient` for self-calls, `Mailgun` sender, Stripe SDK, MySQL connection factories, and custom scoped services (`UserSession`, `CompareTrayService`, `ToastService`, etc.).

2. **Authentication / Authorization**  
   - JWT Bearer auth (issued via `/api/auth/login`) with claims for `email_verified`, `is_admin`, etc.  
   - Policies: `"IsSignedIn"` for authenticated calls, `BuildAccess` custom handler for build-level ACL.

3. **Minimal API Endpoints**  
   Organized roughly as:
   - `/api/auth/*` – login, logout, resend verification, passwordless flows.
   - `/api/users` – sign-up (now requires email verification before issuing a token).
   - `/api/me/*` – user profile, plan usage, billing routes.
   - `/api/builds*` – CRUD for builds, selections, presets, sharing.
   - `/api/shop*` – browse parts, price alerts, vendor click tracking.
   - `/api/admin/*` – manage plans, categories, engines, kits, sockets.
   - `/webhooks/stripe` – handles Checkout + Subscription webhooks.

4. **Schema Management**  
   When the app boots or specific endpoints run, helper methods verify and create tables/columns via `Ensure*` functions. This allows “schema drift” corrections without migrations.

5. **External Integrations**  
   - Stripe: `CheckoutSessionService`, `BillingPortalSessionService`, and direct `Subscription` management.  
   - Mailgun: `MailgunEmailSender` (see `Services/EmailSender.cs`) invoked for verification emails, alerts, etc.  
   - Analytics: custom `AnalyticsEvent` table + ingestion endpoints.

6. **Email gating**  
   Signup sends a verification email, and many server endpoints now return `email_not_verified` until `email_verified_at` is set. Front-end surfaces this status on the plan page, builder, and auth controls.

---

## 4. Database Model

Below is a high-level overview of the primary tables managed in `Program.cs`. Many other domain tables exist already (e.g., `Build`, `Part`, `CategoryTree`, `Vendor`). The tables listed here are those created/altered by the application code.

### Accounts & Roles

| Table | Purpose / Key Columns |
| --- | --- |
| `UserAccount` | Core identity record. Columns include `email`, `display_name`, `password_hash`, `is_admin`, `is_banned`, `email_opt_in`, `email_verified_at`, `email_verification_token/+expires`, `email_bounced`, `email_unsubscribed`. Index on `email` and `email_verification_token`. |
| `AppRole` | Static roles for feature gating (`code`, `name`, `description`, `is_system`). |
| `UserRole` | Join table mapping users to roles (`user_id`, `role_id`). |

### Plans & Limits

| Table | Purpose |
| --- | --- |
| `Plan` | Defines plan `code`, `name`, `monthly_price`, `currency`, `is_archived`. |
| `PlanLimits` | Max active / total builds per plan (`plan_id`, `max_active_builds`, `max_total_builds`). |
| `UserPlan` | Tracks each user’s current/free/paid plan (`status`, `current_period_start`, `current_period_end`). |

### Billing & Stripe Sync

| Table | Purpose |
| --- | --- |
| `BillingCustomer` | Maps `user_id` to Stripe `customer_id`. |
| `BillingSubscription` | Maps `user_id` to Stripe `subscription_id`, stores `plan_code`, lifecycle `status`, `current_period_end`. |

### Build Collaboration & Metadata

| Table | Purpose |
| --- | --- |
| `Build` (existing) | Holds build basics. App ensures extra columns (`is_archived`, `is_shared`, `is_public`). |
| `BuildShare` | Access control list for builds (`build_id`, `user_id`, `role`). |
| `BuildInvite` | Pending invites by email (`build_id`, `email`, `role`, `token`, `expires_at`, `accepted_by`). |
| `EngineFamilyTree` | Many-to-many between engine families and category trees; includes `is_default` flag. |

### Guides & Content

| Table | Purpose |
| --- | --- |
| `Guide` | Static content pages / articles (`slug`, `title`, `content_md`, `published_at`). |
| `GuidePart` | Relates guides ↔ parts to surface recommended kits. |

### Commerce & Notifications

| Table | Purpose |
| --- | --- |
| `PriceWatch` | Stores price alert subscriptions (either tied to a signed-in user or just email) and includes self-serve verification tokens. |
| `ClickAttribution` | Logs outbound vendor clicks with optional UTM metadata and linking to builds/parts/vendors. |

### Analytics

| Table | Purpose |
| --- | --- |
| `AnalyticsEvent` | Generic event log with JSON `extra` payloads, IP hashing, severity levels, and helper indexes for queries. |

These tables integrate with core catalog tables (`Part`, `PartOffering`, `Vendor`, `CategoryTree`, etc.) that are part of the broader RotorBase schema.

---

## 5. Domain Workflows

### Signup & Verification
1. `/api/users` inserts a `UserAccount` row with a verification token and sends a Mailgun email.  
2. The user must click `/verify-email?token=…` before `/api/auth/login` will mint a JWT.  
3. UI surfaces banners across the builder and plan pages reminding users to verify.

### Builds
- Builder UI uses Blazor components (`Builder.razor`) that call `/api/builds`, `/api/builds/{id}/selections`, `/api/builds/{id}/shares`, etc.  
- New builds are restricted by plan limits and now by `email_verified_at`.  
- Sharing is handled via `BuildShare` and `BuildInvite` tables.

### Plans & Billing
- `/api/me/plan` returns current plan usage and available catalog.  
- Upgrades go through `/api/billing/checkout` (Stripe Checkout).  
- Existing subscribers manage payment info via `/api/billing/portal`.  
- Stripe webhooks update `UserPlan` + `BillingSubscription` when checkouts complete, subscriptions renew/cancel, etc.

### Price Alerts
- `/api/alerts/price` allows guests or signed-in users to request notifications. This writes to the `PriceWatch` table and optionally triggers a verification link.  
- Alerts are only available to verified emails.

### Analytics & Vendor Attribution
- Every outbound vendor click posts to `/api/shop/click`, recording metadata in `ClickAttribution`.  
- `AnalyticsEvent` is a general-purpose log for UI/ingestion events.

---

## 6. Configuration

Key settings (environment variables or appsettings overrides):

| Setting | Description |
| --- | --- |
| `ConnectionStrings:DefaultConnection` | MySQL connection string. |
| `App:BaseUrl` | Public HTTPS URL (used for redirects + email links). |
| `Mail:Provider` | Currently `"Mailgun"`. |
| `Mail:FromEmail` / `Mail:FromName` | Sender identity. |
| `Mail:Mailgun:Domain` / `ApiKey` | Mailgun credentials. |
| `Stripe:ApiKey` | Secret key for Checkout + Billing. |
| `Stripe:WebhookSecret` | Signing secret for `/webhooks/stripe`. |
| `Stripe:Prices:PREMIUM`, `Stripe:Prices:STANDARD` | Price IDs mapping plan codes → Stripe products. |
| `JWT:Key` | Symmetric key for JWT tokens. |
| `Analytics:*` | Keys/seeds for metrics ingestion + IP hashing. |

On the Vultr host:

- Config lives in `/opt/rotorbase/app/appsettings.json` + `.Production.json`.  
- Deployment flow: `dotnet publish`, `rsync` to `/opt/rotorbase/app`, restart `rotorbase.service`.  
- nginx terminates TLS for `boostedrotary.com` and proxies to Kestrel.

---

## 7. Local Development

```bash
# Restore dependencies
dotnet restore
npm install --prefix RotorBase

# Run the dev server
dotnet run --project RotorBase/RotorBase.csproj

# Tailwind build (optional, typically handled by MSBuild target)
npm run build --prefix RotorBase
```

The site runs on `http://localhost:5048` with Hot Reload from `dotnet watch` if desired.

**Testing tips**
- Set `ASPNETCORE_ENVIRONMENT=Development` and provide `appsettings.Development.local.json` with secrets.
- Use Gmail aliases (e.g., `user+test@example.com`) to test email verification without creating new inboxes.
- Stripe has distinct test/live keys; make sure `Stripe:ApiKey` aligns with the webhook environment.

---

## 8. Deployment Checklist

1. `dotnet publish -c Release -o ../publish`
2. `rsync -az --delete --exclude 'appsettings*.json' ../publish/ root@HOST:/opt/rotorbase/app/`
3. `ssh root@HOST 'systemctl restart rotorbase'`
4. Verify `systemctl status rotorbase` and `sudo journalctl -u rotorbase -f`.
5. Confirm nginx sees `200` responses (`curl -I https://boostedrotary.com`).

---

## 9. Future Improvements

- Add formal EF Core migrations (instead of runtime `ALTER TABLE` statements).  
- Flesh out automated tests in `RotorBase.Tests`.  
- Add observability hooks (structured logs, metrics) for Stripe/Mailgun success/failure rates.  
- Document the legacy catalog tables (`Part`, `CategoryTree`, etc.) if schema knowledge is needed beyond the app-managed tables above.

---

RotorBase’s codebase is now documented end-to-end – from server architecture to the relational model. Use this README as the entrypoint whenever you need to troubleshoot data, extend endpoints, or onboard someone new to the project. Happy building!
