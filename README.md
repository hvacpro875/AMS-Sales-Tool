# Best in Class Proposal Studio — private cloud deployment

This is a deployable **starter application**, not an audited or already-hosted production service. It preserves the 4-tier proposal studio and the embedded AHRI reference library. It adds one advisor login, PostgreSQL-backed proposals and dealer pricing, and a proposal library usable from iPad and desktop.

## Hosting requirements

- Managed PostgreSQL with automatic backups, TLS, and a private connection string.
- A Docker-compatible HTTPS host with a persistent `DATABASE_URL` environment variable. The app listens on port 8000.
- Set `COOKIE_SECURE=true` (default) behind an HTTPS domain; never expose the service over plain HTTP.
- Only one worker should run until the database migrations and rate limiting are upgraded for multi-instance deployment.

## Deploy

1. Provision a managed PostgreSQL database. Configure its network access and backups. Obtain the `DATABASE_URL` connection string (e.g. `postgresql://user:password@host:5432/database?sslmode=require`). Do **not** commit it to source control.
2. Deploy this directory as a Docker application using the included `Dockerfile`. Set `DATABASE_URL` in your hosting service's secret/environment settings.
3. Start the service. Its startup initializes tables. Confirm `GET /health` returns `{"ok":true}`.
4. Open a shell in the running container and run `python create_user.py` with `DATABASE_URL` set. Enter the advisor email and a strong password. Do not expose account creation as a public endpoint.
5. Open the host's HTTPS URL on both iPad and desktop and sign in. Confirm saving and reopening a test proposal on the other device. Verify dealer settings persist as well.
6. Configure monitoring, database backup restoration drills, incident response, session expiration policy, and retention/deletion procedures before real customer use.

## Usage

- **Save to cloud** writes the current homeowner proposal to PostgreSQL.
- **Open** loads a selected saved proposal. **New** starts a fresh draft. Changes are **not auto-saved**; use Save to cloud before leaving.
- Dealer pricing edits are saved automatically after a brief pause. Confirm the save status in the cloud bar.
- The 4 tiers retain independent financing, equipment, and rebates. Rebate eligibility, lender terms, AHRI combinations, warranty claims, taxes, and financing disclosures must be verified by the dealer before presenting.
- The original prototype's JSON export/import remains for manual backup. Such files can contain personal and confidential dealer information; handle them securely.

## Limitations / production hardening needed

- **Offline editing is not implemented.** Internet access is required for login and cloud saves.
- This app has **one advisor account** and no separate administrator role. Hiding dealer costs in iPad Sales Mode is presentation-only, **not an access-control boundary**.
- There is no electronic signature service, legally compliant e-sign workflow, automatic PDF generation service, email delivery, or lender integration. Browser print-to-PDF is available from the original UI.
- The original prototype embeds a large AHRI dataset in the HTML; it is not a live certification lookup. Revalidate combinations against current authoritative records.
- Login rate limiting is in-process and resets on restart. Add host-level WAF/rate limiting, security monitoring, and preferably MFA/managed identity before handling real customer data.
- The original single-file HTML uses inline scripts and styles; this requires a less restrictive CSP. Refactor to external JS/CSS and enforce a stricter CSP before a security review.
- Concurrent editing of the **same proposal** on two devices uses last-write-wins. Avoid simultaneous editing until version-conflict detection is implemented.
- Verify customer data privacy obligations and applicable financial advertising/disclosure requirements with qualified professionals.

## Architecture

`iPad/desktop browser → HTTPS host → FastAPI → managed PostgreSQL`

Session tokens are random, hashed in the database, delivered in Secure/HttpOnly/SameSite=Strict cookies. Mutating API calls require a CSRF token. Passwords are hashed with Argon2. Database records are scoped to the authenticated advisor. Protect the database connection and backups as carefully as the app itself.
