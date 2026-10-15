# AlphaGuard

AlphaGuard is a small Streamlit workspace for content ownership records:

- **Protect**: embed a UTF-8 ownership or provenance note in a PNG, JPG, or WebP image using RGB LSB steganography.
- **Scan**: search a public image URL with managed SerpApi Google Lens, or use a keyless DuckDuckGo search based on the image filename. The Scan page also searches the web for an optional product title and excludes the account's registered domain. Filename search is not reverse-image matching; it depends on searchable asset names and returns only actual external search results.
- **DMCA notice**: generate a reviewable takedown notice from a guided form.

## Quick start

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
streamlit run app.py
```

Set the managed `SERPAPI_KEY` in `.env` or Streamlit secrets. The scanner requires that key and a publicly reachable image URL; users do not enter provider credentials in the app. The generated notice is a drafting aid, not legal advice.

Set `SUPABASE_URL` and `SUPABASE_KEY` in `.env`, then run [supabase_schema.sql](supabase_schema.sql) in the Supabase SQL editor. The app's server-side `SUPABASE_KEY` must be the Supabase service-role key because backend operations include cross-account administrative queries and run without forwarding each user's JWT; keep it only in private server secrets and never expose it to the browser. Row-level policies on notices and encoded images protect direct authenticated-user access. Configure Supabase Auth email/password sign-in and allow `https://alphaguard-fkre8tyjzbkpv2hjt5gvay.streamlit.app` as a password-recovery redirect URL. Persistent sign-in uses a Secure, SameSite cookie containing an opaque session ID; Supabase access and refresh tokens stay in a server-side SQLite store at `~/.alphaguard/auth_sessions.db` (override with `ALPHAGUARD_SESSION_DB`). Keep that data directory private and persistent on the host to retain logins across app restarts. Complete the onboarding form to start a 14-day full-access trial. Onboarding captures the business contact, mailing address, primary domain and market, and authorized partner domains. Primary domains are normalized and uniquely indexed so a domain cannot be registered by multiple accounts. Profiles and takedown notices are linked to the Supabase Auth UUID; activity-history tables continue to use the user's email in their text `user_id` field. The Plans & Billing page offers Growth ($49/month), Pro ($149/month), and Enterprise/Agency ($499+/month) Payoneer checkout options. Existing subscription access records use `Standard`, `Enterprise`, and legacy `Pro` tiers. The trial unlocks all features, and the Day 13 banner summarizes matches and generated notices.

The schema migrates existing text-keyed profiles and takedown records by matching their email/user ID to `auth.users.email`. Resolve any unmatched legacy accounts to Supabase Auth users before running the migration; it stops with an explicit error rather than dropping unmapped profile or notice data.

AlphaGuard filters scan matches from comma-separated whitelisted partner domains in both interactive and scheduled scans, then queues non-whitelisted results. The Admin Control Center is available to the two configured global administrators and provides approval, false-positive, and enforcement-override actions across accounts. Approval creates a notice for review and download; a person must deliver it and explicitly record the dispatch date. If an unresolved dispatched notice reaches seven days, AlphaGuard creates Google Search, Bing, Namecheap, GoDaddy, Cloudflare, and AWS follow-up drafts. The drafts are not submitted automatically: Google/Bing require applicable official reporting workflows and provider API integrations/credentials are not configured. Technical support is routed to `alphaguard.securitysuite@gmail.com`.

For Stripe subscription updates, set `STRIPE_WEBHOOK_SECRET` and run the webhook service:

```powershell
py -m src.alphaguard.webhooks
```

Configure Stripe to send `checkout.session.completed` and `customer.subscription.deleted` events to `/webhooks/stripe`. Checkout sessions must include the AlphaGuard user email in `metadata.user_id` (or `metadata.user_email`) and may specify `metadata.tier` as `Standard`, `Enterprise`, or a supported legacy Pro tier; sessions without a tier continue to map to legacy `Pro`. The webhook updates `user_profiles.tier`; users default to `Free` when no profile exists. Image scanning and bulk DMCA generation are available during the 14-day onboarding trial and to eligible paid tiers afterward.

The workspace sidebar and Scan paywall link to the Payoneer Standard subscription checkout. Enterprise pricing is shown during onboarding; contact support for Enterprise subscription setup. Users without an active trial or paid tier can also open the paywall's QR code expander to pay on mobile. The SQL schema also creates a `users` table for local salted PBKDF2 password hashes retained for password-reset compatibility; Supabase Auth handles app sign-in.

Password recovery uses Supabase Auth and redirects to the deployed app URL. AlphaGuard supports recovery links that return a PKCE `code` or access and refresh tokens in the URL fragment; fragment tokens are captured and the URL is cleared before the password form is shown. AlphaGuard updates the Supabase Auth password and synchronizes the local password hash.

To run the background ValueSERP monitor, set `SERPAPI_KEY` and start the scheduler from the project root:

```powershell
py -m src.alphaguard.cron_scanner
```

The service scans active assets with a configured public image URL every 24 hours (Enterprise assets are prioritized), excludes whitelisted partner domains, queues new non-whitelisted detections for admin review, prepares due seven-day escalation drafts, writes new rows to `detected_matches`, and updates `user_match_counts`.

Run the core checks with:

```powershell
pytest
```

## Layout

```text
app.py
src/alphaguard/
  dmca.py       # notice rendering
  models.py     # shared data objects
  scanner.py    # SerpApi & ValueSERP adapter
  stego.py      # PNG/JPG/WebP LSB engine
  db.py         # Supabase persistence helpers
  cron_scanner.py # scheduled ValueSERP monitoring
  webhooks.py   # Stripe subscription webhooks
tests/test_core.py
supabase_schema.sql
```
