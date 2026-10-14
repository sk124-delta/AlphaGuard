# AlphaGuard

AlphaGuard is a small Streamlit workspace for content ownership records:

- **Protect**: embed a UTF-8 ownership or provenance note in a PNG, JPG, or WebP image using RGB LSB steganography.
- **Scan**: search a public image URL with SerpApi Google Lens or ValueSERP and review normalized visual matches.
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

For persistent activity history, set `SUPABASE_URL` and `SUPABASE_KEY` in `.env`, then run [supabase_schema.sql](supabase_schema.sql) in the Supabase SQL editor. AlphaGuard stores encoded image metadata, scan result history, and generated DMCA notices in the `encoded_images`, `scan_results`, and `dmca_notices` tables.

For Stripe subscriptions, set `STRIPE_WEBHOOK_SECRET` and run the webhook service:

```powershell
py -m src.alphaguard.webhooks
```

Configure Stripe to send `checkout.session.completed` and `customer.subscription.deleted` events to `/webhooks/stripe`. Checkout sessions must include the AlphaGuard user email in `metadata.user_id` (or `metadata.user_email`). The webhook updates `user_profiles.tier`; users default to `Free` when no profile exists. Scanning and bulk DMCA generation require `Pro`.

The workspace sidebar and Scan paywall link to the Payoneer Pro subscription checkout. Non-Pro users can also open the paywall's QR code expander to pay on mobile. The SQL schema also creates a `users` table for persistent salted PBKDF2 password hashes; run the complete [supabase_schema.sql](supabase_schema.sql) before creating accounts.

Password reset uses Supabase Auth. Add the app URL to Supabase Auth's allowed redirect URLs and set `PASSWORD_RESET_REDIRECT_URL` to that same URL (for local development, `http://localhost:8501`). Configure the Auth flow to return a recovery `code` to the redirect URL; AlphaGuard exchanges that code, updates the Supabase Auth password, and synchronizes the local password hash.

To run the background ValueSERP monitor, set `SERPAPI_KEY` and start the scheduler from the project root:

```powershell
py -m src.alphaguard.cron_scanner
```

The service scans active assets with a configured public image URL every 24 hours, writes new rows to `detected_matches`, and updates `user_match_counts`.

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
