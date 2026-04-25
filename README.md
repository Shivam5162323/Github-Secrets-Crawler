# 🔍 GitHub Secrets Crawler

A self-contained tool that crawls GitHub repositories, detects hardcoded secrets, and presents findings in a modern web dashboard.

---

## Features

- **4 crawl modes** — GitHub user, org, search query, or single repo URL
- **65+ secret patterns** — AWS, GitHub tokens, Stripe, Slack, GCP, Azure, DB URIs, JWTs, SSH keys, and more
- **Severity levels** — CRITICAL / HIGH / MEDIUM / LOW
- **No duplicate scanning** — repos already scanned are skipped automatically
- **Auto cleanup** — each cloned repo is deleted immediately after scanning
- **Live dashboard** — real-time job progress, findings table, file content viewer
- **CSV export** — one-click export of all findings
- **SQLite storage** — all results persist across restarts

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start the server
python app.py

# 3. Open dashboard
open http://localhost:5000
```

---

## Usage

### Crawl Modes

| Mode | Input | Example |
|------|-------|---------|
| **User** | GitHub username | `torvalds` |
| **Org** | GitHub org name | `microsoft` |
| **Search** | GitHub search query | `"hardcoded password" language:python` |
| **Single** | Repo URL or `owner/repo` | `https://github.com/owner/repo` |

### GitHub Token (Optional but recommended)

Without a token the GitHub API allows 60 requests/hour (10 for search).
With a token: 5,000 requests/hour (30 for search).

Generate one at: https://github.com/settings/tokens  
Scopes needed: `public_repo` (or `repo` for private repos).

---

## Secret Patterns Detected (65+)

| Category | Types |
|----------|-------|
| **Cloud** | AWS keys/secrets/session tokens, Azure storage/client, GCP service accounts, DigitalOcean, Cloudflare, Cloudinary |
| **Source Control** | GitHub PAT (classic & fine-grained), GitHub OAuth/App, GitLab tokens |
| **Payments** | Stripe live/test, Square, PayPal/Braintree, Shopify |
| **Messaging** | Slack bot/user tokens & webhooks, Discord, Telegram, Twilio, SendGrid, Mailchimp, Mailgun |
| **Auth** | JWT tokens, Okta, Firebase, Google OAuth, Facebook, LinkedIn, Twitter |
| **Infra** | Heroku, Vault, Consul, Datadog, New Relic, Sentry DSN, PagerDuty |
| **Database** | MongoDB URI, MySQL URI, PostgreSQL URI, Redis (with auth) |
| **Keys** | PEM/RSA/EC private keys, SSH private keys, Basic auth in URLs |
| **Generic** | Hardcoded `password=`, `secret=`, `api_key=`, `access_token=` patterns |

---

## Dashboard Tabs

- **🚀 Crawl** — Launch jobs, monitor real-time progress and logs
- **🔐 Findings** — Browse/filter/search all detected secrets; click any row to view the full file
- **📁 Repos** — All scanned repos with status and findings count
- **📊 Analytics** — Stats cards, top secret types chart, repos with most findings

---

## Architecture

```
app.py          Flask API + embedded dashboard HTML
scanner.py      Git cloning, file walking, regex matching
crawler.db      SQLite — repos, findings, jobs tables
requirements.txt
```

### Database Schema

**repos** — `id, name, url, status, error_msg, findings_count, scanned_at`  
**findings** — `id, repo_id, repo_name, repo_url, file_name, file_path, secret_type, severity, secret_value, line_number, context, file_content, found_at`  
**jobs** — `id, query, query_type, status, repos_found, repos_scanned, findings_total, log, started_at, finished_at`

---

## Notes

- Files larger than 512 KB are skipped to keep scanning fast
- Binary files (`.png`, `.exe`, `.zip`, etc.) are skipped automatically
- `node_modules`, `.git`, `vendor`, `dist`, and similar dirs are excluded
- Secret values are stored truncated to 300 characters
- File content is stored up to the first 60 KB per file
- Each repo is shallow-cloned (`--depth 1`) and deleted after scanning
