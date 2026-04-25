import os
import re
import subprocess
import shutil
import tempfile
from pathlib import Path

# ── Secret patterns ──────────────────────────────────────────────────────────
SECRET_PATTERNS = [
    ("AWS Access Key ID",       r'AKIA[0-9A-Z]{16}'),
    ("AWS Secret Access Key",   r'(?i)aws.{0,30}secret.{0,30}["\']([A-Za-z0-9/+=]{40})["\']'),
    ("AWS Session Token",       r'(?i)aws.{0,30}session.{0,30}token.{0,30}["\']([A-Za-z0-9/+=]{16,})["\']'),
    ("GitHub PAT (classic)",    r'ghp_[A-Za-z0-9]{36}'),
    ("GitHub PAT (fine-grained)",r'github_pat_[A-Za-z0-9_]{82}'),
    ("GitHub OAuth Token",      r'gho_[A-Za-z0-9]{36}'),
    ("GitHub App Token",        r'ghs_[A-Za-z0-9]{36}'),
    ("GitLab Token",            r'glpat-[A-Za-z0-9\-_]{20}'),
    ("Slack Bot Token",         r'xoxb-[0-9]{11}-[0-9]{11}-[A-Za-z0-9]{24}'),
    ("Slack User Token",        r'xoxp-[0-9]{11}-[0-9]{11}-[A-Za-z0-9]{24}'),
    ("Slack Webhook",           r'https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+'),
    ("Google API Key",          r'AIza[0-9A-Za-z\-_]{35}'),
    ("Google OAuth Client ID",  r'[0-9]{12}-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'),
    ("Google Service Account",  r'"type"\s*:\s*"service_account"'),
    ("Firebase API Key",        r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}'),
    ("PEM Private Key",         r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY(?:\s*BLOCK)?-----'),
    ("Stripe Live Key",         r'sk_live_[A-Za-z0-9]{24,}'),
    ("Stripe Test Key",         r'sk_test_[A-Za-z0-9]{24,}'),
    ("Stripe Publishable Key",  r'pk_(?:live|test)_[A-Za-z0-9]{24,}'),
    ("Twilio Account SID",      r'AC[a-f0-9]{32}'),
    ("Twilio Auth Token",       r'(?i)twilio.{0,20}auth.{0,20}token.{0,20}["\']([a-f0-9]{32})["\']'),
    ("SendGrid API Key",        r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}'),
    ("Mailchimp API Key",       r'[0-9a-f]{32}-us[0-9]{1,2}'),
    ("Mailgun API Key",         r'key-[0-9a-zA-Z]{32}'),
    ("Shopify Access Token",    r'shpat_[a-fA-F0-9]{32}'),
    ("Shopify Partner Token",   r'shppa_[a-fA-F0-9]{32}'),
    ("Square Access Token",     r'sq0atp-[0-9A-Za-z\-_]{22}'),
    ("Square OAuth Secret",     r'sq0csp-[0-9A-Za-z\-_]{43}'),
    ("PayPal/Braintree Token",  r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}'),
    ("NPM Access Token",        r'npm_[A-Za-z0-9]{36}'),
    ("PyPI API Token",          r'pypi-[A-Za-z0-9_-]{80,}'),
    ("Heroku API Key",          r'(?i)heroku.{0,30}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'),
    ("DigitalOcean Token",      r'dop_v1_[a-f0-9]{64}'),
    ("DigitalOcean Spaces Key", r'(?i)digitalocean.{0,30}[A-Za-z0-9]{20}'),
    ("Cloudinary URL",          r'cloudinary://[A-Za-z0-9]+:[A-Za-z0-9_\-]+@[A-Za-z0-9]+'),
    ("Cloudflare API Key",      r'(?i)cloudflare.{0,30}[0-9a-f]{37}'),
    ("Discord Bot Token",       r'[MNO][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}'),
    ("Telegram Bot Token",      r'[0-9]{8,10}:[A-Za-z0-9_-]{35}'),
    ("Twitter API Key",         r'(?i)twitter.{0,30}[A-Za-z0-9]{25,}'),
    ("Facebook Access Token",   r'EAACEdEose0cBA[0-9A-Za-z]+'),
    ("LinkedIn Client ID",      r'(?i)linkedin.{0,30}client.{0,10}["\']([a-z0-9]{12})["\']'),
    ("Azure Client Secret",     r'(?i)azure.{0,30}client.{0,10}secret.{0,10}["\']([A-Za-z0-9~.\-_]{34,})["\']'),
    ("Azure Storage Key",       r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88};'),
    ("Okta API Token",          r'(?i)okta.{0,30}api.{0,10}token.{0,10}["\']([A-Za-z0-9_-]{40,})["\']'),
    ("JWT Token",               r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+'),
    ("MongoDB URI",             r'mongodb(?:\+srv)?://[^:]+:[^@]+@[A-Za-z0-9.\-_:/?]+'),
    ("MySQL URI",               r'mysql://[^:]+:[^@]+@[A-Za-z0-9.\-_:/?]+'),
    ("PostgreSQL URI",          r'postgres(?:ql)?://[^:]+:[^@]+@[A-Za-z0-9.\-_:/?]+'),
    ("Redis URI (with auth)",   r'redis://:[^@]+@[A-Za-z0-9.\-_:/?]+'),
    ("Basic Auth in URL",       r'https?://[A-Za-z0-9_\-]+:[A-Za-z0-9_\-!@#$%^&*]{4,}@[A-Za-z0-9.\-_]+'),
    ("Generic API Key",         r'(?i)(?:api[_\-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9\-_]{16,})["\']'),
    ("Generic Secret",          r'(?i)(?:secret|client_secret|app_secret)\s*[=:]\s*["\']([A-Za-z0-9\-_!@#$%^&*]{12,})["\']'),
    ("Generic Password",        r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']'),
    ("Generic Token",           r'(?i)(?:auth_token|access_token|refresh_token)\s*[=:]\s*["\']([A-Za-z0-9\-_.]{20,})["\']'),
    ("Private Key Passphrase",  r'(?i)(?:passphrase|private.?key.?password)\s*[=:]\s*["\']([^"\']{8,})["\']'),
    ("SSH Private Key (inline)", r'-----BEGIN OPENSSH PRIVATE KEY-----'),
    ("Vault Token",             r'(?:^|[^A-Za-z])s\.[A-Za-z0-9]{24}'),
    ("HashiCorp Consul Token",  r'(?i)consul.{0,20}token.{0,10}["\']([A-Za-z0-9\-]{36})["\']'),
    ("Datadog API Key",         r'(?i)datadog.{0,30}api.{0,10}key.{0,10}["\']([a-f0-9]{32})["\']'),
    ("New Relic Key",           r'(?i)newrelic.{0,30}license.{0,10}["\']([A-Za-z0-9]{40})["\']'),
    ("Sentry DSN",              r'https://[a-f0-9]{32}@o[0-9]+\.ingest\.sentry\.io/[0-9]+'),
    ("PagerDuty Key",           r'(?i)pagerduty.{0,30}key.{0,10}["\']([A-Za-z0-9+/=]{16,})["\']'),
    ("Algolia API Key",         r'(?i)algolia.{0,30}(?:api|admin).{0,10}key.{0,10}["\']([A-Za-z0-9]{32})["\']'),
    ("Pusher App Key",          r'(?i)pusher.{0,30}app.{0,10}key.{0,10}["\']([A-Za-z0-9]{20})["\']'),
    ("Mapbox Token",            r'pk\.eyJ1[A-Za-z0-9._\-]+'),
    ("Plaid Key",               r'(?i)plaid.{0,20}(?:secret|client_id).{0,10}["\']([A-Za-z0-9]{24,})["\']'),
]

# Severity mapping
SEVERITY_MAP = {
    "AWS Access Key ID": "CRITICAL",
    "AWS Secret Access Key": "CRITICAL",
    "AWS Session Token": "CRITICAL",
    "GitHub PAT (classic)": "CRITICAL",
    "GitHub PAT (fine-grained)": "CRITICAL",
    "GitHub OAuth Token": "CRITICAL",
    "GitHub App Token": "HIGH",
    "GitLab Token": "CRITICAL",
    "PEM Private Key": "CRITICAL",
    "SSH Private Key (inline)": "CRITICAL",
    "Azure Storage Key": "CRITICAL",
    "Stripe Live Key": "CRITICAL",
    "MongoDB URI": "HIGH",
    "MySQL URI": "HIGH",
    "PostgreSQL URI": "HIGH",
}

def get_severity(secret_type):
    return SEVERITY_MAP.get(secret_type, "MEDIUM")

# ── Skip lists ────────────────────────────────────────────────────────────────
SKIP_DIRS = {
    '.git', 'node_modules', 'vendor', '__pycache__', '.pytest_cache',
    'dist', 'build', '.next', 'coverage', 'venv', '.venv', 'env',
    '.env', 'bower_components', 'jspm_packages', '.yarn', 'target',
    'Pods', '.gradle', '.idea', '.vscode', 'out', 'bin', 'obj',
}

SKIP_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg', '.webp',
    '.mp4', '.mp3', '.wav', '.avi', '.mov', '.mkv', '.flv',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.zip', '.tar', '.gz', '.rar', '.7z', '.bz2', '.xz',
    '.exe', '.dll', '.so', '.dylib', '.bin', '.o', '.a',
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.db', '.sqlite', '.sqlite3',
    '.lock',  # package-lock.json, yarn.lock — but NOT .env.example
    '.map', '.min.js', '.min.css',
    '.pb', '.pkl', '.h5', '.parquet', '.feather',
    '.class', '.jar',
}

MAX_FILE_SIZE = 512 * 1024  # 512 KB

# ── Dedup helper ──────────────────────────────────────────────────────────────
def _make_key(finding):
    return (finding['file_path'], finding['secret_type'], finding['line_number'])

# ── Main functions ─────────────────────────────────────────────────────────────
def clone_repo(url, target_dir, timeout=180):
    """Shallow-clone a repo. Returns (ok, message)."""
    try:
        result = subprocess.run(
            ['git', 'clone', '--depth', '1', '--single-branch', url, target_dir],
            capture_output=True, text=True, timeout=timeout
        )
        if result.returncode == 0:
            return True, "OK"
        return False, result.stderr.strip()[:300]
    except subprocess.TimeoutExpired:
        return False, "Clone timed out"
    except Exception as e:
        return False, str(e)


def scan_directory(clone_dir, repo_url, repo_name):
    """Walk a cloned repo and return list of finding dicts."""
    findings = []
    seen_keys = set()

    for root, dirs, files in os.walk(clone_dir, topdown=True):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for filename in files:
            abs_path = os.path.join(root, filename)
            rel_path = os.path.relpath(abs_path, clone_dir)

            # Extension filter
            suffix = Path(filename).suffix.lower()
            if suffix in SKIP_EXTENSIONS:
                continue
            # .lock files (but allow .env.example, .env.sample)
            if filename.endswith('.lock') and not filename.startswith('.env'):
                continue

            # Size filter
            try:
                if os.path.getsize(abs_path) > MAX_FILE_SIZE:
                    continue
            except OSError:
                continue

            # Read content
            try:
                with open(abs_path, 'r', encoding='utf-8', errors='replace') as fh:
                    content = fh.read()
            except Exception:
                continue

            # Skip binary-looking files
            if '\x00' in content[:1024]:
                continue

            lines = content.splitlines()

            # Scan patterns
            for secret_type, pattern in SECRET_PATTERNS:
                try:
                    for match in re.finditer(pattern, content):
                        line_no = content[:match.start()].count('\n') + 1
                        key = (rel_path, secret_type, line_no)
                        if key in seen_keys:
                            continue
                        seen_keys.add(key)

                        # Context: up to 5 lines around the hit
                        start = max(0, line_no - 4)
                        end   = min(len(lines), line_no + 3)
                        context_snippet = '\n'.join(lines[start:end])

                        findings.append({
                            'repo_url':      repo_url,
                            'repo_name':     repo_name,
                            'file_name':     filename,
                            'file_path':     rel_path,
                            'secret_type':   secret_type,
                            'severity':      get_severity(secret_type),
                            'secret_value':  match.group(0)[:300],
                            'line_number':   line_no,
                            'context':       context_snippet,
                            'file_content':  content[:60_000],  # first 60 KB
                        })
                except re.error:
                    continue

    return findings


def scan_repo(repo_url, repo_name):
    """
    Clone → scan → delete.
    Returns (findings_list, status_string).
    """
    tmp_dir = tempfile.mkdtemp(prefix='ghsc_')
    clone_dir = os.path.join(tmp_dir, 'repo')
    try:
        ok, msg = clone_repo(repo_url, clone_dir)
        if not ok:
            return [], f'clone_failed: {msg}'
        findings = scan_directory(clone_dir, repo_url, repo_name)
        return findings, 'success'
    except Exception as exc:
        return [], f'error: {exc}'
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
