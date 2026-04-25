"""
GitHub Secret Crawler — Flask backend + embedded dashboard
"""

import json
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone

import requests
from flask import Flask, g, jsonify, render_template_string, request

from scanner import scan_repo

# ── App setup ─────────────────────────────────────────────────────────────────
app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), 'crawler.db')


# ── Database helpers ──────────────────────────────────────────────────────────
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH, check_same_thread=False)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA journal_mode=WAL')
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db:
        db.close()


def db_conn():
    """Thread-safe connection for background threads."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    return conn


def init_db():
    conn = db_conn()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS repos (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        name          TEXT    NOT NULL,
        url           TEXT    NOT NULL UNIQUE,
        status        TEXT    NOT NULL DEFAULT 'pending',
        error_msg     TEXT,
        findings_count INTEGER NOT NULL DEFAULT 0,
        scanned_at    TEXT
    );

    CREATE TABLE IF NOT EXISTS findings (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        repo_id       INTEGER NOT NULL,
        repo_name     TEXT    NOT NULL,
        repo_url      TEXT    NOT NULL,
        file_name     TEXT    NOT NULL,
        file_path     TEXT    NOT NULL,
        secret_type   TEXT    NOT NULL,
        severity      TEXT    NOT NULL DEFAULT 'MEDIUM',
        secret_value  TEXT    NOT NULL,
        line_number   INTEGER NOT NULL,
        context       TEXT,
        file_content  TEXT,
        found_at      TEXT    NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY (repo_id) REFERENCES repos(id)
    );

    CREATE TABLE IF NOT EXISTS jobs (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        query          TEXT    NOT NULL,
        query_type     TEXT    NOT NULL,
        github_token   TEXT,
        status         TEXT    NOT NULL DEFAULT 'running',
        repos_found    INTEGER NOT NULL DEFAULT 0,
        repos_scanned  INTEGER NOT NULL DEFAULT 0,
        findings_total INTEGER NOT NULL DEFAULT 0,
        log            TEXT    NOT NULL DEFAULT '',
        started_at     TEXT    NOT NULL DEFAULT (datetime('now')),
        finished_at    TEXT
    );
    """)
    conn.commit()
    conn.close()


# ── GitHub API helpers ────────────────────────────────────────────────────────
GITHUB_API = "https://api.github.com"


def gh_headers(token=None):
    h = {"Accept": "application/vnd.github+json",
         "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def fetch_user_repos(username, token=None, max_repos=100):
    repos, page = [], 1
    while len(repos) < max_repos:
        r = requests.get(
            f"{GITHUB_API}/users/{username}/repos",
            params={"per_page": min(100, max_repos - len(repos)), "page": page, "type": "all"},
            headers=gh_headers(token), timeout=20
        )
        if r.status_code != 200:
            break
        batch = r.json()
        if not batch:
            break
        repos.extend(batch)
        page += 1
        if len(batch) < 100:
            break
    return [{"name": r["full_name"], "url": r["clone_url"], "html_url": r["html_url"]} for r in repos]


def fetch_org_repos(org, token=None, max_repos=200):
    repos, page = [], 1
    while len(repos) < max_repos:
        r = requests.get(
            f"{GITHUB_API}/orgs/{org}/repos",
            params={"per_page": min(100, max_repos - len(repos)), "page": page, "type": "all"},
            headers=gh_headers(token), timeout=20
        )
        if r.status_code != 200:
            break
        batch = r.json()
        if not batch:
            break
        repos.extend(batch)
        page += 1
        if len(batch) < 100:
            break
    return [{"name": r["full_name"], "url": r["clone_url"], "html_url": r["html_url"]} for r in repos]


def search_repos(query, token=None, max_repos=50):
    repos, page = [], 1
    while len(repos) < max_repos:
        r = requests.get(
            f"{GITHUB_API}/search/repositories",
            params={"q": query, "per_page": min(30, max_repos - len(repos)), "page": page, "sort": "updated"},
            headers=gh_headers(token), timeout=20
        )
        if r.status_code != 200:
            break
        data = r.json()
        batch = data.get("items", [])
        if not batch:
            break
        repos.extend(batch)
        page += 1
        if len(batch) < 30:
            break
        time.sleep(1)  # search rate-limit
    return [{"name": r["full_name"], "url": r["clone_url"], "html_url": r["html_url"]} for r in repos]


def single_repo_info(repo_path_or_url, token=None):
    """Accept 'owner/repo', full https URL, or git URL."""
    url = repo_path_or_url.strip()
    if url.startswith("https://github.com/"):
        path = url.replace("https://github.com/", "").rstrip("/").removesuffix(".git")
    elif url.startswith("git@github.com:"):
        path = url.replace("git@github.com:", "").removesuffix(".git")
    else:
        path = url.rstrip("/").removesuffix(".git")
    r = requests.get(f"{GITHUB_API}/repos/{path}", headers=gh_headers(token), timeout=20)
    if r.status_code != 200:
        return None
    d = r.json()
    return {"name": d["full_name"], "url": d["clone_url"], "html_url": d["html_url"]}


# ── Background crawl worker ───────────────────────────────────────────────────
def crawl_worker(job_id: int, query: str, query_type: str, token: str | None):
    conn = db_conn()

    def log(msg):
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        conn.execute(
            "UPDATE jobs SET log = log || ? WHERE id = ?",
            (f"[{ts}] {msg}\n", job_id)
        )
        conn.commit()

    def update_job(**kw):
        sets = ", ".join(f"{k}=?" for k in kw)
        conn.execute(f"UPDATE jobs SET {sets} WHERE id=?", (*kw.values(), job_id))
        conn.commit()

    try:
        log(f"Starting crawl: type={query_type}, query={query}")

        # ── Discover repos ──────────────────────────────────────────────────
        if query_type == "user":
            repo_list = fetch_user_repos(query, token)
        elif query_type == "org":
            repo_list = fetch_org_repos(query, token)
        elif query_type == "search":
            repo_list = search_repos(query, token)
        elif query_type == "single":
            info = single_repo_info(query, token)
            repo_list = [info] if info else []
        else:
            log("Unknown query_type"); update_job(status='failed'); return

        update_job(repos_found=len(repo_list))
        log(f"Found {len(repo_list)} repositories")

        if not repo_list:
            log("No repos found — check query or token"); update_job(status='completed', finished_at=datetime.utcnow().isoformat()); return

        total_findings = 0

        for idx, repo in enumerate(repo_list, 1):
            name     = repo["name"]
            clone_url = repo["url"]
            html_url  = repo.get("html_url", clone_url)

            log(f"[{idx}/{len(repo_list)}] Checking {name} …")

            # ── Skip already-scanned repos ──────────────────────────────────
            row = conn.execute("SELECT id, status FROM repos WHERE url=?", (html_url,)).fetchone()
            if row and row["status"] == "scanned":
                log(f"  ↳ SKIP (already scanned)")
                update_job(repos_scanned=idx)
                continue

            # ── Register / update repo entry ────────────────────────────────
            if row is None:
                conn.execute(
                    "INSERT INTO repos (name, url, status) VALUES (?,?,?)",
                    (name, html_url, 'scanning')
                )
                conn.commit()
            else:
                conn.execute("UPDATE repos SET status='scanning' WHERE url=?", (html_url,))
                conn.commit()

            repo_row = conn.execute("SELECT id FROM repos WHERE url=?", (html_url,)).fetchone()
            repo_id  = repo_row["id"]

            # Inject token into clone URL for private repos
            eff_clone = clone_url
            if token:
                eff_clone = clone_url.replace("https://", f"https://{token}@")

            # ── Clone + Scan ────────────────────────────────────────────────
            findings, status = scan_repo(eff_clone, name)

            if status == "success":
                # Persist findings
                now = datetime.utcnow().isoformat()
                for f in findings:
                    conn.execute("""
                        INSERT INTO findings
                            (repo_id,repo_name,repo_url,file_name,file_path,
                             secret_type,severity,secret_value,line_number,context,file_content,found_at)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                    """, (
                        repo_id, name, html_url,
                        f['file_name'], f['file_path'],
                        f['secret_type'], f['severity'],
                        f['secret_value'], f['line_number'],
                        f.get('context',''), f.get('file_content',''), now
                    ))
                conn.execute(
                    "UPDATE repos SET status='scanned', findings_count=?, scanned_at=? WHERE id=?",
                    (len(findings), now, repo_id)
                )
                total_findings += len(findings)
                log(f"  ↳ OK — {len(findings)} secret(s) found")
            else:
                conn.execute(
                    "UPDATE repos SET status='error', error_msg=? WHERE id=?",
                    (status, repo_id)
                )
                log(f"  ↳ ERROR: {status}")

            conn.commit()
            update_job(repos_scanned=idx, findings_total=total_findings)

            # Be polite to GitHub API
            time.sleep(0.5)

        update_job(status='completed', finished_at=datetime.utcnow().isoformat(), findings_total=total_findings)
        log(f"✓ Done — scanned {len(repo_list)} repos, {total_findings} secrets found")

    except Exception as exc:
        try:
            update_job(status='failed')
            log(f"FATAL: {exc}")
        except Exception:
            pass
    finally:
        conn.close()


# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)


@app.route("/api/crawl", methods=["POST"])
def api_crawl():
    data = request.json or {}
    query      = (data.get("query") or "").strip()
    query_type = (data.get("type")  or "user").strip()
    token      = (data.get("token") or "").strip() or None

    if not query:
        return jsonify({"error": "query is required"}), 400

    conn = db_conn()
    cur = conn.execute(
        "INSERT INTO jobs (query, query_type, github_token) VALUES (?,?,?)",
        (query, query_type, token)
    )
    job_id = cur.lastrowid
    conn.commit()
    conn.close()

    t = threading.Thread(target=crawl_worker, args=(job_id, query, query_type, token), daemon=True)
    t.start()

    return jsonify({"job_id": job_id, "status": "started"})


@app.route("/api/jobs")
def api_jobs():
    db   = get_db()
    rows = db.execute("SELECT * FROM jobs ORDER BY id DESC LIMIT 50").fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/jobs/<int:job_id>")
def api_job(job_id):
    db  = get_db()
    row = db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(row))


@app.route("/api/repos")
def api_repos():
    db     = get_db()
    page   = int(request.args.get("page", 1))
    limit  = int(request.args.get("limit", 50))
    status = request.args.get("status", "")
    offset = (page - 1) * limit

    where = "WHERE status=?" if status else ""
    params_count = (status,) if status else ()
    params_rows  = (status, limit, offset) if status else (limit, offset)

    total = db.execute(f"SELECT COUNT(*) FROM repos {where}", params_count).fetchone()[0]
    rows  = db.execute(f"SELECT * FROM repos {where} ORDER BY scanned_at DESC NULLS LAST LIMIT ? OFFSET ?", params_rows).fetchall()
    return jsonify({"total": total, "repos": [dict(r) for r in rows]})


@app.route("/api/findings")
def api_findings():
    db       = get_db()
    page     = int(request.args.get("page", 1))
    limit    = int(request.args.get("limit", 50))
    severity = request.args.get("severity", "")
    repo_id  = request.args.get("repo_id", "")
    search   = request.args.get("q", "")
    offset   = (page - 1) * limit

    clauses, params = [], []
    if severity:
        clauses.append("severity=?"); params.append(severity)
    if repo_id:
        clauses.append("repo_id=?"); params.append(repo_id)
    if search:
        clauses.append("(secret_type LIKE ? OR file_path LIKE ? OR repo_name LIKE ?)")
        params += [f"%{search}%", f"%{search}%", f"%{search}%"]

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    total = db.execute(f"SELECT COUNT(*) FROM findings {where}", params).fetchone()[0]
    rows  = db.execute(
        f"SELECT id,repo_id,repo_name,repo_url,file_name,file_path,"
        f"secret_type,severity,secret_value,line_number,context,found_at "
        f"FROM findings {where} ORDER BY id DESC LIMIT ? OFFSET ?",
        params + [limit, offset]
    ).fetchall()
    return jsonify({"total": total, "findings": [dict(r) for r in rows]})


@app.route("/api/findings/<int:fid>")
def api_finding(fid):
    db  = get_db()
    row = db.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(row))


@app.route("/api/stats")
def api_stats():
    db = get_db()
    total_repos    = db.execute("SELECT COUNT(*) FROM repos").fetchone()[0]
    scanned_repos  = db.execute("SELECT COUNT(*) FROM repos WHERE status='scanned'").fetchone()[0]
    total_findings = db.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    critical       = db.execute("SELECT COUNT(*) FROM findings WHERE severity='CRITICAL'").fetchone()[0]
    high           = db.execute("SELECT COUNT(*) FROM findings WHERE severity='HIGH'").fetchone()[0]
    top_types      = db.execute(
        "SELECT secret_type, COUNT(*) as cnt FROM findings GROUP BY secret_type ORDER BY cnt DESC LIMIT 8"
    ).fetchall()
    top_repos      = db.execute(
        "SELECT name, url, findings_count FROM repos WHERE findings_count>0 ORDER BY findings_count DESC LIMIT 5"
    ).fetchall()
    active_jobs    = db.execute("SELECT COUNT(*) FROM jobs WHERE status='running'").fetchone()[0]
    return jsonify({
        "total_repos":    total_repos,
        "scanned_repos":  scanned_repos,
        "total_findings": total_findings,
        "critical":       critical,
        "high":           high,
        "active_jobs":    active_jobs,
        "top_types":      [dict(r) for r in top_types],
        "top_repos":      [dict(r) for r in top_repos],
    })


@app.route("/api/export/findings")
def export_findings():
    db   = get_db()
    rows = db.execute(
        "SELECT repo_name,repo_url,file_name,file_path,secret_type,severity,"
        "secret_value,line_number,found_at FROM findings ORDER BY severity,id"
    ).fetchall()
    import csv, io
    buf = io.StringIO()
    w   = csv.DictWriter(buf, fieldnames=rows[0].keys() if rows else [])
    w.writeheader()
    w.writerows([dict(r) for r in rows])
    from flask import Response
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=findings.csv"})


# ── Dashboard HTML ─────────────────────────────────────────────────────────────
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>GitHub Secret Crawler</title>
<style>
:root{
  --bg:#0d1117;--surface:#161b22;--surface2:#21262d;--border:#30363d;
  --text:#e6edf3;--muted:#8b949e;--accent:#58a6ff;--accent2:#1f6feb;
  --green:#3fb950;--yellow:#d29922;--orange:#db6d28;--red:#f85149;--purple:#bc8cff;
  --font:'Segoe UI',system-ui,sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:var(--font);min-height:100vh;}

/* ── layout ── */
.shell{display:flex;flex-direction:column;min-height:100vh;}
header{background:var(--surface);border-bottom:1px solid var(--border);
  padding:14px 28px;display:flex;align-items:center;gap:16px;position:sticky;top:0;z-index:100;}
header h1{font-size:1.1rem;font-weight:600;display:flex;align-items:center;gap:10px;}
header h1 span.icon{font-size:1.4rem;}
.stats-bar{display:flex;gap:10px;margin-left:auto;flex-wrap:wrap;}
.stat-pill{background:var(--surface2);border:1px solid var(--border);border-radius:20px;
  padding:4px 14px;font-size:.78rem;display:flex;align-items:center;gap:6px;}
.stat-pill b{color:var(--accent);}
.dot{width:8px;height:8px;border-radius:50%;background:var(--green);animation:pulse 1.5s infinite;}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}

main{flex:1;padding:24px 28px;max-width:1400px;margin:0 auto;width:100%;}

/* ── tabs ── */
.tabs{display:flex;gap:4px;border-bottom:1px solid var(--border);margin-bottom:20px;}
.tab{padding:10px 18px;cursor:pointer;border:none;background:none;color:var(--muted);
  font-size:.875rem;border-bottom:2px solid transparent;transition:.15s;}
.tab:hover{color:var(--text);}
.tab.active{color:var(--accent);border-bottom-color:var(--accent);}
.tab-panel{display:none;} .tab-panel.active{display:block;}

/* ── cards ── */
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:14px;margin-bottom:24px;}
.card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:18px 20px;}
.card .label{font-size:.75rem;color:var(--muted);margin-bottom:6px;text-transform:uppercase;letter-spacing:.05em;}
.card .value{font-size:1.9rem;font-weight:700;line-height:1;}
.card.red .value{color:var(--red);}
.card.orange .value{color:var(--orange);}
.card.yellow .value{color:var(--yellow);}
.card.green .value{color:var(--green);}
.card.blue .value{color:var(--accent);}

/* ── crawl form ── */
.crawl-box{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:22px;margin-bottom:24px;}
.crawl-box h2{font-size:.95rem;font-weight:600;margin-bottom:14px;display:flex;align-items:center;gap:8px;}
.form-row{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end;}
.form-group{display:flex;flex-direction:column;gap:5px;}
.form-group label{font-size:.78rem;color:var(--muted);}
select,input[type=text],input[type=password]{
  background:var(--surface2);border:1px solid var(--border);border-radius:6px;
  color:var(--text);padding:8px 12px;font-size:.875rem;outline:none;}
select:focus,input:focus{border-color:var(--accent2);}
input[type=text]{min-width:260px;}
.btn{padding:9px 20px;border-radius:6px;border:none;cursor:pointer;font-size:.875rem;
  font-weight:600;transition:.15s;white-space:nowrap;}
.btn-primary{background:var(--accent2);color:#fff;}
.btn-primary:hover{background:#388bfd;}
.btn-primary:disabled{opacity:.5;cursor:not-allowed;}
.btn-secondary{background:var(--surface2);color:var(--text);border:1px solid var(--border);}
.btn-secondary:hover{border-color:var(--accent);}
.btn-danger{background:#3d1f1f;color:var(--red);border:1px solid #6e2020;}
.btn-danger:hover{background:#5a1f1f;}
.btn-sm{padding:5px 12px;font-size:.8rem;}

/* ── job status ── */
.job-card{background:var(--surface2);border:1px solid var(--border);border-radius:8px;
  padding:14px 16px;margin-bottom:10px;}
.job-header{display:flex;align-items:center;gap:10px;margin-bottom:8px;}
.badge{padding:2px 8px;border-radius:4px;font-size:.72rem;font-weight:600;text-transform:uppercase;}
.badge.running{background:#1c2d4a;color:var(--accent);}
.badge.completed{background:#1a2e1a;color:var(--green);}
.badge.failed{background:#2d1a1a;color:var(--red);}
.progress{height:4px;background:var(--border);border-radius:2px;overflow:hidden;margin:8px 0;}
.progress-bar{height:100%;background:linear-gradient(90deg,var(--accent2),var(--purple));transition:width .3s;}
.job-log{font-family:monospace;font-size:.75rem;color:var(--muted);background:var(--bg);
  border-radius:4px;padding:10px;max-height:180px;overflow-y:auto;white-space:pre-wrap;
  border:1px solid var(--border);margin-top:8px;}

/* ── table ── */
.table-wrap{overflow-x:auto;border:1px solid var(--border);border-radius:8px;}
table{width:100%;border-collapse:collapse;font-size:.845rem;}
thead{background:var(--surface2);}
th{padding:11px 14px;text-align:left;color:var(--muted);font-weight:500;
  font-size:.78rem;text-transform:uppercase;letter-spacing:.04em;white-space:nowrap;}
td{padding:10px 14px;border-top:1px solid var(--border);vertical-align:middle;}
tr:hover td{background:rgba(255,255,255,.03);}
.truncate{max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
a.link{color:var(--accent);text-decoration:none;}
a.link:hover{text-decoration:underline;}

/* ── severity badges ── */
.sev{padding:2px 8px;border-radius:4px;font-size:.72rem;font-weight:700;text-transform:uppercase;}
.sev.CRITICAL{background:#3d0f0f;color:#ff6b6b;}
.sev.HIGH{background:#3d1f0a;color:#ffa057;}
.sev.MEDIUM{background:#2d2a0d;color:#e8c84a;}
.sev.LOW{background:#0d2a1a;color:#4ade80;}

/* ── filters bar ── */
.filters{display:flex;gap:10px;margin-bottom:14px;flex-wrap:wrap;align-items:center;}
.filters input{min-width:220px;}
.count-label{color:var(--muted);font-size:.82rem;margin-left:auto;}

/* ── pagination ── */
.pagination{display:flex;gap:6px;justify-content:center;margin-top:16px;flex-wrap:wrap;}
.page-btn{padding:5px 12px;border-radius:6px;border:1px solid var(--border);
  background:var(--surface2);color:var(--text);cursor:pointer;font-size:.82rem;}
.page-btn.active{background:var(--accent2);border-color:var(--accent2);color:#fff;}
.page-btn:hover:not(.active){border-color:var(--accent);}

/* ── modal ── */
.overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:200;
  align-items:center;justify-content:center;padding:20px;}
.overlay.open{display:flex;}
.modal{background:var(--surface);border:1px solid var(--border);border-radius:12px;
  width:100%;max-width:820px;max-height:90vh;display:flex;flex-direction:column;overflow:hidden;}
.modal-head{padding:18px 22px;border-bottom:1px solid var(--border);display:flex;
  align-items:center;justify-content:space-between;gap:14px;}
.modal-head h3{font-size:.95rem;font-weight:600;flex:1;min-width:0;overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap;}
.modal-body{padding:20px 22px;overflow-y:auto;flex:1;}
.meta-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px 20px;margin-bottom:16px;}
.meta-item .k{font-size:.72rem;color:var(--muted);margin-bottom:3px;text-transform:uppercase;}
.meta-item .v{font-size:.875rem;word-break:break-all;}
.secret-box{background:var(--bg);border:1px solid var(--red);border-radius:6px;
  padding:10px 14px;margin-bottom:14px;font-family:monospace;font-size:.82rem;color:var(--red);
  word-break:break-all;}
pre.code{background:var(--bg);border:1px solid var(--border);border-radius:6px;
  padding:12px 14px;font-family:monospace;font-size:.8rem;overflow:auto;
  max-height:340px;white-space:pre;color:var(--text);margin-top:6px;}
.section-title{font-size:.78rem;color:var(--muted);text-transform:uppercase;
  letter-spacing:.05em;margin-bottom:6px;margin-top:14px;}
.close-btn{background:none;border:none;color:var(--muted);font-size:1.3rem;cursor:pointer;
  padding:2px 6px;border-radius:4px;}
.close-btn:hover{color:var(--text);background:var(--surface2);}

/* ── toast ── */
.toast{position:fixed;bottom:24px;right:24px;background:var(--surface2);
  border:1px solid var(--border);border-radius:8px;padding:12px 18px;
  font-size:.875rem;z-index:300;opacity:0;transform:translateY(10px);
  transition:.25s;pointer-events:none;}
.toast.show{opacity:1;transform:translateY(0);}
.toast.success{border-color:var(--green);color:var(--green);}
.toast.error{border-color:var(--red);color:var(--red);}

/* ── chart bars ── */
.bar-list{display:flex;flex-direction:column;gap:8px;margin-top:10px;}
.bar-row{display:flex;align-items:center;gap:10px;font-size:.8rem;}
.bar-label{min-width:180px;color:var(--muted);text-align:right;overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap;}
.bar-track{flex:1;background:var(--border);border-radius:3px;height:12px;overflow:hidden;}
.bar-fill{height:100%;background:linear-gradient(90deg,var(--accent2),var(--purple));
  border-radius:3px;transition:width .4s;}
.bar-count{min-width:30px;color:var(--text);font-weight:600;}

/* ── status dot ── */
.status-dot{width:8px;height:8px;border-radius:50%;display:inline-block;margin-right:5px;}
.status-dot.scanned{background:var(--green);}
.status-dot.error{background:var(--red);}
.status-dot.scanning{background:var(--yellow);}
.status-dot.pending{background:var(--muted);}

/* ── empty state ── */
.empty{text-align:center;padding:50px 20px;color:var(--muted);}
.empty .icon{font-size:3rem;margin-bottom:12px;opacity:.4;}
</style>
</head>
<body>
<div class="shell">
<header>
  <h1><span class="icon">🔍</span> GitHub Secret Crawler</h1>
  <div class="stats-bar" id="header-stats">
    <div class="stat-pill"><span class="dot" id="live-dot" style="display:none"></span>Loading…</div>
  </div>
</header>

<main>
  <div class="tabs">
    <button class="tab active" onclick="switchTab('crawl')">🚀 Crawl</button>
    <button class="tab" onclick="switchTab('findings')">🔐 Findings</button>
    <button class="tab" onclick="switchTab('repos')">📁 Repos</button>
    <button class="tab" onclick="switchTab('analytics')">📊 Analytics</button>
  </div>

  <!-- ══ CRAWL TAB ══ -->
  <div id="tab-crawl" class="tab-panel active">
    <div class="crawl-box">
      <h2>🕷️ New Crawl Job</h2>
      <div class="form-row">
        <div class="form-group">
          <label>Source Type</label>
          <select id="crawl-type" onchange="updatePlaceholder()">
            <option value="user">GitHub User</option>
            <option value="org">GitHub Org</option>
            <option value="search">Search Query</option>
            <option value="single">Single Repo</option>
          </select>
        </div>
        <div class="form-group">
          <label id="query-label">Username</label>
          <input type="text" id="crawl-query" placeholder="e.g. torvalds"/>
        </div>
        <div class="form-group">
          <label>GitHub Token <span style="color:var(--muted)">(optional, ↑ rate limit)</span></label>
          <input type="password" id="crawl-token" placeholder="ghp_…" style="min-width:200px"/>
        </div>
        <div class="form-group">
          <button class="btn btn-primary" id="crawl-btn" onclick="startCrawl()">Start Crawl</button>
        </div>
      </div>
    </div>

    <div id="jobs-container"></div>
  </div>

  <!-- ══ FINDINGS TAB ══ -->
  <div id="tab-findings" class="tab-panel">
    <div class="filters">
      <input type="text" id="findings-search" placeholder="Search type, file, repo…" oninput="debounce(loadFindings,400)()"/>
      <select id="findings-severity" onchange="loadFindings()">
        <option value="">All Severities</option>
        <option value="CRITICAL">🔴 Critical</option>
        <option value="HIGH">🟠 High</option>
        <option value="MEDIUM">🟡 Medium</option>
        <option value="LOW">🟢 Low</option>
      </select>
      <button class="btn btn-secondary btn-sm" onclick="exportCSV()">⬇ Export CSV</button>
      <span class="count-label" id="findings-count"></span>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr>
          <th>Severity</th><th>Secret Type</th><th>Repo</th>
          <th>File Path</th><th>Line</th><th>Detected</th><th>Action</th>
        </tr></thead>
        <tbody id="findings-tbody"></tbody>
      </table>
    </div>
    <div class="pagination" id="findings-pager"></div>
  </div>

  <!-- ══ REPOS TAB ══ -->
  <div id="tab-repos" class="tab-panel">
    <div class="filters">
      <select id="repos-status" onchange="loadRepos()">
        <option value="">All Statuses</option>
        <option value="scanned">Scanned</option>
        <option value="error">Error</option>
        <option value="scanning">Scanning</option>
      </select>
      <span class="count-label" id="repos-count"></span>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr>
          <th>Status</th><th>Repository</th><th>Findings</th><th>Scanned At</th><th>Error</th>
        </tr></thead>
        <tbody id="repos-tbody"></tbody>
      </table>
    </div>
    <div class="pagination" id="repos-pager"></div>
  </div>

  <!-- ══ ANALYTICS TAB ══ -->
  <div id="tab-analytics" class="tab-panel">
    <div class="cards" id="analytics-cards"></div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-top:4px;">
      <div class="crawl-box">
        <h2>🔢 Top Secret Types</h2>
        <div class="bar-list" id="bar-types"></div>
      </div>
      <div class="crawl-box">
        <h2>🏆 Repos with Most Findings</h2>
        <div id="top-repos-list"></div>
      </div>
    </div>
  </div>
</main>
</div>

<!-- ══ Detail Modal ══ -->
<div class="overlay" id="detail-overlay" onclick="if(event.target===this)closeModal()">
  <div class="modal">
    <div class="modal-head">
      <h3 id="modal-title">Finding Details</h3>
      <button class="close-btn" onclick="closeModal()">✕</button>
    </div>
    <div class="modal-body" id="modal-body"></div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
// ── State ─────────────────────────────────────────────────────────────────────
let findingsPage=1, reposPage=1;
let pollTimer=null;

// ── Helpers ───────────────────────────────────────────────────────────────────
const $=id=>document.getElementById(id);
const esc=s=>(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
const fmtDate=s=>s?new Date(s+'Z').toLocaleString():'—';
function debounce(fn,ms){let t;return(...a)=>{clearTimeout(t);t=setTimeout(()=>fn(...a),ms);}}
function toast(msg,type='success'){
  const t=$('toast');t.textContent=msg;t.className='toast '+type+' show';
  setTimeout(()=>t.className='toast',2600);
}
function sevBadge(s){return`<span class="sev ${s}">${s}</span>`;}
function statusDot(s){return`<span class="status-dot ${s}"></span>`;}
function paginate(total,limit,page,loadFn,pagerId){
  const pages=Math.ceil(total/limit)||1;
  const p=$(pagerId);p.innerHTML='';
  if(pages<=1)return;
  for(let i=1;i<=pages;i++){
    const b=document.createElement('button');
    b.className='page-btn'+(i===page?' active':'');
    b.textContent=i;b.onclick=(()=>{const n=i;return()=>{loadFn(n);}})();
    p.appendChild(b);
  }
}

// ── Header stats ──────────────────────────────────────────────────────────────
async function loadHeaderStats(){
  const r=await fetch('/api/stats');
  const d=await r.json();
  const live=d.active_jobs>0;
  $('header-stats').innerHTML=`
    ${live?'<div class="stat-pill"><span class="dot"></span> '+d.active_jobs+' job(s) running</div>':''}
    <div class="stat-pill">📁 <b>${d.scanned_repos}</b> repos</div>
    <div class="stat-pill">🔐 <b>${d.total_findings}</b> secrets</div>
    <div class="stat-pill" style="color:var(--red)">🚨 <b>${d.critical}</b> critical</div>
  `;
  return d;
}

// ── Tabs ──────────────────────────────────────────────────────────────────────
function switchTab(name){
  document.querySelectorAll('.tab').forEach((t,i)=>{
    const names=['crawl','findings','repos','analytics'];
    t.classList.toggle('active',names[i]===name);
    $('tab-'+names[i]).classList.toggle('active',names[i]===name);
  });
  if(name==='findings')loadFindings();
  if(name==='repos')loadRepos();
  if(name==='analytics')loadAnalytics();
}

// ── Crawl ─────────────────────────────────────────────────────────────────────
function updatePlaceholder(){
  const type=$('crawl-type').value;
  const labels={user:'Username e.g. torvalds',org:'Org name e.g. microsoft',
    search:'Query e.g. "django hardcoded password"',single:'URL e.g. https://github.com/owner/repo'};
  $('query-label').textContent=type.charAt(0).toUpperCase()+type.slice(1);
  $('crawl-query').placeholder=labels[type]||'';
}

async function startCrawl(){
  const query=$('crawl-query').value.trim();
  if(!query){toast('Please enter a query','error');return;}
  const btn=$('crawl-btn');btn.disabled=true;btn.textContent='Starting…';
  const res=await fetch('/api/crawl',{
    method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({query,type:$('crawl-type').value,token:$('crawl-token').value.trim()||null})
  });
  const d=await res.json();
  btn.disabled=false;btn.textContent='Start Crawl';
  if(d.job_id){toast('Crawl job #'+d.job_id+' started!');startPolling();}
  else toast('Error: '+(d.error||'unknown'),'error');
}

function startPolling(){
  if(pollTimer)return;
  pollTimer=setInterval(()=>{
    loadJobs();loadHeaderStats();
  },2500);
}

async function loadJobs(){
  const r=await fetch('/api/jobs');
  const jobs=await r.json();
  const c=$('jobs-container');
  if(!jobs.length){c.innerHTML='<div class="empty"><div class="icon">🕷️</div>No crawl jobs yet. Start one above!</div>';return;}
  let anyRunning=false;
  c.innerHTML=jobs.map(j=>{
    const pct=j.repos_found?Math.round(j.repos_scanned/j.repos_found*100):0;
    if(j.status==='running')anyRunning=true;
    return`<div class="job-card">
      <div class="job-header">
        <span class="badge ${j.status}">${j.status}</span>
        <span style="font-weight:600">#${j.id}</span>
        <span style="color:var(--muted);font-size:.82rem">${j.query_type}: <b style="color:var(--text)">${esc(j.query)}</b></span>
        <span style="margin-left:auto;font-size:.8rem;color:var(--muted)">${fmtDate(j.started_at)}</span>
      </div>
      <div style="display:flex;gap:20px;font-size:.82rem;color:var(--muted);margin:4px 0;">
        <span>📂 ${j.repos_scanned}/${j.repos_found} repos</span>
        <span>🔐 ${j.findings_total} secrets found</span>
        ${j.status!=='running'?`<span>Finished: ${fmtDate(j.finished_at)}</span>`:''}
      </div>
      ${j.status==='running'?`<div class="progress"><div class="progress-bar" style="width:${pct}%"></div></div>`:''}
      ${j.log?`<div class="job-log">${esc(j.log.split('\\n').slice(-20).join('\\n'))}</div>`:''}
    </div>`;
  }).join('');
  if(!anyRunning&&pollTimer){clearInterval(pollTimer);pollTimer=null;}
}

// ── Findings ──────────────────────────────────────────────────────────────────
async function loadFindings(page){
  if(page!==undefined)findingsPage=page;
  const q=$('findings-search').value.trim();
  const sev=$('findings-severity').value;
  const params=new URLSearchParams({page:findingsPage,limit:50});
  if(q)params.append('q',q);
  if(sev)params.append('severity',sev);
  const r=await fetch('/api/findings?'+params);
  const d=await r.json();
  $('findings-count').textContent=`${d.total.toLocaleString()} finding(s)`;
  const tbody=$('findings-tbody');
  if(!d.findings.length){
    tbody.innerHTML='<tr><td colspan="7"><div class="empty"><div class="icon">🔒</div>No findings yet.</div></td></tr>';
    return;
  }
  tbody.innerHTML=d.findings.map(f=>`
    <tr>
      <td>${sevBadge(f.severity)}</td>
      <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
          title="${esc(f.secret_type)}">${esc(f.secret_type)}</td>
      <td><a class="link" href="${esc(f.repo_url)}" target="_blank"
          style="max-width:160px;display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
          title="${esc(f.repo_name)}">${esc(f.repo_name)}</a></td>
      <td class="truncate" title="${esc(f.file_path)}">${esc(f.file_path)}</td>
      <td>${f.line_number}</td>
      <td style="white-space:nowrap;font-size:.78rem;color:var(--muted)">${fmtDate(f.found_at)}</td>
      <td><button class="btn btn-secondary btn-sm" onclick="openFinding(${f.id})">View</button></td>
    </tr>`).join('');
  paginate(d.total,50,findingsPage,loadFindings,'findings-pager');
}

async function openFinding(id){
  const r=await fetch('/api/findings/'+id);
  const f=await r.json();
  $('modal-title').textContent=f.secret_type+' — '+f.file_name;
  $('modal-body').innerHTML=`
    <div class="meta-grid">
      <div class="meta-item"><div class="k">Severity</div><div class="v">${sevBadge(f.severity)}</div></div>
      <div class="meta-item"><div class="k">Secret Type</div><div class="v">${esc(f.secret_type)}</div></div>
      <div class="meta-item"><div class="k">Repository</div><div class="v">
        <a class="link" href="${esc(f.repo_url)}" target="_blank">${esc(f.repo_name)}</a></div></div>
      <div class="meta-item"><div class="k">File Path</div><div class="v">${esc(f.file_path)}</div></div>
      <div class="meta-item"><div class="k">Line Number</div><div class="v">${f.line_number}</div></div>
      <div class="meta-item"><div class="k">Found At</div><div class="v">${fmtDate(f.found_at)}</div></div>
    </div>
    <div class="section-title">🚨 Exposed Secret</div>
    <div class="secret-box">${esc(f.secret_value)}</div>
    ${f.context?`<div class="section-title">📋 Context (surrounding lines)</div>
    <pre class="code">${esc(f.context)}</pre>`:''}
    ${f.file_content?`<div class="section-title" style="margin-top:14px">📄 Full File Content</div>
    <pre class="code">${esc(f.file_content)}</pre>`:''}
  `;
  $('detail-overlay').classList.add('open');
}

function closeModal(){$('detail-overlay').classList.remove('open');}

// ── Repos ──────────────────────────────────────────────────────────────────────
async function loadRepos(page){
  if(page!==undefined)reposPage=page;
  const status=$('repos-status').value;
  const params=new URLSearchParams({page:reposPage,limit:50});
  if(status)params.append('status',status);
  const r=await fetch('/api/repos?'+params);
  const d=await r.json();
  $('repos-count').textContent=`${d.total.toLocaleString()} repo(s)`;
  const tbody=$('repos-tbody');
  if(!d.repos.length){
    tbody.innerHTML='<tr><td colspan="5"><div class="empty"><div class="icon">📁</div>No repos scanned yet.</div></td></tr>';
    return;
  }
  tbody.innerHTML=d.repos.map(r=>`
    <tr>
      <td>${statusDot(r.status)}${r.status}</td>
      <td><a class="link" href="${esc(r.url)}" target="_blank">${esc(r.name)}</a></td>
      <td>${r.findings_count>0
        ?`<b style="color:${r.findings_count>10?'var(--red)':'var(--yellow)'}">${r.findings_count}</b>`
        :'<span style="color:var(--green)">0 ✓</span>'}</td>
      <td style="font-size:.8rem;color:var(--muted)">${fmtDate(r.scanned_at)}</td>
      <td style="font-size:.78rem;color:var(--red);max-width:200px;overflow:hidden;
          text-overflow:ellipsis;white-space:nowrap" title="${esc(r.error_msg||'')}">${esc(r.error_msg||'')}</td>
    </tr>`).join('');
  paginate(d.total,50,reposPage,loadRepos,'repos-pager');
}

// ── Analytics ──────────────────────────────────────────────────────────────────
async function loadAnalytics(){
  const r=await fetch('/api/stats');
  const d=await r.json();
  $('analytics-cards').innerHTML=`
    <div class="card blue"><div class="label">Total Repos</div><div class="value">${d.total_repos}</div></div>
    <div class="card green"><div class="label">Scanned</div><div class="value">${d.scanned_repos}</div></div>
    <div class="card red"><div class="label">Critical</div><div class="value">${d.critical}</div></div>
    <div class="card orange"><div class="label">High</div><div class="value">${d.high}</div></div>
    <div class="card yellow"><div class="label">Total Findings</div><div class="value">${d.total_findings}</div></div>
    <div class="card blue"><div class="label">Active Jobs</div><div class="value">${d.active_jobs}</div></div>
  `;
  const maxType=d.top_types.length?d.top_types[0].cnt:1;
  $('bar-types').innerHTML=d.top_types.length
    ?d.top_types.map(t=>`
      <div class="bar-row">
        <div class="bar-label" title="${esc(t.secret_type)}">${esc(t.secret_type)}</div>
        <div class="bar-track"><div class="bar-fill" style="width:${Math.round(t.cnt/maxType*100)}%"></div></div>
        <div class="bar-count">${t.cnt}</div>
      </div>`).join('')
    :'<div class="empty" style="padding:20px 0">No findings yet</div>';
  $('top-repos-list').innerHTML=d.top_repos.length
    ?`<div class="bar-list">${d.top_repos.map(r=>`
      <div class="bar-row">
        <div class="bar-label"><a class="link" href="${esc(r.url)}" target="_blank"
          style="max-width:180px;display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
          title="${esc(r.name)}">${esc(r.name)}</a></div>
        <div class="bar-track"><div class="bar-fill" style="width:${Math.round(r.findings_count/d.top_repos[0].findings_count*100)}%"></div></div>
        <div class="bar-count">${r.findings_count}</div>
      </div>`).join('')}</div>`
    :'<div class="empty" style="padding:20px 0">No findings yet</div>';
}

function exportCSV(){window.location='/api/export/findings';}

// ── Init ──────────────────────────────────────────────────────────────────────
(async()=>{
  await loadHeaderStats();
  await loadJobs();
  updatePlaceholder();
  // auto-poll if running job exists
  const r=await fetch('/api/jobs');
  const jobs=await r.json();
  if(jobs.some(j=>j.status==='running'))startPolling();
  setInterval(loadHeaderStats,10000);
})();
</script>
</body>
</html>"""

# ── Entry point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    print("╔══════════════════════════════════════════════╗")
    print("║   GitHub Secret Crawler — Dashboard          ║")
    print("║   http://localhost:5000                      ║")
    print("╚══════════════════════════════════════════════╝")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
