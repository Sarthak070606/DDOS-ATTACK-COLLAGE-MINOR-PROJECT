from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from collections import defaultdict, deque
from sklearn.ensemble import IsolationForest
import numpy as np
import sqlite3, time, threading, joblib, os, asyncio, json
import uvicorn

app = FastAPI(title="CRETA", version="3.0.0", docs_url=None, redoc_url=None)
templates = Jinja2Templates(directory="templates")

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

WINDOW       = 10
BLOCK_SECS   = 60
TRAIN_EVERY  = 30
MODEL_PATH   = "creta_model.pkl"
EXEMPT_PATHS = {"/ui", "/api/dashboard", "/api/unblock", "/health", "/metrics/stream"}

HONEYPOT_PATHS = {"/admin", "/wp-admin", "/phpmyadmin", "/.env", "/config", "/shell", "/.git", "/passwd"}

SUSPICIOUS_UA = ["sqlmap","nikto","nmap","masscan","zgrab","python-requests",
                 "go-http-client","curl","wget","hydra","burpsuite","locust"]

request_log  = defaultdict(list)
traffic_hist = deque(maxlen=500)
model        = IsolationForest(contamination=0.05, random_state=42)
model_ready  = False
req_count    = 0
req_lock     = threading.Lock()

live_metrics = {
    "total_requests": 0,
    "total_blocked": 0,
    "total_passed": 0,
    "total_honeypot": 0,
    "ml_blocks": 0,
    "rate_blocks": 0,
    "honeypot_blocks": 0,
    "rps_history": deque(maxlen=60),   # last 60s
    "block_history": deque(maxlen=60),
    "recent_events": deque(maxlen=50),
    "lock": threading.Lock(),
}

rps_counter  = 0
rps_timer    = time.time()

def get_conn():
    conn = sqlite3.connect("creta.db", check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    conn = get_conn()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS blocked_ips (
        ip TEXT PRIMARY KEY, blocked_at REAL, reason TEXT
    );
    CREATE TABLE IF NOT EXISTS event_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL, ip TEXT, event TEXT, score REAL
    );
    CREATE TABLE IF NOT EXISTS request_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL, ip TEXT, path TEXT, method TEXT, status INTEGER, ua TEXT
    );
    """)
    conn.commit(); conn.close()

init_db()

def load_model():
    global model, model_ready
    if os.path.exists(MODEL_PATH):
        try:
            model = joblib.load(MODEL_PATH)
            model_ready = True
            print(f"[CRETA] Model loaded")
        except: pass

load_model()

def train_model():
    global model, model_ready
    if len(traffic_hist) < 20: return
    X = np.array(list(traffic_hist))
    model.fit(X)
    model_ready = True
    joblib.dump(model, MODEL_PATH)
    print("[CRETA] Model retrained")


def get_real_ip(request: Request) -> str:
    fwd = request.headers.get("X-Forwarded-For")
    if fwd: return fwd.split(",")[0].strip()
    return request.client.host or "unknown"

def is_suspicious_ua(ua: str) -> bool:
    if not ua: return True
    return any(p in ua.lower() for p in SUSPICIOUS_UA)

def extract_features(ip: str) -> list:
    now   = time.time()
    times = [t for t in request_log[ip] if now - t < WINDOW]
    request_log[ip] = times
    rps     = len(times) / WINDOW
    avg_gap = WINDOW
    if len(times) >= 2:
        gaps    = [times[i+1]-times[i] for i in range(len(times)-1)]
        avg_gap = sum(gaps)/len(gaps)
    hour = time.localtime().tm_hour / 23.0
    return [rps, avg_gap, hour, len(times)]

def is_blocked(ip: str) -> bool:
    conn = get_conn()
    row  = conn.execute("SELECT blocked_at FROM blocked_ips WHERE ip=?", (ip,)).fetchone()
    conn.close()
    if row:
        if time.time() - row[0] < BLOCK_SECS: return True
        unblock_ip(ip)
    return False

def block_ip(ip: str, reason: str):
    conn = get_conn()
    conn.execute("INSERT OR REPLACE INTO blocked_ips VALUES (?,?,?)", (ip, time.time(), reason))
    conn.execute("INSERT INTO event_log(ts,ip,event,score) VALUES (?,?,?,?)",
                 (time.time(), ip, f"BLOCKED: {reason}", 0))
    conn.commit(); conn.close()
    with live_metrics["lock"]:
        live_metrics["total_blocked"] += 1
        live_metrics["recent_events"].appendleft({
            "ts": round(time.time(),2), "ip": ip,
            "event": f"BLOCKED: {reason}", "type": "block"
        })
    print(f"[CRETA] Blocked {ip} — {reason}")

def unblock_ip(ip: str):
    conn = get_conn()
    conn.execute("DELETE FROM blocked_ips WHERE ip=?", (ip,))
    conn.execute("INSERT INTO event_log(ts,ip,event,score) VALUES (?,?,?,?)",
                 (time.time(), ip, "AUTO-RECOVERED", 0))
    conn.commit(); conn.close()

def log_audit(ip, path, method, status, ua):
    try:
        conn = get_conn()
        conn.execute("INSERT INTO request_audit(ts,ip,path,method,status,ua) VALUES (?,?,?,?,?,?)",
                     (time.time(), ip, path, method, status, (ua or "")[:200]))
        conn.commit(); conn.close()
    except: pass

def rps_tracker():
    global rps_counter, rps_timer
    while True:
        time.sleep(1)
        now = time.time()
        with live_metrics["lock"]:
            live_metrics["rps_history"].append(rps_counter)
            live_metrics["block_history"].append(live_metrics["total_blocked"])
        rps_counter = 0

threading.Thread(target=rps_tracker, daemon=True).start()

def cleanup_log():
    while True:
        time.sleep(30)
        now  = time.time()
        dead = [ip for ip, ts in list(request_log.items())
                if not any(now-t < WINDOW for t in ts)]
        for ip in dead: request_log.pop(ip, None)

threading.Thread(target=cleanup_log, daemon=True).start()


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    global req_count, rps_counter

    ip   = get_real_ip(request)
    path = request.url.path
    ua   = request.headers.get("user-agent", "")

    for exempt in EXEMPT_PATHS:
        if path.startswith(exempt):
            return await call_next(request)

    if path in HONEYPOT_PATHS:
        block_ip(ip, "Honeypot triggered")
        with live_metrics["lock"]:
            live_metrics["total_honeypot"] += 1
            live_metrics["honeypot_blocks"] += 1
        log_audit(ip, path, request.method, 403, ua)
        return JSONResponse(status_code=403,
                            content={"status": "forbidden"},
                            headers={"X-CRETA": "honeypot"})

    if is_blocked(ip):
        log_audit(ip, path, request.method, 429, ua)
        return JSONResponse(status_code=429,
                            content={"status": "blocked", "retry_after": BLOCK_SECS},
                            headers={"Retry-After": str(BLOCK_SECS), "X-CRETA": "blocked"})

    with req_lock:
        req_count   += 1
        rps_counter += 1
    with live_metrics["lock"]:
        live_metrics["total_requests"] += 1

    request_log[ip].append(time.time())
    features = extract_features(ip)
    traffic_hist.append(features)

    if req_count % TRAIN_EVERY == 0:
        threading.Thread(target=train_model, daemon=True).start()

    if model_ready:
        score = model.decision_function([features])[0]
        pred  = model.predict([features])[0]
        if pred == -1 and score < -0.15:
            reason = "ML anomaly" + (" + suspicious UA" if is_suspicious_ua(ua) else "")
            block_ip(ip, reason)
            with live_metrics["lock"]:
                live_metrics["ml_blocks"] += 1
            log_audit(ip, path, request.method, 429, ua)
            return JSONResponse(status_code=429,
                                content={"status": "blocked", "reason": "anomaly"},
                                headers={"X-CRETA": "ml-block"})

    if features[0] > 5:
        block_ip(ip, "Rate exceeded")
        with live_metrics["lock"]:
            live_metrics["rate_blocks"] += 1
        log_audit(ip, path, request.method, 429, ua)
        return JSONResponse(status_code=429,
                            content={"status": "blocked", "reason": "rate_exceeded"},
                            headers={"Retry-After": str(BLOCK_SECS), "X-CRETA": "rate-block"})

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"]        = "DENY"
    response.headers["X-CRETA"]                = "passed"

    with live_metrics["lock"]:
        live_metrics["total_passed"] += 1
        live_metrics["recent_events"].appendleft({
            "ts": round(time.time(),2), "ip": ip,
            "event": f"PASSED: {path}", "type": "ok"
        })

    log_audit(ip, path, request.method, response.status_code, ua)
    return response

@app.get("/", response_class=HTMLResponse)
async def target_site(request: Request):
    """This is the TARGET website that Locust attacks"""
    return HTMLResponse(content=open("templates/target.html").read())

@app.get("/about", response_class=HTMLResponse)
async def about(request: Request):
    return HTMLResponse("<h1>About Page</h1><p>Target page 2</p>")

@app.get("/api/data")
async def api_data():
    return {"data": "some response", "ts": time.time()}

@app.get("/ui", response_class=HTMLResponse)
async def dashboard(request: Request):
    return HTMLResponse(content=open("templates/dashboard.html").read())

@app.get("/health")
async def health():
    return {"status": "ok", "model_active": model_ready, "uptime": time.time()}

@app.get("/api/dashboard")
async def api_dashboard():
    conn    = get_conn()
    blocked = conn.execute("SELECT * FROM blocked_ips ORDER BY blocked_at DESC").fetchall()
    logs    = conn.execute("SELECT * FROM event_log ORDER BY ts DESC LIMIT 30").fetchall()
    audit   = conn.execute("SELECT * FROM request_audit ORDER BY ts DESC LIMIT 100").fetchall()
    conn.close()

    with live_metrics["lock"]:
        m = dict(live_metrics)
        rps_hist   = list(m["rps_history"])
        blk_hist   = list(m["block_history"])
        events     = list(m["recent_events"])

    return {
        "total_requests":   req_count,
        "total_blocked":    m["total_blocked"],
        "total_passed":     m["total_passed"],
        "ml_blocks":        m["ml_blocks"],
        "rate_blocks":      m["rate_blocks"],
        "honeypot_blocks":  m["honeypot_blocks"],
        "model_active":     model_ready,
        "currently_blocked": len(blocked),
        "rps_history":      rps_hist,
        "block_history":    blk_hist,
        "recent_events":    events[:20],
        "blocked_ips": [
            {"ip": r[0], "blocked_at": r[1], "reason": r[2],
             "expires_in": max(0, int(BLOCK_SECS - (time.time()-r[1])))}
            for r in blocked
        ],
        "audit_log": [
            {"ts": round(r[1],1), "ip": r[2], "path": r[3],
             "method": r[4], "status": r[5], "ua": (r[6] or "")[:60]}
            for r in audit
        ],
    }

@app.get("/api/unblock/{ip}")
async def unblock(ip: str):
    unblock_ip(ip)
    return {"status": "unblocked", "ip": ip}

@app.get("/api/reset")
async def reset_stats():
    global req_count
    conn = get_conn()
    conn.execute("DELETE FROM blocked_ips")
    conn.execute("DELETE FROM event_log")
    conn.execute("DELETE FROM request_audit")
    conn.commit(); conn.close()
    req_count = 0
    with live_metrics["lock"]:
        live_metrics.update({
            "total_requests":0,"total_blocked":0,"total_passed":0,
            "total_honeypot":0,"ml_blocks":0,"rate_blocks":0,"honeypot_blocks":0
        })
        live_metrics["rps_history"].clear()
        live_metrics["block_history"].clear()
        live_metrics["recent_events"].clear()
    return {"status": "reset"}

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=False, log_level="warning")
