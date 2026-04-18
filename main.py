from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from collections import defaultdict, deque
from sklearn.ensemble import IsolationForest
import numpy as np
import sqlite3, time, threading, joblib, os
import uvicorn

app = FastAPI(
    title="CRETA",
    description="Anomaly Detection & DDoS Protection Engine",
    version="2.0.0",
    docs_url=None,
    redoc_url=None,
)

templates = Jinja2Templates(directory="templates")

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5000", "http://localhost:5000"],
    allow_methods=["GET"],
    allow_headers=["*"],
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["127.0.0.1", "localhost", "*"],
)

WINDOW       = 10
BLOCK_SECS   = 60
TRAIN_EVERY  = 50
MODEL_PATH   = "creta_model.pkl"
EXEMPT_PATHS = {"/ui", "/api/dashboard", "/health", "/docs", "/openapi.json"}

request_log  = defaultdict(list)
traffic_hist = deque(maxlen=200)
model        = IsolationForest(contamination=0.05, random_state=42)
model_ready  = False
req_count    = 0
req_lock     = threading.Lock()

SUSPICIOUS_UA_PATTERNS = [
    "sqlmap", "nikto", "nmap", "masscan", "zgrab",
    "python-requests", "go-http-client", "curl", "wget",
    "hydra", "burpsuite", "dirbuster", "gobuster"
]

HONEYPOT_PATHS = {
    "/admin", "/wp-admin", "/phpmyadmin", "/.env",
    "/config", "/shell", "/cmd", "/passwd", "/.git"
}


def get_conn():
    conn = sqlite3.connect("creta.db", check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    conn = get_conn()
    conn.execute("""CREATE TABLE IF NOT EXISTS blocked_ips (
        ip         TEXT PRIMARY KEY,
        blocked_at REAL,
        reason     TEXT
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS event_log (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        ts         REAL,
        ip         TEXT,
        event      TEXT,
        score      REAL
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS request_audit (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        ts         REAL,
        ip         TEXT,
        path       TEXT,
        method     TEXT,
        status     INTEGER,
        ua         TEXT
    )""")
    conn.commit()
    conn.close()


init_db()


def load_model():
    global model, model_ready
    if os.path.exists(MODEL_PATH):
        try:
            model = joblib.load(MODEL_PATH)
            model_ready = True
            print(f"[CRETA] Model loaded from {MODEL_PATH}")
        except Exception as e:
            print(f"[CRETA] Model load failed: {e}")


load_model()


def get_real_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host or "unknown"


def is_suspicious_ua(ua: str) -> bool:
    if not ua:
        return True
    return any(pattern in ua.lower() for pattern in SUSPICIOUS_UA_PATTERNS)


def extract_features(ip: str) -> list:
    now   = time.time()
    times = [t for t in request_log[ip] if now - t < WINDOW]
    request_log[ip] = times

    req_per_sec = len(times) / WINDOW
    avg_gap     = WINDOW

    if len(times) >= 2:
        gaps    = [times[i+1] - times[i] for i in range(len(times) - 1)]
        avg_gap = sum(gaps) / len(gaps)

    hour = time.localtime().tm_hour / 23.0
    return [req_per_sec, avg_gap, hour, len(times)]


def cleanup_request_log():
    while True:
        time.sleep(30)
        now  = time.time()
        dead = [ip for ip, ts in list(request_log.items())
                if not any(now - t < WINDOW for t in ts)]
        for ip in dead:
            request_log.pop(ip, None)


threading.Thread(target=cleanup_request_log, daemon=True).start()


def train_model():
    global model, model_ready
    if len(traffic_hist) < 10:
        return
    X = np.array(list(traffic_hist))
    model.fit(X)
    model_ready = True
    joblib.dump(model, MODEL_PATH)
    print("[CRETA] Model retrained and saved.")


def is_blocked(ip: str) -> bool:
    conn = get_conn()
    row  = conn.execute(
        "SELECT blocked_at FROM blocked_ips WHERE ip=?", (ip,)
    ).fetchone()
    conn.close()
    if row:
        if time.time() - row[0] < BLOCK_SECS:
            return True
        unblock_ip(ip)
    return False


def block_ip(ip: str, reason: str):
    conn = get_conn()
    conn.execute(
        "INSERT OR REPLACE INTO blocked_ips VALUES (?,?,?)",
        (ip, time.time(), reason)
    )
    conn.execute(
        "INSERT INTO event_log(ts,ip,event,score) VALUES (?,?,?,?)",
        (time.time(), ip, f"BLOCKED: {reason}", 0)
    )
    conn.commit()
    conn.close()
    print(f"[CRETA] Blocked {ip} — {reason}")


def unblock_ip(ip: str):
    conn = get_conn()
    conn.execute("DELETE FROM blocked_ips WHERE ip=?", (ip,))
    conn.execute(
        "INSERT INTO event_log(ts,ip,event,score) VALUES (?,?,?,?)",
        (time.time(), ip, "AUTO-RECOVERED", 0)
    )
    conn.commit()
    conn.close()


def log_audit(ip: str, path: str, method: str, status_code: int, ua: str):
    try:
        conn = get_conn()
        conn.execute(
            "INSERT INTO request_audit(ts,ip,path,method,status,ua) VALUES (?,?,?,?,?,?)",
            (time.time(), ip, path, method, status_code, ua[:200] if ua else "")
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    global req_count

    ip   = get_real_ip(request)
    path = request.url.path
    ua   = request.headers.get("user-agent", "")

    if path in EXEMPT_PATHS:
        return await call_next(request)

    if path in HONEYPOT_PATHS:
        block_ip(ip, "Honeypot triggered")
        log_audit(ip, path, request.method, 403, ua)
        return JSONResponse(
            status_code=403,
            content={"status": "forbidden"},
            headers={"X-CRETA": "honeypot"}
        )

    ua_suspicious = is_suspicious_ua(ua)

    if is_blocked(ip):
        log_audit(ip, path, request.method, 429, ua)
        return JSONResponse(
            status_code=429,
            content={"status": "blocked", "retry_after": BLOCK_SECS},
            headers={"Retry-After": str(BLOCK_SECS), "X-CRETA": "blocked"}
        )

    with req_lock:
        req_count += 1

    request_log[ip].append(time.time())
    features = extract_features(ip)
    traffic_hist.append(features)

    if req_count % TRAIN_EVERY == 0:
        threading.Thread(target=train_model, daemon=True).start()

    if model_ready:
        score = model.decision_function([features])[0]
        pred  = model.predict([features])[0]
        if pred == -1 and score < -0.15:
            reason = "ML anomaly" + (" + suspicious UA" if ua_suspicious else "")
            block_ip(ip, reason)
            log_audit(ip, path, request.method, 429, ua)
            return JSONResponse(
                status_code=429,
                content={"status": "blocked", "reason": "anomaly"},
                headers={"X-CRETA": "ml-block"}
            )

    if features[0] > 5:
        block_ip(ip, "Rate exceeded")
        log_audit(ip, path, request.method, 429, ua)
        return JSONResponse(
            status_code=429,
            content={"status": "blocked", "reason": "rate_exceeded"},
            headers={"Retry-After": str(BLOCK_SECS), "X-CRETA": "rate-block"}
        )

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"]        = "DENY"
    response.headers["X-XSS-Protection"]       = "1; mode=block"
    response.headers["Referrer-Policy"]        = "no-referrer"
    response.headers["Cache-Control"]          = "no-store"

    log_audit(ip, path, request.method, response.status_code, ua)
    return response


@app.get("/ui", response_class=HTMLResponse)
async def ui_dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.get("/health")
async def health():
    return {"status": "ok", "model_active": model_ready, "uptime": time.time()}


@app.get("/api/dashboard")
async def dashboard():
    conn    = get_conn()
    blocked = conn.execute("SELECT * FROM blocked_ips").fetchall()
    logs    = conn.execute(
        "SELECT * FROM event_log ORDER BY ts DESC LIMIT 20"
    ).fetchall()
    audit   = conn.execute(
        "SELECT * FROM request_audit ORDER BY ts DESC LIMIT 50"
    ).fetchall()
    conn.close()

    return {
        "total_requests":    req_count,
        "currently_blocked": len(blocked),
        "model_active":      model_ready,
        "blocked_ips": [
            {"ip": r[0], "blocked_at": r[1], "reason": r[2]}
            for r in blocked
        ],
        "recent_log": [
            {"time": round(r[1], 1), "ip": r[2], "event": r[3]}
            for r in logs
        ],
        "audit_log": [
            {"ts": round(r[1], 1), "ip": r[2], "path": r[3],
             "method": r[4], "status": r[5], "ua": r[6]}
            for r in audit
        ]
    }


@app.get("/api/unblock/{ip}")
async def unblock(ip: str):
    unblock_ip(ip)
    return {"status": "unblocked", "ip": ip}


@app.get("/")
async def home(request: Request):
    return {"status": "ok", "timestamp": round(time.time(), 2)}


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=5000,
        reload=True,
        log_level="info",
    )