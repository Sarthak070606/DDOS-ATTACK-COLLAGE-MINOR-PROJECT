import threading
import requests
import time
import random

TARGET = "http://127.0.0.1:5000/"

# Fake attacker IPs — spoofed via X-Forwarded-For header
FAKE_IPS = [
    "192.168.1.10",
    "192.168.1.20", 
    "192.168.1.30",
    "10.0.0.5",
    "10.0.0.6",
    "172.16.0.1",
    "172.16.0.2",
    "203.0.113.1",
    "203.0.113.2",
    "198.51.100.1",
]

def attacker(fake_ip, uid):
    """Simulates a DDoS attacker from a specific IP"""
    headers = {
        "X-Forwarded-For": fake_ip,
        "User-Agent": f"attacker-bot/{uid}"
    }
    blocked_count = 0
    for i in range(100):
        try:
            r = requests.get(TARGET, headers=headers, timeout=2)
            status = r.status_code
            if status in (429, 403):
                blocked_count += 1
                print(f"[BLOCKED] IP={fake_ip} req={i+1} status={status}")
                time.sleep(0.1)
            else:
                print(f"[OK]      IP={fake_ip} req={i+1}")
            time.sleep(0.05)  # 20 req/sec per attacker
        except Exception as e:
            print(f"[ERROR]   IP={fake_ip} — {e}")

def normal_user(fake_ip):
    """Simulates a normal slow user"""
    headers = {
        "X-Forwarded-For": fake_ip,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    }
    for i in range(10):
        try:
            r = requests.get(TARGET, headers=headers, timeout=2)
            print(f"[NORMAL]  IP={fake_ip} req={i+1} status={r.status_code}")
            time.sleep(1.5)
        except Exception as e:
            print(f"[ERROR]   IP={fake_ip} — {e}")

# ── LAUNCH ────────────────────────────────────────────────
print("=" * 50)
print("  CRETA Multi-IP Attack Simulation")
print("=" * 50)

print("\n[*] Starting normal users...")
normal_ips = ["10.10.10.1", "10.10.10.2", "10.10.10.3"]
for ip in normal_ips:
    threading.Thread(target=normal_user, args=(ip,), daemon=True).start()

time.sleep(2)

print("\n[*] Starting attackers from multiple IPs...")
for i, ip in enumerate(FAKE_IPS):
    threading.Thread(target=attacker, args=(ip, i), daemon=True).start()
    time.sleep(0.2)  # stagger launch slightly

print("\n[*] Attack running — watch the dashboard!")
print("[*] Press Ctrl+C to stop\n")

# Keep main thread alive
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\n[*] Simulation stopped.")