"""
CRETA Load Test — locustfile.py
Run: locust -f locustfile.py --host=http://127.0.0.1:8000 --headless -u 50 -r 10 -t 60s
Or open Locust UI: locust -f locustfile.py --host=http://127.0.0.1:8000
"""
from locust import HttpUser, task, between, constant
import random

ATTACKER_IPS = [
    "192.168.44.21", "10.0.112.7",  "203.0.113.55",
    "198.51.100.12", "172.16.0.3",  "45.33.32.156",
    "91.108.4.10",   "185.220.101.5","77.88.5.5",
    "1.2.3.4",       "5.6.7.8",     "9.10.11.12",
]

ATTACK_UAS = [
    "python-requests/2.31.0",
    "Go-http-client/1.1",
    "curl/7.88.1",
    "masscan/1.3",
    "locust-flood/1.0",
    "DDoS-Sim/2.0",
]

NORMAL_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
]

class NormalUser(HttpUser):
    weight       = 2
    wait_time    = between(1, 4)

    def on_start(self):
        self.ip = random.choice(ATTACKER_IPS[:4])
        self.ua = random.choice(NORMAL_UAS)

    def headers(self):
        return {"X-Forwarded-For": self.ip, "User-Agent": self.ua}

    @task(3)
    def visit_home(self):
        self.client.get("/", headers=self.headers(), name="Home")

    @task(2)
    def visit_about(self):
        self.client.get("/about", headers=self.headers(), name="About")

    @task(1)
    def api_call(self):
        self.client.get("/api/data", headers=self.headers(), name="API")


class VolumetricAttacker(HttpUser):
    weight    = 5
    wait_time = constant(0.05)   # 20 req/s per user

    def on_start(self):
        self.ip = random.choice(ATTACKER_IPS)
        self.ua = random.choice(ATTACK_UAS)

    def headers(self):
        return {
            "X-Forwarded-For": self.ip,
            "X-Real-IP":       self.ip,
            "User-Agent":      self.ua,
        }

    @task(5)
    def flood_home(self):
        self.client.get("/", headers=self.headers(), name="[ATTACK] Home flood")

    @task(3)
    def flood_api(self):
        self.client.get("/api/data", headers=self.headers(), name="[ATTACK] API flood")

    @task(1)
    def probe_honeypot(self):
        path = random.choice(["/admin","/wp-admin","/.env","/config","/.git"])
        self.client.get(path, headers=self.headers(), name="[ATTACK] Honeypot probe")


class HTTPFloodAttacker(HttpUser):
    weight    = 3
    wait_time = constant(0.1)

    def on_start(self):
        self.ip = random.choice(ATTACKER_IPS[4:])
        self.ua = random.choice(ATTACK_UAS)

    def headers(self):
        return {
            "X-Forwarded-For": self.ip,
            "User-Agent":      self.ua,
        }

    @task
    def flood_random(self):
        paths = ["/", "/about", "/api/data", "/login", "/search", "/users"]
        self.client.get(random.choice(paths), headers=self.headers(), name="[ATTACK] HTTP flood")
