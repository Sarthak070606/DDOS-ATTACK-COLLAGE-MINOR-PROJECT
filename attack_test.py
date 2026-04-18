import threading
import requests
import time

TARGET = "http://127.0.0.1:5000/"

def normal_user(uid):
    """Simulates a normal user - slow requests"""
    for i in range(5):
        try:
            r = requests.get(TARGET)
            print(f"[NORMAL-{uid}] {r.json()}")
            time.sleep(2)
        except Exception as e:
            print(f"[NORMAL-{uid}] Error: {e}")

def attacker(uid):
    """Simulates a DDoS attacker - rapid fire"""
    for i in range(50):
        try:
            r = requests.get(TARGET)
            print(f"[ATTACK-{uid}] {r.status_code} - {r.json()}")
            time.sleep(0.05)  # 20 req/sec
        except Exception as e:
            print(f"[ATTACK-{uid}] Error: {e}")

print("=== Starting Normal Traffic ===")
for i in range(3):
    threading.Thread(target=normal_user, args=(i,), daemon=True).start()

time.sleep(3)

print("\n=== Starting DDoS Attack ===")
for i in range(5):
    threading.Thread(target=attacker, args=(i,), daemon=True).start()

time.sleep(30)
print("\n=== Test Complete - Check Dashboard ===")