import socket, threading, subprocess, sys

def _probe(ip, found, lock):
    try:
        with socket.create_connection((ip, 5050), timeout=0.6):
            with lock: found.append(ip)
    except Exception as e:
        print(f"{ip}:", e)
        pass

try:
    raw = subprocess.check_output(["hostname", "-I"], stderr=subprocess.DEVNULL).decode()
    local_ips = raw.split()
except Exception:
    local_ips = []

prefixes = set()
for addr in local_ips:
    parts = addr.strip().split(".")
    if len(parts) == 4:
        prefixes.add(".".join(parts[:3]))

# Always try common private /24 subnets as fallback
for fb in ("192.168.1", "192.168.0", "10.0.0", "172.16.0"):
    prefixes.add(fb)

found = []; lock = threading.Lock(); threads = []
for pfx in sorted(prefixes):
    for i in range(1, 255):
        t = threading.Thread(target=_probe, args=(f"{pfx}.{i}", found, lock), daemon=True)
        threads.append(t); t.start()
for t in threads: t.join()
print(found[0] if found else "", end="")
