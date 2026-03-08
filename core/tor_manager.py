#!/usr/bin/env python3
# core/tor_manager.py

import socket, time, subprocess, threading, os

class TorManager:
    def __init__(self, log, rotate_every=25, socks_port=9050, ctrl_port=9051, password="m7hunter2"):
        self.log          = log
        self.rotate_every = rotate_every
        self.socks        = socks_port
        self.ctrl         = ctrl_port
        self.password     = password
        self.count        = 0
        self._lock        = threading.Lock()
        self._running     = False
        self.current_ip   = "unknown"

    def start(self):
        self.log.section("Tor IP Rotation")
        self._write_torrc()
        subprocess.run(["pkill", "-f", "tor.*m7hunter"], capture_output=True)
        time.sleep(1)
        subprocess.Popen(
            ["tor", "-f", "/tmp/torrc.m7hunter", "--runasdaemon", "1"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        # Wait up to 15s for Tor to bootstrap
        for _ in range(15):
            if self._port_open():
                self._running = True
                self.current_ip = self._get_ip()
                self.log.success(f"Tor ready | SOCKS5: 127.0.0.1:{self.socks} | Exit IP: {self.current_ip}")
                return
            time.sleep(1)
        self.log.warn("Tor didn't start in time — running without rotation")

    def _write_torrc(self):
        h = self._hash_pw()
        cfg = f"""SocksPort {self.socks}
ControlPort {self.ctrl}
HashedControlPassword {h}
DataDirectory /tmp/tor_m7hunter
"""
        with open("/tmp/torrc.m7hunter", "w") as f:
            f.write(cfg)

    def _hash_pw(self):
        r = subprocess.run(["tor","--hash-password", self.password], capture_output=True, text=True)
        for line in r.stdout.split("\n"):
            if line.startswith("16:"):
                return line.strip()
        return "16:E600ADC90A2E3F9D8F0A4D24BCFF62C8F6C1E9B3D2A1F0E9C8B7A6D5"

    def _port_open(self):
        try:
            s = socket.socket(); s.settimeout(2)
            s.connect(("127.0.0.1", self.socks)); s.close(); return True
        except: return False

    def _get_ip(self):
        try:
            r = subprocess.run(
                ["curl","-s","--socks5",f"127.0.0.1:{self.socks}",
                 "--connect-timeout","10","https://api.ipify.org"],
                capture_output=True, text=True, timeout=15
            )
            return r.stdout.strip() or "unknown"
        except: return "unknown"

    def rotate(self):
        try:
            s = socket.socket()
            s.connect(("127.0.0.1", self.ctrl))
            s.send(f'AUTHENTICATE "{self.password}"\r\n'.encode())
            time.sleep(0.3)
            s.send(b"SIGNAL NEWNYM\r\n")
            time.sleep(2)
            s.close()
            self.current_ip = self._get_ip()
            self.log.success(f"[TOR] New circuit — IP: {self.current_ip}")
        except Exception as e:
            self.log.warn(f"[TOR] Rotation failed: {e}")

    def tick(self):
        with self._lock:
            self.count += 1
            if self.count % self.rotate_every == 0:
                self.log.info(f"[TOR] {self.count} requests — rotating IP...")
                self.rotate()

    def is_running(self): return self._running
    def proxy_url(self):  return f"socks5://127.0.0.1:{self.socks}"
    def proxychains(self):return ["proxychains4", "-q"]

    def stop(self):
        subprocess.run(["pkill","-f","tor.*m7hunter"], capture_output=True)
        self.log.info("[TOR] Stopped")
