# AuthProbe-JS — A07 Demo (Juice Shop)

A small educational tool and workflow to demonstrate **Identification & Authentication Failures** (OWASP Top 10) against **OWASP Juice Shop** in a contained lab.

> ⚠️ For **lab use only**. Do not use against systems you do not own or without written permission.

## What this repo contains
- `authprobe.py` — a simple login brute-force script for Juice Shop
- `passwords.txt` — tiny sample wordlist for demos
- `SCOPING.md` — scoping assessment (filled for Juice Shop lab)
- `PENTEST_PLAN.md` — penetration testing plan focused on A07
- `requirements.txt` — Python deps (`requests`)
- `.gitignore`

## Quick start
1. Run Juice Shop locally:
   ```bash
   docker run --rm -p 3000:3000 bkimminich/juice-shop
   ```

2. (Optional) Route through Burp to capture evidence:
   - Burp → Proxy → Proxy listeners: `127.0.0.1:8080` running
   - Browser → HTTP proxy `127.0.0.1:8080`

3. Install Python deps:
   ```bash
   pip3 install -r requirements.txt
   ```

4. Create a **test** user in Juice Shop (e.g., `test1@example.com`).

5. Run AuthProbe-JS:
   ```bash
   python3 authprobe.py --base http://127.0.0.1:3000      --email test1@example.com      --wordlist passwords.txt      --burp http://127.0.0.1:8080      --delay 0.1      --csv results.csv
   ```

- Exit code `0` = hit found, token printed (truncated).  
- Exit code `1` = no hit.

## Evidence to capture
- Burp **HTTP history** & **Intruder** results (if you use Burp too)
- Terminal output from `authprobe.py` showing success
- Optional: `GET /rest/user/whoami` in Burp Repeater with the token

## Ethics
Educational use only, inside a self-hosted lab. Follow your institution’s policy and laws.
