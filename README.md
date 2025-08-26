# Juice Shop Lab — A07 Identification & Authentication Failures (with mini tool)

This repo demonstrates **OWASP A07: Identification & Authentication Failures** against a local **OWASP Juice Shop** lab, plus a tiny Python tool to reproduce findings. Three more OWASP areas are scoped for follow-up: **A04 Insecure Design**, **A06 Vulnerable & Outdated Components**, **A08 Software & Data Integrity Failures**.

---

## TL;DR (run in your own lab)

```bash
# 1) Start Juice Shop locally
docker run --rm -p 3000:3000 bkimminich/juice-shop

# 2) Install deps (Python 3.10+)
pip install -r authprobe-js/requirements.txt

# 3) Try login brute-force demo
python authprobe-js/authprobe.py --base http://127.0.0.1:3000 \
  --email test@example.com --wordlist authprobe-js/passwords.txt \
  --csv results.csv

