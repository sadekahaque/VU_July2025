This guide shows you **exactly** how to run your security lab on Windows using **Docker + OWASP Juice Shop + Burp Suite + Security Lab UI** —  Follow this step-by-step.


## ✅ What we’ll need

- **Windows 10/11** with **PowerShell**
- **Python 3.11+** (3.12 works)
- **Docker Desktop** (running)
- **Burp Suite Community** (or Professional)
- **Firefox** (recommended) or Chrome/Edge
- Your project folder (example):  
  `D:\cyber\VU_July2025\authprobe-js` containing:
  - `security_lab_ui.py` (the UI file)
  - `a06_scanner.py`, `a07_authprobe.py`, `kba_probe.py`, `a08_integrity.py`, `a04_insecure.py`
  - any wordlists/templates you plan to use

---

## 🚀 Quick Start (copy/paste)

Open **PowerShell**, then run these commands (change the path if needed):

```powershell
cd "D:\cyber\VU_July2025\authprobe-js"


# (1) Create and activate venv
python -m venv .venv
.\.venv\Scripts\activate.bat   # or:  Set-ExecutionPolicy -Scope Process Bypass; .\.venv\Scripts\Activate.ps1

# (2) Install Python deps (once)
pip install streamlit requests pyjwt

# (3) Start OWASP Juice Shop in Docker (keep this console open)
docker run --rm -p 3000:3000 bkimminich/juice-shop
````

Open **a second PowerShell** window for the proxy + UI steps below.

---

## 🌐 Configure Burp & Browser Proxy

1. Start **Burp Suite**, set **Proxy → Intercept: OFF**.

2. Configure your browser to send traffic through Burp (port **8080**):

   **Firefox** → *Settings* → *Network Settings* → **Manual proxy**:

   * HTTP Proxy: `127.0.0.1`
   * Port: `8080`
   * ✅ Tick “Use this proxy server for all protocols”
   * **No Proxy for**: `localhost, 127.0.0.1` (keeps Streamlit UI local & fast)

3. In the browser, visit **[http://127.0.0.1:3000](http://127.0.0.1:3000)** — you should see Juice Shop loading through Burp.

> Tip: For HTTPS targets, you’d import Burp’s CA cert into the browser. Juice Shop runs on HTTP, so you can skip that here.

---

## 🖥️ Run the Streamlit UI

In **second PowerShell** window:

```powershell
cd "D:\cyber\VU_July2025\authprobe-js"
.\.venv\Scripts\activate.bat
streamlit run security_lab_ui.py
```

Open browser to **[http://localhost:8501](http://localhost:8501)**. and see tabs for each tool:

* **A06** Vulnerable/Outdated Components (Trivy wrapper)
* **A07** Login brute-force (AuthProbe-JS) — lab use only
* **A07** / Security Questions Probe
* **A08** Integrity: **SRI** & **JWT** checks
* **A04** Insecure Design: Basket quantity/price

Each tab explains inputs and runs 

---

## 🧭 What each tab/tool does 

### A04 — *Insecure Design*

**What it means:** Design flaws in workflows or authorization that allow actions the user shouldn’t perform (e.g., updating basket quantities/prices without proper checks).
**What this tool checks:** Attempts to set basket **quantities** (and optionally **prices** — usually requires elevated privileges) for one or more product IDs.

**UI usage:** Enter Base URL, your **own** user’s email/password (register in Juice Shop), product IDs and quantities, then **Run**.
**Example CLI (PowerShell):**

```powershell
.\.venv\Scripts\python.exe insecure.py `
  --base http://127.0.0.1:3000 `
  --email you@example.com `
  --password YourPassword123 `
  --product 1 6 `
  --quantity 2 `
  --timeout 15 `
  --burp http://127.0.0.1:8080

# Optional (admin scenarios only):
# --price 0.01  (broadcasts if one value is given)
# --basket 5    (target a specific basket ID)
```

---

### A06 — *Vulnerable & Outdated Components*

**What it means:** Using dependencies with known CVEs (Common Vulnerabilities and Exposures).
**What this tool checks:** Scans a container image (default: Juice Shop) and reports **CRITICAL/HIGH** findings.

**UI usage:** Choose image (e.g., `bkimminich/juice-shop:latest`), pick severities, click **Run**, download CSV.
**Example CLI (PowerShell):**

```powershell
.\.venv\Scripts\python.exe a06_scanner.py `
  --image bkimminich/juice-shop:latest `
  --severity CRITICAL,HIGH `
  --csv a06_results.csv
```

---

### A07 — *Identification & Authentication Failures*

**What it means:** Weak login protections, missing rate limits, default/guessable passwords, etc.
**What this tool does:** Attempts **login brute-force** in a controlled lab to illustrate risks (respect rate limits & ethics).

> **Only use with test accounts you created in Juice Shop.**

**UI usage:** Provide base URL, target **email** (your own test user), a **wordlist**, optional delay & CSV logging.
**Example CLI (PowerShell):**

```powershell
.\.venv\Scripts\python.exe authprobe.py `
  --base http://127.0.0.1:3000 `
  --email testuser@example.com `
  --wordlist .\passwords.txt `
  --delay 0.2 `
  --max 100 `
  --timeout 10 `
  --burp http://127.0.0.1:8080 `
  --csv attempts.csv
```
---
### KBA — *Knowledge-Based Authentication* Probe (Security Questions)

**What it means:** Password reset or verification flows that rely on guessable personal info.
**What this tool does:** Sends answers from a list to a captured **reset** endpoint, looking for success keywords.

**UI usage:** Fill Base URL, **endpoint** captured from Burp (e.g., `/rest/path`), choose method (**POST/PUT**), provide a **JSON template** (with `{ANSWER}` and optional `{EMAIL}`), and an **answers file** (one per line).
**Example CLI (PowerShell):**

```powershell
.\.venv\Scripts\python.exe kba_probe.py `
  --base http://127.0.0.1:3000 `
  --endpoint /rest/PUT_YOUR_ENDPOINT_HERE `
  --method POST `
  --template .\template.json `
  --answers .\answers.txt `
  --email you@example.com `
  --success-text "reset,token,success,new password" `
  --timeout 15 `
  --delay 0.1 `
  --max 0 `
  --burp http://127.0.0.1:8080
```

> **Important:** Always obtain the endpoint & JSON structure from **your own Burp capture** in the lab. Do **not** attack real password reset endpoints.


---

### A08 — *Software & Data Integrity Failures* (SRI + JWT)

**What it means:** Missing integrity controls for code/data; weak token signing/verification.

**Two modes:**

1. **SRI scan** — checks if external `<script>`/`<link>` assets include **Subresource Integrity** (`integrity=`) and if the `crossorigin` policy is correct.
2. **JWT integrity** — signs/validates authentication tokens; looks for **`alg: none`** or weak HMAC secrets (lab demonstration).

**UI usage:** Pick **SRI scan** or **JWT integrity**, fill inputs, **Run**.
**Example CLI (PowerShell):**

```powershell
# SRI
.\.venv\Scripts\python.exe a08_integrity.py sri `
  --base http://127.0.0.1:3000 `
  --timeout 15 `
  --out a08_sri_findings.json `
  --burp http://127.0.0.1:8080

# JWT
.\.venv\Scripts\python.exe a08_integrity.py jwt `
  --base http://127.0.0.1:3000 `
  --email you@example.com `
  --password YourPassword123 `
  --timeout 15 `
  --words secret,123456 `
  --wordlist .\secrets.txt `
  --burp http://127.0.0.1:8080
```

---

## 📁 Suggested Folder Layout

```
authprobe-js/
├─ security_lab_ui.py
├─ a06_scanner.py
├─ authprobe.py
├─ a08_integrity.py
├─ insecure.py
├─ kba_probe.py
├─ passwords.txt         # example wordlist (you supply)
├─ secrets.txt           # optional JWT HMAC wordlist
├─ template.json         # KBA JSON body with {ANSWER}, optional {EMAIL}
├─ answers.txt           # KBA answers list (one per line)
└─ a06_results.csv       # output files get created here
```

---

## 📝 Evidence & Reporting

* **A06** tab → **Download CSV** for findings.
* **A08 (SRI)** tab → JSON findings file.
* Copy **stdout/stderr** from the UI after each run into your report.
* Add **screenshots** of Burp proxy, Juice Shop pages, and the Streamlit tabs/results.

---

## 🧰 Troubleshooting

* **Port already in use (3000 or 8501)**
  Stop the other app or change the port. For 3000:

  ```powershell
  netstat -ano | findstr :3000
  taskkill /F /PID <PID>
  ```

* **PowerShell won’t activate venv** (`running scripts is disabled`)

  ```powershell
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
  .\.venv\Scripts\Activate.ps1
  # or simply use:
  .\.venv\Scripts\activate.bat
  ```

* **Burp not seeing traffic**

  * Check browser proxy is 127.0.0.1:8080 and **Intercept is OFF**.
  * Visit: `http://127.0.0.1:3000` (not https).
  * Proxy exclusions include `127.0.0.1, localhost` (so Streamlit UI stays fast).

* **Duplicate widget ID in Streamlit**
  Already fixed: every widget now has a unique `key=`.

---

## 🔒 Good Practice (Lab-only!)

* Create your own **test user(s)** in Juice Shop. Do not target real accounts.
* Use reasonable **delays** in A07/A08/KBA to simulate rate limiting.
* Document what you tested and how you verified results.

---

## 📎 Optional: one-click launcher script (Windows)

Create a file called **`run_ui.ps1`** in the project folder with:

```powershell
cd "$PSScriptRoot"
if (-not (Test-Path .\.venv)) {
  python -m venv .venv
}
.\.venv\Scripts\activate.bat
pip install --upgrade streamlit requests pyjwt
Start-Process powershell -ArgumentList 'docker run --rm -p 3000:3000 bkimminich/juice-shop' -NoNewWindow
Start-Sleep -Seconds 3
streamlit run security_lab_ui.py
```

Run it by right-click → **Run with PowerShell** (or run from a PowerShell window).

---


