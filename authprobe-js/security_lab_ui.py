import os, sys, subprocess, json, tempfile, shlex
import streamlit as st

st.set_page_config(page_title="Security Lab", layout="wide")

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

def run_script(script_path, args_list):
    cmd = [sys.executable, script_path] + args_list
    st.code(" ".join(shlex.quote(c) for c in cmd), language="bash")
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True)
        out = cp.stdout or ""
        err = cp.stderr or ""
        if out:
            st.subheader("Output")
            st.code(out)
        if err:
            st.subheader("Errors / Diagnostics")
            st.code(err)
        st.success(f"Exit code: {cp.returncode}")
    except Exception as e:
        st.error(f"Failed to run script: {e}")

st.title("Security Lab")

with st.expander("Environment quick tips", expanded=False):
    st.markdown("""
- Ensure **Docker Desktop** (or Docker Engine) is running for tools that use containers (A06).
- Start **OWASP Juice Shop** (e.g., `docker run --rm -p 3000:3000 bkimminich/juice-shop`).
- Optional: start **Burp Suite** and set proxy like `http://127.0.0.1:8080` (Intercept OFF).
""")

tab_a06, tab_authkba, tab_a08, tab_a04, tab_idor = st.tabs([
    "A06 Vulnerable/Outdated Components",
    "Auth & KBA",
    "A08 Integrity: SRI & JWT",
    "A04 Insecure Design: Basket Qty/Price",
    "IDOR Probe"
])

# ---------- A06 (a06_scanner.py) ----------
with tab_a06:
    st.header("A06: Trivy wrapper via Docker")
    image = st.text_input("Image to scan (e.g., bkimminich/juice-shop:latest)", value="bkimminich/juice-shop:latest", key="a06_image")
    severity = st.text_input("Severities (comma-separated)", value="CRITICAL,HIGH", key="a06_severity")
    out_csv = st.text_input("Output CSV filename", value="a06_results.csv", key="a06_outcsv")
    use_tar = st.checkbox("Scan from a saved TAR instead of registry/socket?", key="a06_usetar")
    tar_path = st.text_input("Path to image tar (only if checked)", value="", key="a06_tarpath")
    script = os.path.join(BASE_DIR, "a06_scanner.py")
    if st.button("Run A06 Scan", key="a06_run"):
        args = ["--severity", severity, "--csv", out_csv]
        if use_tar and tar_path.strip():
            args += ["--tar", tar_path.strip()]
        else:
            args += ["--image", image]
        run_script(script, args)
        out_path = os.path.join(BASE_DIR, out_csv)
        if os.path.exists(out_path):
            with open(out_path, "rb") as f:
                st.download_button("Download CSV", f, file_name=out_csv, mime="text/csv", key="a06_dl")

# ---------- Auth & KBA combined tab ----------
with tab_authkba:
    st.header("Authentication & KBA (lab only)")

    if "auth_mode" not in st.session_state:
        st.session_state["auth_mode"] = "login"

    col1, col2 = st.columns(2)
    with col1:
        if st.button("Login brute-force", type="primary", key="auth_btn_login"):
            st.session_state["auth_mode"] = "login"
    with col2:
        if st.button("KBA probe", key="auth_btn_kba"):
            st.session_state["auth_mode"] = "kba"

    st.divider()

    # ---------- A07 (authprobe.py) UI ----------
    if st.session_state["auth_mode"] == "login":
        st.subheader("A07: Login brute-force demo")
        base = st.text_input("Base URL", value="http://127.0.0.1:3000", key="auth_login_base")
        email = st.text_input("Target Email (test/lab account)", key="auth_login_email")
        wordlist = st.text_input("Wordlist path", value="passwords.txt", key="auth_login_wordlist")
        burp = st.text_input("Burp proxy (optional)", value="", key="auth_login_burp")
        delay = st.number_input("Delay between attempts (seconds)", value=0.0, min_value=0.0, step=0.1, key="auth_login_delay")
        max_attempts = st.number_input("Max attempts (0 = all)", value=0, min_value=0, step=1, key="auth_login_max")
        timeout = st.number_input("HTTP timeout (seconds)", value=10.0, min_value=1.0, step=1.0, key="auth_login_timeout")
        verbose = st.checkbox("Verbose output", key="auth_login_verbose")
        csv_out = st.text_input("Save attempt log to CSV (optional)", value="", key="auth_login_csv")
        script = os.path.join(BASE_DIR, "authprobe.py")
        if st.button("Run AuthProbe", key="auth_login_run"):
            args = ["--base", base, "--email", email, "--wordlist", wordlist,
                    "--delay", str(delay), "--max", str(max_attempts), "--timeout", str(timeout)]
            if burp.strip():
                args += ["--burp", burp.strip()]
            if verbose:
                args += ["--verbose"]
            if csv_out.strip():
                args += ["--csv", csv_out.strip()]
            run_script(script, args)
            if csv_out.strip():
                out_path = os.path.join(BASE_DIR, csv_out.strip())
                if os.path.exists(out_path):
                    with open(out_path, "rb") as f:
                        st.download_button("Download AuthProbe CSV", f, file_name=csv_out.strip(), mime="text/csv", key="auth_login_dl")

    # ---------- KBA (kba_probe.py) UI ----------
        
    else:
        st.subheader("KBA / Security Question probe")

        # Inputs with Juice Shop-friendly defaults
        base = st.text_input("Base URL", value="http://127.0.0.1:3000", key="auth_kba_base")
        endpoint = st.text_input(
            "Endpoint (from Burp)",
            value="/rest/user/reset-password",  # default to the real reset endpoint
            key="auth_kba_endpoint",
            help="Example for Juice Shop: /rest/user/reset-password"
        )
        method = st.selectbox("HTTP method", ["POST", "PUT"], index=0, key="auth_kba_method")
        template = st.text_input(
            "JSON template file (must include {ANSWER} and {EMAIL})",
            value="kba_template.json",  # point to your file
            key="auth_kba_template",
            help='Example template should include: {"email":"{EMAIL}","answer":"{ANSWER}","new":"<pw>","repeat":"<pw>"}'
        )
        answers = st.text_input("Answers list file (one per line)", value="answers.txt", key="auth_kba_answers")
        email = st.text_input("Value to substitute for {EMAIL}", value="", key="auth_kba_email")
        burp = st.text_input("Burp proxy (optional)", value="", key="auth_kba_burp")
        timeout = st.number_input("Timeout (seconds)", value=15.0, min_value=1.0, step=1.0, key="auth_kba_timeout")
        delay = st.number_input("Delay between attempts (seconds)", value=0.0, min_value=0.0, step=0.1, key="auth_kba_delay")
        max_guesses = st.number_input("Max guesses (0 = all)", value=0, min_value=0, step=1, key="auth_kba_max")
        success_text = st.text_input(
            "Success keywords (comma-separated)",
            value="reset,token,success,new password",
            key="auth_kba_success",
            help="If the API returns 2xx + one of these words in the body, it's a HIT"
        )

        # Small helper to show the expected JSON structure from your kba_template.json
        with st.expander("Template JSON example", expanded=False):
            st.code(
                '{\n'
                '  "email": "{EMAIL}",\n'
                '  "answer": "{ANSWER}",\n'
                '  "new": "P@ssw0rd1234!",\n'
                '  "repeat": "P@ssw0rd1234!"\n'
                '}\n',
                language="json"
            )

        script = os.path.join(BASE_DIR, "kba_probe.py")

        if st.button("Run KBA Probe", key="auth_kba_run"):
            args = [
                "--base", base,
                "--endpoint", endpoint,
                "--method", method,
                "--template", template,
                "--answers", answers,
                "--timeout", str(timeout),
                "--delay", str(delay),
                "--max", str(max_guesses),
                "--success-text", success_text,
            ]
            if email.strip():
                args += ["--email", email.strip()]
            if burp.strip():
                args += ["--burp", burp.strip()]
            run_script(script, args)


# ---------- A08 (a08_integrity.py) ----------
with tab_a08:
    st.header("A08: SRI scan & JWT integrity checks")
    choice = st.radio("Mode", ["SRI scan", "JWT integrity"], horizontal=True, key="a08_mode")
    script = os.path.join(BASE_DIR, "a08_integrity.py")
    if choice == "SRI scan":
        base = st.text_input("Base page (e.g., http://127.0.0.1:3000)", value="http://127.0.0.1:3000", key="a08_sri_base")
        burp = st.text_input("Burp proxy (optional)", value="", key="a08_sri_burp")
        timeout = st.number_input("Timeout (seconds)", value=15.0, min_value=1.0, step=1.0, key="a08_sri_timeout")
        out_json = st.text_input("Write findings to JSON (optional)", value="a08_sri_findings.json", key="a08_sri_out")
        if st.button("Run SRI scan", key="a08_sri_run"):
            args = ["sri", "--base", base, "--timeout", str(timeout)]
            if burp.strip():
                args += ["--burp", burp.strip()]
            if out_json.strip():
                args += ["--out", out_json.strip()]
            run_script(script, args)
            out_path = os.path.join(BASE_DIR, out_json.strip())
            if out_json.strip() and os.path.exists(out_path):
                with open(out_path, "rb") as f:
                    st.download_button("Download Findings JSON", f, file_name=out_json.strip(), mime="application/json", key="a08_sri_dl")
    else:
        base = st.text_input("API root (e.g., http://127.0.0.1:3000)", value="http://127.0.0.1:3000", key="a08_jwt_base")
        email = st.text_input("Email", key="a08_jwt_email")
        password = st.text_input("Password", type="password", key="a08_jwt_pw")
        words = st.text_input("Comma-separated HMAC secrets (optional)", value="", key="a08_jwt_words")
        wordlist = st.text_input("Wordlist of HMAC secrets (optional)", value="", key="a08_jwt_wordlist")
        burp = st.text_input("Burp proxy (optional)", value="", key="a08_jwt_burp")
        timeout = st.number_input("Timeout (seconds)", value=15.0, min_value=1.0, step=1.0, key="a08_jwt_timeout")
        if st.button("Run JWT checks", key="a08_jwt_run"):
            args = ["jwt", "--base", base, "--email", email, "--password", password, "--timeout", str(timeout)]
            if words.strip():
                args += ["--words", words.strip()]
            if wordlist.strip():
                args += ["--wordlist", wordlist.strip()]
            if burp.strip():
                args += ["--burp", burp.strip()]
            run_script(script, args)

# ---------- A04 Insecure Design (insecure.py) ----------
with tab_a04:
    st.header("A04: Multi-product basket quantity / price setter")
    base = st.text_input("Base URL", value="http://127.0.0.1:3000", key="a04_base")
    email = st.text_input("Email", key="a04_email")
    password = st.text_input("Password", type="password", key="a04_pw")
    products = st.text_input("Product IDs (space-separated)", value="1 6", key="a04_products")
    quantities = st.text_input("Quantities (space-separated; 1 value broadcasts)", value="2", key="a04_quantities")
    prices = st.text_input("Prices (optional; space-separated; admin only; 1 value broadcasts)", value="", key="a04_prices")
    basket_id = st.text_input("Basket ID (optional)", value="", key="a04_basket")
    burp = st.text_input("Burp proxy (optional)", value="", key="a04_burp")
    timeout = st.number_input("Timeout (seconds)", value=15.0, min_value=1.0, step=1.0, key="a04_timeout")
    script = os.path.join(BASE_DIR, "insecure.py")
    if st.button("Run Basket Update", key="a04_run"):
        args = ["--base", base, "--email", email, "--password", password]
        if products.strip():
            args += ["--product"] + products.split()
        if quantities.strip():
            args += ["--quantity"] + quantities.split()
        if prices.strip():
            args += ["--price"] + prices.split()
        if basket_id.strip():
            args += ["--basket", basket_id.strip()]
        if burp.strip():
            args += ["--burp", burp.strip()]
        args += ["--timeout", str(timeout)]
        run_script(script, args)

# ---------- IDOR (idor.py) ----------
with tab_idor:
    st.header("IDOR probe: enumerate baskets you don't own")
    base = st.text_input("Base URL", value="http://127.0.0.1:3000", key="idor_base")
    email = st.text_input("Email", key="idor_email")
    password = st.text_input("Password", type="password", key="idor_pw")
    max_id = st.number_input("Max Basket ID to check", value=50, min_value=1, step=1, key="idor_maxid")
    script = os.path.join(BASE_DIR, "idor.py")
    st.info("This wrapper will import and call the check() function if available; otherwise falls back to a subprocess.")
    if st.button("Run IDOR check", key="idor_run"):
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location("idor_mod", script)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)  # type: ignore
            if hasattr(mod, "check"):
                st.caption("Running via direct function call")
                res = mod.check(base, email, password, int(max_id))  # type: ignore
                st.json(res)
            else:
                raise AttributeError("No check() in idor.py")
        except Exception as e:
            st.warning(f"Direct import failed ({e}); running as subprocess with env vars.")
            args = []
            run_script(script, args)

st.markdown("---")
st.caption("This interface wraps your existing scripts without changing them.")
