# Penetration Test Report — OWASP Juice Shop (A07 Focus)

**Author:** <Your Name>  
**Date:** <Date>

## 1. Executive Summary
One paragraph for non-technical readers: what was tested, what was found, and the business risk.

## 2. Scope & Method
- Scope as per `SCOPING.md`
- Methods: Burp (Proxy/Intruder/Repeater), AuthProbe-JS PoC
- OWASP Top 10 A07, MITRE ATT&CK T1110

## 3. Findings

### F-01: Weak Authentication Controls – Brute-forceable Login (A07) — High
**Affected Endpoint**: `POST /rest/user/login`  
**Description**: The login endpoint permits unlimited password guesses without lockout/backoff.  
**Evidence**:  
- Intruder table showing successful attempt with password `<value>`  
- `authprobe.py` output: success for user `<email>` with `<password>` (screenshot/CSV)  
- Optional: `GET /rest/user/whoami` shows authenticated user after token use  
**Impact**: Account takeover leading to data exposure and fraud.  
**Likelihood**: High (internet-exposed login forms are frequently attacked).  
**Risk**: High (CVSS v3.1: put your calculated vector here).  
**Recommendations**: Rate-limiting, progressive delays, temporary lockout, 2FA, monitoring.

### (Optional) F-02: Security Question Brute Force (A07) — Medium
Add details if tested and reproduced.

## 4. Risk Assessment
- Approach: CVSS v3.1 + organizational impact context  
- Table summarizing each finding with Severity, CVSS, Status

## 5. Remediation Plan
- Short-term mitigations (WAF rules, throttle)  
- Engineering backlog items (lockout, 2FA, KBA removal)  
- Monitoring/alerting improvements

## 6. Appendix
- Tools versions; wordlists used  
- Raw request/response samples (sanitized)  
- How to reproduce (step-by-step)

