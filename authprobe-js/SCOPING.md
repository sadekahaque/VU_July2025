# Scoping Assessment — OWASP Juice Shop A07 (Auth Failures)

**Objective**  
Demonstrate Identification & Authentication Failures (OWASP Top 10) against a deliberately vulnerable application (OWASP Juice Shop) in a contained Docker lab. Produce evidence and a small PoC tool.

**In Scope**  
- Target host: `http://127.0.0.1:3000` (Docker container `bkimminich/juice-shop`)  
- Endpoints: `/rest/user/login`, password-reset/KBA endpoints discovered during testing  
- Accounts: newly created test user(s) by assessor

**Out of Scope**  
- Host OS and other containers/services  
- DoS beyond light rate-limit checks  
- Exploits that leak outside the container

**Architecture (as understood)**  
- Node.js/Express app serving HTML + REST API  
- JWT-based authentication; API endpoints under `/rest/*`  
- Stateless back-end; data persisted in container runtime

**Data Sensitivity**  
- PII-like data in user profile/order history (lab data only)

**Assumptions & Constraints**  
- Testing during lab hours only; container can be reset at any time  
- No real users or real data

**Rules of Engagement**  
- Only the assessor’s lab environment is targeted  
- Capture minimal data; keep tokens/passwords private  
- Save all evidence (screenshots + tool outputs)

**Threats Considered (OWASP mappings)**  
- A07 Identification & Authentication Failures (primary)  
- A04 Insecure Design (secondary: missing rate limits is a design flaw)

**Success Criteria**  
- Demonstrate brute-forceable login or KBA answer without lockout  
- Provide reproducible PoC (script) and remediation guidance
