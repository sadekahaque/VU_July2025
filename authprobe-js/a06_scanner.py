#!/usr/bin/env python3
"""
OWASP A06 helper: run Trivy in a Docker container and export a CSV of HIGH/CRITICAL vulns.
Strategy order:
  1) Remote registry scan by image name (no tar, no socket)  <-- best on Windows
  2) Local engine via Docker socket                          <-- needs Docker Desktop running
  3) Optional tar scan if --tar is supplied
"""

import argparse, csv, json, shutil, subprocess, sys

def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    print("\n[cmd] " + " ".join(cmd))
    # Force UTF-8 to avoid Windows cp1252 decode crashes
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def trivy_remote(image: str, severity: str) -> dict:
    # Scan directly from the registry (no socket/tar). Works well on Windows.
    cmd = [
        "docker","run","--rm",
        "aquasec/trivy:latest","image",
        "--scanners","vuln",
        "--severity", severity,
        "--format","json",
        "--no-progress",
        image  # e.g. bkimminich/juice-shop:latest
    ]
    cp = _run(cmd)
    if cp.returncode != 0:
        raise RuntimeError(cp.stderr.strip() or cp.stdout[:4000])
    out = (cp.stdout or "").strip()
    if not out:
        # Trivy didn’t write JSON to stdout – surface stderr so you can see why
        raise RuntimeError(cp.stderr.strip() or "Trivy produced no JSON on stdout")
    return json.loads(out)


def trivy_socket(image: str, severity: str) -> dict:
    # Use the host Docker engine via its socket
    cmd = [
        "docker","run","--rm",
        "-v","//var/run/docker.sock:/var/run/docker.sock",
        "aquasec/trivy:latest","image",
        "--scanners","vuln",
        "--severity", severity,
        "--format","json",
        "--no-progress",
        image
    ]
    cp = _run(cmd)
    if cp.returncode != 0:
        raise RuntimeError(cp.stderr.strip() or cp.stdout[:4000])
    out = (cp.stdout or "").strip()
    if not out:
        # Trivy didn’t write JSON to stdout – surface stderr so you can see why
        raise RuntimeError(cp.stderr.strip() or "Trivy produced no JSON on stdout")
    return json.loads(out)


def trivy_from_tar(tar_path: str, severity: str) -> dict:
    # Only used if user passes --tar; some Windows setups hit a tar bug.
    cmd = [
        "docker","run","--rm",
        "-v", f"{tar_path}:/work/image.tar",
        "aquasec/trivy:latest","image",
        "--input","/work/image.tar",
        "--scanners","vuln",
        "--severity", severity,
        "--format","json",
        "--no-progress",
    ]
    cp = _run(cmd)
    if cp.returncode != 0:
        raise RuntimeError(cp.stderr.strip() or cp.stdout[:4000])
    out = (cp.stdout or "").strip()
    if not out:
        # Trivy didn’t write JSON to stdout – surface stderr so you can see why
        raise RuntimeError(cp.stderr.strip() or "Trivy produced no JSON on stdout")
    return json.loads(out)


def write_csv(trivy_json: dict, out_csv: str):
    fields = ["Target","PkgName","InstalledVersion","VulnerabilityID","Severity","Title"]
    rows = []
    for res in trivy_json.get("Results", []) or []:
        tgt = res.get("Target","")
        for v in res.get("Vulnerabilities") or []:
            rows.append([
                tgt,
                v.get("PkgName",""),
                v.get("InstalledVersion",""),
                v.get("VulnerabilityID",""),
                v.get("Severity",""),
                v.get("Title",""),
            ])
    with open(out_csv,"w",newline="",encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(fields); w.writerows(rows)
    print(f"[+] Wrote CSV: {out_csv}  (rows: {len(rows)})")

def main():
    ap = argparse.ArgumentParser(description="A06 scanner wrapper (Trivy via Docker).")
    ap.add_argument("--image", help="Image name, e.g. bkimminich/juice-shop:latest")
    ap.add_argument("--tar", help="Optional path to docker save tar (only used if provided)")
    ap.add_argument("--csv", default="a06_results.csv", help="Output CSV")
    ap.add_argument("--severity", default="CRITICAL,HIGH", help="CRITICAL,HIGH[,MEDIUM...]")
    args = ap.parse_args()

    if not shutil.which("docker"):
        print("[-] Docker not in PATH. Start Docker Desktop and retry.", file=sys.stderr)
        sys.exit(1)

    err_msgs = []

    # Prefer remote scan by name if image provided
    if args.image:
        try:
            data = trivy_remote(args.image, args.severity)
            write_csv(data, args.csv)
            return
        except Exception as e:
            err_msgs.append(f"remote: {e}")

        # Fallback: socket scan
        try:
            data = trivy_socket(args.image, args.severity)
            write_csv(data, args.csv)
            return
        except Exception as e:
            err_msgs.append(f"socket: {e}")

    # Optional tar fallback
    if args.tar:
        try:
            data = trivy_from_tar(args.tar, args.severity)
            write_csv(data, args.csv)
            return
        except Exception as e:
            err_msgs.append(f"tar: {e}")

    print("[-] All strategies failed.\n" + "\n".join(f"  * {m}" for m in err_msgs))
    sys.exit(2)

if __name__ == "__main__":
    main()
