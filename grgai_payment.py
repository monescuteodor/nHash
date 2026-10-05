"""
GrgAI <-> nHash payment (single-address mode).

Runs next to `corehash-pay`, which watches YOUR nHash address and matches each order by
a unique amount. Flow:
  1. user clicks "Buy PRO with nHash"  -> create_invoice() -> show address + exact amount
  2. user sends that exact amount from coremine / wallet
  3. backend polls check_paid() -> when True, activate PRO

Start the gateway once (on the machine running a node):
    corehash-pay 127.0.0.1:9334 a3cb24487a4f6728fb64d05ef813dcf00931c0238352225356db859b34f344a7 8080
"""
import requests

GATEWAY = "http://127.0.0.1:8080"     # where corehash-pay listens
PRO_PRICE = 50                         # nHash for 1 PRO plan (you set this)


def create_invoice(user_id: str) -> dict:
    """Reserve a unique payment for this user; returns address + exact amount to display."""
    r = requests.get(f"{GATEWAY}/invoice",
                     params={"order": user_id, "amount": PRO_PRICE}, timeout=5)
    r.raise_for_status()
    return r.json()   # {"address", "amount_units", "amount_display"}


def check_paid(invoice: dict) -> bool:
    """True once the exact amount has arrived at your address on-chain."""
    r = requests.get(f"{GATEWAY}/status",
                     params={"amount": invoice["amount_units"]}, timeout=5)
    r.raise_for_status()
    return r.json().get("paid", False)


# ---- Wiring into your account system (replace grant_pro / storage) ---------
_invoices = {}   # user_id -> invoice  (persist in your DB, not memory)

def start_purchase(user_id: str) -> dict:
    inv = create_invoice(user_id)
    _invoices[user_id] = inv
    return inv   # {address, amount_display} -> show to the user

def poll_and_activate(user_id: str) -> bool:
    inv = _invoices.get(user_id)
    if inv and check_paid(inv):
        grant_pro(user_id)             # <-- your existing "make this user PRO" function
        _invoices.pop(user_id, None)
        return True
    return False

def grant_pro(user_id: str):
    # TODO: set the user's plan to PRO in Firebase / your subscription store,
    # the same effect your Stripe webhook has.
    print(f"[nHash] PRO activated for {user_id}")


if __name__ == "__main__":
    inv = start_purchase("demo-user")
    print(f"Send exactly {inv['amount_display']} nHash to {inv['address']}")
    print("paid?", poll_and_activate("demo-user"))
