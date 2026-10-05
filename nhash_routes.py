"""
nhash_routes.py — "Pay for PRO with nHash" endpoints for GrgAI (FastAPI).

Add to server.py:
    from nhash_routes import router as nhash_router
    app.include_router(nhash_router)

Frontend flow:
    POST /api/nhash/invoice {user_id}      -> {address, amount, amount_units}
        show the address + amount, let the user send from coremine/wallet
    POST /api/nhash/status  {user_id, amount_units} -> {paid}
        poll every few seconds; when paid, PRO is activated server-side
"""
from fastapi import APIRouter, Request
from grgai_payment import create_invoice, check_paid

router = APIRouter()


@router.post("/api/nhash/invoice")
async def nhash_invoice(request: Request):
    body = await request.json()
    user_id = body.get("user_id")
    if not user_id:
        return {"error": "missing user_id"}
    inv = create_invoice(user_id)          # unique amount to YOUR address
    return {"address": inv["address"], "amount": inv["amount_display"], "amount_units": inv["amount_units"]}


@router.post("/api/nhash/status")
async def nhash_status(request: Request):
    body = await request.json()
    user_id = body.get("user_id")
    units = body.get("amount_units")
    if not user_id or not units:
        return {"error": "missing user_id or amount_units"}
    paid = check_paid({"amount_units": int(units)})
    if paid:
        activate_pro_for(user_id)           # grant PRO, same effect as your Stripe success
    return {"paid": paid}


def activate_pro_for(user_id: str):
    """
    TODO: mark this user PRO in your subscription store (Firebase/Firestore),
    exactly like your Stripe webhook does. For example, set a 'plan: pro' field
    on the user's document, or reuse a helper from stripe_handler.
    """
    print(f"[nHash] PRO granted to {user_id}")
