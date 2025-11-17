import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import stripe
import jwt
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr

from database import db

app = FastAPI()

# CORS
FRONTEND_URL = os.getenv("FRONTEND_URL", "*")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL] if FRONTEND_URL != "*" else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Secrets / Config
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_EXPIRES_MIN = int(os.getenv("JWT_EXPIRES_MIN", "60"))

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
stripe.api_key = STRIPE_SECRET_KEY

# Models
class MagicLinkRequest(BaseModel):
    email: EmailStr

class UpdateProfile(BaseModel):
    name: Optional[str] = None

class CheckoutPayload(BaseModel):
    price_id: str
    success_url: str
    cancel_url: str

# Helpers

def create_jwt(user_id: str, email: str) -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRES_MIN),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def require_auth(request: Request):
    auth = request.headers.get("authorization") or request.headers.get("Authorization")
    if not auth or not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = auth.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user_id = payload.get("sub")
        email = payload.get("email")
        return {"user_id": user_id, "email": email}
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


@app.get("/")
def read_root():
    return {"message": "SaaS Starter API running"}


@app.post("/auth/magic-link/request")
def request_magic_link(body: MagicLinkRequest):
    email = body.email.lower()
    # Ensure user exists
    user = db["user"].find_one({"email": email})
    if not user:
        user_doc = {
            "email": email,
            "name": None,
            "stripeCustomerId": None,
            "subscriptionStatus": None,
            "priceId": None,
            "currentPeriodEnd": None,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
        }
        res = db["user"].insert_one(user_doc)
        user = db["user"].find_one({"_id": res.inserted_id})

    # Create a one-time token stored in DB (5 min expiry)
    token = secrets.token_urlsafe(32)
    db["authtoken"].insert_one({
        "token": token,
        "email": email,
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=5),
        "used": False,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    })

    # In production, email this link. For demo, return it.
    return {
        "message": "Magic link generated",
        "login_url": f"{os.getenv('FRONTEND_URL','http://localhost:3000')}/auth/callback?token={token}",
    }


@app.get("/auth/magic-link/verify")
def verify_magic_link(token: str):
    rec = db["authtoken"].find_one({"token": token})
    if not rec:
        raise HTTPException(status_code=400, detail="Invalid token")
    if rec.get("used"):
        raise HTTPException(status_code=400, detail="Token already used")
    if rec.get("expires_at") < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Token expired")

    email = rec["email"]
    user = db["user"].find_one({"email": email})
    if not user:
        raise HTTPException(status_code=400, detail="User not found")

    # Mark token used
    db["authtoken"].update_one({"_id": rec["_id"]}, {"$set": {"used": True, "updated_at": datetime.now(timezone.utc)}})

    jwt_token = create_jwt(str(user["_id"]), email)
    return {"token": jwt_token}


@app.get("/me")
def me(ctx=Depends(require_auth)):
    user = db["user"].find_one({"email": ctx["email"]})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    # Convert ObjectId
    user["id"] = str(user.pop("_id"))
    return user


@app.put("/me")
def update_me(payload: UpdateProfile, ctx=Depends(require_auth)):
    updates = {"updated_at": datetime.now(timezone.utc)}
    if payload.name is not None:
        updates["name"] = payload.name
    db["user"].update_one({"email": ctx["email"]}, {"$set": updates})
    user = db["user"].find_one({"email": ctx["email"]})
    user["id"] = str(user.pop("_id"))
    return user


@app.post("/billing/create-checkout-session")
def create_checkout_session(payload: CheckoutPayload, ctx=Depends(require_auth)):
    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=500, detail="Stripe not configured")

    user = db["user"].find_one({"email": ctx["email"]})
    customer_id = user.get("stripeCustomerId")
    if not customer_id:
        customer = stripe.Customer.create(email=ctx["email"])
        customer_id = customer.id
        db["user"].update_one({"_id": user["_id"]}, {"$set": {"stripeCustomerId": customer_id}})

    session = stripe.checkout.Session.create(
        customer=customer_id,
        mode="subscription",
        line_items=[{"price": payload.price_id, "quantity": 1}],
        success_url=payload.success_url,
        cancel_url=payload.cancel_url,
        allow_promotion_codes=True,
    )
    return {"url": session.url}


@app.post("/billing/portal")
def create_billing_portal(ctx=Depends(require_auth)):
    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=500, detail="Stripe not configured")
    user = db["user"].find_one({"email": ctx["email"]})
    customer_id = user.get("stripeCustomerId")
    if not customer_id:
        raise HTTPException(status_code=400, detail="No Stripe customer")
    session = stripe.billing_portal.Session.create(customer=customer_id, return_url=os.getenv('FRONTEND_URL','http://localhost:3000')+"/dashboard")
    return {"url": session.url}


@app.post("/webhooks/stripe")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    try:
        if STRIPE_WEBHOOK_SECRET:
            event = stripe.Webhook.construct_event(
                payload=payload, sig_header=sig_header, secret=STRIPE_WEBHOOK_SECRET
            )
        else:
            event = stripe.Event.construct_from(request.json(), stripe.api_key)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Handle events
    if event["type"] in [
        "customer.subscription.created",
        "customer.subscription.updated",
        "customer.subscription.deleted",
    ]:
        sub = event["data"]["object"]
        customer_id = sub.get("customer")
        status = sub.get("status")
        price_id = None
        items = sub.get("items", {}).get("data", [])
        if items:
            price_id = items[0]["price"]["id"]
        current_period_end = datetime.fromtimestamp(sub.get("current_period_end", 0), tz=timezone.utc)
        db["user"].update_one(
            {"stripeCustomerId": customer_id},
            {"$set": {
                "subscriptionStatus": status,
                "priceId": price_id,
                "currentPeriodEnd": current_period_end,
                "updated_at": datetime.now(timezone.utc),
            }}
        )

    return JSONResponse({"received": True})


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_name"] = getattr(db, 'name', None) or "Unknown"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️ Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️ Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"
    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
