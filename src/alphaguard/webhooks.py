"""Stripe webhook endpoint for AlphaGuard subscription state."""

import os
from typing import Any

import stripe
from fastapi import FastAPI, HTTPException, Request

from .db import DatabaseError, get_user_id_by_stripe_customer, update_user_subscription


app = FastAPI(title="AlphaGuard webhooks")


def _metadata_value(metadata: Any, key: str) -> str | None:
    value = metadata.get(key) if isinstance(metadata, dict) else None
    return str(value).strip() if value else None


def _handle_checkout_completed(session: Any) -> None:
    metadata = session.get("metadata") or {}
    user_id = _metadata_value(metadata, "user_id") or _metadata_value(metadata, "user_email")
    if not user_id:
        raise HTTPException(status_code=400, detail="Checkout session is missing user metadata.")
    update_user_subscription(
        user_id,
        "Pro",
        stripe_customer_id=str(session.get("customer")) if session.get("customer") else None,
        stripe_subscription_id=str(session.get("subscription")) if session.get("subscription") else None,
    )


def _handle_subscription_deleted(subscription: Any) -> None:
    customer_id = str(subscription.get("customer")) if subscription.get("customer") else ""
    user_id = _metadata_value(subscription.get("metadata"), "user_id") or (
        get_user_id_by_stripe_customer(customer_id) if customer_id else None
    )
    if not user_id:
        raise HTTPException(status_code=400, detail="Subscription is not associated with an AlphaGuard user.")
    update_user_subscription(user_id, "Free", stripe_customer_id=customer_id or None)


@app.post("/webhooks/stripe")
async def stripe_webhook(request: Request) -> dict[str, bool]:
    """Verify and process Stripe subscription lifecycle events."""
    webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET")
    signature = request.headers.get("stripe-signature")
    if not webhook_secret or not signature:
        raise HTTPException(status_code=400, detail="Stripe webhook configuration is incomplete.")

    payload = await request.body()
    try:
        event = stripe.Webhook.construct_event(payload, signature, webhook_secret)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid Stripe webhook payload.") from exc
    except stripe.error.SignatureVerificationError as exc:
        raise HTTPException(status_code=400, detail="Invalid Stripe webhook signature.") from exc

    try:
        event_type = event["type"]
        event_object = event["data"]["object"]
        if event_type == "checkout.session.completed":
            _handle_checkout_completed(event_object)
        elif event_type == "customer.subscription.deleted":
            _handle_subscription_deleted(event_object)
    except DatabaseError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    return {"received": True}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("src.alphaguard.webhooks:app", host="0.0.0.0", port=8000)