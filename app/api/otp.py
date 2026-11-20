from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.core.client_ip import get_client_ip
from app.dependencies import get_otp_service
from app.schemas.errors import error_doc
from app.schemas.otp import SendOtpRequest, SendOtpResponse, VerifyOtpRequest, VerifyOtpResponse
from app.services.otp_service import OtpService

router = APIRouter(prefix="/otp", tags=["OTP"])

_422 = error_doc("Invalid request body (msisdn / code format)", "validation_error", "code must be exactly 6 digits")
_503 = error_doc("Storage (Redis) or SMS outbox temporarily unavailable", "service_unavailable", "Service temporarily unavailable")


@router.post(
    "/send",
    response_model=SendOtpResponse,
    summary="Issue a 6-digit OTP",
    description=(
        "Generates a 6-digit OTP with `secrets`, stores only its HMAC-SHA256 digest in Redis "
        "with a 120 s TTL and invalidates any previous code for the number.\n\n"
        "**Delivery (demo mode):** the code is appended to `outbox/sms.jsonl` on the server "
        "before HTTP 200 is returned. The code is never returned by the API.\n\n"
        "**Limits:** progressive cooldown between successful sends 30 s → 60 s → 120 s, "
        "maximum 3 successful sends per number per 10 minutes (window starts at the first send). "
        "Refused requests (429) do not create a code and do not restart the window."
    ),
    responses={
        429: error_doc(
            "Send limit hit: cooldown active or 3 sends per 10 minutes used (see Retry-After)",
            "send_rate_limited", "Please wait 30 s before requesting a new code", retry_after=30,
        ),
        423: error_doc("Number is blocked after 5 wrong codes", "phone_blocked", "Phone number is temporarily blocked", retry_after=900),
        422: _422,
        503: _503,
    },
)
async def send_otp(body: SendOtpRequest, request: Request, svc: OtpService = Depends(get_otp_service)):
    result = await svc.send(body.normalized, body.msisdn, get_client_ip(request))
    return SendOtpResponse(
        expires_in=result.expires_in,
        retry_after=result.retry_after,
        sends_remaining=result.sends_remaining,
    )


@router.post(
    "/verify",
    response_model=VerifyOtpResponse,
    summary="Verify an OTP",
    description=(
        "Checks order: **(1)** per-IP limit — 20 verifications per 60 s fixed window per real TCP "
        "peer IP, summed over all numbers (429); **(2)** number block (423); **(3)** code.\n\n"
        "A correct code succeeds exactly once, even under concurrent requests (atomic Redis Lua). "
        "A wrong code returns 401; the 5th wrong code blocks the number for 15 minutes (423). "
        "Expired (120 s), already used or replaced codes return 410.\n\n"
        "`X-Forwarded-For` / `X-Real-IP` are ignored."
    ),
    responses={
        401: error_doc("Wrong code", "invalid_otp", "Invalid OTP code", attempts_left=4),
        410: error_doc("Code expired, already used or replaced by a newer one", "otp_expired", "OTP expired or not found, request a new code"),
        423: error_doc("Number blocked for 15 minutes after 5 wrong codes", "phone_blocked", "Phone number is temporarily blocked", retry_after=900),
        429: error_doc("More than 20 verifications per minute from this IP", "ip_rate_limited", "Too many verification attempts from this IP", retry_after=42),
        422: _422,
        503: _503,
    },
)
async def verify_otp(body: VerifyOtpRequest, request: Request, svc: OtpService = Depends(get_otp_service)):
    await svc.verify(body.normalized, body.code, get_client_ip(request))
    return VerifyOtpResponse()
