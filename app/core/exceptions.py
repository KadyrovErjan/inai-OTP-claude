"""Domain errors mapped to HTTP responses in app.main."""
from __future__ import annotations


class OtpError(Exception):
    status_code = 400
    error = "error"
    message = "Request failed"

    def __init__(self, message: str | None = None, *, retry_after: int | None = None, **extra) -> None:
        super().__init__(message or self.message)
        self.message = message or self.message
        self.retry_after = retry_after
        self.extra = extra

    def body(self) -> dict:
        data = {"success": False, "error": self.error, "message": self.message}
        if self.retry_after is not None:
            data["retry_after"] = self.retry_after
        data.update(self.extra)
        return data


class InvalidOtp(OtpError):
    status_code = 401
    error = "invalid_otp"
    message = "Invalid OTP code"


class OtpGone(OtpError):
    status_code = 410
    error = "otp_expired"
    message = "OTP expired, already used or replaced"


class PhoneBlocked(OtpError):
    status_code = 423
    error = "phone_blocked"
    message = "Phone number is temporarily blocked"


class SendRateLimited(OtpError):
    status_code = 429
    error = "send_rate_limited"
    message = "Too many OTP requests"


class IpRateLimited(OtpError):
    status_code = 429
    error = "ip_rate_limited"
    message = "Too many verification attempts from this IP"


class ServiceUnavailable(OtpError):
    status_code = 503
    error = "service_unavailable"
    message = "Service temporarily unavailable"
