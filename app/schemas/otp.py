from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

_SEPARATORS = re.compile(r"[\s\-().]")
_E164 = re.compile(r"^\+[1-9]\d{7,14}$")
_CODE = re.compile(r"^\d{6}$")


def normalize_msisdn(value: str) -> str:
    """Normalize to E.164 (+ followed by 8-15 digits). Every valid number is treated
    the same way - there are no special-cased numbers anywhere in the service."""
    v = _SEPARATORS.sub("", value.strip())
    if v.startswith("00"):
        v = "+" + v[2:]
    elif not v.startswith("+"):
        v = "+" + v
    if not _E164.fullmatch(v):
        raise ValueError("msisdn must be a phone number in international format, e.g. +996700123456")
    return v


class SendOtpRequest(BaseModel):
    model_config = ConfigDict(json_schema_extra={"examples": [{"msisdn": "+996700123456"}]})

    msisdn: str = Field(..., min_length=8, max_length=32, description="Phone number, E.164")

    @field_validator("msisdn")
    @classmethod
    def _check(cls, v: str) -> str:
        normalize_msisdn(v)
        return v.strip()

    @property
    def normalized(self) -> str:
        return normalize_msisdn(self.msisdn)


class VerifyOtpRequest(SendOtpRequest):
    model_config = ConfigDict(
        json_schema_extra={"examples": [{"msisdn": "+996700123456", "code": "482916"}]}
    )

    code: str = Field(..., description="6-digit OTP taken from the SMS (outbox/sms.jsonl in demo mode)")

    @field_validator("code", mode="before")
    @classmethod
    def _code(cls, v):
        if isinstance(v, bool):
            raise ValueError("code must be 6 digits")
        if isinstance(v, int):
            if not 0 <= v <= 999_999:
                raise ValueError("code must be 6 digits")
            v = f"{v:06d}"
        if not isinstance(v, str) or not _CODE.fullmatch(v.strip()):
            raise ValueError("code must be exactly 6 digits")
        return v.strip()


class SendOtpResponse(BaseModel):
    success: bool = True
    message: str = "OTP issued successfully"
    expires_in: int = Field(..., description="OTP lifetime in seconds (120)")
    retry_after: int = Field(..., description="Seconds until the next /otp/send is allowed (30/60/120)")
    sends_remaining: int = Field(..., description="Sends left in the current 10-minute window")


class VerifyOtpResponse(BaseModel):
    success: bool = True
    verified: bool = True
    message: str = "Phone successfully verified"
