from __future__ import annotations

from pydantic import BaseModel


class ErrorResponse(BaseModel):
    success: bool = False
    error: str
    message: str
    retry_after: int | None = None
    attempts_left: int | None = None


def error_doc(description: str, error: str, message: str, **extra) -> dict:
    example = {"success": False, "error": error, "message": message, **extra}
    return {
        "model": ErrorResponse,
        "description": description,
        "content": {"application/json": {"example": example}},
    }
