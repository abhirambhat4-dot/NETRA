from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

# Password policy shared by registration and password reset.
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 128


class RegisterRequest(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH)

    @field_validator("email", mode="after")
    @classmethod
    def normalize_email(cls, email: EmailStr) -> str:
        return str(email).strip().lower()

    @field_validator("full_name", mode="before")
    @classmethod
    def trim_full_name(cls, full_name: object) -> object:
        return full_name.strip() if isinstance(full_name, str) else full_name


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)

    @field_validator("email", mode="after")
    @classmethod
    def normalize_email(cls, email: EmailStr) -> str:
        return str(email).strip().lower()


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: EmailStr
    full_name: str
    role: str
    is_active: bool
    created_at: datetime
    updated_at: datetime


class ForgotPasswordRequest(BaseModel):
    email: EmailStr

    @field_validator("email", mode="after")
    @classmethod
    def normalize_email(cls, email: EmailStr) -> str:
        return str(email).strip().lower()


class ResetPasswordRequest(BaseModel):
    # Presence and policy are checked by the reset service: FastAPI validation errors echo the
    # submitted input, which must never include the raw reset token.
    token: str = ""
    new_password: str = ""


class MessageResponse(BaseModel):
    message: str
