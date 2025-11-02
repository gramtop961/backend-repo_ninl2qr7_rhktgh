from pydantic import BaseModel, Field, EmailStr
from typing import Optional, Literal
from datetime import datetime

# Authentication and Users
class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Unique email")
    password_hash: str = Field(..., description="Derived hash of password")
    password_salt: str = Field(..., description="Salt for PBKDF2")
    role: Literal["owner", "manager", "staff"] = Field("owner", description="Global role; business-specific roles stored in membership")
    is_active: bool = Field(True)

class Session(BaseModel):
    user_id: str
    token: str
    created_at: Optional[datetime] = None

# Core domain
class Business(BaseModel):
    name: str
    gstin: Optional[str] = None
    address: Optional[str] = None
    owner_id: str

class Membership(BaseModel):
    business_id: str
    user_id: str
    role: Literal["owner", "manager", "staff"] = "owner"

class Cashbook(BaseModel):
    business_id: str
    name: str
    default_mode: Literal["cash", "bank", "upi", "credit_card", "debit_card"] = "cash"
    opening_balance: float = 0.0

class Category(BaseModel):
    business_id: str
    name: str
    type: Literal["income", "expense"]

class Transaction(BaseModel):
    business_id: str
    cashbook_id: str
    date: datetime
    type: Literal["income", "expense"]
    amount: float
    mode: Literal["cash", "bank", "upi", "credit_card", "debit_card"] = "cash"
    category_id: Optional[str] = None
    notes: Optional[str] = None
