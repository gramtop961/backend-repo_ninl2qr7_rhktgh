import os
import secrets
import hashlib
from datetime import datetime, timezone
from typing import Optional, List, Literal

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from bson import ObjectId

from database import db, create_document, get_documents
from schemas import User as UserSchema, Session as SessionSchema, Business as BusinessSchema, Membership as MembershipSchema, Cashbook as CashbookSchema, Category as CategorySchema, Transaction as TransactionSchema

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Utility: ObjectId conversion

def oid(oid_str: str) -> ObjectId:
    try:
        return ObjectId(oid_str)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid ID format")

# Password hashing

PBKDF2_ITERATIONS = 200_000

def hash_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
    if not salt:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), bytes.fromhex(salt), PBKDF2_ITERATIONS
    )
    return dk.hex(), salt


def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    dk_hex, _ = hash_password(password, salt)
    return secrets.compare_digest(dk_hex, stored_hash)

# Auth models
class RegisterPayload(BaseModel):
    name: str
    email: EmailStr
    password: str

class LoginPayload(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    token: str
    user: dict

# Auth dependency
async def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    token = authorization.split(" ", 1)[1]
    session = db["session"].find_one({"token": token})
    if not session:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db["user"].find_one({"_id": session["user_id"]}) if isinstance(session.get("user_id"), ObjectId) else db["user"].find_one({"_id": oid(session["user_id"])})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# Role helpers

def require_business_role(user: dict, business_id: str, roles: List[str]):
    membership = db["membership"].find_one({
        "business_id": oid(business_id),
        "user_id": user["_id"],
    })
    if not membership or membership.get("role") not in roles:
        raise HTTPException(status_code=403, detail="Insufficient permissions")

# Routes: Health
@app.get("/")
def read_root():
    return {"message": "Cashbook API running"}

@app.get("/test")
def test_database():
    try:
        names = db.list_collection_names() if db else []
        return {"status": "ok", "collections": names}
    except Exception as e:
        return {"status": "error", "error": str(e)}

# Routes: Auth
@app.post("/auth/register", response_model=TokenResponse)
def register(payload: RegisterPayload):
    if db["user"].find_one({"email": payload.email}):
        raise HTTPException(status_code=409, detail="Email already registered")
    pwd_hash, salt = hash_password(payload.password)
    user = UserSchema(
        name=payload.name,
        email=payload.email,
        password_hash=pwd_hash,
        password_salt=salt,
        role="owner",
        is_active=True,
    )
    user_id = create_document("user", user)
    token = secrets.token_urlsafe(32)
    db["session"].insert_one({
        "user_id": oid(user_id),
        "token": token,
        "created_at": datetime.now(timezone.utc),
    })
    return {"token": token, "user": {"_id": user_id, "name": user.name, "email": user.email, "role": user.role}}

@app.post("/auth/login", response_model=TokenResponse)
def login(payload: LoginPayload):
    user = db["user"].find_one({"email": payload.email})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_password(payload.password, user["password_hash"], user["password_salt"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = secrets.token_urlsafe(32)
    db["session"].insert_one({
        "user_id": user["_id"],
        "token": token,
        "created_at": datetime.now(timezone.utc),
    })
    user_out = {"_id": str(user["_id"]), "name": user["name"], "email": user["email"], "role": user.get("role", "owner")}
    return {"token": token, "user": user_out}

@app.get("/auth/me")
def me(user=Depends(get_current_user)):
    return {"_id": str(user["_id"]), "name": user["name"], "email": user["email"], "role": user.get("role", "owner")}

@app.post("/auth/logout")
def logout(authorization: Optional[str] = Header(None)):
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1]
        db["session"].delete_one({"token": token})
    return {"ok": True}

# Routes: Businesses
class BusinessCreate(BaseModel):
    name: str
    gstin: Optional[str] = None
    address: Optional[str] = None

@app.get("/businesses")
def list_businesses(user=Depends(get_current_user)):
    # fetch memberships for user
    memberships = list(db["membership"].find({"user_id": user["_id"]}))
    biz_ids = [m["business_id"] for m in memberships]
    businesses = list(db["business"].find({"_id": {"$in": biz_ids}})) if biz_ids else []
    return [{"_id": str(b["_id"]), "name": b["name"], "gstin": b.get("gstin"), "address": b.get("address") } for b in businesses]

@app.post("/businesses")
def create_business(payload: BusinessCreate, user=Depends(get_current_user)):
    biz = BusinessSchema(name=payload.name, gstin=payload.gstin, address=payload.address, owner_id=str(user["_id"]))
    biz_id = create_document("business", biz)
    membership = MembershipSchema(business_id=biz_id, user_id=str(user["_id"]), role="owner")
    create_document("membership", membership)
    return {"_id": biz_id, "name": biz.name, "gstin": biz.gstin, "address": biz.address}

@app.patch("/businesses/{business_id}")
def update_business(business_id: str, payload: BusinessCreate, user=Depends(get_current_user)):
    require_business_role(user, business_id, ["owner", "manager"]) 
    update = {k: v for k, v in payload.model_dump().items() if v is not None}
    db["business"].update_one({"_id": oid(business_id)}, {"$set": update})
    b = db["business"].find_one({"_id": oid(business_id)})
    return {"_id": business_id, "name": b["name"], "gstin": b.get("gstin"), "address": b.get("address")}

@app.delete("/businesses/{business_id}")
def delete_business(business_id: str, user=Depends(get_current_user)):
    require_business_role(user, business_id, ["owner"]) 
    db["business"].delete_one({"_id": oid(business_id)})
    db["membership"].delete_many({"business_id": oid(business_id)})
    db["cashbook"].delete_many({"business_id": oid(business_id)})
    db["category"].delete_many({"business_id": oid(business_id)})
    db["transaction"].delete_many({"business_id": oid(business_id)})
    return {"ok": True}

# Routes: Cashbooks
class CashbookCreate(BaseModel):
    name: str
    default_mode: Literal["cash", "bank", "upi", "credit_card", "debit_card"] = "cash"
    opening_balance: float = 0.0

@app.get("/businesses/{business_id}/cashbooks")
def list_cashbooks(business_id: str, user=Depends(get_current_user)):
    require_business_role(user, business_id, ["owner", "manager", "staff"]) 
    c = list(db["cashbook"].find({"business_id": oid(business_id)}))
    return [{"_id": str(x["_id"]), "name": x["name"], "default_mode": x.get("default_mode", "cash"), "opening_balance": x.get("opening_balance", 0.0)} for x in c]

@app.post("/businesses/{business_id}/cashbooks")
def create_cashbook(business_id: str, payload: CashbookCreate, user=Depends(get_current_user)):
    require_business_role(user, business_id, ["owner", "manager"]) 
    cb = CashbookSchema(business_id=business_id, name=payload.name, default_mode=payload.default_mode, opening_balance=payload.opening_balance)
    cb_id = create_document("cashbook", cb)
    return {"_id": cb_id, "name": cb.name, "default_mode": cb.default_mode, "opening_balance": cb.opening_balance}

@app.patch("/cashbooks/{cashbook_id}")
def update_cashbook(cashbook_id: str, payload: CashbookCreate, user=Depends(get_current_user)):
    cb = db["cashbook"].find_one({"_id": oid(cashbook_id)})
    if not cb:
        raise HTTPException(status_code=404, detail="Not found")
    require_business_role(user, str(cb["business_id"]), ["owner", "manager"]) 
    update = {k: v for k, v in payload.model_dump().items() if v is not None}
    db["cashbook"].update_one({"_id": oid(cashbook_id)}, {"$set": update})
    cb = db["cashbook"].find_one({"_id": oid(cashbook_id)})
    return {"_id": str(cb["_id"]), "name": cb["name"], "default_mode": cb.get("default_mode", "cash"), "opening_balance": cb.get("opening_balance", 0.0)}

@app.delete("/cashbooks/{cashbook_id}")
def delete_cashbook(cashbook_id: str, user=Depends(get_current_user)):
    cb = db["cashbook"].find_one({"_id": oid(cashbook_id)})
    if not cb:
        return {"ok": True}
    require_business_role(user, str(cb["business_id"]), ["owner", "manager"]) 
    db["cashbook"].delete_one({"_id": oid(cashbook_id)})
    db["transaction"].delete_many({"cashbook_id": oid(cashbook_id)})
    return {"ok": True}

# Routes: Categories
class CategoryCreate(BaseModel):
    name: str
    type: Literal["income", "expense"]

@app.get("/businesses/{business_id}/categories")
def list_categories(business_id: str, user=Depends(get_current_user)):
    require_business_role(user, business_id, ["owner", "manager", "staff"]) 
    cats = list(db["category"].find({"business_id": oid(business_id)}))
    return [{"_id": str(x["_id"]), "name": x["name"], "type": x["type"]} for x in cats]

@app.post("/businesses/{business_id}/categories")
def create_category(business_id: str, payload: CategoryCreate, user=Depends(get_current_user)):
    require_business_role(user, business_id, ["owner", "manager"]) 
    cat = CategorySchema(business_id=business_id, name=payload.name, type=payload.type)
    cat_id = create_document("category", cat)
    return {"_id": cat_id, "name": cat.name, "type": cat.type}

@app.patch("/categories/{category_id}")
def update_category(category_id: str, payload: CategoryCreate, user=Depends(get_current_user)):
    cat = db["category"].find_one({"_id": oid(category_id)})
    if not cat:
        raise HTTPException(status_code=404, detail="Not found")
    require_business_role(user, str(cat["business_id"]), ["owner", "manager"]) 
    update = {k: v for k, v in payload.model_dump().items() if v is not None}
    db["category"].update_one({"_id": oid(category_id)}, {"$set": update})
    cat = db["category"].find_one({"_id": oid(category_id)})
    return {"_id": str(cat["_id"]), "name": cat["name"], "type": cat["type"]}

@app.delete("/categories/{category_id}")
def delete_category(category_id: str, user=Depends(get_current_user)):
    cat = db["category"].find_one({"_id": oid(category_id)})
    if not cat:
        return {"ok": True}
    require_business_role(user, str(cat["business_id"]), ["owner", "manager"]) 
    db["category"].delete_one({"_id": oid(category_id)})
    return {"ok": True}

# Routes: Transactions
class TransactionCreate(BaseModel):
    date: datetime
    type: Literal["income", "expense"]
    amount: float
    mode: Literal["cash", "bank", "upi", "credit_card", "debit_card"] = "cash"
    category_id: Optional[str] = None
    notes: Optional[str] = None

@app.get("/cashbooks/{cashbook_id}/transactions")
def list_transactions(cashbook_id: str, user=Depends(get_current_user)):
    cb = db["cashbook"].find_one({"_id": oid(cashbook_id)})
    if not cb:
        raise HTTPException(status_code=404, detail="Not found")
    require_business_role(user, str(cb["business_id"]), ["owner", "manager", "staff"]) 
    txs = list(db["transaction"].find({"cashbook_id": oid(cashbook_id)}).sort("date", 1))
    def ser(t):
        return {
            "_id": str(t["_id"]),
            "date": t["date"].isoformat() if isinstance(t["date"], datetime) else str(t["date"]),
            "type": t["type"],
            "amount": t["amount"],
            "mode": t.get("mode", "cash"),
            "category_id": str(t.get("category_id")) if t.get("category_id") else None,
            "notes": t.get("notes"),
        }
    return [ser(t) for t in txs]

@app.post("/cashbooks/{cashbook_id}/transactions")
def create_transaction(cashbook_id: str, payload: TransactionCreate, user=Depends(get_current_user)):
    cb = db["cashbook"].find_one({"_id": oid(cashbook_id)})
    if not cb:
        raise HTTPException(status_code=404, detail="Not found")
    require_business_role(user, str(cb["business_id"]), ["owner", "manager", "staff"]) 
    t = TransactionSchema(
        business_id=str(cb["business_id"]),
        cashbook_id=cashbook_id,
        date=payload.date,
        type=payload.type,
        amount=payload.amount,
        mode=payload.mode,
        category_id=payload.category_id,
        notes=payload.notes,
    )
    t_id = create_document("transaction", t)
    return {"_id": t_id}

@app.patch("/transactions/{transaction_id}")
def update_transaction(transaction_id: str, payload: TransactionCreate, user=Depends(get_current_user)):
    t = db["transaction"].find_one({"_id": oid(transaction_id)})
    if not t:
        raise HTTPException(status_code=404, detail="Not found")
    cb = db["cashbook"].find_one({"_id": t["cashbook_id"]})
    require_business_role(user, str(cb["business_id"]), ["owner", "manager"]) 
    update = {k: v for k, v in payload.model_dump().items() if v is not None}
    if "category_id" in update and update["category_id"] is not None:
        update["category_id"] = oid(update["category_id"])
    if "date" in update and isinstance(update["date"], str):
        update["date"] = datetime.fromisoformat(update["date"])  # type: ignore
    db["transaction"].update_one({"_id": oid(transaction_id)}, {"$set": update})
    return {"ok": True}

@app.delete("/transactions/{transaction_id}")
def delete_transaction(transaction_id: str, user=Depends(get_current_user)):
    t = db["transaction"].find_one({"_id": oid(transaction_id)})
    if not t:
        return {"ok": True}
    cb = db["cashbook"].find_one({"_id": t["cashbook_id"]})
    require_business_role(user, str(cb["business_id"]), ["owner", "manager"]) 
    db["transaction"].delete_one({"_id": oid(transaction_id)})
    return {"ok": True}

# Routes: Membership (Staff)
class StaffInvite(BaseModel):
    email: EmailStr
    role: Literal["manager", "staff"] = "staff"

@app.get("/businesses/{business_id}/staff")
def list_staff(business_id: str, user=Depends(get_current_user)):
    require_business_role(user, business_id, ["owner", "manager"]) 
    members = list(db["membership"].find({"business_id": oid(business_id)}))
    users = {u["_id"]: u for u in db["user"].find({"_id": {"$in": [m["user_id"] for m in members]}})} if members else {}
    out = []
    for m in members:
        u = users.get(m["user_id"]) or {}
        out.append({
            "_id": str(m["_id"]),
            "user_id": str(m["user_id"]),
            "name": u.get("name", ""),
            "email": u.get("email", ""),
            "role": m.get("role", "staff"),
        })
    return out

@app.post("/businesses/{business_id}/staff")
def add_staff(business_id: str, payload: StaffInvite, user=Depends(get_current_user)):
    require_business_role(user, business_id, ["owner", "manager"]) 
    u = db["user"].find_one({"email": payload.email})
    if not u:
        raise HTTPException(status_code=404, detail="User not found. Ask them to register first.")
    existing = db["membership"].find_one({"business_id": oid(business_id), "user_id": u["_id"]})
    if existing:
        raise HTTPException(status_code=409, detail="User already added")
    mem = MembershipSchema(business_id=business_id, user_id=str(u["_id"]), role=payload.role)
    mem_id = create_document("membership", mem)
    return {"_id": mem_id, "user_id": str(u["_id"]), "role": payload.role}

@app.patch("/staff/{membership_id}")
def update_staff(membership_id: str, payload: StaffInvite, user=Depends(get_current_user)):
    m = db["membership"].find_one({"_id": oid(membership_id)})
    if not m:
        raise HTTPException(status_code=404, detail="Not found")
    require_business_role(user, str(m["business_id"]), ["owner"]) 
    db["membership"].update_one({"_id": oid(membership_id)}, {"$set": {"role": payload.role}})
    return {"ok": True}

@app.delete("/staff/{membership_id}")
def delete_staff(membership_id: str, user=Depends(get_current_user)):
    m = db["membership"].find_one({"_id": oid(membership_id)})
    if not m:
        return {"ok": True}
    require_business_role(user, str(m["business_id"]), ["owner", "manager"]) 
    db["membership"].delete_one({"_id": oid(membership_id)})
    return {"ok": True}

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
