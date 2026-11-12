"""PalPluss Collect - API only (deploy on Render). Frontend lives on Vercel."""
import os, re, uuid, hmac, hashlib, secrets, time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import jwt, requests
from fastapi import FastAPI, Depends, HTTPException, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text, or_, func, case
from sqlalchemy.orm import declarative_base, sessionmaker, Session

API_KEY = os.getenv("PALPLUSS_API_KEY", "")
PAL_URL = os.getenv("PALPLUSS_URL", "https://api.palpluss.com/v1/payments/stk")
CALLBACK_URL = os.getenv("CALLBACK_URL", "")
CALLBACK_TOKEN = os.getenv("CALLBACK_TOKEN", "")
SECRET = os.getenv("SECRET_KEY") or secrets.token_hex(32)  # set SECRET_KEY so logins survive restarts
TOKEN_HOURS = int(os.getenv("TOKEN_HOURS", "12"))
DB_URL = os.getenv("DATABASE_URL", "sqlite:///./data/app.db")
if DB_URL.startswith("postgres://"):
    DB_URL = DB_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DB_URL.startswith("postgresql://"):
    DB_URL = DB_URL.replace("postgresql://", "postgresql+psycopg://", 1)
ORIGINS = [o.strip().rstrip("/") for o in os.getenv("FRONTEND_ORIGIN", "*").split(",") if o.strip()]

if DB_URL.startswith("sqlite"):
    os.makedirs("data", exist_ok=True)
engine = create_engine(DB_URL, pool_pre_ping=True, connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {})
Session_ = sessionmaker(bind=engine, autoflush=False)
Base = declarative_base()
now = lambda: datetime.now(timezone.utc).replace(tzinfo=None)


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, index=True)
    pw = Column(String(256))


class Tx(Base):
    __tablename__ = "transactions"
    id = Column(Integer, primary_key=True)
    tx_id = Column(String(64), index=True)
    checkout_id = Column(String(96), index=True)
    reference = Column(String(24))
    phone = Column(String(16), index=True)
    amount = Column(Float)
    status = Column(String(16), index=True, default="PENDING")  # PENDING | SUCCESS | FAILED
    description = Column(String(120))
    result = Column(Text, default="")
    created_at = Column(DateTime, default=now, index=True)
    updated_at = Column(DateTime, default=now)


Base.metadata.create_all(engine)


def hash_pw(p, salt=None):
    salt = salt or secrets.token_hex(8)
    return f"{salt}${hashlib.pbkdf2_hmac('sha256', p.encode(), salt.encode(), 200_000).hex()}"


def check_pw(p, stored):
    salt = stored.split("$")[0]
    return hmac.compare_digest(hash_pw(p, salt), stored)


with Session_() as s:
    if not s.query(User).count():
        s.add(User(username=os.getenv("ADMIN_USERNAME", "admin"),
                   pw=hash_pw(os.getenv("ADMIN_PASSWORD", "admin123"))))
        s.commit()

app = FastAPI(title="PalPluss Collect API", docs_url=None, redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=ORIGINS, allow_methods=["*"], allow_headers=["*"], max_age=600)
bearer = HTTPBearer(auto_error=False)


def db():
    s = Session_()
    try:
        yield s
    finally:
        s.close()


def current_user(cred: HTTPAuthorizationCredentials = Depends(bearer), s: Session = Depends(db)):
    if not cred:
        raise HTTPException(401, "Sign in to continue")
    try:
        uid = jwt.decode(cred.credentials, SECRET, algorithms=["HS256"])["sub"]
    except jwt.PyJWTError:
        raise HTTPException(401, "Session expired. Sign in again")
    u = s.get(User, int(uid))
    if not u:
        raise HTTPException(401, "Account not found")
    return u


# ---------- auth ----------
fails = defaultdict(list)


class Login(BaseModel):
    username: str
    password: str


@app.post("/api/auth/login")
def login(b: Login, request: Request, s: Session = Depends(db)):
    ip = (request.headers.get("x-forwarded-for", "").split(",")[0].strip()) or (request.client.host if request.client else "?")
    fails[ip] = [t for t in fails[ip] if time.time() - t < 300]
    if len(fails[ip]) >= 5:
        raise HTTPException(429, "Too many attempts. Try again in 5 minutes")
    u = s.query(User).filter_by(username=b.username.strip()).first()
    if not u or not check_pw(b.password, u.pw):
        fails[ip].append(time.time())
        raise HTTPException(401, "Wrong username or password")
    exp = datetime.now(timezone.utc) + timedelta(hours=TOKEN_HOURS)
    return {"token": jwt.encode({"sub": str(u.id), "exp": exp}, SECRET, algorithm="HS256"), "username": u.username}


class PwChange(BaseModel):
    current: str
    new: str


@app.post("/api/auth/password")
def change_pw(b: PwChange, u: User = Depends(current_user), s: Session = Depends(db)):
    if not check_pw(b.current, u.pw):
        raise HTTPException(400, "Current password is incorrect")
    if len(b.new) < 8:
        raise HTTPException(400, "New password must be at least 8 characters")
    u.pw = hash_pw(b.new)
    s.commit()
    return {"ok": True}


# ---------- payments ----------
def norm_phone(p):
    p = re.sub(r"[\s\-+]", "", p)
    if re.fullmatch(r"0[71]\d{8}", p):
        p = "254" + p[1:]
    if not re.fullmatch(r"254[71]\d{8}", p):
        raise HTTPException(400, "Enter a Safaricom number like 0712345678 or 254712345678")
    return p


def norm_status(x):
    x = str(x or "").upper()
    if "." in x:  # PalPluss event_type style, e.g. "transaction.success"
        x = x.rsplit(".", 1)[-1]
    if x in {"SUCCESS", "SUCCESSFUL", "COMPLETED", "PAID"}:
        return "SUCCESS"
    if x in {"FAILED", "CANCELLED", "CANCELED", "TIMEOUT", "EXPIRED", "REJECTED"}:
        return "FAILED"
    return "PENDING"


class Stk(BaseModel):
    phone: str
    amount: float
    description: str = "Payment"


@app.post("/api/stk")
def send_stk(b: Stk, u: User = Depends(current_user), s: Session = Depends(db)):
    if not API_KEY:
        raise HTTPException(500, "PALPLUSS_API_KEY is not set on the server")
    if not 1 <= b.amount <= 250000:
        raise HTTPException(400, "Amount must be between KES 1 and 250,000")
    phone = norm_phone(b.phone)
    ref = f"ORD{uuid.uuid4().hex[:6].upper()}"
    desc = (b.description or "Payment").strip()[:60] or "Payment"
    payload = {"amount": b.amount, "phone": phone, "accountReference": ref,
               "transactionDesc": desc, "callbackUrl": CALLBACK_URL}
    tx = Tx(reference=ref, phone=phone, amount=b.amount, description=desc)
    try:
        r = requests.post(PAL_URL, json=payload, timeout=30,
                          headers={"Authorization": f"Basic {API_KEY}", "Content-Type": "application/json"})
        data = r.json()
    except Exception as e:
        tx.status, tx.result = "FAILED", f"Could not reach PalPluss: {e}"
        s.add(tx); s.commit()
        raise HTTPException(502, tx.result)
    d = data.get("data") or {}
    tx.tx_id = d.get("transactionId")
    tx.checkout_id = d.get("providerCheckoutId")
    tx.result = d.get("resultDescription") or data.get("message") or data.get("error") or ""
    tx.status = norm_status(d.get("status")) if data.get("success") else "FAILED"
    s.add(tx); s.commit()
    if not data.get("success"):
        raise HTTPException(400, tx.result or "PalPluss rejected the request")
    return ser(tx)


@app.post("/api/palpluss/callback")
async def callback(request: Request, token: str = "", s: Session = Depends(db)):
    if CALLBACK_TOKEN and not hmac.compare_digest(token, CALLBACK_TOKEN):
        raise HTTPException(403, "Bad token")
    
    body = await request.json()
    
    # PalPluss wraps transaction details in a "transaction" object, but support "data" or root level as fallbacks
    t_obj = body.get("transaction") or body.get("data") or body
    
    tid = t_obj.get("id") or t_obj.get("transactionId")
    cid = t_obj.get("provider_checkout_id") or t_obj.get("providerCheckoutId")
    ref = t_obj.get("external_reference") or t_obj.get("accountReference")
    
    q = s.query(Tx)
    tx = (
        (q.filter(Tx.tx_id == tid).first() if tid else None) or 
        (q.filter(Tx.checkout_id == cid).first() if cid else None) or
        (q.filter(Tx.reference == ref).first() if ref else None)
    )
    
    if tx:
        # PalPluss uses event_type like "transaction.success", "transaction.failed", etc.
        raw_status = t_obj.get("status") or body.get("event_type")
        tx.status = norm_status(raw_status)
        tx.result = t_obj.get("result_desc") or t_obj.get("resultDescription") or t_obj.get("message") or tx.result
        tx.updated_at = now()
        s.commit()
        
    return {"received": True}


def ser(t):
    return {"id": t.id, "tx_id": t.tx_id, "checkout_id": t.checkout_id, "reference": t.reference,
            "phone": t.phone, "amount": t.amount, "status": t.status, "description": t.description,
            "result": t.result, "created_at": t.created_at.isoformat() + "Z",
            "updated_at": t.updated_at.isoformat() + "Z"}


@app.get("/api/transactions")
def list_tx(page: int = 1, limit: int = Query(15, le=200), q: str = "", status: str = "",
            u: User = Depends(current_user), s: Session = Depends(db)):
    qs = s.query(Tx)
    if status:
        qs = qs.filter(Tx.status == status.upper())
    if q:
        like = f"%{q.strip()}%"
        qs = qs.filter(or_(Tx.phone.ilike(like), Tx.reference.ilike(like), Tx.tx_id.ilike(like)))
    total = qs.count()
    rows = qs.order_by(Tx.id.desc()).offset((max(page, 1) - 1) * limit).limit(limit).all()
    return {"items": [ser(r) for r in rows], "total": total, "page": page, "limit": limit}


@app.get("/api/stats")
def stats(days: int = Query(30, ge=1, le=90), u: User = Depends(current_user), s: Session = Depends(db)):
    t = now()
    start = t - timedelta(days=days)
    rows = s.query(Tx).filter(Tx.created_at >= t - timedelta(days=days * 2)).all()
    cur = [r for r in rows if r.created_at >= start]
    prev_total = sum(r.amount for r in rows if r.created_at < start and r.status == "SUCCESS")
    today = t.date()
    by_day = {today - timedelta(days=i): [0.0, 0] for i in range(days - 1, -1, -1)}
    for r in cur:
        d = by_day.get(r.created_at.date())
        if d:
            d[1] += 1
            if r.status == "SUCCESS":
                d[0] += r.amount
    ok = [r for r in cur if r.status == "SUCCESS"]
    done = [r for r in cur if r.status != "PENDING"]
    total = sum(r.amount for r in ok)
    return {"days": days, "collected": total, "previous": prev_total,
            "collected_today": sum(r.amount for r in ok if r.created_at.date() == today),
            "count": len(cur), "pending": sum(r.status == "PENDING" for r in cur),
            "success_rate": round(len(ok) / len(done) * 100, 1) if done else 0,
            "avg_ticket": round(total / len(ok), 2) if ok else 0,
            "split": {k: sum(r.status == k for r in cur) for k in ("SUCCESS", "PENDING", "FAILED")},
            "series": [{"day": k.isoformat(), "amount": v[0], "count": v[1]} for k, v in by_day.items()],
            "configured": bool(API_KEY), "callback": CALLBACK_URL}


@app.get("/api/customers")
def customers(q: str = "", u: User = Depends(current_user), s: Session = Depends(db)):
    paid = func.sum(case((Tx.status == "SUCCESS", Tx.amount), else_=0))
    qs = s.query(Tx.phone, func.count(Tx.id), paid, func.max(Tx.created_at)).group_by(Tx.phone)
    if q:
        qs = qs.filter(Tx.phone.ilike(f"%{q.strip()}%"))
    rows = qs.order_by(paid.desc()).limit(200).all()
    return {"items": [{"phone": p, "requests": n, "paid": float(a or 0), "last": m.isoformat() + "Z"} for p, n, a, m in rows]}


@app.get("/api/health")
def health():
    return {"ok": True}


@app.get("/")
def root():
    return {"service": "palpluss-collect-api", "ok": True}