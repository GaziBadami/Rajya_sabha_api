from fastapi import FastAPI, Query, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional
from database import get_database_connection, close_connection
from auth import verify_api_key
from config import APP_NAME, APP_VERSION
import logging
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# ---------------- LOGGING ----------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# ---------------- RATE LIMIT ----------------
limiter = Limiter(key_func=get_remote_address)

# ---------------- APP ----------------
app = FastAPI(
    title=APP_NAME,
    description="Rajya Sabha Public Data API",
    version=APP_VERSION
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ---------------- CORS ----------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- PUBLIC ----------------
@app.get("/")
def home():
    return {
        "message": f"Welcome to {APP_NAME}",
        "version": APP_VERSION,
        "docs": "/docs"
    }

@app.get("/health")
def health():
    conn = get_database_connection()
    if conn:
        close_connection(conn)
        return {"status": "healthy"}
    return {"status": "unhealthy"}

# =====================================================
# MEMBERS
# =====================================================
@app.get("/members")
@limiter.limit("100/minute")
def members(
    request: Request,
    page: int = 1,
    limit: int = 50,
    api_key: str = Depends(verify_api_key)
):
    conn = get_database_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT COUNT(*) total FROM members")
    total = cursor.fetchone()["total"]

    offset = (page - 1) * limit
    cursor.execute(
        "SELECT * FROM members ORDER BY srno LIMIT %s OFFSET %s",
        (limit, offset)
    )
    data = cursor.fetchall()

    cursor.close()
    close_connection(conn)

    return {"total": total, "page": page, "data": data}

@app.get("/members/{srno}")
@limiter.limit("100/minute")
def member(srno: int, request: Request, api_key: str = Depends(verify_api_key)):
    conn = get_database_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM members WHERE srno=%s", (srno,))
    data = cursor.fetchone()

    cursor.close()
    close_connection(conn)

    if not data:
        raise HTTPException(404, "Member not found")
    return data

# =====================================================
# GENERIC TABLE FETCHER
# =====================================================
def fetch_table(table: str, srno: Optional[int] = None):
    conn = get_database_connection()
    cursor = conn.cursor(dictionary=True)

    if srno:
        cursor.execute(f"SELECT * FROM {table} WHERE srno=%s", (srno,))
    else:
        cursor.execute(f"SELECT * FROM {table}")

    data = cursor.fetchall()
    cursor.close()
    close_connection(conn)
    return {"count": len(data), "data": data}

# =====================================================
# OTHER TABLES
# =====================================================
@app.get("/assurance")
def assurance(request: Request, srno: Optional[int] = None, api_key: str = Depends(verify_api_key)):
    return fetch_table("assurance", srno)

@app.get("/education-levels")
def education_levels(request: Request, srno: Optional[int] = None, api_key: str = Depends(verify_api_key)):
    return fetch_table("education_levels", srno)

@app.get("/gallery")
def gallery(request: Request, srno: Optional[int] = None, api_key: str = Depends(verify_api_key)):
    return fetch_table("gallery", srno)

@app.get("/member-attendance")
def member_attendance(request: Request, srno: Optional[int] = None, api_key: str = Depends(verify_api_key)):
    return fetch_table("member_attendance", srno)

@app.get("/member-bills")
def member_bills(request: Request, srno: Optional[int] = None, api_key: str = Depends(verify_api_key)):
    return fetch_table("member_bills", srno)

@app.get("/member-committees")
def member_committees(request: Request, srno: Optional[int] = None, api_key: str = Depends(verify_api_key)):
    return fetch_table("member_committees", srno)

@app.get("/member-dashboard")
def member_dashboard(request: Request, srno: Optional[int] = None, api_key: str = Depends(verify_api_key)):
    return fetch_table("member_dashboard", srno)

@app.get("/member-debates")
def member_debates(request: Request, srno: Optional[int] = None, api_key: str = Depends(verify_api_key)):
    return fetch_table("member_debates", srno)

@app.get("/member-other-details")
def member_other_details(request: Request, srno: Optional[int] = None, api_key: str = Depends(verify_api_key)):
    return fetch_table("member_other_details", srno)

@app.get("/member-personal-details")
def member_personal_details(request: Request, srno: Optional[int] = None, api_key: str = Depends(verify_api_key)):
    return fetch_table("member_personal_details", srno)

@app.get("/member-questions")
def member_questions(request: Request, srno: Optional[int] = None, api_key: str = Depends(verify_api_key)):
    return fetch_table("member_questions", srno)

@app.get("/member-special-mentions")
def member_special_mentions(
    request: Request,
    srno: Optional[int] = None,
    api_key: str = Depends(verify_api_key)
):
    return fetch_table("member_special_mentions", srno)

@app.get("/mp-tour")
def mp_tour(
    request: Request,
    srno: Optional[int] = None,
    api_key: str = Depends(verify_api_key)
):
    return fetch_table("mp_tour", srno)

