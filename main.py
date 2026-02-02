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

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Rate limiter
limiter = Limiter(key_func=get_remote_address)

# Create FastAPI app
app = FastAPI(
    title=APP_NAME,
    description="Secure API to access Rajya Sabha members data with authentication",
    version=APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add rate limiter to app
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Public endpoints - No authentication required
@app.get("/")
def home():
    """Welcome page - Public access"""
    return {
        "message": f"Welcome to {APP_NAME}",
        "version": APP_VERSION,
        "status": "online",
        "authentication": "Required for all data endpoints",
        "documentation": {
            "swagger": "/docs",
            "redoc": "/redoc"
        },
        "note": "Include 'X-API-Key' header in all requests"
    }

@app.get("/health")
def health_check():
    """Check if API and database are working - Public access"""
    conn = get_database_connection()
    if conn:
        close_connection(conn)
        return {"status": "healthy", "database": "connected"}
    else:
        return {"status": "unhealthy", "database": "disconnected"}

# Protected endpoints - Require API key
@app.get("/members")
@limiter.limit("100/minute")
def get_all_members(
    request: Request,
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(50, ge=1, le=500, description="Items per page"),
    api_key: str = Depends(verify_api_key)
):
    """
    Get all Rajya Sabha members with pagination
    
    **Authentication Required**: Include X-API-Key header
    **Rate Limit**: 100 requests per minute
    """
    
    logger.info(f"GET /members - page={page}, limit={limit}")
    
    conn = get_database_connection()
    if not conn:
        logger.error("Database connection failed")
        raise HTTPException(status_code=500, detail="Database connection failed")
    
    try:
        cursor = conn.cursor(dictionary=True)
        
        # Get total count
        cursor.execute("SELECT COUNT(*) as total FROM members")
        total_count = cursor.fetchone()['total']
        
        # Get paginated data
        offset = (page - 1) * limit
        query = "SELECT * FROM members ORDER BY srno LIMIT %s OFFSET %s"
        cursor.execute(query, (limit, offset))
        data = cursor.fetchall()
        
        cursor.close()
        close_connection(conn)
        
        logger.info(f"Returned {len(data)} members")
        
        return {
            "total": total_count,
            "page": page,
            "limit": limit,
            "total_pages": (total_count + limit - 1) // limit,
            "data": data
        }
    
    except Exception as e:
        logger.error(f"Error in get_all_members: {str(e)}")
        close_connection(conn)
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

@app.get("/members/{srno}")
@limiter.limit("100/minute")
def get_member_by_srno(
    request: Request,
    srno: int,
    api_key: str = Depends(verify_api_key)
):
    """
    Get a specific member by SRNO
    
    **Authentication Required**: Include X-API-Key header
    """
    
    logger.info(f"GET /members/{srno}")
    
    conn = get_database_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")
    
    try:
        cursor = conn.cursor(dictionary=True)
        
        query = "SELECT * FROM members WHERE srno = %s"
        cursor.execute(query, (srno,))
        data = cursor.fetchone()
        
        cursor.close()
        close_connection(conn)
        
        if not data:
            raise HTTPException(status_code=404, detail="Member not found")
        
        return data
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_member_by_srno: {str(e)}")
        close_connection(conn)
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

@app.get("/members/name/{member_name}")
@limiter.limit("100/minute")
def get_members_by_name(
    request: Request,
    member_name: str,
    api_key: str = Depends(verify_api_key)
):
    """
    Search members by name (partial match)
    
    **Authentication Required**: Include X-API-Key header
    """
    
    logger.info(f"GET /members/name/{member_name}")
    
    conn = get_database_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")
    
    try:
        cursor = conn.cursor(dictionary=True)
        
        query = "SELECT * FROM members WHERE member_name LIKE %s"
        cursor.execute(query, (f"%{member_name}%",))
        data = cursor.fetchall()
        
        cursor.close()
        close_connection(conn)
        
        return {
            "count": len(data),
            "data": data
        }
    
    except Exception as e:
        logger.error(f"Error in get_members_by_name: {str(e)}")
        close_connection(conn)
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

@app.get("/members/state/{state_ut}")
@limiter.limit("100/minute")
def get_members_by_state(
    request: Request,
    state_ut: str,
    api_key: str = Depends(verify_api_key)
):
    """
    Get members by State/UT
    
    **Authentication Required**: Include X-API-Key header
    """
    
    logger.info(f"GET /members/state/{state_ut}")
    
    conn = get_database_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")
    
    try:
        cursor = conn.cursor(dictionary=True)
        
        query = "SELECT * FROM members WHERE state_ut = %s ORDER BY member_name"
        cursor.execute(query, (state_ut,))
        data = cursor.fetchall()
        
        cursor.close()
        close_connection(conn)
        
        return {
            "state_ut": state_ut,
            "count": len(data),
            "data": data
        }
    
    except Exception as e:
        logger.error(f"Error in get_members_by_state: {str(e)}")
        close_connection(conn)
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

@app.get("/members/party/{party}")
@limiter.limit("100/minute")
def get_members_by_party(
    request: Request,
    party: str,
    api_key: str = Depends(verify_api_key)
):
    """
    Get members by Party
    
    **Authentication Required**: Include X-API-Key header
    """
    
    logger.info(f"GET /members/party/{party}")
    
    conn = get_database_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")
    
    try:
        cursor = conn.cursor(dictionary=True)
        
        query = "SELECT * FROM members WHERE party LIKE %s ORDER BY member_name"
        cursor.execute(query, (f"%{party}%",))
        data = cursor.fetchall()
        
        cursor.close()
        close_connection(conn)
        
        return {
            "party": party,
            "count": len(data),
            "data": data
        }
    
    except Exception as e:
        logger.error(f"Error in get_members_by_party: {str(e)}")
        close_connection(conn)
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

@app.get("/members/status/{status}")
@limiter.limit("100/minute")
def get_members_by_status(
    request: Request,
    status: str,
    api_key: str = Depends(verify_api_key)
):
    """
    Get members by Status (Active/Inactive)
    
    **Authentication Required**: Include X-API-Key header
    """
    
    logger.info(f"GET /members/status/{status}")
    
    conn = get_database_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")
    
    try:
        cursor = conn.cursor(dictionary=True)
        
        query = "SELECT * FROM members WHERE status = %s ORDER BY member_name"
        cursor.execute(query, (status,))
        data = cursor.fetchall()
        
        cursor.close()
        close_connection(conn)
        
        return {
            "status": status,
            "count": len(data),
            "data": data
        }
    
    except Exception as e:
        logger.error(f"Error in get_members_by_status: {str(e)}")
        close_connection(conn)
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")