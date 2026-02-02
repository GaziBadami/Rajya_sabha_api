from fastapi import Header, HTTPException
from config import API_KEY

def verify_api_key(x_api_key: str = Header(..., description="API Key for authentication")):
    """
    Verify API key from request header
    Users must send: X-API-Key: your-key-here
    """
    if x_api_key != API_KEY:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key"
        )
    return x_api_key