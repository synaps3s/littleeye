import os
import logging
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from littleeye.dashboard.db import verify_agent_token

logger = logging.getLogger("littleeye.dashboard.auth")

DB_PATH = os.environ.get("LITTLEEYE_DB_PATH", "data/littleeye.db")

security = HTTPBearer()


async def get_agent(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    token = credentials.credentials
    if not await verify_agent_token(DB_PATH, token):
        logger.warning(f"Unauthorized API request using token suffix: ...{token[-4:] if len(token) > 4 else token}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid agent token"
        )
    return token
