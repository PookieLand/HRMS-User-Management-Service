"""Common dependencies for API endpoints."""

from typing import Annotated

from fastapi import Depends
from sqlmodel import Session

from app.core.database import get_session
from app.core.security import (
    TokenData,
    get_current_active_user,
    get_current_user,
    require_role,
)

# Database session dependency
SessionDep = Annotated[Session, Depends(get_session)]

# Current user dependency
CurrentUserDep = Annotated[TokenData, Depends(get_current_active_user)]
