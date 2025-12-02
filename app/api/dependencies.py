from typing import Annotated

from fastapi import Depends
from sqlmodel import Session

from app.core.database import get_session
from app.core.security import (
    TokenData,
    get_current_user,
    get_current_active_user,
    require_role,
    require_permission,
    require_all_roles,
)

# Database session dependency
SessionDep = Annotated[Session, Depends(get_session)]

# Current user dependencies
CurrentUserDep = Annotated[TokenData, Depends(get_current_active_user)]

# Re-export security functions for convenience
__all__ = [
    "SessionDep",
    "CurrentUserDep",
    "TokenData",
    "get_current_user",
    "get_current_active_user",
    "require_role",
    "require_permission",
    "require_all_roles",
]
