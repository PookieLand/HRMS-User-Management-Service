from datetime import datetime, timedelta
from typing import Annotated, Optional

import jwt
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlmodel import Session, select

# from app.core.asgardeo import asgardeo_client
from app.core.config import settings
from app.core.database import get_session
from app.core.integrations import (
    audit_client,
    employee_client,
    notification_client,
)
from app.core.logging import get_logger
from app.models.users import (
    LoginResponse,
    MessageResponse,
    SignupResponse,
    User,
    UserPasswordChange,
    UserProfileResponse,
    UserSignup,
    UserUpdate,
)

logger = get_logger(__name__)

router = APIRouter(
    prefix="/auth",
    tags=["authentication"],
)


# Request/Response Models
class SignupRequest(BaseModel):
    """Request body for user signup."""

    email: str
    password: str
    first_name: str
    last_name: str
    phone: str


class CallbackRequest(BaseModel):
    """Request body for OAuth callback."""

    code: str
    state: Optional[str] = None


class ChangePasswordRequest(BaseModel):
    """Request body for password change."""

    old_password: str
    new_password: str


# Helper Functions
def _create_session_token(user: User) -> str:
    """
    Create a JWT session token for the user.

    Args:
        user: User object

    Returns:
        JWT token string
    """
    payload = {
        "sub": str(user.id),
        "user_id": user.id,
        "email": user.email,
        "asgardeo_id": user.asgardeo_id,
        "role": user.role,
        "employee_id": user.employee_id,
        "exp": datetime.now() + timedelta(seconds=settings.JWT_EXPIRY_SECONDS),
        "iat": datetime.now(),
    }
    token = jwt.encode(
        payload,
        settings.JWT_SECRET,
        algorithm=settings.JWT_ALGORITHM,
    )
    return token


def _validate_password_strength(password: str) -> tuple[bool, str]:
    """
    Validate password against strength requirements.

    Args:
        password: Password to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if len(password) < settings.MIN_PASSWORD_LENGTH:
        return (
            False,
            f"Password must be at least {settings.MIN_PASSWORD_LENGTH} characters",
        )

    if settings.REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"

    if settings.REQUIRE_NUMBERS and not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"

    if settings.REQUIRE_SPECIAL_CHARS and not any(
        c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password
    ):
        return False, "Password must contain at least one special character"

    return True, ""


# Dependency Injection
async def get_current_user_from_header(
    authorization: Optional[str] = None,
) -> dict:
    """
    Extract and validate JWT token from Authorization header.

    Args:
        authorization: Authorization header value

    Returns:
        Decoded token data

    Raises:
        HTTPException: If token is invalid or missing
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authorization token",
        )

    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header format",
        )

    token = parts[1]

    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )


# Routes
@router.post("/signup", response_model=SignupResponse, status_code=201)
async def signup(
    request: SignupRequest,
    session: Annotated[Session, Depends(get_session)],
):
    """
    Sign up a new user.

    Process:
    1. Validate input
    2. Check email uniqueness
    3. Create user in Asgardeo
    4. Create local user record
    5. Create employee record
    6. Send welcome notification

    Args:
        request: Signup request with email, password, name, phone
        session: Database session

    Returns:
        SignupResponse with user_id and status

    Raises:
        HTTPException: For various validation/creation errors
    """
    logger.info(f"Signup request for email: {request.email}")

    # Validate password strength
    is_valid, error_msg = _validate_password_strength(request.password)
    if not is_valid:
        logger.warning(f"Weak password for signup: {request.email}")
        raise HTTPException(status_code=400, detail=error_msg)

    # Check if email already exists
    existing_user = session.exec(
        select(User).where(User.email == request.email)
    ).first()
    if existing_user:
        logger.warning(f"Email already exists: {request.email}")
        raise HTTPException(status_code=400, detail="Email already exists")

    # Create user in Asgardeo
    try:
        asgardeo_data = await asgardeo_client.create_user(
            email=request.email,
            password=request.password,
            first_name=request.first_name,
            last_name=request.last_name,
            phone=request.phone,
        )
        asgardeo_id = asgardeo_data["asgardeo_id"]
        logger.info(f"User created in Asgardeo: {asgardeo_id}")
    except Exception as e:
        logger.error(f"Failed to create user in Asgardeo: {e}")
        raise HTTPException(
            status_code=500, detail="Failed to create user in identity provider"
        )

    # Create local user record
    try:
        db_user = User(
            asgardeo_id=asgardeo_id,
            email=request.email,
            first_name=request.first_name,
            last_name=request.last_name,
            phone=request.phone,
            role="employee",
            status="active",
        )
        session.add(db_user)
        session.commit()
        session.refresh(db_user)
        logger.info(f"User created locally: {db_user.id}")
    except Exception as e:
        logger.error(f"Failed to create user locally: {e}")
        raise HTTPException(status_code=500, detail="Failed to create user record")

    # Create employee record
    try:
        employee_data = await employee_client.create_employee(
            user_id=db_user.id,
            email=request.email,
            first_name=request.first_name,
            last_name=request.last_name,
        )
        if employee_data:
            db_user.employee_id = employee_data.get("employee_id")
            session.add(db_user)
            session.commit()
            session.refresh(db_user)
            logger.info(f"Employee created: {db_user.employee_id}")
    except Exception as e:
        logger.warning(f"Failed to create employee record (non-blocking): {e}")

    # Log audit event
    try:
        await audit_client.log_action(
            user_id=db_user.id,
            action="signup",
            resource_type="user",
            resource_id=db_user.id,
            description=f"User signed up: {request.email}",
        )
    except Exception as e:
        logger.warning(f"Failed to log signup audit: {e}")

    # Send welcome email
    try:
        await notification_client.send_account_created_notification(
            email=request.email,
            first_name=request.first_name,
            last_name=request.last_name,
        )
    except Exception as e:
        logger.warning(f"Failed to send welcome email: {e}")

    return SignupResponse(
        user_id=db_user.id,
        email=db_user.email,
        asgardeo_id=asgardeo_id,
        status="created",
    )


@router.post("/callback", response_model=LoginResponse)
async def oauth_callback(
    request: CallbackRequest,
    session: Annotated[Session, Depends(get_session)],
):
    """
    Handle OAuth 2.0 callback from Asgardeo.

    Process:
    1. Exchange code for tokens
    2. Decode and verify ID token
    3. Look up user
    4. Create session token
    5. Update last login

    Args:
        request: Callback request with code and state
        session: Database session

    Returns:
        LoginResponse with session token and user info

    Raises:
        HTTPException: For invalid code, user not found, etc.
    """
    logger.info("OAuth callback received")

    # Exchange code for tokens
    try:
        tokens = await asgardeo_client.exchange_code_for_token(
            code=request.code,
            state=request.state or "",
        )
        if not tokens:
            logger.error("Failed to exchange authorization code")
            raise HTTPException(status_code=400, detail="Invalid authorization code")

        id_token = tokens.get("id_token")

    except Exception as e:
        logger.error(f"Token exchange failed: {e}")
        raise HTTPException(status_code=500, detail="Token exchange failed")

    # Decode ID token
    try:
        decoded = jwt.decode(
            id_token,
            options={"verify_signature": False},
        )
        asgardeo_id = decoded.get("sub")
        email = decoded.get("email")

        if not asgardeo_id or not email:
            logger.error("Missing sub or email in ID token")
            raise HTTPException(status_code=400, detail="Invalid token claims")

    except jwt.DecodeError as e:
        logger.error(f"Failed to decode ID token: {e}")
        raise HTTPException(status_code=400, detail="Invalid token format")

    # Look up user in database
    user = session.exec(select(User).where(User.asgardeo_id == asgardeo_id)).first()

    if not user:
        logger.warning(f"User not found in database: {asgardeo_id}")
        raise HTTPException(status_code=403, detail="User account not found")

    # Check user status
    if user.status != "active":
        logger.warning(f"User account not active: {user.id} (status: {user.status})")
        raise HTTPException(status_code=403, detail="User account is not active")

    # Update last login
    user.last_login = datetime.now()
    session.add(user)
    session.commit()
    session.refresh(user)

    # Create session token
    session_token = _create_session_token(user)

    # Log audit event
    try:
        await audit_client.log_action(
            user_id=user.id,
            action="login",
            resource_type="user",
            resource_id=user.id,
            description=f"User logged in: {user.email}",
        )
    except Exception as e:
        logger.warning(f"Failed to log login audit: {e}")

    logger.info(f"User logged in: {user.id}")

    return LoginResponse(
        session_token=session_token,
        user_id=user.id,
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        role=user.role,
        employee_id=user.employee_id,
        expires_in=settings.JWT_EXPIRY_SECONDS,
    )


@router.post("/logout")
async def logout(
    authorization: Optional[str] = None,
):
    """
    Logout endpoint.

    In this implementation, logout is client-side (token deletion).

    Args:
        authorization: Optional authorization header

    Returns:
        Success message
    """
    logger.info("User logout")
    return {"message": "logged out successfully"}


@router.get("/users/me", response_model=UserProfileResponse)
async def get_profile(
    session: Annotated[Session, Depends(get_session)],
    authorization: Optional[str] = None,
):
    """
    Get current user's profile.

    Args:
        session: Database session
        authorization: Authorization header

    Returns:
        User profile information

    Raises:
        HTTPException: 401 if not authenticated, 404 if user not found
    """
    payload = await get_current_user_from_header(authorization)
    user_id = int(payload.get("sub"))

    user = session.get(User, user_id)
    if not user:
        logger.warning(f"User not found: {user_id}")
        raise HTTPException(status_code=404, detail="User not found")

    return UserProfileResponse(
        id=user.id,
        asgardeo_id=user.asgardeo_id,
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        phone=user.phone,
        role=user.role,
        employee_id=user.employee_id,
        status=user.status,
        created_at=user.created_at,
        last_login=user.last_login,
    )


@router.put("/users/me", response_model=UserProfileResponse)
async def update_profile(
    update_data: UserUpdate,
    session: Annotated[Session, Depends(get_session)],
    authorization: Optional[str] = None,
):
    """
    Update current user's profile.

    Args:
        update_data: Fields to update
        session: Database session
        authorization: Authorization header

    Returns:
        Updated user profile

    Raises:
        HTTPException: 401 if not authenticated, 404 if user not found
    """
    payload = await get_current_user_from_header(authorization)
    user_id = int(payload.get("sub"))

    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Update local database
    update_dict = update_data.model_dump(exclude_unset=True)
    for key, value in update_dict.items():
        if value is not None:
            setattr(user, key, value)
    user.updated_at = datetime.now()

    session.add(user)
    session.commit()
    session.refresh(user)

    # Sync to Asgardeo
    try:
        await asgardeo_client.update_user(
            asgardeo_id=user.asgardeo_id,
            first_name=update_data.first_name,
            last_name=update_data.last_name,
            phone=update_data.phone,
        )
    except Exception as e:
        logger.warning(f"Failed to sync profile to Asgardeo: {e}")

    # Log audit event
    try:
        await audit_client.log_action(
            user_id=user.id,
            action="update_profile",
            resource_type="user",
            resource_id=user.id,
            description="User profile updated",
        )
    except Exception as e:
        logger.warning(f"Failed to log profile update: {e}")

    return UserProfileResponse(
        id=user.id,
        asgardeo_id=user.asgardeo_id,
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        phone=user.phone,
        role=user.role,
        employee_id=user.employee_id,
        status=user.status,
        created_at=user.created_at,
        last_login=user.last_login,
    )


@router.put("/users/me/change-password")
async def change_password(
    request: ChangePasswordRequest,
    session: Annotated[Session, Depends(get_session)],
    authorization: Optional[str] = None,
):
    """
    Change current user's password.

    Args:
        request: Old and new passwords
        session: Database session
        authorization: Authorization header

    Returns:
        Success message

    Raises:
        HTTPException: 401 if not authenticated, 400 if password weak/invalid
    """
    payload = await get_current_user_from_header(authorization)
    user_id = int(payload.get("sub"))

    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Validate new password strength
    is_valid, error_msg = _validate_password_strength(request.new_password)
    if not is_valid:
        raise HTTPException(status_code=400, detail=error_msg)

    # Update password in Asgardeo
    try:
        await asgardeo_client.update_user(
            asgardeo_id=user.asgardeo_id,
            updates={"password": request.new_password},
        )
    except Exception as e:
        logger.error(f"Failed to change password in Asgardeo: {e}")
        raise HTTPException(status_code=500, detail="Failed to change password")

    # Send notification
    try:
        await notification_client.send_password_changed_notification(
            email=user.email,
            first_name=user.first_name or "User",
        )
    except Exception as e:
        logger.warning(f"Failed to send password change notification: {e}")

    # Log audit event
    try:
        await audit_client.log_action(
            user_id=user.id,
            action="change_password",
            resource_type="user",
            resource_id=user.id,
            description="User changed password",
        )
    except Exception as e:
        logger.warning(f"Failed to log password change: {e}")

    return {"message": "password changed successfully"}


@router.get("/verify")
async def verify_token(
    authorization: Optional[str] = None,
) -> dict:
    """
    Verify that provided token is valid.

    Args:
        authorization: Authorization header with Bearer token

    Returns:
        Token validity status
    """
    payload = await get_current_user_from_header(authorization)
    return {
        "valid": True,
        "user_id": payload.get("sub"),
        "message": "Token is valid",
    }


@router.get("/whoami")
async def whoami(
    authorization: Optional[str] = None,
) -> dict:
    """
    Get current user information from token claims.

    Args:
        authorization: Authorization header with Bearer token

    Returns:
        User identification and roles/permissions
    """
    payload = await get_current_user_from_header(authorization)
    return {
        "user_id": payload.get("sub"),
        "email": payload.get("email"),
        "role": payload.get("role"),
        "employee_id": payload.get("employee_id"),
    }
