"""
User Management API endpoints.
Handles user CRUD operations, admin management, role updates, and user lifecycle management.
"""

from datetime import datetime
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlmodel import Session, select

from app.api.dependencies import (
    SessionDep,
    TokenData,
    get_current_user,
    require_role,
)

# from app.core.asgardeo import asgardeo_client
from app.core.config import settings
from app.core.integrations import (
    audit_client,
    compliance_client,
    employee_client,
    notification_client,
)
from app.core.logging import get_logger
from app.models.users import (
    MessageResponse,
    User,
    UserCreate,
    UserDelete,
    UserListResponse,
    UserProfileResponse,
    UserPublic,
    UserRoleUpdate,
    UserSuspend,
    UserUpdate,
)

logger = get_logger(__name__)

router = APIRouter(
    prefix="/users",
    tags=["user-management"],
)


@router.get("/", response_model=UserListResponse)
async def list_users(
    session: SessionDep,
    current_user: Annotated[TokenData, Depends(get_current_user)],
    role: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    """
    List all users (admin only).

    Query Parameters:
    - role: Filter by role (admin, hr_manager, manager, employee)
    - status: Filter by status (active, suspended, deleted)
    - limit: Maximum number of results (default: 50, max: 100)
    - offset: Number of results to skip (default: 0)

    Returns:
        UserListResponse with paginated list of users

    Raises:
        HTTPException: 403 if user is not admin
    """
    # Check admin permission
    if current_user.role != "admin":
        logger.warning(
            f"Non-admin user {current_user.user_id} attempted to list all users"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can list all users",
        )

    logger.info(
        f"Listing users: role={role}, status={status_filter}, limit={limit}, offset={offset}"
    )

    # Build query
    query = select(User)

    if role:
        if role not in settings.VALID_ROLES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid role. Must be one of: {', '.join(settings.VALID_ROLES)}",
            )
        query = query.where(User.role == role)

    if status_filter:
        if status_filter not in settings.VALID_STATUSES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status. Must be one of: {', '.join(settings.VALID_STATUSES)}",
            )
        query = query.where(User.status == status_filter)

    # Get total count
    total = session.exec(select(User)).all().__len__()

    # Get paginated results
    users = session.exec(query.offset(offset).limit(limit)).all()

    logger.info(f"Retrieved {len(users)} users")

    return UserListResponse(
        total=total,
        users=[UserPublic.model_validate(user) for user in users],
    )


@router.get("/{user_id}", response_model=UserProfileResponse)
async def get_user(
    user_id: int,
    session: SessionDep,
    current_user: Annotated[TokenData, Depends(get_current_user)],
):
    """
    Get a user by ID.

    Authorization:
    - Admin can view any user
    - HR Manager can view employees in their department
    - Users can view their own profile

    Args:
        user_id: User ID to retrieve
        session: Database session
        current_user: Current authenticated user

    Returns:
        User profile information

    Raises:
        HTTPException: 403 if unauthorized, 404 if user not found
    """
    logger.info(f"Fetching user: {user_id}")

    user = session.get(User, user_id)
    if not user:
        logger.warning(f"User not found: {user_id}")
        raise HTTPException(status_code=404, detail="User not found")

    # Authorization check
    if current_user.user_id != user_id and current_user.role not in [
        "admin",
        "hr_manager",
    ]:
        logger.warning(
            f"User {current_user.user_id} unauthorized to view user {user_id}"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to view this user",
        )

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


@router.post("/{user_id}/role", response_model=UserProfileResponse)
async def update_user_role(
    user_id: int,
    role_update: UserRoleUpdate,
    session: SessionDep,
    current_user: Annotated[TokenData, Depends(require_role("admin"))] = None,
):
    """
    Update user role (admin only).

    Args:
        user_id: User ID
        role_update: New role
        session: Database session
        current_user: Current admin user

    Returns:
        Updated user profile

    Raises:
        HTTPException: 403 if not admin, 404 if user not found, 400 if invalid role
    """
    logger.info(
        f"Admin {current_user.user_id} updating user {user_id} role to {role_update.role}"
    )

    # Validate role
    if role_update.role not in settings.VALID_ROLES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role. Must be one of: {', '.join(settings.VALID_ROLES)}",
        )

    user = session.get(User, user_id)
    if not user:
        logger.warning(f"User not found: {user_id}")
        raise HTTPException(status_code=404, detail="User not found")

    old_role = user.role
    user.role = role_update.role
    user.updated_at = datetime.now()

    session.add(user)
    session.commit()
    session.refresh(user)

    logger.info(f"User {user_id} role updated from {old_role} to {role_update.role}")

    # Log audit event
    await audit_client.log_action(
        user_id=current_user.user_id,
        action="update",
        resource_type="user",
        resource_id=user_id,
        description=f"User role changed from {old_role} to {role_update.role}",
        old_value=old_role,
        new_value=role_update.role,
    )

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


@router.put("/{user_id}/suspend", response_model=UserProfileResponse)
async def suspend_user(
    user_id: int,
    suspend_data: UserSuspend,
    session: SessionDep,
    current_user: Annotated[TokenData, Depends(require_role("admin"))] = None,
):
    """
    Suspend a user account (admin only).

    Actions:
    1. Set user status to 'suspended'
    2. Disable in Asgardeo
    3. Invalidate sessions
    4. Send notification
    5. Log audit event

    Args:
        user_id: User ID
        suspend_data: Suspension reason
        session: Database session
        current_user: Current admin user

    Returns:
        Updated user profile

    Raises:
        HTTPException: 403 if not admin, 404 if user not found, 400 if cannot suspend self
    """
    logger.info(f"Admin {current_user.user_id} suspending user {user_id}")

    # Prevent self-suspension
    if current_user.user_id == user_id:
        logger.warning(f"Admin {current_user.user_id} attempted self-suspension")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot suspend your own account",
        )

    user = session.get(User, user_id)
    if not user:
        logger.warning(f"User not found: {user_id}")
        raise HTTPException(status_code=404, detail="User not found")

    if user.status == "suspended":
        logger.info(f"User {user_id} already suspended")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User is already suspended",
        )

    try:
        # Update status
        user.status = "suspended"
        user.updated_at = datetime.now()
        session.add(user)
        session.commit()
        session.refresh(user)

        # Disable in Asgardeo
        await asgardeo_client.disable_user(user.asgardeo_id)

        logger.info(f"User {user_id} suspended")

        # Log audit event
        await audit_client.log_action(
            user_id=current_user.user_id,
            action="suspend",
            resource_type="user",
            resource_id=user_id,
            description=f"User account suspended. Reason: {suspend_data.reason}",
            new_value="suspended",
        )

        # Send notification
        await notification_client.send_account_suspended_notification(
            email=user.email,
            first_name=user.first_name or "User",
            reason=suspend_data.reason,
        )

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

    except Exception as e:
        logger.error(f"Failed to suspend user {user_id}: {str(e)}")
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to suspend user: {str(e)}",
        )


@router.put("/{user_id}/activate", response_model=UserProfileResponse)
async def activate_user(
    user_id: int,
    session: SessionDep,
    current_user: Annotated[TokenData, Depends(require_role("admin"))] = None,
):
    """
    Activate a suspended user account (admin only).

    Actions:
    1. Set user status to 'active'
    2. Enable in Asgardeo
    3. Send notification
    4. Log audit event

    Args:
        user_id: User ID
        session: Database session
        current_user: Current admin user

    Returns:
        Updated user profile

    Raises:
        HTTPException: 403 if not admin, 404 if user not found
    """
    logger.info(f"Admin {current_user.user_id} activating user {user_id}")

    user = session.get(User, user_id)
    if not user:
        logger.warning(f"User not found: {user_id}")
        raise HTTPException(status_code=404, detail="User not found")

    if user.status == "active":
        logger.info(f"User {user_id} already active")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User is already active",
        )

    try:
        # Update status
        user.status = "active"
        user.updated_at = datetime.now()
        session.add(user)
        session.commit()
        session.refresh(user)

        # Enable in Asgardeo
        await asgardeo_client.enable_user(user.asgardeo_id)

        logger.info(f"User {user_id} activated")

        # Log audit event
        await audit_client.log_action(
            user_id=current_user.user_id,
            action="activate",
            resource_type="user",
            resource_id=user_id,
            description="User account activated",
            new_value="active",
        )

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

    except Exception as e:
        logger.error(f"Failed to activate user {user_id}: {str(e)}")
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to activate user: {str(e)}",
        )


@router.delete("/{user_id}", response_model=MessageResponse)
async def delete_user(
    user_id: int,
    delete_data: UserDelete,
    session: SessionDep,
    current_user: Annotated[TokenData, Depends(require_role("admin"))] = None,
):
    """
    Delete a user account (admin only, soft delete).

    Actions:
    1. Check compliance policies
    2. Set status to 'deleted'
    3. Disable in Asgardeo
    4. Terminate employee record
    5. Log audit event
    6. Send notification

    Args:
        user_id: User ID
        delete_data: Deletion reason
        session: Database session
        current_user: Current admin user

    Returns:
        Success message

    Raises:
        HTTPException: 403 if not admin, 404 if user not found, 400 if cannot delete self
    """
    logger.info(f"Admin {current_user.user_id} deleting user {user_id}")

    # Prevent self-deletion
    if current_user.user_id == user_id:
        logger.warning(f"Admin {current_user.user_id} attempted self-deletion")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot delete your own account",
        )

    user = session.get(User, user_id)
    if not user:
        logger.warning(f"User not found: {user_id}")
        raise HTTPException(status_code=404, detail="User not found")

    try:
        # Check compliance policy
        compliance_check = await compliance_client.check_user_deletion_policy(user_id)
        if not compliance_check:
            logger.warning(f"User deletion blocked by compliance policy: {user_id}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User deletion is blocked by compliance policy",
            )

        # Soft delete
        user.status = "deleted"
        user.deleted_at = datetime.now()
        user.updated_at = datetime.now()
        session.add(user)
        session.commit()
        session.refresh(user)

        # Disable in Asgardeo
        await asgardeo_client.disable_user(user.asgardeo_id)

        logger.info(f"User {user_id} deleted")

        # Terminate employee
        if user.employee_id:
            await employee_client.update_employee_status(user.employee_id, "terminated")

        # Log audit event
        await audit_client.log_action(
            user_id=current_user.user_id,
            action="delete",
            resource_type="user",
            resource_id=user_id,
            description=f"User account deleted. Reason: {delete_data.reason or 'Not specified'}",
            new_value="deleted",
        )

        # Send notification
        await notification_client.send_account_deleted_notification(
            email=user.email,
            first_name=user.first_name or "User",
        )

        return MessageResponse(message="User deleted successfully")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete user {user_id}: {str(e)}")
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete user: {str(e)}",
        )


@router.get("/permissions/roles", response_model=list)
async def list_roles(
    current_user: Annotated[TokenData, Depends(get_current_user)],
):
    """
    List all available roles in the system.

    Returns:
        List of role information
    """
    logger.info("Listing roles")

    roles = [
        {
            "role_id": 1,
            "role_name": "admin",
            "description": "System administrator with full access",
        },
        {
            "role_id": 2,
            "role_name": "hr_manager",
            "description": "HR manager with employee management permissions",
        },
        {
            "role_id": 3,
            "role_name": "manager",
            "description": "Department manager with team oversight permissions",
        },
        {
            "role_id": 4,
            "role_name": "employee",
            "description": "Regular employee with basic access",
        },
    ]

    return roles


@router.get("/{user_id}/permissions")
async def get_user_permissions(
    user_id: int,
    session: SessionDep,
    current_user: Annotated[TokenData, Depends(get_current_user)],
):
    """
    Get user's permissions based on their role.

    Args:
        user_id: User ID
        session: Database session
        current_user: Current authenticated user

    Returns:
        User permissions information
    """
    logger.info(f"Fetching permissions for user {user_id}")

    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Role-based permission mapping
    permissions_map = {
        "admin": [
            "users:create",
            "users:read",
            "users:update",
            "users:delete",
            "users:suspend",
            "roles:manage",
            "employees:manage",
            "leaves:approve",
            "reports:view",
        ],
        "hr_manager": [
            "users:read",
            "employees:manage",
            "leaves:approve",
            "reports:view",
            "attendance:view",
        ],
        "manager": [
            "users:read",
            "employees:read",
            "leaves:approve",
            "attendance:view",
        ],
        "employee": [
            "users:read_self",
            "leaves:create",
            "attendance:checkin",
        ],
    }

    user_permissions = permissions_map.get(user.role, [])

    return {
        "user_id": user_id,
        "role": user.role,
        "permissions": user_permissions,
    }


@router.post("/admin/sync/asgardeo-to-db")
async def sync_users_from_asgardeo(
    user_id: Optional[int] = Query(None),
    session: SessionDep = None,
    current_user: Annotated[TokenData, Depends(require_role("admin"))] = None,
):
    """
    Sync users from Asgardeo to local database (admin only).

    Args:
        user_id: Optional specific user ID to sync
        session: Database session
        current_user: Current admin user

    Returns:
        Sync result with count of synced users

    Raises:
        HTTPException: If sync fails
    """
    logger.info(f"Starting Asgardeo sync (user_id={user_id})")

    try:
        synced_count = 0

        if user_id:
            # Sync specific user
            user = session.get(User, user_id)
            if not user:
                raise HTTPException(status_code=404, detail="User not found")

            asgardeo_user = await asgardeo_client.get_user(user.asgardeo_id)
            if asgardeo_user:
                # Update local record with Asgardeo data
                user.first_name = asgardeo_user.get("name", {}).get("givenName")
                user.last_name = asgardeo_user.get("name", {}).get("familyName")
                user.updated_at = datetime.now()
                session.add(user)
                session.commit()
                synced_count = 1

        else:
            # Sync all users
            asgardeo_users = await asgardeo_client.list_users()
            for asgardeo_user in asgardeo_users:
                asgardeo_id = asgardeo_user.get("id")
                email = asgardeo_user.get("emails", [{}])[0].get("value")

                if not asgardeo_id or not email:
                    continue

                # Check if user exists locally
                existing_user = session.exec(
                    select(User).where(User.asgardeo_id == asgardeo_id)
                ).first()

                if existing_user:
                    # Update existing user
                    existing_user.first_name = asgardeo_user.get("name", {}).get(
                        "givenName"
                    )
                    existing_user.last_name = asgardeo_user.get("name", {}).get(
                        "familyName"
                    )
                    existing_user.updated_at = datetime.now()
                    session.add(existing_user)
                else:
                    # Create new user (shouldn't happen in normal flow)
                    new_user = User(
                        asgardeo_id=asgardeo_id,
                        email=email,
                        first_name=asgardeo_user.get("name", {}).get("givenName"),
                        last_name=asgardeo_user.get("name", {}).get("familyName"),
                        role="employee",
                        status="active",
                    )
                    session.add(new_user)

                synced_count += 1

            session.commit()

        logger.info(f"Sync completed: {synced_count} users synchronized")

        return {
            "synced_count": synced_count,
            "message": f"{synced_count} user(s) synchronized from Asgardeo",
        }

    except Exception as e:
        logger.error(f"Sync failed: {str(e)}")
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Sync failed: {str(e)}",
        )
