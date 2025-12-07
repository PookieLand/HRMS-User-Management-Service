"""
User management API endpoints.

Provides CRUD operations for users with proper RBAC enforcement.
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
from app.core.asgardeo import asgardeo_service
from app.core.cache import (
    cache_user_profile,
    get_cached_user_profile,
    invalidate_user_cache,
)
from app.core.config import settings
from app.core.events import (
    EventType,
    UserActivatedEvent,
    UserDeletedEvent,
    UserRoleChangedEvent,
    UserSuspendedEvent,
    create_event,
)
from app.core.integrations import (
    audit_client,
    compliance_client,
    employee_client,
    notification_client,
)
from app.core.kafka import publish_event
from app.core.logging import get_logger
from app.core.rbac import RBACManager, get_highest_role
from app.core.topics import KafkaTopics
from app.models.users import (
    MessageResponse,
    User,
    UserDelete,
    UserListResponse,
    UserProfileResponse,
    UserPublic,
    UserRoleUpdate,
    UserSuspend,
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
    List all users with optional filters.

    Authorization:
    - HR_Admin: Can list all users
    - HR_Manager: Can list manager and employee users (not other HR_Managers)
    - manager: Can list employees in their team only
    - employee: Cannot list users

    Query Parameters:
    - role: Filter by role (HR_Admin, HR_Manager, manager, employee)
    - status: Filter by status (active, suspended, deleted)
    - limit: Maximum number of results (default: 50, max: 100)
    - offset: Number of results to skip (default: 0)

    Returns:
        UserListResponse with paginated list of users
    """
    actor_role = get_highest_role(current_user.roles)

    # RBAC check
    if actor_role not in ["HR_Admin", "HR_Manager", "admin"]:
        logger.warning(
            f"User {current_user.sub} ({actor_role}) attempted to list all users"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only HR Admin and HR Manager can list users",
        )

    logger.info(
        f"Listing users: role={role}, status={status_filter}, limit={limit}, offset={offset}"
    )

    # Build query
    query = select(User)

    # Filter by role
    if role:
        if role not in settings.ROLES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid role. Must be one of: {', '.join(settings.ROLES)}",
            )
        query = query.where(User.role == role)

    # Filter by status
    if status_filter:
        if status_filter not in settings.USER_STATUSES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status. Must be one of: {', '.join(settings.USER_STATUSES)}",
            )
        query = query.where(User.status == status_filter)

    # HR_Manager cannot see other HR_Managers
    if actor_role == "HR_Manager":
        query = query.where(User.role != "HR_Admin")

    # Get total count
    total = len(session.exec(query).all())

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
    - HR_Admin: Can view any user
    - HR_Manager: Can view users except other HR_Managers
    - manager: Can view employees in their team
    - employee: Can view only their own profile

    Args:
        user_id: User ID to retrieve
        session: Database session
        current_user: Current authenticated user

    Returns:
        User profile information
    """
    logger.info(f"Fetching user: {user_id}")

    actor_role = get_highest_role(current_user.roles)

    # Try to get from cache first
    cached_profile = await get_cached_user_profile(user_id)
    if cached_profile:
        logger.debug(f"Returning cached profile for user {user_id}")
        # Still need to do RBAC check
        target_role = cached_profile.get("role")
        if actor_role == "HR_Manager" and target_role in ["HR_Admin", "HR_Manager"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="HR Manager cannot view HR Admin or other HR Manager profiles",
            )
        return UserProfileResponse(**cached_profile)

    user = session.get(User, user_id)
    if not user:
        logger.warning(f"User not found: {user_id}")
        raise HTTPException(status_code=404, detail="User not found")

    # Get actor's user record to check if accessing own profile
    actor_user = session.exec(
        select(User).where(User.asgardeo_id == current_user.sub)
    ).first()

    # RBAC check
    if actor_role not in ["HR_Admin", "admin"]:
        # Allow users to view their own profile
        if actor_user and actor_user.id == user_id:
            pass
        elif actor_role == "HR_Manager":
            # HR_Manager cannot view HR_Admin or other HR_Manager
            if user.role in ["HR_Admin", "HR_Manager"]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="HR Manager cannot view HR Admin or other HR Manager profiles",
                )
        elif actor_role == "manager":
            # manager can only view employees
            if user.role != "employee":
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Manager can only view employee profiles",
                )
        else:
            # employee can only view own profile
            if not actor_user or actor_user.id != user_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="You can only view your own profile",
                )

    profile_response = UserProfileResponse(
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
        updated_at=user.updated_at,
        last_login=user.last_login,
    )

    # Cache the profile
    await cache_user_profile(user_id, profile_response.model_dump(mode="json"))

    return profile_response


@router.put("/{user_id}/role", response_model=UserProfileResponse)
async def update_user_role(
    user_id: int,
    role_update: UserRoleUpdate,
    session: SessionDep,
    current_user: Annotated[TokenData, Depends(get_current_user)],
):
    """
    Update user role.

    Authorization:
    - HR_Admin: Can change any user's role to any role
    - HR_Manager: Can change manager and employee roles (not to HR_Admin or HR_Manager)
    - Others: Cannot change roles

    Args:
        user_id: User ID
        role_update: New role
        session: Database session
        current_user: Current user

    Returns:
        Updated user profile
    """
    actor_role = get_highest_role(current_user.roles)

    logger.info(
        f"User {current_user.sub} ({actor_role}) updating user {user_id} role to {role_update.role}"
    )

    # Only HR_Admin and HR_Manager can change roles
    if actor_role not in ["HR_Admin", "HR_Manager", "admin"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only HR Admin and HR Manager can change user roles",
        )

    # Validate new role
    if role_update.role not in settings.ROLES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role. Must be one of: {', '.join(settings.ROLES)}",
        )

    user = session.get(User, user_id)
    if not user:
        logger.warning(f"User not found: {user_id}")
        raise HTTPException(status_code=404, detail="User not found")

    # HR_Manager restrictions
    if actor_role == "HR_Manager":
        # Cannot change HR_Admin or other HR_Manager
        if user.role in ["HR_Admin", "HR_Manager"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="HR Manager cannot change HR Admin or other HR Manager roles",
            )
        # Cannot promote to HR_Admin or HR_Manager
        if role_update.role in ["HR_Admin", "HR_Manager"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="HR Manager cannot assign HR Admin or HR Manager roles",
            )

    old_role = user.role
    user.role = role_update.role
    user.updated_at = datetime.now()

    session.add(user)
    session.commit()
    session.refresh(user)

    logger.info(f"User {user_id} role updated from {old_role} to {role_update.role}")

    # Get actor's user ID
    actor_user = session.exec(
        select(User).where(User.asgardeo_id == current_user.sub)
    ).first()
    actor_user_id = actor_user.id if actor_user else 0

    # Publish Kafka event
    try:
        event_data = UserRoleChangedEvent(
            user_id=user.id,
            email=user.email,
            old_role=old_role,
            new_role=role_update.role,
            changed_by=actor_user_id,
        )
        event = create_event(
            EventType.USER_ROLE_CHANGED,
            event_data,
            actor_user_id=str(actor_user_id),
            actor_role=actor_role,
        )
        await publish_event(KafkaTopics.USER_ROLE_CHANGED, event)
        logger.info(f"Published role change event for user {user_id}")
    except Exception as e:
        logger.warning(f"Failed to publish role change event: {e}")

    # Update role in Asgardeo
    try:
        # Remove old role
        await asgardeo_service.remove_role(user.asgardeo_id, old_role)
        # Assign new role
        await asgardeo_service.assign_role(user.asgardeo_id, role_update.role)
        logger.info(f"Updated role in Asgardeo for user {user_id}")
    except Exception as e:
        logger.warning(f"Failed to update role in Asgardeo: {e}")

    # Log audit event
    try:
        await audit_client.log_action(
            user_id=actor_user_id,
            action="update_role",
            resource_type="user",
            resource_id=user_id,
            description=f"User role changed from {old_role} to {role_update.role}",
            old_value=old_role,
            new_value=role_update.role,
        )
    except Exception as e:
        logger.warning(f"Failed to log audit event: {e}")

    # Invalidate cache
    await invalidate_user_cache(user_id)

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
        updated_at=user.updated_at,
        last_login=user.last_login,
    )


@router.put("/{user_id}/suspend", response_model=UserProfileResponse)
async def suspend_user(
    user_id: int,
    suspend_data: UserSuspend,
    session: SessionDep,
    current_user: Annotated[TokenData, Depends(get_current_user)],
):
    """
    Suspend a user account.

    Authorization:
    - HR_Admin: Can suspend anyone except themselves
    - HR_Manager: Can suspend manager and employee (not HR_Admin or HR_Manager)

    Actions:
    1. Set user status to 'suspended'
    2. Disable in Asgardeo
    3. Send notification
    4. Log audit event
    """
    actor_role = get_highest_role(current_user.roles)

    logger.info(f"User {current_user.sub} ({actor_role}) suspending user {user_id}")

    # Only HR roles can suspend
    if actor_role not in ["HR_Admin", "HR_Manager", "admin"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only HR Admin and HR Manager can suspend users",
        )

    # Get actor's user record
    actor_user = session.exec(
        select(User).where(User.asgardeo_id == current_user.sub)
    ).first()
    actor_user_id = actor_user.id if actor_user else 0

    # Prevent self-suspension
    if actor_user and actor_user.id == user_id:
        logger.warning(f"User {current_user.sub} attempted self-suspension")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot suspend your own account",
        )

    user = session.get(User, user_id)
    if not user:
        logger.warning(f"User not found: {user_id}")
        raise HTTPException(status_code=404, detail="User not found")

    # HR_Manager restrictions
    if actor_role == "HR_Manager":
        if user.role in ["HR_Admin", "HR_Manager"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="HR Manager cannot suspend HR Admin or other HR Manager",
            )

    if user.status == "suspended":
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
        try:
            await asgardeo_service.disable_user(user.asgardeo_id)
        except Exception as e:
            logger.warning(f"Failed to disable user in Asgardeo: {e}")

        logger.info(f"User {user_id} suspended")

        # Publish Kafka event
        try:
            event_data = UserSuspendedEvent(
                user_id=user.id,
                email=user.email,
                suspended_by=actor_user_id,
                reason=suspend_data.reason,
            )
            event = create_event(
                EventType.USER_SUSPENDED,
                event_data,
                actor_user_id=str(actor_user_id),
                actor_role=actor_role,
            )
            await publish_event(KafkaTopics.USER_SUSPENDED, event)
        except Exception as e:
            logger.warning(f"Failed to publish suspend event: {e}")

        # Log audit event
        try:
            await audit_client.log_action(
                user_id=actor_user_id,
                action="suspend",
                resource_type="user",
                resource_id=user_id,
                description=f"User account suspended. Reason: {suspend_data.reason}",
                new_value="suspended",
            )
        except Exception as e:
            logger.warning(f"Failed to log audit event: {e}")

        # Send notification
        try:
            await notification_client.send_account_suspended_notification(
                email=user.email,
                first_name=user.first_name or "User",
                reason=suspend_data.reason,
            )
        except Exception as e:
            logger.warning(f"Failed to send suspension notification: {e}")

        # Invalidate cache
        await invalidate_user_cache(user_id)

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
            updated_at=user.updated_at,
            last_login=user.last_login,
        )

    except HTTPException:
        raise
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
    current_user: Annotated[TokenData, Depends(get_current_user)],
):
    """
    Activate a suspended user account.

    Authorization:
    - HR_Admin: Can activate anyone
    - HR_Manager: Can activate manager and employee (not HR_Admin or HR_Manager)

    Actions:
    1. Set user status to 'active'
    2. Enable in Asgardeo
    3. Log audit event
    """
    actor_role = get_highest_role(current_user.roles)

    logger.info(f"User {current_user.sub} ({actor_role}) activating user {user_id}")

    # Only HR roles can activate
    if actor_role not in ["HR_Admin", "HR_Manager", "admin"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only HR Admin and HR Manager can activate users",
        )

    user = session.get(User, user_id)
    if not user:
        logger.warning(f"User not found: {user_id}")
        raise HTTPException(status_code=404, detail="User not found")

    # HR_Manager restrictions
    if actor_role == "HR_Manager":
        if user.role in ["HR_Admin", "HR_Manager"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="HR Manager cannot activate HR Admin or other HR Manager",
            )

    if user.status == "active":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User is already active",
        )

    # Get actor's user ID
    actor_user = session.exec(
        select(User).where(User.asgardeo_id == current_user.sub)
    ).first()
    actor_user_id = actor_user.id if actor_user else 0

    try:
        # Update status
        user.status = "active"
        user.updated_at = datetime.now()
        session.add(user)
        session.commit()
        session.refresh(user)

        # Enable in Asgardeo
        try:
            await asgardeo_service.enable_user(user.asgardeo_id)
        except Exception as e:
            logger.warning(f"Failed to enable user in Asgardeo: {e}")

        logger.info(f"User {user_id} activated")

        # Publish Kafka event
        try:
            event_data = UserActivatedEvent(
                user_id=user.id,
                email=user.email,
                activated_by=actor_user_id,
            )
            event = create_event(
                EventType.USER_ACTIVATED,
                event_data,
                actor_user_id=str(actor_user_id),
                actor_role=actor_role,
            )
            await publish_event(KafkaTopics.USER_ACTIVATED, event)
        except Exception as e:
            logger.warning(f"Failed to publish activate event: {e}")

        # Log audit event
        try:
            await audit_client.log_action(
                user_id=actor_user_id,
                action="activate",
                resource_type="user",
                resource_id=user_id,
                description="User account activated",
                new_value="active",
            )
        except Exception as e:
            logger.warning(f"Failed to log audit event: {e}")

        # Invalidate cache
        await invalidate_user_cache(user_id)

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
            updated_at=user.updated_at,
            last_login=user.last_login,
        )

    except HTTPException:
        raise
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
    current_user: Annotated[TokenData, Depends(get_current_user)],
):
    """
    Delete a user account (soft delete).

    Authorization:
    - HR_Admin: Can delete anyone except themselves
    - HR_Manager: Can delete manager and employee (not HR_Admin or HR_Manager)

    Actions:
    1. Check compliance policies
    2. Set status to 'deleted'
    3. Disable in Asgardeo
    4. Terminate employee record
    5. Log audit event
    6. Send notification
    """
    actor_role = get_highest_role(current_user.roles)

    logger.info(f"User {current_user.sub} ({actor_role}) deleting user {user_id}")

    # Only HR roles can delete
    if actor_role not in ["HR_Admin", "HR_Manager", "admin"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only HR Admin and HR Manager can delete users",
        )

    # Get actor's user record
    actor_user = session.exec(
        select(User).where(User.asgardeo_id == current_user.sub)
    ).first()
    actor_user_id = actor_user.id if actor_user else 0

    # Prevent self-deletion
    if actor_user and actor_user.id == user_id:
        logger.warning(f"User {current_user.sub} attempted self-deletion")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot delete your own account",
        )

    user = session.get(User, user_id)
    if not user:
        logger.warning(f"User not found: {user_id}")
        raise HTTPException(status_code=404, detail="User not found")

    # HR_Manager restrictions
    if actor_role == "HR_Manager":
        if user.role in ["HR_Admin", "HR_Manager"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="HR Manager cannot delete HR Admin or other HR Manager",
            )

    try:
        # Check compliance policy
        try:
            compliance_check = await compliance_client.check_user_deletion_policy(
                user_id
            )
            if not compliance_check:
                logger.warning(f"User deletion blocked by compliance policy: {user_id}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="User deletion is blocked by compliance policy",
                )
        except HTTPException:
            raise
        except Exception as e:
            logger.warning(f"Compliance check failed (continuing): {e}")

        # Soft delete
        user.status = "deleted"
        user.deleted_at = datetime.now()
        user.updated_at = datetime.now()
        session.add(user)
        session.commit()
        session.refresh(user)

        # Disable in Asgardeo
        try:
            await asgardeo_service.disable_user(user.asgardeo_id)
        except Exception as e:
            logger.warning(f"Failed to disable user in Asgardeo: {e}")

        logger.info(f"User {user_id} deleted")

        # Terminate employee
        if user.employee_id:
            try:
                await employee_client.update_employee_status(
                    user.employee_id, "terminated"
                )
            except Exception as e:
                logger.warning(f"Failed to terminate employee: {e}")

        # Publish Kafka event
        try:
            event_data = UserDeletedEvent(
                user_id=user.id,
                email=user.email,
                deleted_by=actor_user_id,
                reason=delete_data.reason,
            )
            event = create_event(
                EventType.USER_DELETED,
                event_data,
                actor_user_id=str(actor_user_id),
                actor_role=actor_role,
            )
            await publish_event(KafkaTopics.USER_DELETED, event)
        except Exception as e:
            logger.warning(f"Failed to publish delete event: {e}")

        # Log audit event
        try:
            await audit_client.log_action(
                user_id=actor_user_id,
                action="delete",
                resource_type="user",
                resource_id=user_id,
                description=f"User account deleted. Reason: {delete_data.reason or 'Not specified'}",
                new_value="deleted",
            )
        except Exception as e:
            logger.warning(f"Failed to log audit event: {e}")

        # Send notification
        try:
            await notification_client.send_account_deleted_notification(
                email=user.email,
                first_name=user.first_name or "User",
            )
        except Exception as e:
            logger.warning(f"Failed to send deletion notification: {e}")

        # Invalidate cache
        await invalidate_user_cache(user_id)

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
        List of role information with hierarchy levels
    """
    logger.info("Listing roles")

    roles = [
        {
            "role_id": 4,
            "role_name": "HR_Admin",
            "display_name": "HR Administrator",
            "description": "Highest authority with full system access",
            "level": RBACManager.get_role_level("HR_Admin"),
        },
        {
            "role_id": 3,
            "role_name": "HR_Manager",
            "display_name": "HR Manager",
            "description": "Can manage employees, approve leaves, view reports",
            "level": RBACManager.get_role_level("HR_Manager"),
        },
        {
            "role_id": 2,
            "role_name": "manager",
            "display_name": "Team Manager",
            "description": "Can manage team members, approve team leaves",
            "level": RBACManager.get_role_level("manager"),
        },
        {
            "role_id": 1,
            "role_name": "employee",
            "display_name": "Employee",
            "description": "Regular employee with basic access",
            "level": RBACManager.get_role_level("employee"),
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

    # Get permissions from RBAC manager
    permissions = RBACManager.get_role_permissions(user.role)

    return {
        "user_id": user_id,
        "role": user.role,
        "role_level": RBACManager.get_role_level(user.role),
        "permissions": permissions,
        "asgardeo_group": RBACManager.get_asgardeo_group(user.role),
    }


@router.post("/admin/sync/asgardeo-to-db")
async def sync_users_from_asgardeo(
    user_id: Optional[int] = Query(None),
    session: SessionDep = None,
    current_user: Annotated[
        TokenData, Depends(require_role("admin", "HR_Admin"))
    ] = None,
):
    """
    Sync users from Asgardeo to local database (admin only).

    Args:
        user_id: Optional specific user ID to sync
        session: Database session
        current_user: Current admin user

    Returns:
        Sync result with count of synced users
    """
    logger.info(f"Starting Asgardeo sync (user_id={user_id})")

    try:
        synced_count = 0

        if user_id:
            # Sync specific user
            user = session.get(User, user_id)
            if not user:
                raise HTTPException(status_code=404, detail="User not found")

            asgardeo_user = await asgardeo_service.get_user(user.asgardeo_id)
            if asgardeo_user:
                # Update local record with Asgardeo data
                user.first_name = asgardeo_user.get("name", {}).get("givenName")
                user.last_name = asgardeo_user.get("name", {}).get("familyName")
                user.updated_at = datetime.now()
                session.add(user)
                session.commit()
                synced_count = 1

                # Invalidate cache
                await invalidate_user_cache(user_id)

        else:
            # Sync all users
            asgardeo_users = await asgardeo_service.list_users()
            for asgardeo_user in asgardeo_users:
                asgardeo_id = asgardeo_user.get("id")
                emails = asgardeo_user.get("emails", [])
                email = emails[0].get("value") if emails else None

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

                    # Invalidate cache
                    await invalidate_user_cache(existing_user.id)
                else:
                    # Create new user
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

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Sync failed: {str(e)}")
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Sync failed: {str(e)}",
        )
