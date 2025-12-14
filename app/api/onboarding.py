"""
Onboarding API endpoints for User Management Service.

Provides endpoints for the complete employee onboarding flow:
1. HR Admin/Manager initiates onboarding with employee details
2. Employee receives invitation email
3. Employee completes signup step 1 (creates Asgardeo user)
4. Employee completes signup step 2 (creates employee record)

RBAC Rules:
- HR_Admin: Can onboard anyone (HR_Manager, manager, employee)
- HR_Manager: Can onboard manager and employee only (NOT HR_Manager)
- manager: Cannot initiate onboarding
- employee: Cannot initiate onboarding
"""

from datetime import datetime, timedelta
from secrets import token_urlsafe
from typing import Annotated, Optional

from dateutil.relativedelta import relativedelta
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlmodel import Session, select

from app.api.dependencies import SessionDep, TokenData, get_current_active_user
from app.core.asgardeo import asgardeo_service
from app.core.config import settings
from app.core.events import (
    EventType,
    OnboardingAsgardeoUserCreatedEvent,
    OnboardingCancelledEvent,
    OnboardingCompletedEvent,
    OnboardingEmployeeCreatedEvent,
    OnboardingFailedEvent,
    OnboardingInitiatedEvent,
    OnboardingInvitationSentEvent,
    create_event,
)
from app.core.integrations import employee_client, notification_client
from app.core.kafka import publish_event
from app.core.logging import get_logger
from app.core.rbac import get_highest_role
from app.core.topics import KafkaTopics
from app.models.onboarding import (
    CancelOnboardingRequest,
    EmploymentType,
    InitiateOnboardingRequest,
    InitiateOnboardingResponse,
    OnboardingListResponse,
    OnboardingPreviewData,
    OnboardingStatus,
    OnboardingStatusResponse,
    SignupStep1Request,
    SignupStep1Response,
    SignupStep2Request,
    SignupStep2Response,
)
from app.models.users import OnboardingInvitation, User

logger = get_logger(__name__)

router = APIRouter(
    prefix="/onboarding",
    tags=["onboarding"],
)


# Constants
INVITATION_EXPIRY_DAYS = settings.INVITATION_EXPIRY_DAYS
PROBATION_END_NOTIFICATION_DAYS = settings.PROBATION_END_NOTIFICATION_DAYS


def validate_password_strength(password: str) -> tuple[bool, str]:
    """
    Validate password against strength requirements.

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


def can_onboard_role(actor_role: str, target_role: str) -> tuple[bool, str]:
    """
    Check if the actor can onboard someone with the target role.

    RBAC Rules:
    - HR_Admin: Can onboard HR_Manager, manager, employee
    - HR_Manager: Can onboard manager, employee (NOT HR_Manager)
    - manager, employee: Cannot onboard anyone

    Args:
        actor_role: Role of the person initiating onboarding
        target_role: Role to be assigned to the new employee

    Returns:
        Tuple of (is_allowed, error_message)
    """
    # Normalize admin alias
    if actor_role == "admin":
        actor_role = "HR_Admin"

    # Only HR_Admin and HR_Manager can initiate onboarding
    if actor_role not in ["HR_Admin", "HR_Manager"]:
        return False, "Only HR Admin and HR Manager can initiate onboarding"

    # Validate target role
    valid_target_roles = ["HR_Manager", "manager", "employee", "Manager", "Employee"]
    if target_role not in valid_target_roles:
        return False, f"Invalid role. Must be one of: {', '.join(valid_target_roles)}"

    # HR_Manager cannot onboard another HR_Manager
    if actor_role == "HR_Manager" and target_role == "HR_Manager":
        return False, "HR Manager cannot onboard another HR Manager"

    return True, ""


def generate_invitation_token() -> str:
    """Generate a secure random invitation token."""
    return token_urlsafe(32)


def calculate_dates(
    joining_date,
    employment_type: str,
    probation_months: Optional[int] = None,
) -> dict:
    """
    Calculate important dates based on joining date.

    Returns dict with:
    - probation_end_date (if applicable)
    - performance_review_date (yearly anniversary)
    - salary_increment_date (yearly anniversary)
    """
    dates = {
        "performance_review_date": joining_date + relativedelta(years=1),
        "salary_increment_date": joining_date + relativedelta(years=1),
    }

    # Performance review and salary increment on yearly anniversary

    # Probation end date for permanent employees
    if employment_type == "permanent" and probation_months:
        dates["probation_end_date"] = joining_date + relativedelta(
            months=probation_months
        )

    return dates


@router.post(
    "/initiate",
    response_model=InitiateOnboardingResponse,
    status_code=status.HTTP_201_CREATED,
)
async def initiate_onboarding(
    request: InitiateOnboardingRequest,
    session: SessionDep,
    current_user: Annotated[TokenData, Depends(get_current_active_user)],
):
    """
    Initiate employee onboarding process.

    This endpoint is called by HR Admin or HR Manager to start onboarding
    a new employee. It creates an invitation record and triggers an
    invitation email.

    Authorization:
    - HR_Admin: Can onboard anyone
    - HR_Manager: Can onboard manager and employee (not HR_Manager)

    Process:
    1. Validate RBAC permissions
    2. Check email uniqueness
    3. Create invitation record
    4. Publish onboarding initiated event
    5. Send invitation email via notification service

    Returns:
        InitiateOnboardingResponse with invitation details
    """
    logger.info(
        f"Onboarding initiation requested by user {current_user.sub} for {request.email}"
    )

    # Get actor's highest role
    actor_role = get_highest_role(current_user.roles)

    # Check RBAC permissions
    can_onboard, error_msg = can_onboard_role(actor_role, request.role)
    if not can_onboard:
        logger.warning(
            f"RBAC denied: User {current_user.sub} ({actor_role}) "
            f"cannot onboard role {request.role}. Reason: {error_msg}"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=error_msg,
        )

    # Check if email already exists in users table
    existing_user = session.exec(
        select(User).where(User.email == request.email)
    ).first()
    if existing_user:
        logger.warning(f"Email already exists as user: {request.email}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with this email already exists",
        )

    # Check if there's already a pending invitation for this email
    existing_invitation = session.exec(
        select(OnboardingInvitation).where(
            OnboardingInvitation.email == request.email,
            OnboardingInvitation.status.in_(
                ["initiated", "invitation_sent", "asgardeo_user_created"]
            ),
        )
    ).first()
    if existing_invitation:
        logger.warning(f"Pending invitation already exists for: {request.email}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A pending onboarding invitation already exists for this email",
        )

    # Validate contract dates for contract employees
    if request.employment_type == EmploymentType.CONTRACT:
        if not request.contract_start_date or not request.contract_end_date:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Contract start and end dates are required for contract employees",
            )
        if request.contract_end_date <= request.contract_start_date:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Contract end date must be after start date",
            )

    # Generate invitation token and calculate dates
    invitation_token = generate_invitation_token()
    calculated_dates = calculate_dates(
        request.joining_date,
        request.employment_type.value,
        request.probation_months,
    )

    # Calculate expiry time
    expires_at = datetime.now() + timedelta(days=INVITATION_EXPIRY_DAYS)

    # Get initiator's user ID from database
    initiator = session.exec(
        select(User).where(User.asgardeo_id == current_user.sub)
    ).first()
    initiator_id = initiator.id if initiator else 0
    initiator_name = (
        f"{initiator.first_name} {initiator.last_name}" if initiator else "System"
    )

    # Create invitation record
    invitation = OnboardingInvitation(
        invitation_token=invitation_token,
        email=request.email,
        role=request.role,
        job_title=request.job_title,
        salary=request.salary,
        salary_currency=request.salary_currency,
        employment_type=request.employment_type.value,
        probation_months=request.probation_months,
        probation_end_date=calculated_dates.get("probation_end_date"),
        contract_start_date=request.contract_start_date,
        contract_end_date=request.contract_end_date,
        department=request.department,
        team=request.team,
        manager_id=request.manager_id,
        joining_date=request.joining_date,
        performance_review_date=calculated_dates.get("performance_review_date"),
        salary_increment_date=calculated_dates.get("salary_increment_date"),
        notes=request.notes,
        status=OnboardingStatus.INITIATED.value,
        initiated_by=initiator_id,
        initiated_at=datetime.now(),
        expires_at=expires_at,
    )

    session.add(invitation)
    session.commit()
    session.refresh(invitation)
    logger.info(f"Created onboarding invitation: {invitation.id} for {request.email}")

    # Build invitation link
    # In production, this would be the frontend URL
    invitation_link = f"http://localhost:3000/signup?token={invitation_token}"

    # Publish onboarding initiated event
    try:
        event_data = OnboardingInitiatedEvent(
            invitation_token=invitation_token,
            email=request.email,
            role=request.role,
            job_title=request.job_title,
            salary=request.salary,
            salary_currency=request.salary_currency,
            employment_type=request.employment_type.value,
            probation_months=request.probation_months,
            contract_start_date=request.contract_start_date,
            contract_end_date=request.contract_end_date,
            joining_date=request.joining_date,
            department=request.department,
            team=request.team,
            manager_id=request.manager_id,
            initiated_by=initiator_id,
            initiated_by_name=initiator_name,
        )
        event = create_event(
            EventType.ONBOARDING_INITIATED,
            event_data,
            actor_user_id=str(initiator_id),
            actor_role=actor_role,
        )
        await publish_event(KafkaTopics.ONBOARDING_INITIATED, event)
        logger.info(f"Published onboarding initiated event for {request.email}")
    except Exception as e:
        logger.warning(f"Failed to publish onboarding initiated event: {e}")

    # Publish invitation notification event
    try:
        invitation_event = OnboardingInvitationSentEvent(
            invitation_token=invitation_token,
            email=request.email,
            role=request.role,
            job_title=request.job_title,
            invitation_link=invitation_link,
            expires_at=expires_at,
        )
        event = create_event(
            EventType.ONBOARDING_INVITATION_SENT,
            invitation_event,
            actor_user_id=str(initiator_id),
            actor_role=actor_role,
        )
        await publish_event(KafkaTopics.NOTIFICATION_INVITATION_EMAIL, event)

        # Update invitation status
        invitation.status = OnboardingStatus.INVITATION_SENT.value
        invitation.invitation_sent_at = datetime.utcnow()
        session.add(invitation)
        session.commit()
        logger.info(f"Published invitation email event for {request.email}")
    except Exception as e:
        logger.warning(f"Failed to publish invitation email event: {e}")

    return InitiateOnboardingResponse(
        message="Onboarding initiated successfully",
        invitation_token=invitation_token,
        email=request.email,
        role=request.role,
        job_title=request.job_title,
        invitation_link=invitation_link,
        expires_at=expires_at,
    )


@router.get("/preview/{invitation_token}", response_model=OnboardingPreviewData)
async def get_onboarding_preview(
    invitation_token: str,
    session: SessionDep,
):
    """
    Get onboarding preview data for an invitation.

    This endpoint is called when an employee clicks the invitation link.
    It returns the pre-filled data from HR that the employee cannot change.

    No authentication required as this is accessed via invitation link.
    """
    logger.info(f"Fetching onboarding preview for token: {invitation_token[:8]}...")

    invitation = session.exec(
        select(OnboardingInvitation).where(
            OnboardingInvitation.invitation_token == invitation_token
        )
    ).first()

    if not invitation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invalid invitation token",
        )

    # Check if expired
    is_expired = datetime.utcnow() > invitation.expires_at

    # Check if already completed or cancelled
    if invitation.status in [
        OnboardingStatus.COMPLETED.value,
        OnboardingStatus.CANCELLED.value,
    ]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"This invitation has already been {invitation.status}",
        )

    return OnboardingPreviewData(
        email=invitation.email,
        role=invitation.role,
        job_title=invitation.job_title,
        salary=invitation.salary,
        salary_currency=invitation.salary_currency,
        employment_type=EmploymentType(invitation.employment_type),
        probation_months=invitation.probation_months,
        contract_start_date=invitation.contract_start_date,
        contract_end_date=invitation.contract_end_date,
        department=invitation.department,
        team=invitation.team,
        joining_date=invitation.joining_date,
        is_valid=not is_expired,
        is_expired=is_expired,
    )


@router.post("/signup/step1", response_model=SignupStep1Response)
async def signup_step1(
    request: SignupStep1Request,
    session: SessionDep,
):
    """
    Complete signup step 1: Create user account.

    This endpoint is called when the employee fills in their personal
    information and password. It creates the Asgardeo user account
    and local user record.

    No authentication required as this is part of the signup flow.

    Process:
    1. Validate invitation token
    2. Validate password strength
    3. Create user in Asgardeo
    4. Create local user record
    5. Publish events
    """
    logger.info(f"Signup step 1 for token: {request.invitation_token[:8]}...")

    # Fetch invitation
    invitation = session.exec(
        select(OnboardingInvitation).where(
            OnboardingInvitation.invitation_token == request.invitation_token
        )
    ).first()

    if not invitation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invalid invitation token",
        )

    # Check if expired
    if datetime.utcnow() > invitation.expires_at:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This invitation has expired",
        )

    # Check status
    if invitation.status == OnboardingStatus.COMPLETED.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This onboarding has already been completed",
        )

    if invitation.status == OnboardingStatus.CANCELLED.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This invitation has been cancelled",
        )

    # If Asgardeo user already created, skip to step 2
    if invitation.status == OnboardingStatus.ASGARDEO_USER_CREATED.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Step 1 already completed. Please proceed to step 2.",
        )

    # Validate password
    is_valid, error_msg = validate_password_strength(request.password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_msg,
        )

    # Create user in Asgardeo
    try:
        asgardeo_data = await asgardeo_service.create_user(
            email=invitation.email,
            password=request.password,
            first_name=request.first_name,
            last_name=request.last_name,
            phone=request.phone,
        )
        asgardeo_id = asgardeo_data["asgardeo_id"]
        logger.info(f"Created Asgardeo user: {asgardeo_id}")
    except Exception as e:
        logger.error(f"Failed to create Asgardeo user: {e}")

        # Publish failure event
        try:
            failure_event = OnboardingFailedEvent(
                invitation_token=invitation.invitation_token,
                email=invitation.email,
                step="asgardeo_user_creation",
                error_message=str(e),
                initiated_by=invitation.initiated_by,
            )
            event = create_event(EventType.ONBOARDING_FAILED, failure_event)
            await publish_event(KafkaTopics.ONBOARDING_FAILED, event)
        except Exception:
            pass

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user account. Please try again later.",
        )

    # Assign role in Asgardeo
    try:
        # Map invitation role to Asgardeo role name expected by assign_role
        # assign_role expects: HR_Admin, HR_Manager, Manager, Employee
        role_mapping = {
            "HR_Admin": "HR_Admin",
            "HR_Manager": "HR_Manager",
            "manager": "Manager",
            "employee": "Employee",
        }
        asgardeo_role = role_mapping.get(invitation.role, "Employee")
        await asgardeo_service.assign_role(asgardeo_id, asgardeo_role)
        logger.info(f"Assigned role {asgardeo_role} to user {asgardeo_id}")
    except Exception as e:
        logger.warning(f"Failed to assign role in Asgardeo (non-blocking): {e}")

    # Create local user record
    try:
        db_user = User(
            asgardeo_id=asgardeo_id,
            email=invitation.email,
            first_name=request.first_name,
            last_name=request.last_name,
            phone=request.phone,
            role=invitation.role,
            status="active",
        )
        session.add(db_user)
        session.commit()
        session.refresh(db_user)
        logger.info(f"Created local user record: {db_user.id}")
    except Exception as e:
        logger.error(f"Failed to create local user: {e}")

        # Try to clean up Asgardeo user
        try:
            await asgardeo_service.delete_user(asgardeo_id)
        except Exception:
            pass

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user record",
        )

    # Update invitation
    invitation.asgardeo_id = asgardeo_id
    invitation.user_id = db_user.id
    invitation.status = OnboardingStatus.ASGARDEO_USER_CREATED.value
    invitation.asgardeo_created_at = datetime.utcnow()
    session.add(invitation)
    session.commit()

    # Publish Asgardeo user created event
    try:
        event_data = OnboardingAsgardeoUserCreatedEvent(
            invitation_token=invitation.invitation_token,
            email=invitation.email,
            asgardeo_id=asgardeo_id,
            user_id=db_user.id,
            first_name=request.first_name,
            last_name=request.last_name,
        )
        event = create_event(EventType.ONBOARDING_ASGARDEO_USER_CREATED, event_data)
        await publish_event(KafkaTopics.ONBOARDING_ASGARDEO_USER_CREATED, event)
        logger.info(f"Published Asgardeo user created event for {invitation.email}")
    except Exception as e:
        logger.warning(f"Failed to publish Asgardeo user created event: {e}")

    return SignupStep1Response(
        message="User account created successfully",
        email=invitation.email,
        asgardeo_id=asgardeo_id,
        user_id=db_user.id,
        next_step="complete_employee_profile",
    )


@router.post("/signup/step2", response_model=SignupStep2Response)
async def signup_step2(
    request: SignupStep2Request,
    session: SessionDep,
):
    """
    Complete signup step 2: Create employee record.

    This endpoint is called when the employee fills in additional
    personal details. It creates the employee record in the
    employee management service and completes the onboarding.

    No authentication required as this is part of the signup flow.

    Process:
    1. Validate invitation token and status
    2. Create employee record in employee service
    3. Update invitation status
    4. Publish completion events
    """
    logger.info(f"Signup step 2 for token: {request.invitation_token[:8]}...")

    # Fetch invitation
    invitation = session.exec(
        select(OnboardingInvitation).where(
            OnboardingInvitation.invitation_token == request.invitation_token
        )
    ).first()

    if not invitation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invalid invitation token",
        )

    # Check status - must have completed step 1
    if invitation.status != OnboardingStatus.ASGARDEO_USER_CREATED.value:
        if invitation.status in [
            OnboardingStatus.INITIATED.value,
            OnboardingStatus.INVITATION_SENT.value,
        ]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Please complete step 1 first",
            )
        elif invitation.status == OnboardingStatus.COMPLETED.value:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Onboarding already completed",
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid invitation status: {invitation.status}",
            )

    # Fetch user record
    db_user = session.exec(select(User).where(User.id == invitation.user_id)).first()

    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User record not found",
        )

    # Create employee record in employee service with full onboarding data
    try:
        # Use the comprehensive onboarding endpoint with all HR and personal data
        employee_data = await employee_client.create_employee_from_onboarding(
            user_id=db_user.id,
            email=invitation.email,
            first_name=db_user.first_name,
            last_name=db_user.last_name,
            phone=db_user.phone,
            role=invitation.role,
            job_title=invitation.job_title,
            department=invitation.department,
            team=invitation.team,
            manager_id=invitation.manager_id,
            salary=invitation.salary,
            salary_currency=invitation.salary_currency,
            employment_type=invitation.employment_type,
            joining_date=invitation.joining_date,
            probation_months=invitation.probation_months,
            probation_end_date=invitation.probation_end_date,
            contract_start_date=invitation.contract_start_date,
            contract_end_date=invitation.contract_end_date,
            performance_review_date=invitation.performance_review_date,
            salary_increment_date=invitation.salary_increment_date,
            # Personal details from step 2
            date_of_birth=request.date_of_birth,
            gender=request.gender,
            nationality=request.nationality,
            address_line_1=request.address_line_1,
            address_line_2=request.address_line_2,
            city=request.city,
            state=request.state,
            country=request.country,
            postal_code=request.postal_code,
            emergency_contact_name=request.emergency_contact_name,
            emergency_contact_phone=request.emergency_contact_phone,
            emergency_contact_relationship=request.emergency_contact_relationship,
            bank_name=request.bank_name,
            bank_account_number=request.bank_account_number,
            bank_routing_number=request.bank_routing_number,
        )

        if employee_data:
            employee_id = employee_data.get("id")
            db_user.employee_id = employee_id
            session.add(db_user)
            session.commit()
            logger.info(
                f"Created employee record with full onboarding data: {employee_id}"
            )
        else:
            # Employee service might be unavailable, but we can still continue
            employee_id = None
            logger.warning(
                "Employee service unavailable, continuing without employee record"
            )

    except Exception as e:
        logger.error(f"Failed to create employee record: {e}")
        employee_id = None

    # Update invitation status
    invitation.employee_id = employee_id
    invitation.status = OnboardingStatus.COMPLETED.value
    invitation.employee_created_at = datetime.utcnow()
    invitation.completed_at = datetime.utcnow()
    session.add(invitation)
    session.commit()

    # Publish employee created event
    if employee_id:
        try:
            event_data = OnboardingEmployeeCreatedEvent(
                invitation_token=invitation.invitation_token,
                email=invitation.email,
                user_id=db_user.id,
                employee_id=employee_id,
                role=invitation.role,
                job_title=invitation.job_title,
                employment_type=invitation.employment_type,
                joining_date=invitation.joining_date,
            )
            event = create_event(EventType.ONBOARDING_EMPLOYEE_CREATED, event_data)
            await publish_event(KafkaTopics.ONBOARDING_EMPLOYEE_CREATED, event)
            logger.info(f"Published employee created event for {invitation.email}")
        except Exception as e:
            logger.warning(f"Failed to publish employee created event: {e}")

    # Publish onboarding completed event
    try:
        completed_event = OnboardingCompletedEvent(
            invitation_token=invitation.invitation_token,
            email=invitation.email,
            user_id=db_user.id,
            employee_id=employee_id or 0,
            asgardeo_id=invitation.asgardeo_id or "",
            role=invitation.role,
            job_title=invitation.job_title,
            employment_type=invitation.employment_type,
            joining_date=invitation.joining_date,
            initiated_by=invitation.initiated_by,
            completed_at=datetime.utcnow(),
        )
        event = create_event(EventType.ONBOARDING_COMPLETED, completed_event)
        await publish_event(KafkaTopics.ONBOARDING_COMPLETED, event)
        logger.info(f"Published onboarding completed event for {invitation.email}")
    except Exception as e:
        logger.warning(f"Failed to publish onboarding completed event: {e}")

    # Publish welcome notification event
    try:
        await notification_client.send_account_created_notification(
            email=invitation.email,
            first_name=db_user.first_name,
            last_name=db_user.last_name,
        )
    except Exception as e:
        logger.warning(f"Failed to send welcome notification: {e}")

    return SignupStep2Response(
        message="Onboarding completed successfully",
        user_id=db_user.id,
        employee_id=employee_id or 0,
        email=invitation.email,
        role=invitation.role,
        job_title=invitation.job_title,
        employment_type=invitation.employment_type,
        joining_date=invitation.joining_date,
        check_email_for_password=True,
    )


@router.get("/status/{invitation_token}", response_model=OnboardingStatusResponse)
async def get_onboarding_status(
    invitation_token: str,
    session: SessionDep,
    current_user: Annotated[TokenData, Depends(get_current_active_user)],
):
    """
    Get the status of an onboarding invitation.

    Authorization:
    - HR_Admin: Can view any invitation
    - HR_Manager: Can view invitations they initiated
    """
    logger.info(f"Fetching onboarding status for token: {invitation_token[:8]}...")

    actor_role = get_highest_role(current_user.roles)

    invitation = session.exec(
        select(OnboardingInvitation).where(
            OnboardingInvitation.invitation_token == invitation_token
        )
    ).first()

    if not invitation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invitation not found",
        )

    # RBAC check - HR_Manager can only see their own invitations
    if actor_role == "HR_Manager":
        initiator = session.exec(
            select(User).where(User.asgardeo_id == current_user.sub)
        ).first()
        if initiator and invitation.initiated_by != initiator.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only view invitations you initiated",
            )

    # Get initiator name
    initiator = session.exec(
        select(User).where(User.id == invitation.initiated_by)
    ).first()
    initiator_name = (
        f"{initiator.first_name} {initiator.last_name}" if initiator else None
    )

    return OnboardingStatusResponse(
        invitation_token=invitation.invitation_token,
        email=invitation.email,
        status=OnboardingStatus(invitation.status),
        role=invitation.role,
        job_title=invitation.job_title,
        employment_type=EmploymentType(invitation.employment_type),
        joining_date=invitation.joining_date,
        initiated_by_name=initiator_name,
        initiated_at=invitation.initiated_at,
        asgardeo_user_created=invitation.asgardeo_id is not None,
        employee_created=invitation.employee_id is not None,
        completed_at=invitation.completed_at,
        is_expired=datetime.utcnow() > invitation.expires_at,
    )


@router.get("/list", response_model=OnboardingListResponse)
async def list_onboarding_invitations(
    session: SessionDep,
    current_user: Annotated[TokenData, Depends(get_current_active_user)],
    status_filter: Optional[str] = Query(None, alias="status"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    """
    List onboarding invitations.

    Authorization:
    - HR_Admin: Can view all invitations
    - HR_Manager: Can view invitations they initiated
    """
    logger.info(f"Listing onboarding invitations for user {current_user.sub}")

    actor_role = get_highest_role(current_user.roles)

    # Only HR roles can list invitations
    if actor_role not in ["HR_Admin", "HR_Manager", "admin"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only HR Admin and HR Manager can view onboarding invitations",
        )

    # Build query
    query = select(OnboardingInvitation)

    # HR_Manager can only see their own invitations
    if actor_role == "HR_Manager":
        initiator = session.exec(
            select(User).where(User.asgardeo_id == current_user.sub)
        ).first()
        if initiator:
            query = query.where(OnboardingInvitation.initiated_by == initiator.id)

    # Filter by status
    if status_filter:
        query = query.where(OnboardingInvitation.status == status_filter)

    # Order by created date descending
    query = query.order_by(OnboardingInvitation.initiated_at.desc())

    # Get total count
    all_invitations = session.exec(query).all()
    total = len(all_invitations)

    # Paginate
    invitations = session.exec(query.offset(offset).limit(limit)).all()

    # Build response
    response_items = []
    for inv in invitations:
        initiator = session.exec(
            select(User).where(User.id == inv.initiated_by)
        ).first()
        initiator_name = (
            f"{initiator.first_name} {initiator.last_name}" if initiator else None
        )

        response_items.append(
            OnboardingStatusResponse(
                invitation_token=inv.invitation_token,
                email=inv.email,
                status=OnboardingStatus(inv.status),
                role=inv.role,
                job_title=inv.job_title,
                employment_type=EmploymentType(inv.employment_type),
                joining_date=inv.joining_date,
                initiated_by_name=initiator_name,
                initiated_at=inv.initiated_at,
                asgardeo_user_created=inv.asgardeo_id is not None,
                employee_created=inv.employee_id is not None,
                completed_at=inv.completed_at,
                is_expired=datetime.utcnow() > inv.expires_at,
            )
        )

    return OnboardingListResponse(
        total=total,
        invitations=response_items,
    )


@router.post("/cancel/{invitation_token}")
async def cancel_onboarding(
    invitation_token: str,
    request: CancelOnboardingRequest,
    session: SessionDep,
    current_user: Annotated[TokenData, Depends(get_current_active_user)],
):
    """
    Cancel an ongoing onboarding invitation.

    Authorization:
    - HR_Admin: Can cancel any invitation
    - HR_Manager: Can cancel invitations they initiated
    """
    logger.info(f"Cancelling onboarding for token: {invitation_token[:8]}...")

    actor_role = get_highest_role(current_user.roles)

    # Only HR roles can cancel
    if actor_role not in ["HR_Admin", "HR_Manager", "admin"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only HR Admin and HR Manager can cancel onboarding",
        )

    invitation = session.exec(
        select(OnboardingInvitation).where(
            OnboardingInvitation.invitation_token == invitation_token
        )
    ).first()

    if not invitation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invitation not found",
        )

    # HR_Manager can only cancel their own invitations
    if actor_role == "HR_Manager":
        initiator = session.exec(
            select(User).where(User.asgardeo_id == current_user.sub)
        ).first()
        if initiator and invitation.initiated_by != initiator.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only cancel invitations you initiated",
            )

    # Check if already completed or cancelled
    if invitation.status == OnboardingStatus.COMPLETED.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot cancel completed onboarding",
        )

    if invitation.status == OnboardingStatus.CANCELLED.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invitation already cancelled",
        )

    # Get canceller ID
    canceller = session.exec(
        select(User).where(User.asgardeo_id == current_user.sub)
    ).first()
    canceller_id = canceller.id if canceller else 0

    # Update invitation
    invitation.status = OnboardingStatus.CANCELLED.value
    invitation.cancelled_at = datetime.utcnow()
    invitation.cancelled_by = canceller_id
    invitation.cancellation_reason = request.reason
    session.add(invitation)
    session.commit()

    # Publish cancellation event
    try:
        event_data = OnboardingCancelledEvent(
            invitation_token=invitation_token,
            email=invitation.email,
            cancelled_by=canceller_id,
            reason=request.reason,
        )
        event = create_event(
            EventType.ONBOARDING_CANCELLED,
            event_data,
            actor_user_id=str(canceller_id),
            actor_role=actor_role,
        )
        await publish_event(KafkaTopics.ONBOARDING_FAILED, event)
        logger.info(f"Published onboarding cancelled event for {invitation.email}")
    except Exception as e:
        logger.warning(f"Failed to publish cancellation event: {e}")

    return {"message": "Onboarding cancelled successfully", "email": invitation.email}


@router.post("/resend-invitation/{invitation_token}")
async def resend_invitation(
    invitation_token: str,
    session: SessionDep,
    current_user: Annotated[TokenData, Depends(get_current_active_user)],
):
    """
    Resend invitation email for an onboarding.

    Authorization:
    - HR_Admin: Can resend any invitation
    - HR_Manager: Can resend invitations they initiated
    """
    logger.info(f"Resending invitation for token: {invitation_token[:8]}...")

    actor_role = get_highest_role(current_user.roles)

    # Only HR roles can resend
    if actor_role not in ["HR_Admin", "HR_Manager", "admin"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only HR Admin and HR Manager can resend invitations",
        )

    invitation = session.exec(
        select(OnboardingInvitation).where(
            OnboardingInvitation.invitation_token == invitation_token
        )
    ).first()

    if not invitation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invitation not found",
        )

    # HR_Manager can only resend their own invitations
    if actor_role == "HR_Manager":
        initiator = session.exec(
            select(User).where(User.asgardeo_id == current_user.sub)
        ).first()
        if initiator and invitation.initiated_by != initiator.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only resend invitations you initiated",
            )

    # Check status
    if invitation.status in [
        OnboardingStatus.COMPLETED.value,
        OnboardingStatus.CANCELLED.value,
    ]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot resend invitation for {invitation.status} onboarding",
        )

    # Extend expiry
    invitation.expires_at = datetime.utcnow() + timedelta(days=INVITATION_EXPIRY_DAYS)
    invitation.invitation_sent_at = datetime.utcnow()
    session.add(invitation)
    session.commit()

    # Build invitation link
    invitation_link = f"http://localhost:3000/signup?token={invitation_token}"

    # Publish invitation event
    try:
        invitation_event = OnboardingInvitationSentEvent(
            invitation_token=invitation_token,
            email=invitation.email,
            role=invitation.role,
            job_title=invitation.job_title,
            invitation_link=invitation_link,
            expires_at=invitation.expires_at,
        )
        event = create_event(EventType.ONBOARDING_INVITATION_SENT, invitation_event)
        await publish_event(KafkaTopics.NOTIFICATION_INVITATION_EMAIL, event)
        logger.info(f"Resent invitation email for {invitation.email}")
    except Exception as e:
        logger.warning(f"Failed to publish invitation email event: {e}")

    return {
        "message": "Invitation resent successfully",
        "email": invitation.email,
        "expires_at": invitation.expires_at.isoformat(),
    }
