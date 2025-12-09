"""
User database models and schemas for User Management Service.
"""

from datetime import date, datetime
from typing import Optional

from sqlmodel import Field, SQLModel

# Database Models


class OnboardingInvitation(SQLModel, table=True):
    """Database model for tracking employee onboarding invitations."""

    __tablename__ = "onboarding_invitations"

    id: Optional[int] = Field(default=None, primary_key=True)

    # Invitation identification
    invitation_token: str = Field(
        index=True, unique=True, max_length=100, description="Unique invitation token"
    )

    # Employee email and role
    email: str = Field(index=True, max_length=255, description="Employee email")
    role: str = Field(max_length=50, description="Assigned role")

    # Job details
    job_title: str = Field(max_length=100, description="Job title")
    salary: float = Field(description="Monthly salary")
    salary_currency: str = Field(default="USD", max_length=3)

    # Employment type
    employment_type: str = Field(
        default="permanent", max_length=20, description="permanent or contract"
    )

    # Probation for permanent employees
    probation_months: Optional[int] = Field(
        default=None, description="Probation period in months"
    )
    probation_end_date: Optional[date] = Field(
        default=None, description="Calculated probation end date"
    )

    # Contract dates for contract employees
    contract_start_date: Optional[date] = Field(default=None)
    contract_end_date: Optional[date] = Field(default=None)

    # Department and team
    department: Optional[str] = Field(default=None, max_length=100)
    team: Optional[str] = Field(default=None, max_length=100)
    manager_id: Optional[int] = Field(default=None)

    # Important dates
    joining_date: date = Field(description="Expected joining date")
    performance_review_date: Optional[date] = Field(
        default=None, description="Next performance review date"
    )
    salary_increment_date: Optional[date] = Field(
        default=None, description="Next salary increment date"
    )

    # Notes
    notes: Optional[str] = Field(default=None, max_length=500)

    # Onboarding status tracking
    status: str = Field(default="initiated", max_length=50)
    initiated_by: int = Field(description="User ID who initiated onboarding")
    initiated_at: datetime = Field(default_factory=datetime.utcnow)

    # Asgardeo tracking
    asgardeo_id: Optional[str] = Field(default=None, max_length=255)

    # Local records tracking
    user_id: Optional[int] = Field(default=None)
    employee_id: Optional[int] = Field(default=None)

    # Timestamps
    invitation_sent_at: Optional[datetime] = Field(default=None)
    asgardeo_created_at: Optional[datetime] = Field(default=None)
    employee_created_at: Optional[datetime] = Field(default=None)
    completed_at: Optional[datetime] = Field(default=None)
    expires_at: datetime = Field(description="Invitation expiry timestamp")

    # Cancellation tracking
    cancelled_at: Optional[datetime] = Field(default=None)
    cancelled_by: Optional[int] = Field(default=None)
    cancellation_reason: Optional[str] = Field(default=None, max_length=500)


class User(SQLModel, table=True):
    """User database table model."""

    id: Optional[int] = Field(default=None, primary_key=True)

    # Asgardeo Integration
    asgardeo_id: str = Field(index=True, max_length=255, nullable=False, unique=True)

    # User Identity
    email: str = Field(index=True, max_length=255, nullable=False, unique=True)
    first_name: Optional[str] = Field(default=None, max_length=100, nullable=True)
    last_name: Optional[str] = Field(default=None, max_length=100, nullable=True)
    phone: Optional[str] = Field(default=None, max_length=20, nullable=True)

    # Role and Status
    role: str = Field(default="employee", max_length=50, nullable=False)
    status: str = Field(default="active", max_length=50, nullable=False)

    # Links to Other Services
    employee_id: Optional[int] = Field(default=None, nullable=True)

    # Timestamps
    created_at: datetime = Field(default_factory=datetime.now, nullable=False)
    updated_at: datetime = Field(default_factory=datetime.now, nullable=False)
    last_login: Optional[datetime] = Field(default=None, nullable=True)
    deleted_at: Optional[datetime] = Field(default=None, nullable=True)


# Request Schemas


class UserUpdate(SQLModel):
    """Schema for updating user profile."""

    first_name: Optional[str] = Field(default=None, max_length=100)
    last_name: Optional[str] = Field(default=None, max_length=100)
    phone: Optional[str] = Field(default=None, max_length=20)


class UserRoleUpdate(SQLModel):
    """Schema for updating user role."""

    role: str = Field(max_length=50)


class UserSuspend(SQLModel):
    """Schema for suspending a user."""

    reason: str = Field(max_length=500)


class UserDelete(SQLModel):
    """Schema for deleting a user."""

    reason: Optional[str] = Field(default=None, max_length=500)


# Response Schemas


class UserPublic(SQLModel):
    """Public user data for list responses."""

    id: int
    email: str
    first_name: Optional[str]
    last_name: Optional[str]
    phone: Optional[str]
    role: str
    status: str
    asgardeo_id: str
    employee_id: Optional[int]
    created_at: datetime
    updated_at: datetime
    last_login: Optional[datetime]


class UserProfileResponse(SQLModel):
    """User profile response schema."""

    id: int
    email: str
    first_name: Optional[str]
    last_name: Optional[str]
    phone: Optional[str]
    role: str
    status: str
    asgardeo_id: str
    employee_id: Optional[int]
    created_at: datetime
    updated_at: datetime
    last_login: Optional[datetime]


class UserListResponse(SQLModel):
    """Paginated user list response."""

    total: int
    users: list[UserPublic]


class SignupResponse(SQLModel):
    """Response for signup endpoint."""

    user_id: int
    email: str
    asgardeo_id: str
    status: str = "created"


class MessageResponse(SQLModel):
    """Generic message response."""

    message: str
