"""
User database model and schemas.
Defines the SQLModel table structure for the User entity and Pydantic schemas
with full support for Asgardeo integration, roles, permissions, and status tracking.
"""

from datetime import date, datetime
from typing import Optional

from sqlmodel import Field, SQLModel


class OnboardingInvitation(SQLModel, table=True):
    """
    Database model for tracking employee onboarding invitations.
    Created when HR initiates onboarding, updated as employee completes signup steps.
    """

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
        default=None, description="Next performance review date (yearly anniversary)"
    )
    salary_increment_date: Optional[date] = Field(
        default=None, description="Next salary increment date (yearly anniversary)"
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
    """
    User database table model.
    Represents the user table in the database with all required fields.
    Synced from Asgardeo identity provider.
    """

    id: Optional[int] = Field(default=None, primary_key=True)

    # Asgardeo Integration
    asgardeo_id: str = Field(
        index=True,
        max_length=255,
        nullable=False,
        unique=True,
        description="Unique identifier from Asgardeo",
    )

    # User Identity
    email: str = Field(
        index=True,
        max_length=255,
        nullable=False,
        unique=True,
        description="User email address",
    )
    first_name: Optional[str] = Field(
        default=None, max_length=100, nullable=True, description="User first name"
    )
    last_name: Optional[str] = Field(
        default=None, max_length=100, nullable=True, description="User last name"
    )
    phone: Optional[str] = Field(
        default=None, max_length=20, nullable=True, description="User phone number"
    )

    # Role and Permissions
    role: str = Field(
        default="employee",
        max_length=50,
        nullable=False,
        description="User role: admin, hr_manager, manager, employee",
    )

    # Status Management
    status: str = Field(
        default="active",
        max_length=50,
        nullable=False,
        description="User status: active, suspended, deleted",
    )

    # Links to Other Services
    employee_id: Optional[int] = Field(
        default=None, nullable=True, description="Employee ID from Employee Service"
    )

    # Timestamps
    created_at: datetime = Field(
        default_factory=datetime.now,
        nullable=False,
        description="Account creation timestamp",
    )
    updated_at: datetime = Field(
        default_factory=datetime.now,
        nullable=False,
        description="Last update timestamp",
    )
    last_login: Optional[datetime] = Field(
        default=None, nullable=True, description="Last login timestamp"
    )
    deleted_at: Optional[datetime] = Field(
        default=None, nullable=True, description="Deletion timestamp (if deleted)"
    )


class UserBase(SQLModel):
    """
    Base user schema with shared fields.
    Used as foundation for other user schemas.
    """

    email: str = Field(max_length=255, min_length=1)
    first_name: Optional[str] = Field(default=None, max_length=100)
    last_name: Optional[str] = Field(default=None, max_length=100)
    phone: Optional[str] = Field(default=None, max_length=20)
    role: str = Field(default="employee", max_length=50)
    status: str = Field(default="active", max_length=50)


class UserCreate(SQLModel):
    """
    Schema for creating a new user (signup).
    Requires email, password, and basic profile information.
    """

    email: str = Field(max_length=255, min_length=1)
    password: str = Field(min_length=8, description="Must be at least 8 characters")
    first_name: str = Field(max_length=100, min_length=1)
    last_name: str = Field(max_length=100, min_length=1)
    phone: str = Field(max_length=20, min_length=1)


class UserSignup(SQLModel):
    """
    Schema for user signup via local authentication.
    """

    email: str = Field(max_length=255, min_length=1)
    password: str = Field(min_length=8, description="Must be at least 8 characters")
    first_name: str = Field(max_length=100, min_length=1)
    last_name: str = Field(max_length=100, min_length=1)
    phone: str = Field(max_length=20, min_length=1)


class UserUpdate(SQLModel):
    """
    Schema for updating user profile (partial update).
    All fields are optional to support partial updates.
    """

    first_name: Optional[str] = Field(default=None, max_length=100)
    last_name: Optional[str] = Field(default=None, max_length=100)
    phone: Optional[str] = Field(default=None, max_length=20)


class PasswordChange(SQLModel):
    """
    Schema for changing user password.
    """

    old_password: str = Field(min_length=1, description="Current password")
    new_password: str = Field(
        min_length=8, description="New password (at least 8 chars)"
    )


class UserPasswordChange(SQLModel):
    """
    Schema for password change (alias for PasswordChange).
    """

    old_password: str = Field(min_length=1, description="Current password")
    new_password: str = Field(
        min_length=8, description="New password (at least 8 chars)"
    )


class UserRole(SQLModel):
    """
    Schema for updating user role.
    """

    role: str = Field(
        max_length=50, description="New role: admin, hr_manager, manager, employee"
    )


class UserRoleUpdate(SQLModel):
    """
    Schema for updating user role (alias for UserRole).
    """

    role: str = Field(
        max_length=50, description="New role: admin, hr_manager, manager, employee"
    )


class UserSuspend(SQLModel):
    """
    Schema for suspending a user.
    """

    reason: str = Field(max_length=500, description="Reason for suspension")


class UserDelete(SQLModel):
    """
    Schema for deleting a user.
    """

    reason: Optional[str] = Field(
        default=None, max_length=500, description="Reason for deletion"
    )


class UserPublic(UserBase):
    """
    Schema for user responses (public data).
    Includes the id, asgardeo_id, and timestamps.
    """

    id: int
    asgardeo_id: str
    employee_id: Optional[int]
    created_at: datetime
    updated_at: datetime
    last_login: Optional[datetime]


class UserDetail(UserPublic):
    """
    Detailed user schema including all fields.
    """

    pass


class SignupResponse(SQLModel):
    """
    Response schema for signup endpoint.
    """

    user_id: int
    email: str
    asgardeo_id: str
    status: str = "created"


class LoginResponse(SQLModel):
    """
    Response schema for login callback endpoint.
    """

    session_token: str
    user_id: int
    email: str
    first_name: Optional[str]
    last_name: Optional[str]
    role: str
    employee_id: Optional[int]
    expires_in: int = 3600


class UserListResponse(SQLModel):
    """
    Response schema for listing users (paginated).
    """

    total: int
    users: list[UserPublic]


class RoleInfo(SQLModel):
    """
    Schema for role information.
    """

    role_id: int
    role_name: str
    description: str


class UserPermissions(SQLModel):
    """
    Schema for user permissions.
    """

    user_id: int
    role: str
    permissions: list[str]


class MessageResponse(SQLModel):
    """
    Generic message response.
    """

    message: str
    user: Optional[UserPublic] = None


class UserProfileResponse(SQLModel):
    """
    Schema for user profile response.
    Includes user details and profile information.
    """

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
