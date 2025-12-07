"""
Onboarding schemas for user management service.

Defines request/response models for the employee onboarding flow
including support for permanent employees with probation periods
and contract employees with start/end dates.
"""

from datetime import date, datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, EmailStr, Field


class EmploymentType(str, Enum):
    """Type of employment for the new hire."""

    PERMANENT = "permanent"
    CONTRACT = "contract"


class OnboardingStatus(str, Enum):
    """Status of the onboarding process."""

    INITIATED = "initiated"
    INVITATION_SENT = "invitation_sent"
    ASGARDEO_USER_CREATED = "asgardeo_user_created"
    EMPLOYEE_CREATED = "employee_created"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class InitiateOnboardingRequest(BaseModel):
    """
    Request to initiate employee onboarding.
    This is filled by HR Admin or HR Manager when hiring a new employee.
    """

    # Required employee information
    email: EmailStr = Field(description="Email address of the new employee")
    role: str = Field(
        description="Role to assign: HR_Manager, manager, or employee",
        pattern="^(HR_Manager|manager|employee)$",
    )
    job_title: str = Field(
        description="Job title (e.g., Software Engineer, Accountant)",
        min_length=2,
        max_length=100,
    )

    # Compensation
    salary: float = Field(description="Monthly salary amount", gt=0)
    salary_currency: str = Field(default="USD", max_length=3)

    # Employment type and related fields
    employment_type: EmploymentType = Field(
        default=EmploymentType.PERMANENT,
        description="Type of employment: permanent or contract",
    )

    # For permanent employees
    probation_months: Optional[int] = Field(
        default=None,
        description="Probation period in months (for permanent employees)",
        ge=1,
        le=12,
    )

    # For contract employees
    contract_start_date: Optional[date] = Field(
        default=None, description="Contract start date (for contract employees)"
    )
    contract_end_date: Optional[date] = Field(
        default=None, description="Contract end date (for contract employees)"
    )

    # Department and team
    department: Optional[str] = Field(default=None, max_length=100)
    team: Optional[str] = Field(default=None, max_length=100)
    manager_id: Optional[int] = Field(
        default=None, description="ID of the employee's manager"
    )

    # Start date
    joining_date: date = Field(description="Expected joining date")

    # Additional notes
    notes: Optional[str] = Field(default=None, max_length=500)


class OnboardingInvitation(BaseModel):
    """
    Onboarding invitation record stored in database.
    Tracks the state of an ongoing onboarding process.
    """

    id: Optional[int] = None
    invitation_token: str = Field(description="Unique token for the invitation link")
    email: EmailStr
    role: str
    job_title: str
    salary: float
    salary_currency: str
    employment_type: EmploymentType
    probation_months: Optional[int] = None
    contract_start_date: Optional[date] = None
    contract_end_date: Optional[date] = None
    department: Optional[str] = None
    team: Optional[str] = None
    manager_id: Optional[int] = None
    joining_date: date
    notes: Optional[str] = None

    # Onboarding process tracking
    status: OnboardingStatus = OnboardingStatus.INITIATED
    initiated_by: int = Field(description="User ID of HR who initiated onboarding")
    initiated_at: datetime = Field(default_factory=datetime.utcnow)

    # Asgardeo user tracking
    asgardeo_id: Optional[str] = None

    # Local user/employee tracking
    user_id: Optional[int] = None
    employee_id: Optional[int] = None

    # Timestamps
    invitation_sent_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    expires_at: datetime = Field(
        description="Invitation expiry time (default 7 days from creation)"
    )


class SignupStep1Request(BaseModel):
    """
    Step 1 of signup: Employee provides personal information.
    This creates the Asgardeo user account.
    """

    invitation_token: str = Field(description="Token from invitation email")
    password: str = Field(
        min_length=8,
        description="Password must be at least 8 characters with uppercase, number, and special char",
    )
    first_name: str = Field(min_length=1, max_length=100)
    last_name: str = Field(min_length=1, max_length=100)
    phone: str = Field(min_length=1, max_length=20)


class SignupStep1Response(BaseModel):
    """Response after completing signup step 1."""

    message: str = "User account created successfully"
    email: str
    asgardeo_id: str
    user_id: int
    next_step: str = "complete_employee_profile"


class SignupStep2Request(BaseModel):
    """
    Step 2 of signup: Employee provides additional personal details.
    This creates the employee record.
    """

    invitation_token: str = Field(description="Token from invitation email")

    # Personal information
    date_of_birth: Optional[date] = None
    gender: Optional[str] = Field(default=None, pattern="^(male|female|other)$")
    nationality: Optional[str] = Field(default=None, max_length=100)

    # Address
    address_line_1: Optional[str] = Field(default=None, max_length=200)
    address_line_2: Optional[str] = Field(default=None, max_length=200)
    city: Optional[str] = Field(default=None, max_length=100)
    state: Optional[str] = Field(default=None, max_length=100)
    country: Optional[str] = Field(default=None, max_length=100)
    postal_code: Optional[str] = Field(default=None, max_length=20)

    # Emergency contact
    emergency_contact_name: Optional[str] = Field(default=None, max_length=100)
    emergency_contact_phone: Optional[str] = Field(default=None, max_length=20)
    emergency_contact_relationship: Optional[str] = Field(default=None, max_length=50)

    # Bank details for salary
    bank_name: Optional[str] = Field(default=None, max_length=100)
    bank_account_number: Optional[str] = Field(default=None, max_length=50)
    bank_routing_number: Optional[str] = Field(default=None, max_length=50)


class SignupStep2Response(BaseModel):
    """Response after completing signup step 2 (final step)."""

    message: str = "Onboarding completed successfully"
    user_id: int
    employee_id: int
    email: str
    role: str
    job_title: str
    employment_type: str
    joining_date: date
    check_email_for_password: bool = Field(
        default=True,
        description="Reminder to check email for password setup if using Asgardeo invitation",
    )


class OnboardingStatusResponse(BaseModel):
    """Response showing current onboarding status."""

    invitation_token: str
    email: str
    status: OnboardingStatus
    role: str
    job_title: str
    employment_type: EmploymentType
    joining_date: date
    initiated_by_name: Optional[str] = None
    initiated_at: datetime
    asgardeo_user_created: bool = False
    employee_created: bool = False
    completed_at: Optional[datetime] = None
    is_expired: bool = False


class OnboardingListResponse(BaseModel):
    """Response for listing onboarding invitations."""

    total: int
    invitations: list[OnboardingStatusResponse]


class InitiateOnboardingResponse(BaseModel):
    """Response after initiating onboarding."""

    message: str = "Onboarding initiated successfully"
    invitation_token: str
    email: str
    role: str
    job_title: str
    invitation_link: str
    expires_at: datetime


class CancelOnboardingRequest(BaseModel):
    """Request to cancel an ongoing onboarding."""

    reason: Optional[str] = Field(default=None, max_length=500)


class OnboardingPreviewData(BaseModel):
    """
    Data shown to employee when they click the invitation link.
    Contains pre-filled information from HR that cannot be changed.
    """

    email: str
    role: str
    job_title: str
    salary: float
    salary_currency: str
    employment_type: EmploymentType
    probation_months: Optional[int] = None
    contract_start_date: Optional[date] = None
    contract_end_date: Optional[date] = None
    department: Optional[str] = None
    team: Optional[str] = None
    joining_date: date
    company_name: str = "HRMS Company"
    is_valid: bool = True
    is_expired: bool = False
