"""
Onboarding request/response schemas for User Management Service.

Defines Pydantic models for the employee onboarding flow.
Note: The database model OnboardingInvitation is in users.py
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


# Request Schemas


class InitiateOnboardingRequest(BaseModel):
    """Request to initiate employee onboarding by HR."""

    email: EmailStr
    role: str = Field(pattern="^(HR_Manager|manager|employee)$")
    job_title: str = Field(min_length=2, max_length=100)
    salary: float = Field(gt=0)
    salary_currency: str = Field(default="USD", max_length=3)
    employment_type: EmploymentType = EmploymentType.PERMANENT
    probation_months: Optional[int] = Field(default=None, ge=1, le=12)
    contract_start_date: Optional[date] = None
    contract_end_date: Optional[date] = None
    department: Optional[str] = Field(default=None, max_length=100)
    team: Optional[str] = Field(default=None, max_length=100)
    manager_id: Optional[int] = None
    joining_date: date
    notes: Optional[str] = Field(default=None, max_length=500)
    frontend_origin: Optional[str] = Field(default=None, max_length=255)


class SignupStep1Request(BaseModel):
    """Step 1: Employee creates their user account."""

    invitation_token: str
    password: str = Field(min_length=8)
    first_name: str = Field(min_length=1, max_length=100)
    last_name: str = Field(min_length=1, max_length=100)
    phone: str = Field(min_length=1, max_length=20)


class SignupStep2Request(BaseModel):
    """Step 2: Employee provides additional personal details."""

    invitation_token: str
    date_of_birth: Optional[date] = None
    gender: Optional[str] = Field(default=None, pattern="^(male|female|other)$")
    nationality: Optional[str] = Field(default=None, max_length=100)
    address_line_1: Optional[str] = Field(default=None, max_length=200)
    address_line_2: Optional[str] = Field(default=None, max_length=200)
    city: Optional[str] = Field(default=None, max_length=100)
    state: Optional[str] = Field(default=None, max_length=100)
    country: Optional[str] = Field(default=None, max_length=100)
    postal_code: Optional[str] = Field(default=None, max_length=20)
    emergency_contact_name: Optional[str] = Field(default=None, max_length=100)
    emergency_contact_phone: Optional[str] = Field(default=None, max_length=20)
    emergency_contact_relationship: Optional[str] = Field(default=None, max_length=50)
    bank_name: Optional[str] = Field(default=None, max_length=100)
    bank_account_number: Optional[str] = Field(default=None, max_length=50)
    bank_routing_number: Optional[str] = Field(default=None, max_length=50)


class CancelOnboardingRequest(BaseModel):
    """Request to cancel an ongoing onboarding."""

    reason: Optional[str] = Field(default=None, max_length=500)


# Response Schemas


class InitiateOnboardingResponse(BaseModel):
    """Response after initiating onboarding."""

    message: str = "Onboarding initiated successfully"
    invitation_token: str
    email: str
    role: str
    job_title: str
    invitation_link: str
    expires_at: datetime


class SignupStep1Response(BaseModel):
    """Response after completing signup step 1."""

    message: str = "User account created successfully"
    email: str
    asgardeo_id: str
    user_id: int
    next_step: str = "complete_employee_profile"


class SignupStep2Response(BaseModel):
    """Response after completing signup step 2."""

    message: str = "Onboarding completed successfully"
    user_id: int
    employee_id: int
    email: str
    role: str
    job_title: str
    employment_type: str
    joining_date: date
    check_email_for_password: bool = True


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


class OnboardingPreviewData(BaseModel):
    """Data shown to employee when they click the invitation link."""

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
