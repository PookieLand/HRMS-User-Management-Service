"""
Event definitions for User Management Service.

Defines all event types and their data structures for Kafka publishing.
Events are categorized into:
- User lifecycle events (create, update, delete, suspend, activate)
- Onboarding events (step-by-step tracking)
- Special events (birthdays, work anniversaries)
- HR events (probation, contracts, reviews)
"""

from datetime import date, datetime
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class EventType(str, Enum):
    """All event types produced by the User Management Service."""

    # User Lifecycle Events
    USER_CREATED = "user.created"
    USER_UPDATED = "user.updated"
    USER_DELETED = "user.deleted"
    USER_SUSPENDED = "user.suspended"
    USER_ACTIVATED = "user.activated"
    USER_ROLE_CHANGED = "user.role.changed"

    # Onboarding Events
    ONBOARDING_INITIATED = "onboarding.initiated"
    ONBOARDING_INVITATION_SENT = "onboarding.invitation.sent"
    ONBOARDING_ASGARDEO_USER_CREATED = "onboarding.asgardeo.user.created"
    ONBOARDING_EMPLOYEE_CREATED = "onboarding.employee.created"
    ONBOARDING_COMPLETED = "onboarding.completed"
    ONBOARDING_FAILED = "onboarding.failed"
    ONBOARDING_CANCELLED = "onboarding.cancelled"

    # Special Events (Celebrations)
    SPECIAL_BIRTHDAY = "special.birthday"
    SPECIAL_WORK_ANNIVERSARY = "special.work.anniversary"

    # HR Events
    HR_PROBATION_ENDING_SOON = "hr.probation.ending.soon"
    HR_PROBATION_ENDED = "hr.probation.ended"
    HR_CONTRACT_EXPIRING_SOON = "hr.contract.expiring.soon"
    HR_CONTRACT_EXPIRED = "hr.contract.expired"
    HR_PERFORMANCE_REVIEW_DUE = "hr.performance.review.due"
    HR_SALARY_INCREMENT_DUE = "hr.salary.increment.due"

    # Notification Triggers
    NOTIFICATION_WELCOME = "notification.welcome"
    NOTIFICATION_INVITATION = "notification.invitation"

    # Audit Events
    AUDIT_USER_ACTION = "audit.user.action"


class EventMetadata(BaseModel):
    """Metadata attached to every event for tracing and correlation."""

    source_service: str = "user-management-service"
    correlation_id: str = Field(default_factory=lambda: str(uuid4()))
    causation_id: Optional[str] = None
    actor_user_id: Optional[str] = None
    actor_role: Optional[str] = None
    trace_id: Optional[str] = None
    ip_address: Optional[str] = None


class EventEnvelope(BaseModel):
    """
    Standard envelope for all events.
    Provides consistent structure for Kafka messages.
    """

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    event_type: EventType
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    version: str = "1.0"
    data: dict[str, Any]
    metadata: EventMetadata = Field(default_factory=EventMetadata)


# User Lifecycle Event Data Models


class UserCreatedEvent(BaseModel):
    """Data for user.created event."""

    user_id: int
    email: str
    first_name: str
    last_name: str
    role: str
    status: str
    asgardeo_id: Optional[str] = None
    employee_id: Optional[int] = None


class UserUpdatedEvent(BaseModel):
    """Data for user.updated event."""

    user_id: int
    email: str
    updated_fields: dict[str, Any]
    previous_values: Optional[dict[str, Any]] = None


class UserDeletedEvent(BaseModel):
    """Data for user.deleted event."""

    user_id: int
    email: str
    deleted_by: int
    reason: Optional[str] = None


class UserSuspendedEvent(BaseModel):
    """Data for user.suspended event."""

    user_id: int
    email: str
    suspended_by: int
    reason: Optional[str] = None


class UserActivatedEvent(BaseModel):
    """Data for user.activated event."""

    user_id: int
    email: str
    activated_by: int


class UserRoleChangedEvent(BaseModel):
    """Data for user.role.changed event."""

    user_id: int
    email: str
    old_role: str
    new_role: str
    changed_by: int


# Onboarding Event Data Models


class OnboardingInitiatedEvent(BaseModel):
    """Data for onboarding.initiated event."""

    invitation_token: str
    email: str
    role: str
    job_title: str
    salary: float
    salary_currency: str
    employment_type: str
    probation_months: Optional[int] = None
    contract_start_date: Optional[date] = None
    contract_end_date: Optional[date] = None
    joining_date: date
    department: Optional[str] = None
    team: Optional[str] = None
    manager_id: Optional[int] = None
    initiated_by: int
    initiated_by_name: Optional[str] = None


class OnboardingInvitationSentEvent(BaseModel):
    """Data for onboarding.invitation.sent event."""

    invitation_token: str
    email: str
    role: str
    job_title: str
    invitation_link: str
    expires_at: datetime


class OnboardingAsgardeoUserCreatedEvent(BaseModel):
    """Data for onboarding.asgardeo.user.created event."""

    invitation_token: str
    email: str
    asgardeo_id: str
    user_id: int
    first_name: str
    last_name: str


class OnboardingEmployeeCreatedEvent(BaseModel):
    """Data for onboarding.employee.created event."""

    invitation_token: str
    email: str
    user_id: int
    employee_id: int
    role: str
    job_title: str
    employment_type: str
    joining_date: date


class OnboardingCompletedEvent(BaseModel):
    """Data for onboarding.completed event."""

    invitation_token: str
    email: str
    user_id: int
    employee_id: int
    asgardeo_id: str
    role: str
    job_title: str
    employment_type: str
    joining_date: date
    initiated_by: int
    completed_at: datetime


class OnboardingFailedEvent(BaseModel):
    """Data for onboarding.failed event."""

    invitation_token: str
    email: str
    step: str
    error_message: str
    initiated_by: int


class OnboardingCancelledEvent(BaseModel):
    """Data for onboarding.cancelled event."""

    invitation_token: str
    email: str
    cancelled_by: int
    reason: Optional[str] = None


# Special Event Data Models


class BirthdayEvent(BaseModel):
    """Data for special.birthday event."""

    user_id: int
    employee_id: int
    email: str
    first_name: str
    last_name: str
    date_of_birth: date
    age: Optional[int] = None


class WorkAnniversaryEvent(BaseModel):
    """Data for special.work.anniversary event."""

    user_id: int
    employee_id: int
    email: str
    first_name: str
    last_name: str
    joining_date: date
    years_of_service: int


# HR Event Data Models


class ProbationEndingEvent(BaseModel):
    """Data for hr.probation.ending.soon event."""

    user_id: int
    employee_id: int
    email: str
    first_name: str
    last_name: str
    probation_end_date: date
    days_remaining: int
    manager_id: Optional[int] = None
    manager_email: Optional[str] = None


class ProbationEndedEvent(BaseModel):
    """Data for hr.probation.ended event."""

    user_id: int
    employee_id: int
    email: str
    first_name: str
    last_name: str
    probation_end_date: date
    manager_id: Optional[int] = None


class ContractExpiringEvent(BaseModel):
    """Data for hr.contract.expiring.soon event."""

    user_id: int
    employee_id: int
    email: str
    first_name: str
    last_name: str
    contract_end_date: date
    days_remaining: int
    manager_id: Optional[int] = None
    manager_email: Optional[str] = None


class ContractExpiredEvent(BaseModel):
    """Data for hr.contract.expired event."""

    user_id: int
    employee_id: int
    email: str
    first_name: str
    last_name: str
    contract_end_date: date


class PerformanceReviewDueEvent(BaseModel):
    """Data for hr.performance.review.due event."""

    user_id: int
    employee_id: int
    email: str
    first_name: str
    last_name: str
    review_due_date: date
    years_since_joining: int
    manager_id: Optional[int] = None
    manager_email: Optional[str] = None


class SalaryIncrementDueEvent(BaseModel):
    """Data for hr.salary.increment.due event."""

    user_id: int
    employee_id: int
    email: str
    first_name: str
    last_name: str
    increment_due_date: date
    years_of_service: int
    current_salary: Optional[float] = None


# Notification Event Data Models


class WelcomeNotificationEvent(BaseModel):
    """Data for notification.welcome event."""

    user_id: int
    email: str
    first_name: str
    last_name: str
    role: str
    job_title: str


class InvitationNotificationEvent(BaseModel):
    """Data for notification.invitation event."""

    email: str
    invitation_link: str
    role: str
    job_title: str
    company_name: str
    expires_at: datetime
    initiated_by_name: Optional[str] = None


# Audit Event Data Model


class AuditUserActionEvent(BaseModel):
    """Data for audit.user.action event."""

    actor_user_id: int
    actor_email: str
    actor_role: str
    action: str
    resource_type: str
    resource_id: int
    description: str
    old_value: Optional[dict[str, Any]] = None
    new_value: Optional[dict[str, Any]] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None


# Helper functions for creating events


def create_event(
    event_type: EventType,
    data: BaseModel,
    actor_user_id: Optional[str] = None,
    actor_role: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> EventEnvelope:
    """
    Helper function to create an event envelope with proper metadata.

    Args:
        event_type: Type of the event
        data: Event data as a Pydantic model
        actor_user_id: ID of the user performing the action
        actor_role: Role of the user performing the action
        correlation_id: Optional correlation ID for tracing

    Returns:
        EventEnvelope ready for publishing
    """
    metadata = EventMetadata(
        actor_user_id=actor_user_id,
        actor_role=actor_role,
        correlation_id=correlation_id or str(uuid4()),
    )

    return EventEnvelope(
        event_type=event_type,
        data=data.model_dump(mode="json"),
        metadata=metadata,
    )
