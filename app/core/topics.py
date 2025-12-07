"""
Kafka Topic Definitions for User Management Service.

Topic naming follows the pattern: <domain>-<event-type>
This makes topics easily identifiable and organized by business domain.
"""


class KafkaTopics:
    """
    Central registry of all Kafka topics used by the User Management Service.
    Topics are named following the pattern: <domain>-<event-type>
    """

    # User Events - General user lifecycle events
    USER_CREATED = "user-created"
    USER_UPDATED = "user-updated"
    USER_DELETED = "user-deleted"
    USER_SUSPENDED = "user-suspended"
    USER_ACTIVATED = "user-activated"
    USER_ROLE_CHANGED = "user-role-changed"

    # Onboarding Events - Step by step onboarding flow
    ONBOARDING_INITIATED = "user-onboarding-initiated"
    ONBOARDING_ASGARDEO_USER_CREATED = "user-onboarding-asgardeo-created"
    ONBOARDING_EMPLOYEE_CREATED = "user-onboarding-employee-created"
    ONBOARDING_COMPLETED = "user-onboarding-completed"
    ONBOARDING_FAILED = "user-onboarding-failed"

    # Special Events - Celebrations and milestones
    SPECIAL_BIRTHDAY = "user-special-birthday"
    SPECIAL_WORK_ANNIVERSARY = "user-special-work-anniversary"

    # HR Events - HR specific notifications
    HR_PROBATION_ENDING = "hr-probation-ending"
    HR_PROBATION_ENDED = "hr-probation-ended"
    HR_CONTRACT_EXPIRING = "hr-contract-expiring"
    HR_CONTRACT_EXPIRED = "hr-contract-expired"
    HR_PERFORMANCE_REVIEW_DUE = "hr-performance-review-due"
    HR_SALARY_INCREMENT_DUE = "hr-salary-increment-due"

    # Notification Events - Triggers for notification service
    NOTIFICATION_WELCOME_EMAIL = "notification-welcome-email"
    NOTIFICATION_INVITATION_EMAIL = "notification-invitation-email"
    NOTIFICATION_PASSWORD_SET = "notification-password-set"

    # Audit Events - For audit service consumption
    AUDIT_USER_ACTION = "audit-user-action"

    @classmethod
    def all_topics(cls) -> list[str]:
        """Return list of all topic names."""
        return [
            value
            for name, value in vars(cls).items()
            if isinstance(value, str) and not name.startswith("_")
        ]

    @classmethod
    def user_topics(cls) -> list[str]:
        """Return list of user-related topics."""
        return [
            cls.USER_CREATED,
            cls.USER_UPDATED,
            cls.USER_DELETED,
            cls.USER_SUSPENDED,
            cls.USER_ACTIVATED,
            cls.USER_ROLE_CHANGED,
        ]

    @classmethod
    def onboarding_topics(cls) -> list[str]:
        """Return list of onboarding-related topics."""
        return [
            cls.ONBOARDING_INITIATED,
            cls.ONBOARDING_ASGARDEO_USER_CREATED,
            cls.ONBOARDING_EMPLOYEE_CREATED,
            cls.ONBOARDING_COMPLETED,
            cls.ONBOARDING_FAILED,
        ]

    @classmethod
    def special_event_topics(cls) -> list[str]:
        """Return list of special event topics."""
        return [
            cls.SPECIAL_BIRTHDAY,
            cls.SPECIAL_WORK_ANNIVERSARY,
        ]

    @classmethod
    def hr_event_topics(cls) -> list[str]:
        """Return list of HR event topics."""
        return [
            cls.HR_PROBATION_ENDING,
            cls.HR_PROBATION_ENDED,
            cls.HR_CONTRACT_EXPIRING,
            cls.HR_CONTRACT_EXPIRED,
            cls.HR_PERFORMANCE_REVIEW_DUE,
            cls.HR_SALARY_INCREMENT_DUE,
        ]
