"""
Scheduler module for User Management Service.

Provides background tasks for daily checks:
- Birthday notifications
- Work anniversary notifications
- Probation ending notifications
- Contract expiring notifications
- Performance review due notifications
- Salary increment due notifications

These tasks run daily and publish events to Kafka topics
for the notification service to consume.
"""

import asyncio
from datetime import date, timedelta
from typing import Optional

from sqlmodel import Session, select

from app.core.config import settings
from app.core.database import engine
from app.core.events import (
    BirthdayEvent,
    ContractExpiringEvent,
    EventType,
    PerformanceReviewDueEvent,
    ProbationEndingEvent,
    SalaryIncrementDueEvent,
    WorkAnniversaryEvent,
    create_event,
)
from app.core.kafka import publish_event
from app.core.logging import get_logger
from app.core.topics import KafkaTopics
from app.models.users import OnboardingInvitation, User

logger = get_logger(__name__)


# Configuration for how many days before to send notifications
PROBATION_NOTIFICATION_DAYS = 7
CONTRACT_NOTIFICATION_DAYS = 30
PERFORMANCE_REVIEW_NOTIFICATION_DAYS = 14
SALARY_INCREMENT_NOTIFICATION_DAYS = 14


class DailyScheduler:
    """
    Scheduler class for running daily checks.

    This class manages background tasks that need to run daily
    to check for events like birthdays, anniversaries, etc.
    """

    def __init__(self):
        self.is_running = False
        self.task: Optional[asyncio.Task] = None

    async def start(self):
        """Start the daily scheduler."""
        if self.is_running:
            logger.warning("Scheduler already running")
            return

        self.is_running = True
        self.task = asyncio.create_task(self._run_scheduler())
        logger.info("Daily scheduler started")

    async def stop(self):
        """Stop the daily scheduler."""
        self.is_running = False
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass
        logger.info("Daily scheduler stopped")

    async def _run_scheduler(self):
        """Main scheduler loop that runs once per day."""
        while self.is_running:
            try:
                # Run all daily checks
                await self.run_daily_checks()

                # Wait until next day (calculate time until midnight)
                await self._wait_until_next_run()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in scheduler: {e}")
                # Wait 1 hour before retrying on error
                await asyncio.sleep(3600)

    async def _wait_until_next_run(self):
        """Wait until the next scheduled run time (default: midnight)."""
        # For simplicity, wait 24 hours
        # In production, calculate time until next midnight
        await asyncio.sleep(86400)  # 24 hours in seconds

    async def run_daily_checks(self):
        """
        Run all daily checks.

        This method is the main entry point for daily scheduled tasks.
        It can also be called manually for testing.
        """
        logger.info("Starting daily checks")
        today = date.today()

        try:
            # Run all checks concurrently
            await asyncio.gather(
                self.check_birthdays(today),
                self.check_work_anniversaries(today),
                self.check_probation_endings(today),
                self.check_contract_expirations(today),
                self.check_performance_reviews(today),
                self.check_salary_increments(today),
            )
            logger.info("Daily checks completed successfully")
        except Exception as e:
            logger.error(f"Error running daily checks: {e}")

    async def check_birthdays(self, today: date):
        """
        Check for employee birthdays today and publish events.

        Args:
            today: The date to check for birthdays
        """
        logger.info("Checking for birthdays...")

        with Session(engine) as session:
            # Get all active users
            # In a real implementation, we'd join with employee table
            # to get date_of_birth
            users = session.exec(select(User).where(User.status == "active")).all()

            birthday_count = 0
            for user in users:
                # Skip if no employee_id (employee data not available)
                if not user.employee_id:
                    continue

                # In a real implementation, we'd fetch date_of_birth from
                # employee service or have it in our database
                # For now, we'll skip this check
                # TODO: Implement when employee service integration is ready
                pass

            logger.info(f"Found {birthday_count} birthdays today")

    async def check_work_anniversaries(self, today: date):
        """
        Check for work anniversaries today and publish events.

        Args:
            today: The date to check for anniversaries
        """
        logger.info("Checking for work anniversaries...")

        with Session(engine) as session:
            # Get all completed onboarding invitations
            invitations = session.exec(
                select(OnboardingInvitation).where(
                    OnboardingInvitation.status == "completed"
                )
            ).all()

            anniversary_count = 0
            for inv in invitations:
                # Check if today is the anniversary of joining date
                joining_date = inv.joining_date
                if (
                    joining_date.month == today.month
                    and joining_date.day == today.day
                    and joining_date.year < today.year
                ):
                    # Get user
                    user = session.exec(
                        select(User).where(User.id == inv.user_id)
                    ).first()

                    if user and user.status == "active":
                        years = today.year - joining_date.year

                        # Publish anniversary event
                        try:
                            event_data = WorkAnniversaryEvent(
                                user_id=user.id,
                                employee_id=inv.employee_id or 0,
                                email=user.email,
                                first_name=user.first_name or "",
                                last_name=user.last_name or "",
                                joining_date=joining_date,
                                years_of_service=years,
                            )
                            event = create_event(
                                EventType.SPECIAL_WORK_ANNIVERSARY, event_data
                            )
                            await publish_event(
                                KafkaTopics.SPECIAL_WORK_ANNIVERSARY, event
                            )
                            anniversary_count += 1
                            logger.info(
                                f"Published work anniversary event for {user.email} "
                                f"({years} years)"
                            )
                        except Exception as e:
                            logger.error(
                                f"Failed to publish anniversary event for {user.email}: {e}"
                            )

            logger.info(f"Found {anniversary_count} work anniversaries today")

    async def check_probation_endings(self, today: date):
        """
        Check for probation periods ending soon and publish events.

        Args:
            today: The date to check against
        """
        logger.info("Checking for probation endings...")

        notification_date = today + timedelta(days=PROBATION_NOTIFICATION_DAYS)

        with Session(engine) as session:
            # Get invitations with probation ending on or before notification date
            invitations = session.exec(
                select(OnboardingInvitation).where(
                    OnboardingInvitation.status == "completed",
                    OnboardingInvitation.employment_type == "permanent",
                    OnboardingInvitation.probation_end_date != None,
                    OnboardingInvitation.probation_end_date <= notification_date,
                    OnboardingInvitation.probation_end_date >= today,
                )
            ).all()

            probation_count = 0
            for inv in invitations:
                user = session.exec(select(User).where(User.id == inv.user_id)).first()

                if user and user.status == "active":
                    days_remaining = (inv.probation_end_date - today).days

                    # Get manager info if available
                    manager = None
                    if inv.manager_id:
                        manager = session.exec(
                            select(User).where(User.id == inv.manager_id)
                        ).first()

                    try:
                        event_data = ProbationEndingEvent(
                            user_id=user.id,
                            employee_id=inv.employee_id or 0,
                            email=user.email,
                            first_name=user.first_name or "",
                            last_name=user.last_name or "",
                            probation_end_date=inv.probation_end_date,
                            days_remaining=days_remaining,
                            manager_id=inv.manager_id,
                            manager_email=manager.email if manager else None,
                        )
                        event = create_event(
                            EventType.HR_PROBATION_ENDING_SOON, event_data
                        )
                        await publish_event(KafkaTopics.HR_PROBATION_ENDING, event)
                        probation_count += 1
                        logger.info(
                            f"Published probation ending event for {user.email} "
                            f"({days_remaining} days remaining)"
                        )
                    except Exception as e:
                        logger.error(
                            f"Failed to publish probation event for {user.email}: {e}"
                        )

            logger.info(f"Found {probation_count} probation periods ending soon")

    async def check_contract_expirations(self, today: date):
        """
        Check for contracts expiring soon and publish events.

        Args:
            today: The date to check against
        """
        logger.info("Checking for contract expirations...")

        notification_date = today + timedelta(days=CONTRACT_NOTIFICATION_DAYS)

        with Session(engine) as session:
            # Get invitations with contracts expiring soon
            invitations = session.exec(
                select(OnboardingInvitation).where(
                    OnboardingInvitation.status == "completed",
                    OnboardingInvitation.employment_type == "contract",
                    OnboardingInvitation.contract_end_date != None,
                    OnboardingInvitation.contract_end_date <= notification_date,
                    OnboardingInvitation.contract_end_date >= today,
                )
            ).all()

            contract_count = 0
            for inv in invitations:
                user = session.exec(select(User).where(User.id == inv.user_id)).first()

                if user and user.status == "active":
                    days_remaining = (inv.contract_end_date - today).days

                    # Get manager info if available
                    manager = None
                    if inv.manager_id:
                        manager = session.exec(
                            select(User).where(User.id == inv.manager_id)
                        ).first()

                    try:
                        event_data = ContractExpiringEvent(
                            user_id=user.id,
                            employee_id=inv.employee_id or 0,
                            email=user.email,
                            first_name=user.first_name or "",
                            last_name=user.last_name or "",
                            contract_end_date=inv.contract_end_date,
                            days_remaining=days_remaining,
                            manager_id=inv.manager_id,
                            manager_email=manager.email if manager else None,
                        )
                        event = create_event(
                            EventType.HR_CONTRACT_EXPIRING_SOON, event_data
                        )
                        await publish_event(KafkaTopics.HR_CONTRACT_EXPIRING, event)
                        contract_count += 1
                        logger.info(
                            f"Published contract expiring event for {user.email} "
                            f"({days_remaining} days remaining)"
                        )
                    except Exception as e:
                        logger.error(
                            f"Failed to publish contract event for {user.email}: {e}"
                        )

            logger.info(f"Found {contract_count} contracts expiring soon")

    async def check_performance_reviews(self, today: date):
        """
        Check for performance reviews due soon and publish events.

        Performance reviews are due yearly on the anniversary of joining date.

        Args:
            today: The date to check against
        """
        logger.info("Checking for performance reviews...")

        notification_date = today + timedelta(days=PERFORMANCE_REVIEW_NOTIFICATION_DAYS)

        with Session(engine) as session:
            # Get invitations with performance review coming up
            invitations = session.exec(
                select(OnboardingInvitation).where(
                    OnboardingInvitation.status == "completed",
                    OnboardingInvitation.performance_review_date != None,
                )
            ).all()

            review_count = 0
            for inv in invitations:
                # Check if review date falls within notification window
                review_date = inv.performance_review_date
                if review_date and today <= review_date <= notification_date:
                    user = session.exec(
                        select(User).where(User.id == inv.user_id)
                    ).first()

                    if user and user.status == "active":
                        years = review_date.year - inv.joining_date.year

                        # Get manager info if available
                        manager = None
                        if inv.manager_id:
                            manager = session.exec(
                                select(User).where(User.id == inv.manager_id)
                            ).first()

                        try:
                            event_data = PerformanceReviewDueEvent(
                                user_id=user.id,
                                employee_id=inv.employee_id or 0,
                                email=user.email,
                                first_name=user.first_name or "",
                                last_name=user.last_name or "",
                                review_due_date=review_date,
                                years_since_joining=years,
                                manager_id=inv.manager_id,
                                manager_email=manager.email if manager else None,
                            )
                            event = create_event(
                                EventType.HR_PERFORMANCE_REVIEW_DUE, event_data
                            )
                            await publish_event(
                                KafkaTopics.HR_PERFORMANCE_REVIEW_DUE, event
                            )
                            review_count += 1
                            logger.info(
                                f"Published performance review event for {user.email}"
                            )
                        except Exception as e:
                            logger.error(
                                f"Failed to publish review event for {user.email}: {e}"
                            )

            logger.info(f"Found {review_count} performance reviews due soon")

    async def check_salary_increments(self, today: date):
        """
        Check for salary increments due soon and publish events.

        Salary increments are due yearly on the anniversary of joining date.

        Args:
            today: The date to check against
        """
        logger.info("Checking for salary increments...")

        notification_date = today + timedelta(days=SALARY_INCREMENT_NOTIFICATION_DAYS)

        with Session(engine) as session:
            # Get invitations with salary increment coming up
            invitations = session.exec(
                select(OnboardingInvitation).where(
                    OnboardingInvitation.status == "completed",
                    OnboardingInvitation.salary_increment_date != None,
                )
            ).all()

            increment_count = 0
            for inv in invitations:
                # Check if increment date falls within notification window
                increment_date = inv.salary_increment_date
                if increment_date and today <= increment_date <= notification_date:
                    user = session.exec(
                        select(User).where(User.id == inv.user_id)
                    ).first()

                    if user and user.status == "active":
                        years = increment_date.year - inv.joining_date.year

                        try:
                            event_data = SalaryIncrementDueEvent(
                                user_id=user.id,
                                employee_id=inv.employee_id or 0,
                                email=user.email,
                                first_name=user.first_name or "",
                                last_name=user.last_name or "",
                                increment_due_date=increment_date,
                                years_of_service=years,
                                current_salary=inv.salary,
                            )
                            event = create_event(
                                EventType.HR_SALARY_INCREMENT_DUE, event_data
                            )
                            await publish_event(
                                KafkaTopics.HR_SALARY_INCREMENT_DUE, event
                            )
                            increment_count += 1
                            logger.info(
                                f"Published salary increment event for {user.email}"
                            )
                        except Exception as e:
                            logger.error(
                                f"Failed to publish increment event for {user.email}: {e}"
                            )

            logger.info(f"Found {increment_count} salary increments due soon")


# Global scheduler instance
daily_scheduler = DailyScheduler()


async def run_manual_daily_checks():
    """
    Manually trigger daily checks.

    This function can be called from an API endpoint for testing
    or administrative purposes.
    """
    scheduler = DailyScheduler()
    await scheduler.run_daily_checks()
