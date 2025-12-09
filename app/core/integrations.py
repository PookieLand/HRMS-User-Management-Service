"""
Client integrations for external microservices.

Provides HTTP clients for:
- Employee Management Service
- Audit Service
- Compliance Service
- Notification Service

All clients use httpx for async HTTP requests and include
proper error handling and logging.
"""

from datetime import date
from decimal import Decimal
from typing import Any, Dict, Optional

import httpx

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


def serialize_value(value: Any) -> Any:
    """Serialize complex types for JSON payload."""
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value)
    return value


class EmployeeServiceClient:
    """
    Client for Employee Management Service integration.
    Handles employee creation and status updates during onboarding.
    """

    def __init__(self):
        """Initialize Employee Service client."""
        self.base_url = settings.EMPLOYEE_SERVICE_URL
        self.timeout = settings.SERVICE_REQUEST_TIMEOUT

    async def create_employee(
        self,
        user_id: int,
        email: str,
        first_name: str,
        last_name: str,
        phone: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Create basic employee record in Employee Service.
        This is the simple internal endpoint for quick employee creation.

        Args:
            user_id: User ID from User Management Service
            email: Employee email
            first_name: Employee first name
            last_name: Employee last name
            phone: Employee phone/contact number (optional)

        Returns:
            Employee data with employee_id, or None if failed
        """
        url = f"{self.base_url.rstrip('/')}/api/v1/employees/internal"

        payload = {
            "user_id": user_id,
            "email": email,
            "first_name": first_name,
            "last_name": last_name,
            "contact_number": phone,
        }

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, follow_redirects=True
            ) as client:
                response = await client.post(url, json=payload)

                if response.status_code in [200, 201]:
                    data = response.json()
                    logger.info(
                        f"✅ Employee created successfully: {data.get('id')} "
                        f"for user {user_id}"
                    )
                    return data
                elif response.status_code == 401:
                    logger.error(
                        f"❌ 401 Unauthorized from Employee Service\n"
                        f"The employee endpoint requires authentication.\n"
                        f"Fix: Make employee creation endpoint allow internal service calls\n"
                        f"     OR send a service token with the request"
                    )
                    return None
                elif response.status_code == 307:
                    logger.error(
                        f"❌ 307 Redirect from Employee Service\n"
                        f"URL: {url}\n"
                        f"This usually means URL format issue (missing/extra slash)\n"
                        f"Response: {response.text}"
                    )
                    return None
                else:
                    logger.error(
                        f"❌ Failed to create employee: HTTP {response.status_code}\n"
                        f"URL: {url}\n"
                        f"Response: {response.text[:500]}"
                    )
                    return None

        except httpx.RequestError as e:
            logger.error(
                f"❌ Network error calling Employee Service at {url}\n"
                f"Error: {e}\n"
                f"Check if employee-service is running: curl {self.base_url}/health"
            )
            return None
        except Exception as e:
            logger.error(f"❌ Unexpected error creating employee: {e}")
            return None

    async def create_employee_from_onboarding(
        self,
        user_id: int,
        email: str,
        first_name: str,
        last_name: str,
        phone: Optional[str] = None,
        role: str = "employee",
        job_title: str = "Employee",
        department: Optional[str] = None,
        team: Optional[str] = None,
        manager_id: Optional[int] = None,
        salary: float = 0.0,
        salary_currency: str = "USD",
        employment_type: str = "permanent",
        joining_date: Optional[date] = None,
        probation_months: Optional[int] = None,
        probation_end_date: Optional[date] = None,
        contract_start_date: Optional[date] = None,
        contract_end_date: Optional[date] = None,
        performance_review_date: Optional[date] = None,
        salary_increment_date: Optional[date] = None,
        date_of_birth: Optional[date] = None,
        gender: Optional[str] = None,
        nationality: Optional[str] = None,
        address_line_1: Optional[str] = None,
        address_line_2: Optional[str] = None,
        city: Optional[str] = None,
        state: Optional[str] = None,
        country: Optional[str] = None,
        postal_code: Optional[str] = None,
        emergency_contact_name: Optional[str] = None,
        emergency_contact_phone: Optional[str] = None,
        emergency_contact_relationship: Optional[str] = None,
        bank_name: Optional[str] = None,
        bank_account_number: Optional[str] = None,
        bank_routing_number: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Create full employee record from onboarding data.
        Uses the comprehensive onboarding endpoint with all HR and personal data.

        Args:
            user_id: User ID from User Management Service
            email: Employee email
            first_name: Employee first name
            last_name: Employee last name
            phone: Employee phone number
            role: Employee role (HR_Manager, manager, employee)
            job_title: Job title
            department: Department name
            team: Team name
            manager_id: Manager's employee ID
            salary: Monthly salary
            salary_currency: Currency code (USD, EUR, etc.)
            employment_type: 'permanent' or 'contract'
            joining_date: Date employee joins
            probation_months: Number of months for probation
            probation_end_date: Calculated probation end date
            contract_start_date: Contract start date (for contract employees)
            contract_end_date: Contract end date (for contract employees)
            performance_review_date: Next performance review date
            salary_increment_date: Next salary increment date
            date_of_birth: Employee's date of birth
            gender: Employee's gender
            nationality: Employee's nationality
            address_line_1: Address line 1
            address_line_2: Address line 2
            city: City
            state: State/Province
            country: Country
            postal_code: Postal/ZIP code
            emergency_contact_name: Emergency contact name
            emergency_contact_phone: Emergency contact phone
            emergency_contact_relationship: Relationship to employee
            bank_name: Bank name for payroll
            bank_account_number: Bank account number
            bank_routing_number: Bank routing number
            notes: Additional notes

        Returns:
            Employee data with employee_id, or None if failed
        """
        url = f"{self.base_url.rstrip('/')}/api/v1/employees/internal/onboarding"

        # Build payload with all fields, serializing dates and decimals
        payload = {
            "user_id": user_id,
            "email": email,
            "first_name": first_name,
            "last_name": last_name,
            "phone": phone,
            "role": role,
            "job_title": job_title,
            "department": department,
            "team": team,
            "manager_id": manager_id,
            "salary": serialize_value(salary),
            "salary_currency": salary_currency,
            "employment_type": employment_type,
            "joining_date": serialize_value(joining_date) if joining_date else None,
            "probation_months": probation_months,
            "probation_end_date": serialize_value(probation_end_date)
            if probation_end_date
            else None,
            "contract_start_date": serialize_value(contract_start_date)
            if contract_start_date
            else None,
            "contract_end_date": serialize_value(contract_end_date)
            if contract_end_date
            else None,
            "performance_review_date": serialize_value(performance_review_date)
            if performance_review_date
            else None,
            "salary_increment_date": serialize_value(salary_increment_date)
            if salary_increment_date
            else None,
            "date_of_birth": serialize_value(date_of_birth) if date_of_birth else None,
            "gender": gender,
            "nationality": nationality,
            "address_line_1": address_line_1,
            "address_line_2": address_line_2,
            "city": city,
            "state": state,
            "country": country,
            "postal_code": postal_code,
            "emergency_contact_name": emergency_contact_name,
            "emergency_contact_phone": emergency_contact_phone,
            "emergency_contact_relationship": emergency_contact_relationship,
            "bank_name": bank_name,
            "bank_account_number": bank_account_number,
            "bank_routing_number": bank_routing_number,
            "notes": notes,
        }

        # Remove None values to keep payload clean
        payload = {k: v for k, v in payload.items() if v is not None}

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, follow_redirects=True
            ) as client:
                response = await client.post(url, json=payload)

                if response.status_code in [200, 201]:
                    data = response.json()
                    logger.info(
                        f"✅ Employee created from onboarding: {data.get('id')} "
                        f"for user {user_id} ({email})"
                    )
                    return data
                elif response.status_code == 400:
                    logger.warning(
                        f"⚠️ Bad request creating employee: {response.text[:500]}"
                    )
                    return None
                elif response.status_code == 401:
                    logger.error(
                        f"❌ 401 Unauthorized from Employee Service\nURL: {url}"
                    )
                    return None
                else:
                    logger.error(
                        f"❌ Failed to create employee from onboarding: HTTP {response.status_code}\n"
                        f"URL: {url}\n"
                        f"Response: {response.text[:500]}"
                    )
                    return None

        except httpx.RequestError as e:
            logger.error(
                f"❌ Network error calling Employee Service at {url}\n"
                f"Error: {e}\n"
                f"Check if employee-service is running"
            )
            return None
        except Exception as e:
            logger.error(f"❌ Unexpected error creating employee from onboarding: {e}")
            return None

    async def update_employee_status(self, employee_id: int, status: str) -> bool:
        """
        Update employee status (e.g., terminate).

        Args:
            employee_id: Employee ID
            status: New status (e.g., 'terminated', 'active', 'suspended')

        Returns:
            True if successful, False otherwise
        """
        url = f"{self.base_url}/api/v1/employees/{employee_id}"

        payload = {"status": status}

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.patch(url, json=payload)

                if response.status_code == 200:
                    logger.info(f"Employee status updated: {employee_id} -> {status}")
                    return True
                else:
                    logger.error(
                        f"Failed to update employee status: {response.status_code}"
                    )
                    return False

        except httpx.RequestError as e:
            logger.error(f"Error calling Employee Service: {e}")
            return False

    async def get_employee(self, employee_id: int) -> Optional[Dict[str, Any]]:
        """
        Get employee information.

        Args:
            employee_id: Employee ID

        Returns:
            Employee data or None if not found
        """
        url = f"{self.base_url}/api/v1/employees/internal/{employee_id}"

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(url)

                if response.status_code == 200:
                    return response.json()
                else:
                    logger.warning(f"Employee not found: {employee_id}")
                    return None

        except httpx.RequestError as e:
            logger.error(f"Error calling Employee Service: {e}")
            return None

    async def get_employee_by_user_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """
        Get employee by user ID (from User Management Service).

        Args:
            user_id: User ID from User Management Service

        Returns:
            Employee data or None if not found
        """
        url = f"{self.base_url}/api/v1/employees/internal/by-user/{user_id}"

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(url)

                if response.status_code == 200:
                    return response.json()
                else:
                    logger.warning(f"Employee not found for user_id: {user_id}")
                    return None

        except httpx.RequestError as e:
            logger.error(f"Error calling Employee Service: {e}")
            return None

    async def get_employee_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """
        Get employee by email.

        Args:
            email: Employee email

        Returns:
            Employee data or None if not found
        """
        url = f"{self.base_url}/api/v1/employees/internal/by-email/{email}"

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(url)

                if response.status_code == 200:
                    return response.json()
                else:
                    logger.warning(f"Employee not found for email: {email}")
                    return None

        except httpx.RequestError as e:
            logger.error(f"Error calling Employee Service: {e}")
            return None


class AuditServiceClient:
    """
    Client for Audit Service integration.
    Logs all user-related actions for compliance and auditing.
    """

    def __init__(self):
        """Initialize Audit Service client."""
        self.base_url = settings.AUDIT_SERVICE_URL
        self.timeout = settings.SERVICE_REQUEST_TIMEOUT

    async def log_action(
        self,
        user_id: int,
        action: str,
        resource_type: str,
        resource_id: int,
        description: Optional[str] = None,
        old_value: Optional[str] = None,
        new_value: Optional[str] = None,
    ) -> bool:
        """
        Log an audit event.

        Args:
            user_id: User performing the action
            action: Action type (e.g., 'create', 'update', 'delete')
            resource_type: Type of resource affected (e.g., 'user')
            resource_id: ID of the affected resource
            description: Optional action description
            old_value: Previous value (for updates)
            new_value: New value (for updates)

        Returns:
            True if logged successfully, False otherwise
        """
        url = f"{self.base_url}/api/v1/audit-logs"

        payload = {
            "user_id": user_id,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "description": description,
            "old_value": old_value,
            "new_value": new_value,
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(url, json=payload)

                if response.status_code in [200, 201]:
                    logger.info(
                        f"Audit logged: {action} on {resource_type} {resource_id}"
                    )
                    return True
                else:
                    logger.warning(
                        f"Failed to log audit: {response.status_code} - {response.text}"
                    )
                    return False

        except httpx.RequestError as e:
            logger.warning(f"Error calling Audit Service (non-blocking): {e}")
            # Don't fail the main operation if audit fails
            return False


class ComplianceServiceClient:
    """
    Client for Compliance Service integration.
    Checks compliance policies before critical operations.
    """

    def __init__(self):
        """Initialize Compliance Service client."""
        self.base_url = settings.COMPLIANCE_SERVICE_URL
        self.timeout = settings.SERVICE_REQUEST_TIMEOUT

    async def validate_policy(
        self, policy_name: str, context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Validate a compliance policy.

        Args:
            policy_name: Name of the policy to validate
            context: Context data for the policy

        Returns:
            Response with validation status and details
        """
        url = f"{self.base_url}/api/v1/policies/validate"

        payload = {
            "policy_name": policy_name,
            "context": context,
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(url, json=payload)

                if response.status_code == 200:
                    data = response.json()
                    logger.info(f"Policy validation: {policy_name} -> {data}")
                    return data
                else:
                    logger.error(f"Policy validation failed: {response.status_code}")
                    return {"valid": False, "error": "Policy validation failed"}

        except httpx.RequestError as e:
            logger.error(f"Error calling Compliance Service: {e}")
            return {"valid": False, "error": f"Service error: {e}"}

    async def check_user_deletion_policy(self, user_id: int) -> bool:
        """
        Check if user can be deleted according to compliance policies.

        Args:
            user_id: User ID to check

        Returns:
            True if deletion is allowed, False otherwise
        """
        result = await self.validate_policy("user_deletion", {"user_id": user_id})
        return result.get("valid", False)

    async def check_data_retention_policy(self, user_id: int) -> Dict[str, Any]:
        """
        Check data retention policy for user deletion.

        Args:
            user_id: User ID

        Returns:
            Retention policy details
        """
        result = await self.validate_policy("data_retention", {"user_id": user_id})
        return result


class NotificationServiceClient:
    """
    Client for Notification Service integration.
    Sends notifications to users (asynchronous, fire-and-forget).
    """

    def __init__(self):
        """Initialize Notification Service client."""
        self.base_url = settings.NOTIFICATION_SERVICE_URL
        self.timeout = settings.SERVICE_REQUEST_TIMEOUT

    async def send_email(
        self,
        to_email: str,
        subject: str,
        template_name: str,
        template_data: Dict[str, Any],
    ) -> bool:
        """
        Send email notification (fire-and-forget).

        Args:
            to_email: Recipient email address
            subject: Email subject
            template_name: Template name
            template_data: Template variables

        Returns:
            True if sent (best effort), False if immediate failure
        """
        url = f"{self.base_url}/api/v1/notifications/email"

        payload = {
            "to": to_email,
            "subject": subject,
            "template": template_name,
            "data": template_data,
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(url, json=payload)

                if response.status_code in [200, 201, 202]:
                    logger.info(f"Email sent to {to_email}")
                    return True
                else:
                    logger.warning(
                        f"Failed to send email: {response.status_code} - {response.text}"
                    )
                    return False

        except httpx.RequestError as e:
            logger.warning(f"Error calling Notification Service: {e}")
            # Fire-and-forget, so don't fail
            return False

    async def send_account_created_notification(
        self, email: str, first_name: str, last_name: str
    ) -> bool:
        """
        Send account creation notification.

        Args:
            email: User email
            first_name: User first name
            last_name: User last name

        Returns:
            True if sent, False if failed
        """
        return await self.send_email(
            to_email=email,
            subject="Welcome to HRMS!",
            template_name="account_created",
            template_data={
                "email": email,
                "first_name": first_name,
                "last_name": last_name,
            },
        )

    async def send_onboarding_invitation(
        self,
        email: str,
        invitation_link: str,
        role: str,
        job_title: str,
        company_name: str = "HRMS Company",
        expires_at: Optional[str] = None,
        initiated_by_name: Optional[str] = None,
    ) -> bool:
        """
        Send onboarding invitation email.

        Args:
            email: Recipient email
            invitation_link: Signup invitation link
            role: Assigned role
            job_title: Job title
            company_name: Company name
            expires_at: Invitation expiry time
            initiated_by_name: Name of person who initiated onboarding

        Returns:
            True if sent, False if failed
        """
        return await self.send_email(
            to_email=email,
            subject=f"Welcome to {company_name} - Complete Your Onboarding",
            template_name="onboarding_invitation",
            template_data={
                "email": email,
                "invitation_link": invitation_link,
                "role": role,
                "job_title": job_title,
                "company_name": company_name,
                "expires_at": expires_at,
                "initiated_by_name": initiated_by_name,
            },
        )

    async def send_password_changed_notification(
        self, email: str, first_name: str
    ) -> bool:
        """
        Send password change notification.

        Args:
            email: User email
            first_name: User first name

        Returns:
            True if sent, False if failed
        """
        return await self.send_email(
            to_email=email,
            subject="Password Changed",
            template_name="password_changed",
            template_data={
                "first_name": first_name,
                "email": email,
            },
        )

    async def send_account_suspended_notification(
        self, email: str, first_name: str, reason: str
    ) -> bool:
        """
        Send account suspension notification.

        Args:
            email: User email
            first_name: User first name
            reason: Reason for suspension

        Returns:
            True if sent, False if failed
        """
        return await self.send_email(
            to_email=email,
            subject="Account Suspended",
            template_name="account_suspended",
            template_data={
                "first_name": first_name,
                "email": email,
                "reason": reason,
            },
        )

    async def send_account_deleted_notification(
        self, email: str, first_name: str
    ) -> bool:
        """
        Send account deletion notification.

        Args:
            email: User email
            first_name: User first name

        Returns:
            True if sent, False if failed
        """
        return await self.send_email(
            to_email=email,
            subject="Account Deleted",
            template_name="account_deleted",
            template_data={
                "first_name": first_name,
                "email": email,
            },
        )


# Create global client instances
employee_client = EmployeeServiceClient()
audit_client = AuditServiceClient()
compliance_client = ComplianceServiceClient()
notification_client = NotificationServiceClient()
