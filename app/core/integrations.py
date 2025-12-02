"""
Client integrations
- Employee Management Service
- Audit Service
- Compliance Service
- Notification Service
"""

from typing import Any, Dict, Optional

import httpx

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class EmployeeServiceClient:
    """
    Client for Employee Management Service integration.
    Handles employee creation and status updates.
    """

    def __init__(self):
        """Initialize Employee Service client."""
        self.base_url = settings.EMPLOYEE_SERVICE_URL
        self.timeout = settings.SERVICE_REQUEST_TIMEOUT

    async def create_employee(
        self, user_id: int, email: str, first_name: str, last_name: str
    ) -> Optional[Dict[str, Any]]:
        """
        Create employee record in Employee Service.

        Args:
            user_id: User ID from User Management Service
            email: Employee email
            first_name: Employee first name
            last_name: Employee last name

        Returns:
            Employee data with employee_id, or None if failed
        """
        url = f"{self.base_url}/api/v1/employees"

        payload = {
            "user_id": user_id,
            "email": email,
            "first_name": first_name,
            "last_name": last_name,
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(url, json=payload)

                if response.status_code in [200, 201]:
                    data = response.json()
                    logger.info(f"Employee created: {data.get('employee_id')}")
                    return data
                else:
                    logger.error(
                        f"Failed to create employee: {response.status_code} - {response.text}"
                    )
                    return None

        except httpx.RequestError as e:
            logger.error(f"Error calling Employee Service: {e}")
            return None

    async def update_employee_status(self, employee_id: int, status: str) -> bool:
        """
        Update employee status (e.g., terminate).

        Args:
            employee_id: Employee ID
            status: New status (e.g., 'terminated', 'active')

        Returns:
            True if successful, False otherwise
        """
        url = f"{self.base_url}/api/v1/employees/{employee_id}"

        payload = {"status": status}

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.put(url, json=payload)

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
        url = f"{self.base_url}/api/v1/employees/{employee_id}"

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
