# HR Management System - Asgardeo Integration Guide

## 🎯 Integration Overview

This guide shows how to integrate Asgardeo with your **User/Identity Service** for role-based access control in your HR Management System.

---

## 📋 What You Need from Asgardeo

Based on your project requirements, you need Asgardeo for:

### ✅ **User Management (Primary Focus)**
- Create users when employees are onboarded
- Update user details when employee info changes
- Deactivate users when employees leave
- List/search users for admin functions

### ✅ **Group Management (RBAC Only)**
- 3 Role Groups: `HR-Admins`, `HR-Managers`, `Employees`
- Assign users to role groups during onboarding
- Change user roles (move between groups)
- **NOT NEEDED**: Complex group hierarchies, group deletion, frequent group updates

---

## 🚀 Quick Start - Complete Integration

### Step 1: Setup (One-time)

```python
# config.py
import os
from asgardeo_client import AsgardeoConfig

asgardeo_config = AsgardeoConfig(
    organization=os.getenv("ASGARDEO_ORG"),
    client_id=os.getenv("ASGARDEO_CLIENT_ID"),
    client_secret=os.getenv("ASGARDEO_CLIENT_SECRET")
)

# Role group names for your HR system
ROLE_GROUPS = {
    "admin": "HR-Admins",
    "hr_manager": "HR-Managers",
    "employee": "Employees"
}
```

### Step 2: Create User/Identity Service

```python
# services/identity_service.py
from asgardeo_client import AsgardeoClient
from config import asgardeo_config, ROLE_GROUPS
from typing import Optional
import httpx

class IdentityService:
    """
    User Identity Service for HR Management System
    Integrates with Asgardeo for user management and RBAC
    """
    
    def __init__(self):
        self.client = AsgardeoClient(asgardeo_config)
    
    async def close(self):
        await self.client.close()
    
    # ==================== User Management ====================
    
    async def create_employee_user(
        self,
        email: str,
        first_name: str,
        last_name: str,
        role: str,  # "admin", "hr_manager", or "employee"
        employee_id: str,
        department: Optional[str] = None
    ) -> dict:
        """
        Create user account for new employee
        
        Returns:
            dict with asgardeo_user_id and status
        """
        try:
            # Create user in Asgardeo
            user = await self.client.create_user(
                username=f"DEFAULT/{email}",
                email=email,
                given_name=first_name,
                family_name=last_name,
                ask_password=True,  # User gets invitation email
                additional_attributes={
                    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
                        "employeeNumber": employee_id,
                        "department": department or "General"
                    }
                }
            )
            
            # Assign to role group
            await self._assign_role(user['id'], role, f"{first_name} {last_name}")
            
            return {
                "asgardeo_user_id": user['id'],
                "status": "created",
                "username": user['userName'],
                "invitation_sent": True
            }
        
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 409:
                # User already exists - try to find them
                existing_user = await self._find_user_by_email(email)
                if existing_user:
                    return {
                        "asgardeo_user_id": existing_user['id'],
                        "status": "already_exists",
                        "username": existing_user['userName']
                    }
            raise
    
    async def update_employee_role(
        self,
        asgardeo_user_id: str,
        old_role: str,
        new_role: str
    ) -> dict:
        """
        Change employee role (e.g., promote employee to HR manager)
        """
        # Get user details
        user = await self.client.get_user(asgardeo_user_id)
        display_name = f"{user['name']['givenName']} {user['name']['familyName']}"
        
        # Remove from old role group
        old_group = await self.client.find_group_by_name(ROLE_GROUPS[old_role])
        if old_group:
            await self.client.remove_user_from_group(
                group_id=old_group['id'],
                user_id=asgardeo_user_id
            )
        
        # Add to new role group
        await self._assign_role(asgardeo_user_id, new_role, display_name)
        
        return {
            "status": "role_updated",
            "old_role": old_role,
            "new_role": new_role
        }
    
    async def deactivate_employee(self, asgardeo_user_id: str) -> dict:
        """
        Deactivate user when employee leaves the organization
        """
        await self.client.patch_user(
            user_id=asgardeo_user_id,
            operations=[
                {
                    "op": "replace",
                    "path": "active",
                    "value": False
                }
            ]
        )
        
        return {"status": "deactivated"}
    
    async def reactivate_employee(self, asgardeo_user_id: str) -> dict:
        """
        Reactivate user (e.g., employee returning from leave)
        """
        await self.client.patch_user(
            user_id=asgardeo_user_id,
            operations=[
                {
                    "op": "replace",
                    "path": "active",
                    "value": True
                }
            ]
        )
        
        return {"status": "reactivated"}
    
    async def update_employee_details(
        self,
        asgardeo_user_id: str,
        email: Optional[str] = None,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        department: Optional[str] = None
    ) -> dict:
        """
        Update employee details in Asgardeo
        """
        operations = []
        
        if email:
            operations.append({
                "op": "replace",
                "path": "emails[type eq \"work\"].value",
                "value": email
            })
        
        if first_name:
            operations.append({
                "op": "replace",
                "path": "name.givenName",
                "value": first_name
            })
        
        if last_name:
            operations.append({
                "op": "replace",
                "path": "name.familyName",
                "value": last_name
            })
        
        if department:
            operations.append({
                "op": "replace",
                "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User.department",
                "value": department
            })
        
        if operations:
            await self.client.patch_user(
                user_id=asgardeo_user_id,
                operations=operations
            )
        
        return {"status": "updated", "operations_applied": len(operations)}
    
    async def list_employees(
        self,
        role: Optional[str] = None,
        department: Optional[str] = None,
        active_only: bool = True
    ) -> list:
        """
        List employees with optional filtering
        """
        filters = []
        
        if active_only:
            filters.append('active eq true')
        
        if department:
            filters.append(f'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User.department eq "{department}"')
        
        filter_str = " and ".join(filters) if filters else None
        
        users = await self.client.list_users(filter=filter_str, count=100)
        
        # If role filter specified, filter by group membership
        if role:
            group = await self.client.find_group_by_name(ROLE_GROUPS[role])
            if group and 'members' in group:
                role_user_ids = {m['value'] for m in group['members']}
                users['Resources'] = [
                    u for u in users['Resources'] 
                    if u['id'] in role_user_ids
                ]
        
        return users['Resources']
    
    # ==================== Internal Helper Methods ====================
    
    async def _assign_role(
        self,
        user_id: str,
        role: str,
        display_name: str
    ):
        """Assign user to role group"""
        role_group_name = ROLE_GROUPS.get(role, ROLE_GROUPS["employee"])
        
        await self.client.assign_user_role(
            user_id=user_id,
            role_group_name=role_group_name,
            user_display_name=display_name
        )
    
    async def _find_user_by_email(self, email: str) -> Optional[dict]:
        """Find user by email address"""
        users = await self.client.list_users(
            filter=f'emails.value eq "{email}"',
            count=1
        )
        
        if users.get('totalResults', 0) > 0:
            return users['Resources'][0]
        return None
    
    # ==================== Setup Methods ====================
    
    async def setup_role_groups(self):
        """
        One-time setup: Create the three role groups if they don't exist
        Call this during system initialization
        """
        created_groups = []
        
        for role_key, group_name in ROLE_GROUPS.items():
            existing_group = await self.client.find_group_by_name(group_name)
            
            if not existing_group:
                group = await self.client.create_group(group_name)
                created_groups.append(group_name)
                print(f"✅ Created group: {group_name}")
            else:
                print(f"ℹ️  Group already exists: {group_name}")
        
        return {
            "status": "complete",
            "created": created_groups,
            "total_groups": len(ROLE_GROUPS)
        }
```

### Step 3: Integrate with FastAPI

```python
# main.py
from fastapi import FastAPI, HTTPException, Depends
from contextlib import asynccontextmanager
from services.identity_service import IdentityService
from pydantic import BaseModel, EmailStr

# Request/Response Models
class CreateEmployeeRequest(BaseModel):
    email: EmailStr
    first_name: str
    last_name: str
    role: str  # "admin", "hr_manager", or "employee"
    employee_id: str
    department: str | None = None

class UpdateRoleRequest(BaseModel):
    old_role: str
    new_role: str

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize identity service and create role groups
    app.state.identity = IdentityService()
    
    # One-time setup: ensure role groups exist
    print("🔧 Setting up Asgardeo role groups...")
    await app.state.identity.setup_role_groups()
    print("✅ Asgardeo integration ready")
    
    yield
    
    # Shutdown
    await app.state.identity.close()

app = FastAPI(title="HR Management System", lifespan=lifespan)

def get_identity_service() -> IdentityService:
    return app.state.identity

# ==================== API Endpoints ====================

@app.post("/api/employees", status_code=201)
async def create_employee(
    request: CreateEmployeeRequest,
    identity: IdentityService = Depends(get_identity_service)
):
    """
    Create new employee and Asgardeo user account
    """
    try:
        # Create user in Asgardeo
        result = await identity.create_employee_user(
            email=request.email,
            first_name=request.first_name,
            last_name=request.last_name,
            role=request.role,
            employee_id=request.employee_id,
            department=request.department
        )
        
        # TODO: Also create employee record in your MySQL database here
        # employee_db_record = await employee_service.create(...)
        
        return {
            "message": "Employee created successfully",
            "asgardeo_user_id": result["asgardeo_user_id"],
            "username": result["username"],
            "invitation_sent": result.get("invitation_sent", False)
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.patch("/api/employees/{asgardeo_user_id}/role")
async def update_employee_role(
    asgardeo_user_id: str,
    request: UpdateRoleRequest,
    identity: IdentityService = Depends(get_identity_service)
):
    """
    Change employee role (update group membership)
    """
    try:
        result = await identity.update_employee_role(
            asgardeo_user_id=asgardeo_user_id,
            old_role=request.old_role,
            new_role=request.new_role
        )
        
        return result
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/employees/{asgardeo_user_id}/deactivate")
async def deactivate_employee(
    asgardeo_user_id: str,
    identity: IdentityService = Depends(get_identity_service)
):
    """
    Deactivate employee user account
    """
    try:
        result = await identity.deactivate_employee(asgardeo_user_id)
        
        # TODO: Also update employee status in MySQL
        # await employee_service.update_status(asgardeo_user_id, "inactive")
        
        return result
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/employees")
async def list_employees(
    role: str | None = None,
    department: str | None = None,
    active_only: bool = True,
    identity: IdentityService = Depends(get_identity_service)
):
    """
    List employees with optional filters
    """
    try:
        employees = await identity.list_employees(
            role=role,
            department=department,
            active_only=active_only
        )
        
        return {
            "total": len(employees),
            "employees": employees
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
```

---

## 🔄 Common Workflows

### 1. Employee Onboarding
```python
# When new employee joins
result = await identity_service.create_employee_user(
    email="john.doe@company.com",
    first_name="John",
    last_name="Doe",
    role="employee",
    employee_id="EMP001",
    department="Engineering"
)

# User receives email invitation to set password
# They are automatically assigned to "Employees" group
```

### 2. Promotion to HR Manager
```python
# When employee is promoted
await identity_service.update_employee_role(
    asgardeo_user_id="user-id-123",
    old_role="employee",
    new_role="hr_manager"
)

# User is removed from "Employees" group
# User is added to "HR-Managers" group
```

### 3. Employee Departure
```python
# When employee leaves
await identity_service.deactivate_employee(
    asgardeo_user_id="user-id-123"
)

# User account is deactivated (can't login)
# Group memberships remain (for audit purposes)
```

### 4. Department Transfer
```python
# When employee changes department
await identity_service.update_employee_details(
    asgardeo_user_id="user-id-123",
    department="Sales"
)

# Department attribute is updated in Asgardeo
```

---

## 🎯 Role-Based Access Control (RBAC)

### Group Permissions Mapping

Map Asgardeo groups to your application permissions:

```python
# middleware/rbac.py
from fastapi import HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security = HTTPBearer()

ROLE_PERMISSIONS = {
    "HR-Admins": [
        "employee:create",
        "employee:read",
        "employee:update",
        "employee:delete",
        "leave:approve",
        "audit:view",
        "system:configure"
    ],
    "HR-Managers": [
        "employee:read",
        "employee:update",
        "leave:approve",
        "attendance:manage"
    ],
    "Employees": [
        "profile:read",
        "profile:update",
        "leave:apply",
        "attendance:view"
    ]
}

async def require_permission(permission: str):
    """
    Dependency to check if user has required permission
    """
    async def permission_checker(
        credentials: HTTPAuthorizationCredentials = Security(security)
    ):
        # Decode JWT token from Asgardeo
        token = credentials.credentials
        user_groups = extract_groups_from_token(token)
        
        # Check if any of user's groups has the permission
        user_permissions = []
        for group in user_groups:
            user_permissions.extend(ROLE_PERMISSIONS.get(group, []))
        
        if permission not in user_permissions:
            raise HTTPException(
                status_code=403,
                detail=f"Permission denied. Required: {permission}"
            )
        
        return True
    
    return permission_checker

# Usage in endpoints
@app.post("/api/employees", dependencies=[Depends(require_permission("employee:create"))])
async def create_employee(...):
    pass

@app.get("/api/employees/{id}", dependencies=[Depends(require_permission("employee:read"))])
async def get_employee(...):
    pass
```

---

## 📊 Database Schema Integration

Your MySQL database should store the Asgardeo user ID:

```sql
-- employees table
CREATE TABLE employees (
    id INT PRIMARY KEY AUTO_INCREMENT,
    employee_id VARCHAR(50) UNIQUE NOT NULL,
    asgardeo_user_id VARCHAR(255) UNIQUE NOT NULL,  -- Link to Asgardeo
    email VARCHAR(255) UNIQUE NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    department VARCHAR(100),
    position VARCHAR(100),
    start_date DATE NOT NULL,
    contract_type ENUM('permanent', 'contract', 'probation'),
    status ENUM('active', 'inactive', 'on_leave') DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_asgardeo_user_id (asgardeo_user_id),
    INDEX idx_email (email)
);
```

---

## 🔒 Security Best Practices

### 1. Token Validation
```python
# Validate JWT tokens from Asgardeo in your API
from fastapi.security import HTTPBearer
from jose import jwt, JWTError

ASGARDEO_JWKS_URL = f"https://api.asgardeo.io/t/{org}/oauth2/jwks"

async def validate_token(token: str):
    try:
        # Fetch JWKS and validate
        payload = jwt.decode(
            token,
            key=get_jwks(),
            algorithms=["RS256"],
            audience="your-client-id"
        )
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
```

### 2. Scope Verification
```python
# Ensure M2M application has correct scopes enabled:
REQUIRED_SCOPES = [
    "internal_user_mgt_create",
    "internal_user_mgt_view",
    "internal_user_mgt_update",
    "internal_user_mgt_delete",
    "internal_org_group_mgt_view",
    "internal_org_group_mgt_create",
    "internal_org_group_mgt_update"
]
```

### 3. Credential Management
```bash
# .env file
ASGARDEO_ORG=your-org
ASGARDEO_CLIENT_ID=your-m2m-client-id
ASGARDEO_CLIENT_SECRET=your-m2m-client-secret

# Never commit credentials to git!
```

---

## 🧪 Testing

```python
# tests/test_identity_service.py
import pytest
from services.identity_service import IdentityService

@pytest.fixture
async def identity_service():
    service = IdentityService()
    yield service
    await service.close()

@pytest.mark.asyncio
async def test_create_employee_user(identity_service):
    result = await identity_service.create_employee_user(
        email="test@example.com",
        first_name="Test",
        last_name="User",
        role="employee",
        employee_id="TEST001",
        department="Testing"
    )
    
    assert result["status"] == "created"
    assert result["asgardeo_user_id"]
    assert result["invitation_sent"] == True

@pytest.mark.asyncio
async def test_role_change(identity_service):
    # First create user
    user = await identity_service.create_employee_user(...)
    
    # Then promote
    result = await identity_service.update_employee_role(
        asgardeo_user_id=user["asgardeo_user_id"],
        old_role="employee",
        new_role="hr_manager"
    )
    
    assert result["status"] == "role_updated"
```

---

## 📈 Monitoring & Logging

```python
# Add logging to track Asgardeo operations
import logging

logger = logging.getLogger(__name__)

async def create_employee_user(self, ...):
    logger.info(f"Creating Asgardeo user for employee: {email}")
    
    try:
        user = await self.client.create_user(...)
        logger.info(f"✅ User created: {user['id']}")
        
        await self._assign_role(user['id'], role, ...)
        logger.info(f"✅ Role assigned: {role}")
        
        return result
    
    except Exception as e:
        logger.error(f"❌ Failed to create user: {e}")
        raise
```

---

## 🎯 Summary

### What You're Using from Asgardeo:
✅ **Users**: Create, update, deactivate, list  
✅ **Groups**: 3 role groups for RBAC  
✅ **User-Group Assignment**: Add/remove users from role groups

### What You're NOT Using:
❌ Group deletion  
❌ Complex group hierarchies  
❌ Group search (simple list with filter is enough)  
❌ Frequent group updates

### Simplified Client Methods for HR System:
- `create_user()` - Onboarding
- `patch_user()` - Updates and deactivation
- `list_users()` - Admin functions
- `create_group()` - One-time setup
- `add_user_to_group()` - Role assignment
- `remove_user_from_group()` - Role changes
- `find_group_by_name()` - Helper for role lookup
- `assign_user_role()` - High-level role assignment

This focused approach gives you everything you need for your HR system's RBAC without unnecessary complexity! 🚀
