# Asgardeo SCIM2 Client - Usage Guide

A comprehensive Python client for Asgardeo's SCIM2 API with OAuth2 Client Credentials authentication for machine-to-machine communication.

## Table of Contents
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Authentication](#authentication)
- [User Management](#user-management)
- [Group Management](#group-management)
- [Bulk Operations](#bulk-operations)
- [Advanced Features](#advanced-features)
- [Error Handling](#error-handling)
- [Integration with FastAPI](#integration-with-fastapi)

---

## Installation

### Prerequisites
```bash
pip install httpx pydantic
```

### Setup
1. Copy `asgardeo_client.py` to your project
2. Register a Machine-to-Machine (M2M) application in Asgardeo:
   - Go to Asgardeo Console → Applications → New Application
   - Select "Machine to Machine Application"
   - Enable required scopes (see [Required Scopes](#required-scopes))
   - Copy Client ID and Client Secret

---

## Quick Start

```python
import asyncio
from asgardeo_client import AsgardeoClient, AsgardeoConfig

async def main():
    # Initialize client
    config = AsgardeoConfig(
        organization="your-org-name",
        client_id="your-client-id",
        client_secret="your-client-secret"
    )
    
    async with AsgardeoClient(config) as client:
        # Create a user
        user = await client.create_user(
            username="john.doe@example.com",
            email="john.doe@example.com",
            given_name="John",
            family_name="Doe",
            ask_password=True  # User gets invitation email
        )
        print(f"Created user: {user['id']}")
        
        # List all users
        users = await client.list_users(count=10)
        print(f"Total users: {users['totalResults']}")
        
        # Create a group
        group = await client.create_group(
            display_name="Engineering",
            members=[user['id']]
        )
        print(f"Created group: {group['id']}")

if __name__ == "__main__":
    asyncio.run(main())
```

---

## Configuration

### AsgardeoConfig Parameters

```python
config = AsgardeoConfig(
    organization="your-org",          # Your Asgardeo organization name
    client_id="abc123",               # M2M application client ID
    client_secret="secret456",        # M2M application client secret
    base_url="https://api.asgardeo.io",  # Optional: API base URL
    token_cache_buffer=300            # Optional: Token refresh buffer (seconds)
)
```

### Environment Variables (Recommended)

```python
import os
from asgardeo_client import AsgardeoClient, AsgardeoConfig

config = AsgardeoConfig(
    organization=os.getenv("ASGARDEO_ORG"),
    client_id=os.getenv("ASGARDEO_CLIENT_ID"),
    client_secret=os.getenv("ASGARDEO_CLIENT_SECRET")
)
```

---

## Authentication

The client automatically handles OAuth2 Client Credentials flow:

1. **Automatic Token Management**: Tokens are fetched and cached automatically
2. **Auto-Refresh**: Tokens are refreshed 5 minutes before expiry
3. **Scope Handling**: Required scopes are requested based on the operation

### Required Scopes

Configure these scopes in your Asgardeo M2M application:

**User Management:**
- `internal_user_mgt_list` - List users
- `internal_user_mgt_create` - Create users
- `internal_user_mgt_view` - View user details
- `internal_user_mgt_update` - Update/patch users
- `internal_user_mgt_delete` - Delete users

**Group Management:**
- `internal_group_mgt_list` - List groups
- `internal_group_mgt_create` - Create groups
- `internal_group_mgt_view` - View group details
- `internal_group_mgt_update` - Update/patch groups
- `internal_group_mgt_delete` - Delete groups

### Manual Token Access

```python
# Get current access token
token = await client.get_access_token()

# Get token with specific scopes
token = await client.get_access_token(
    scopes=["internal_user_mgt_list", "internal_user_mgt_view"]
)
```

---

## User Management

### Create User

**Option 1: With Password**
```python
user = await client.create_user(
    username="DEFAULT/john@example.com",  # Note: DEFAULT/ prefix required
    password="SecurePass123!",
    email="john@example.com",
    given_name="John",
    family_name="Doe"
)
```

**Option 2: Send Invitation (Recommended)**
```python
user = await client.create_user(
    username="DEFAULT/john@example.com",
    email="john@example.com",
    given_name="John",
    family_name="Doe",
    ask_password=True  # User receives email invitation
)
```

**Option 3: With Email Verification**
```python
user = await client.create_user(
    username="DEFAULT/john@example.com",
    password="SecurePass123!",
    email="john@example.com",
    given_name="John",
    family_name="Doe",
    verify_email=True  # User must verify email before access
)
```

**Option 3: With Additional Attributes**
```python
user = await client.create_user(
    username="DEFAULT/john@example.com",
    email="john@example.com",
    given_name="John",
    family_name="Doe",
    ask_password=True,
    additional_attributes={
        "phoneNumbers": [
            {"type": "work", "value": "+1234567890"}
        ],
        "addresses": [
            {
                "type": "work",
                "streetAddress": "123 Main St",
                "locality": "San Francisco",
                "region": "CA",
                "postalCode": "94105",
                "country": "US"
            }
        ],
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
            "manager": {
                "value": "Taylor"
            }
        }
    }
)
```

> **Important:** Username Format
> - By default, username should be in format: `DEFAULT/<email>` (e.g., `DEFAULT/john@example.com`)
> - If your organization uses alphanumeric username validation, use alphanumeric values instead

### List Users

```python
# Simple list
users = await client.list_users(count=20)

# With pagination
users = await client.list_users(start_index=21, count=20)

# With filtering
users = await client.list_users(
    filter='emails.value eq "john@example.com"',
    count=10
)

# With specific user store domain
users = await client.list_users(
    filter='userName sw "john"',
    domain="PRIMARY",
    count=50
)

# With specific attributes
users = await client.list_users(
    attributes=["userName", "emails", "name"],
    count=50
)
```

> **Note:** For organizations created after November 19, 2024, a maximum threshold of 100 is applied to the count parameter.

### Search Users (POST)

For complex queries with multiple attributes:

```python
# Search with filtering and specific attributes
results = await client.search_users(
    filter='userName sw ki and name.familyName co err',
    attributes=['name.familyName', 'userName'],
    domain='DEFAULT',
    count=10
)
```

> **Note:** The `.search` endpoint uses POST and supports the same filtering as GET, but with a request body format.

### Get User by ID

```python
user = await client.get_user(user_id="user-id-123")
print(user['userName'])
print(user['emails'][0]['value'])
```

### Update User (Full Replacement)

```python
# Get existing user first
user = await client.get_user("user-id-123")

# Modify and update
user['name']['givenName'] = "Jane"
user['emails'][0]['value'] = "jane@example.com"

updated_user = await client.update_user("user-id-123", user)
```

### Patch User (Partial Update)

**Replace Attribute:**
```python
await client.patch_user(
    user_id="user-id-123",
    operations=[
        {
            "op": "replace",
            "path": "name.givenName",
            "value": "Jane"
        }
    ]
)
```

**Update Email:**
```python
await client.patch_user(
    user_id="user-id-123",
    operations=[
        {
            "op": "replace",
            "path": "emails[type eq \"work\"].value",
            "value": "newemail@example.com"
        }
    ]
)
```

**Add Phone Number:**
```python
await client.patch_user(
    user_id="user-id-123",
    operations=[
        {
            "op": "add",
            "value": {
                "phoneNumbers": [
                    {"type": "mobile", "value": "+1234567890"}
                ]
            }
        }
    ]
)
```

> **Important:** For `add` operations with complex objects, use `value` directly without `path`.

**Deactivate User:**
```python
await client.patch_user(
    user_id="user-id-123",
    operations=[
        {
            "op": "replace",
            "path": "active",
            "value": False
        }
    ]
)
```

**Multiple Operations:**
```python
await client.patch_user(
    user_id="user-id-123",
    operations=[
        {"op": "replace", "path": "name.givenName", "value": "Jane"},
        {"op": "replace", "path": "name.familyName", "value": "Smith"},
        {"op": "replace", "path": "emails[type eq \"work\"].value", "value": "jane.smith@example.com"}
    ]
)
```

### Delete User

```python
result = await client.delete_user("user-id-123")
print(result)  # {'status': 'success', 'statusCode': 204}
```

---

## Group Management

> **Note for HR System**: Groups are primarily used for Role-Based Access Control (RBAC). You'll create 3 groups (HR-Admins, HR-Managers, Employees) during setup and mainly use them to assign/change user roles.

### Create Group

```python
# One-time setup: Create role groups
admin_group = await client.create_group("HR-Admins")
manager_group = await client.create_group("HR-Managers")
employee_group = await client.create_group("Employees")
```

### List Groups

```python
# Find group by name
groups = await client.list_groups(
    filter='displayName eq "HR-Managers"'
)

if groups['totalResults'] > 0:
    group_id = groups['Resources'][0]['id']
```

### Get Group

```python
group = await client.get_group("group-id-123")
print(group['displayName'])
print(group['members'])  # List of users in this group
```

### Assign User to Role Group (Simplified)

```python
# Add user to HR Managers group
await client.add_user_to_group(
    group_id=manager_group_id,
    user_id=user_id,
    display_name="John Doe"
)
```

### Remove User from Role Group

```python
# Remove user when changing roles
await client.remove_user_from_group(
    group_id=old_role_group_id,
    user_id=user_id
)
```

### High-Level Role Assignment Helper

```python
# Automatically find/create group and assign user
await client.assign_user_role(
    user_id=new_user_id,
    role_group_name="HR-Managers",
    user_display_name="John Doe"
)
```

### Find Group by Name Helper

```python
# Find group helper
group = await client.find_group_by_name("HR-Admins")
if group:
    group_id = group['id']
    members = group.get('members', [])
```

---

## Bulk Operations

Execute multiple operations in a single API call:

```python
result = await client.bulk_operations([
    # Create multiple users
    {
        "method": "POST",
        "path": "/Users",
        "bulkId": "user1",
        "data": {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "user1@example.com",
            "password": "Password123!",
            "emails": [{"primary": True, "value": "user1@example.com"}]
        }
    },
    {
        "method": "POST",
        "path": "/Users",
        "bulkId": "user2",
        "data": {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "user2@example.com",
            "password": "Password123!",
            "emails": [{"primary": True, "value": "user2@example.com"}]
        }
    },
    # Create a group
    {
        "method": "POST",
        "path": "/Groups",
        "bulkId": "group1",
        "data": {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": "New Team"
        }
    },
    # Update existing user
    {
        "method": "PATCH",
        "path": "/Users/existing-user-id",
        "bulkId": "update1",
        "data": {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [
                {"op": "replace", "path": "active", "value": False}
            ]
        }
    }
])

# Check results
for operation in result['Operations']:
    print(f"BulkId: {operation['bulkId']}, Status: {operation['status']}")
```

---

## Advanced Features

### SCIM Filtering

Build complex filters using helper methods:

```python
# Simple filter
filter1 = client.build_filter('userName', 'eq', 'john@example.com')

# Combined filters
filter2 = client.combine_filters([
    client.build_filter('userName', 'co', '@example.com'),
    client.build_filter('active', 'eq', 'true')
], 'and')

users = await client.list_users(filter=filter2)
```

**Common SCIM Operators (Asgardeo):**
- `eq` - Equal
- `ne` - Not equal
- `co` - Contains
- `sw` - Starts with
- `ew` - Ends with
- `and` - Logical AND

> **Note:** Asgardeo officially supports `eq`, `ne`, `co`, `sw`, `ew`, and `and` operators as per the API specification.

**Filter Examples:**
```python
# Find users by email domain
filter = 'emails.value ew "@example.com"'

# Find users by username pattern
filter = 'userName sw "DEFAULT/"'

# Complex filter with AND
filter = 'userName sw ki and name.familyName co err'

# Find by exact match
filter = 'userName eq "DEFAULT/john@example.com"'
```

### Resource Discovery

```python
# Get supported resource types
resource_types = await client.get_resource_types()

# Get SCIM schemas
schemas = await client.get_schemas()

# Get service provider configuration
config = await client.get_service_provider_config()
```

---

## Error Handling

```python
import httpx

async def safe_user_operation():
    try:
        user = await client.create_user(
            username="john@example.com",
            email="john@example.com",
            ask_password=True
        )
        return user
    
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 409:
            print("User already exists")
        elif e.response.status_code == 401:
            print("Authentication failed - check credentials")
        elif e.response.status_code == 403:
            print("Insufficient permissions - check scopes")
        else:
            print(f"HTTP error: {e.response.status_code}")
            print(e.response.json())
    
    except httpx.RequestError as e:
        print(f"Network error: {e}")
    
    except ValueError as e:
        print(f"Invalid input: {e}")
```

**Common HTTP Status Codes:**
- `200` - Success
- `201` - Created
- `204` - No Content (successful deletion)
- `400` - Bad Request (invalid data)
- `401` - Unauthorized (invalid credentials)
- `403` - Forbidden (insufficient scopes)
- `404` - Not Found
- `409` - Conflict (user/group already exists)
- `500` - Internal Server Error

---

## Integration with FastAPI

### Option 1: Dependency Injection

```python
from fastapi import FastAPI, Depends
from asgardeo_client import AsgardeoClient, AsgardeoConfig
import os

app = FastAPI()

# Global client instance
asgardeo_config = AsgardeoConfig(
    organization=os.getenv("ASGARDEO_ORG"),
    client_id=os.getenv("ASGARDEO_CLIENT_ID"),
    client_secret=os.getenv("ASGARDEO_CLIENT_SECRET")
)

# Dependency
async def get_asgardeo_client():
    client = AsgardeoClient(asgardeo_config)
    try:
        yield client
    finally:
        await client.close()

# Use in endpoints
@app.get("/users")
async def list_users(
    client: AsgardeoClient = Depends(get_asgardeo_client)
):
    users = await client.list_users(count=50)
    return users

@app.post("/users")
async def create_user(
    user_data: dict,
    client: AsgardeoClient = Depends(get_asgardeo_client)
):
    user = await client.create_user(
        username=user_data["username"],
        email=user_data["email"],
        given_name=user_data.get("givenName"),
        family_name=user_data.get("familyName"),
        ask_password=True
    )
    return user
```

### Option 2: Lifespan Events

```python
from contextlib import asynccontextmanager
from fastapi import FastAPI
from asgardeo_client import AsgardeoClient, AsgardeoConfig

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    app.state.asgardeo = AsgardeoClient(AsgardeoConfig(
        organization=os.getenv("ASGARDEO_ORG"),
        client_id=os.getenv("ASGARDEO_CLIENT_ID"),
        client_secret=os.getenv("ASGARDEO_CLIENT_SECRET")
    ))
    yield
    # Shutdown
    await app.state.asgardeo.close()

app = FastAPI(lifespan=lifespan)

@app.get("/users/{user_id}")
async def get_user(user_id: str):
    user = await app.state.asgardeo.get_user(user_id)
    return user
```

### Option 3: Service Layer

```python
# services/asgardeo_service.py
from asgardeo_client import AsgardeoClient, AsgardeoConfig
import os

class AsgardeoService:
    def __init__(self):
        config = AsgardeoConfig(
            organization=os.getenv("ASGARDEO_ORG"),
            client_id=os.getenv("ASGARDEO_CLIENT_ID"),
            client_secret=os.getenv("ASGARDEO_CLIENT_SECRET")
        )
        self.client = AsgardeoClient(config)
    
    async def create_employee_user(self, employee_data: dict):
        """Create user with employee-specific logic"""
        user = await self.client.create_user(
            username=employee_data["email"],
            email=employee_data["email"],
            given_name=employee_data["firstName"],
            family_name=employee_data["lastName"],
            ask_password=True,
            additional_attributes={
                "urn:scim:schemas:extension:enterprise:2.0:User": {
                    "employeeNumber": employee_data["employeeId"],
                    "department": employee_data["department"]
                }
            }
        )
        return user
    
    async def assign_to_department_group(self, user_id: str, department: str):
        """Add user to department group"""
        # Find group by department name
        groups = await self.client.list_groups(
            filter=f'displayName eq "{department}"'
        )
        
        if groups['totalResults'] > 0:
            group_id = groups['Resources'][0]['id']
            await self.client.patch_group(
                group_id=group_id,
                operations=[{
                    "op": "add",
                    "path": "members",
                    "value": [{"value": user_id}]
                }]
            )
    
    async def close(self):
        await self.client.close()

# main.py
from fastapi import FastAPI
from services.asgardeo_service import AsgardeoService

app = FastAPI()
asgardeo = AsgardeoService()

@app.on_event("shutdown")
async def shutdown():
    await asgardeo.close()

@app.post("/employees")
async def onboard_employee(employee_data: dict):
    # Create user
    user = await asgardeo.create_employee_user(employee_data)
    
    # Assign to department group
    await asgardeo.assign_to_department_group(
        user['id'],
        employee_data['department']
    )
    
    return {"user_id": user['id'], "status": "onboarded"}
```

---

## Best Practices

### 1. Always Use Context Manager

```python
# Good
async with AsgardeoClient(config) as client:
    users = await client.list_users()

# Also Good
client = AsgardeoClient(config)
try:
    users = await client.list_users()
finally:
    await client.close()
```

### 2. Use `ask_password=True` for User Creation

Let users set their own passwords via email invitation rather than setting initial passwords.

### 3. Handle Pagination

```python
async def get_all_users(client: AsgardeoClient):
    all_users = []
    start_index = 1
    count = 100
    
    while True:
        response = await client.list_users(
            start_index=start_index,
            count=count
        )
        
        all_users.extend(response['Resources'])
        
        if len(response['Resources']) < count:
            break
        
        start_index += count
    
    return all_users
```

### 4. Batch Operations When Possible

Use bulk operations instead of multiple individual API calls for better performance.

### 5. Use PATCH for Partial Updates

Prefer `patch_user()` over `update_user()` when updating specific fields to avoid overwriting unchanged data.

---

## Troubleshooting

### Issue: Authentication Failed (401)
- Verify client ID and client secret
- Check organization name
- Ensure M2M application is created in Asgardeo

### Issue: Insufficient Permissions (403)
- Verify required scopes are enabled in M2M application
- Check scope configuration matches operation requirements

### Issue: User Already Exists (409)
```python
try:
    user = await client.create_user(...)
except httpx.HTTPStatusError as e:
    if e.response.status_code == 409:
        # Handle existing user
        print("User already exists, fetching instead...")
        users = await client.list_users(
            filter=f'userName eq "{username}"'
        )
        user = users['Resources'][0] if users['totalResults'] > 0 else None
```

### Issue: Token Expiry
The client automatically handles token refresh, but if you experience issues:
- Check `token_cache_buffer` setting (default 300 seconds)
- Verify network connectivity to Asgardeo

---

## HR System Integration Example

Based on your HR Management System project:

```python
# user_identity_service.py
from asgardeo_client import AsgardeoClient, AsgardeoConfig
from fastapi import HTTPException

class UserIdentityService:
    def __init__(self, asgardeo_client: AsgardeoClient):
        self.client = asgardeo_client
    
    async def onboard_employee(
        self,
        employee_id: str,
        email: str,
        first_name: str,
        last_name: str,
        department: str,
        role: str
    ):
        """Create Asgardeo user when employee is onboarded"""
        try:
            # Create user in Asgardeo
            user = await self.client.create_user(
                username=email,
                email=email,
                given_name=first_name,
                family_name=last_name,
                ask_password=True,
                additional_attributes={
                    "urn:scim:schemas:extension:enterprise:2.0:User": {
                        "employeeNumber": employee_id,
                        "department": department
                    }
                }
            )
            
            # Assign to role-based group
            await self._assign_role_group(user['id'], role)
            
            return user['id']
        
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 409:
                raise HTTPException(409, "User already exists")
            raise HTTPException(500, f"Asgardeo error: {e}")
    
    async def _assign_role_group(self, user_id: str, role: str):
        """Assign user to role-based group (Admin, HR Manager, Employee)"""
        role_group_map = {
            "admin": "HR-Admins",
            "hr_manager": "HR-Managers",
            "employee": "Employees"
        }
        
        group_name = role_group_map.get(role, "Employees")
        
        # Find or create group
        groups = await self.client.list_groups(
            filter=f'displayName eq "{group_name}"'
        )
        
        if groups['totalResults'] == 0:
            group = await self.client.create_group(display_name=group_name)
            group_id = group['id']
        else:
            group_id = groups['Resources'][0]['id']
        
        # Add user to group
        await self.client.patch_group(
            group_id=group_id,
            operations=[{
                "op": "add",
                "path": "members",
                "value": [{"value": user_id}]
            }]
        )
    
    async def update_employee_role(self, user_id: str, new_role: str):
        """Update employee role by changing group membership"""
        # Get current user
        user = await self.client.get_user(user_id)
        
        # Remove from all role groups
        if 'groups' in user:
            for group in user['groups']:
                await self.client.patch_group(
                    group_id=group['value'],
                    operations=[{
                        "op": "remove",
                        "path": f'members[value eq "{user_id}"]'
                    }]
                )
        
        # Assign new role group
        await self._assign_role_group(user_id, new_role)
    
    async def deactivate_employee(self, user_id: str):
        """Deactivate user when employee leaves"""
        await self.client.patch_user(
            user_id=user_id,
            operations=[{
                "op": "replace",
                "path": "active",
                "value": False
            }]
        )
```

---

## Additional Resources

- **Asgardeo Documentation**: https://wso2.com/asgardeo/docs/
- **SCIM 2.0 Specification**: https://datatracker.ietf.org/doc/html/rfc7644
- **OAuth 2.0 Client Credentials**: https://datatracker.ietf.org/doc/html/rfc6749#section-4.4

---

## License

This client is provided as-is for use in the HR Management System project (G07 Development Team).
