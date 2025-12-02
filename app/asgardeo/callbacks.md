## User
@auth.py why do we need oauth callback endpoint

## Why We Need the OAuth Callback Endpoint

The OAuth callback endpoint (`oauth_callback`) is a **critical part of the OAuth 2.0 authentication flow**. Here's why it's essential:

### 1. **Completing the OAuth Authorization Code Flow**
OAuth 2.0 works in multiple steps:
   - Client redirects user to Asgardeo login
   - User authenticates and authorizes the app
   - Asgardeo redirects back to your app with an authorization code
   - **Your callback endpoint exchanges that code for tokens** ← This is what `oauth_callback` does

Without this endpoint, the authorization code would have nowhere to go, and authentication would fail.

### 2. **Securely Exchanging Authorization Code for Tokens**
The callback endpoint:
   - Takes the authorization code from Asgardeo
   - Exchanges it for actual tokens (access token + ID token)
   - This exchange happens **server-to-server** (more secure than exposing tokens to the client)

### 3. **Validating and Decoding the ID Token**
Once tokens are received, the endpoint:
   - Decodes the JWT ID token
   - Extracts user information (email, Asgardeo ID, etc.)
   - Validates that the token contains required claims (`sub`, `email`)

### 4. **Database Synchronization**
The endpoint:
   - Looks up the user in your local database
   - Verifies the user account is active
   - Updates the `last_login` timestamp
   - Ensures the user exists in your system

### 5. **Session Token Creation**
Finally, it:
   - Creates a **session token** for your application
   - Returns user info to the frontend
   - Enables the user to access your app

### The Flow Diagram
```
1. Frontend → Asgardeo Login Page (via browser)
2. User authenticates at Asgardeo
3. Asgardeo → Your callback endpoint (with authorization code)
4. Callback endpoint → Asgardeo (exchanges code for tokens)
5. Callback endpoint → Database (validates user)
6. Callback endpoint → Frontend (returns session token)
7. Frontend can now use session token to call your API
```

Without this endpoint, the OAuth handshake cannot complete, and users cannot log in through Asgardeo.

## User

@users.py why do we need the asgardeo to db endpoint

## Why We Need the `sync_users_from_asgardeo` Endpoint

This endpoint is essential for keeping your **local database in sync with your identity provider (Asgardeo)**. Here's why it's critical:

### 1. **Data Consistency Between Systems**
Your application has two sources of truth:
   - **Asgardeo** - The identity provider (manages authentication, user profiles)
   - **Local Database** - Your HRMS application (stores roles, permissions, employee data, etc.)

This endpoint synchronizes user data between them so they stay in sync.

### 2. **Handling Updates from Asgardeo**
When user information changes in Asgardeo (name, email, etc.), the sync endpoint:
   - Fetches the updated user data from Asgardeo
   - Updates the corresponding records in your local database
   - Ensures your app always has current user information

### 3. **Creating Missing User Records**
If a user is created in Asgardeo but doesn't exist in your database:
   - The sync endpoint detects this
   - Creates a new user record in your database with `role: "employee"` and `status: "active"`
   - Prevents "user not found" errors during login

### 4. **Admin Bulk Operations**
The endpoint supports two modes:
   - **Specific user sync** (`user_id` parameter): Update one user's data
   - **Bulk sync**: Synchronize all users from Asgardeo at once

This is useful when:
   - An admin wants to refresh all user data after a major Asgardeo update
   - A specific user's profile changed and needs to be refreshed

### 5. **User Profile Updates Flow**
```
┌─────────────────────────────────────────────────────────┐
│ User updates profile in Asgardeo (name, email, etc.)    │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│ Admin calls sync_users_from_asgardeo endpoint           │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│ Endpoint fetches updated user data from Asgardeo        │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│ Updates local database records with new data            │
└─────────────────────────────────────────────────────────┘
```

### Key Use Cases:
- **After Asgardeo bulk imports** - Sync users created in Asgardeo to your database
- **Profile updates** - Keep first_name, last_name in sync with Asgardeo
- **Daily/Weekly sync jobs** - Automated scheduled syncs to maintain consistency
- **Manual admin refresh** - Allow admins to manually sync when needed

### Why Not Just Use Asgardeo Data?
You can't rely solely on Asgardeo because:
- Your app stores **additional data** (employee_id, department, salary, etc.)
- You have **local roles and permissions** specific to your HRMS
- You need **audit trails** and local history
- Asgardeo is for authentication; your DB is for application-specific data

The sync endpoint is the **bridge** that keeps both systems aligned while maintaining the separation of concerns.

## User

i dont want that to happen i want that to be real time is that possible

## Real-Time Sync Options

### **Option 1: Webhooks (RECOMMENDED) 🔥**
Asgardeo sends webhook events to your app when user data changes. This is true real-time.

**How it works:**
```
1. User changes profile in Asgardeo
2. Asgardeo immediately sends webhook POST to your app
3. Your app receives and processes the event
4. Database updated instantly
```

**Implementation:**
```/data/wso2group7/HRMS/services/user-management-service/app/api/auth.py#L1-50
# Add a new webhook handler endpoint
@router.post("/webhooks/asgardeo/user-updated")
async def handle_asgardeo_webhook(
    request: Request,
    session: SessionDep = None
):
    """Handle real-time user updates from Asgardeo"""
    payload = await request.json()
    
    # Verify webhook signature (security)
    if not verify_webhook_signature(payload):
        raise HTTPException(status_code=401, detail="Invalid signature")
    
    # Extract event details
    event_type = payload.get("eventType")  # e.g., "user.updated"
    user_data = payload.get("user")
    
    if event_type == "user.updated":
        user = session.exec(
            select(User).where(User.asgardeo_id == user_data["id"])
        ).first()
        
        if user:
            user.first_name = user_data.get("name", {}).get("givenName")
            user.last_name = user_data.get("name", {}).get("familyName")
            user.updated_at = datetime.now()
            session.add(user)
            session.commit()
    
    return {"status": "processed"}
```

**Asgardeo Setup:**
1. Go to Asgardeo Console → Webhooks
2. Configure webhook URL: `https://your-app.com/webhooks/asgardeo/user-updated`
3. Select events: `user.updated`, `user.created`, `user.deleted`
4. Asgardeo will send POST requests whenever these events occur

**Pros:**
- True real-time ✅
- No polling overhead
- Event-driven architecture
- Scalable

**Cons:**
- Requires webhook setup in Asgardeo
- Need to handle failed deliveries (retry logic)
- Security: must verify signatures

---

### **Option 2: Event Streaming with Message Queue**
Use RabbitMQ, Kafka, or similar for event-driven architecture.

```
Asgardeo Webhooks → Your API → Message Queue (RabbitMQ/Kafka)
                                     ↓
                         Background Worker Service
                                     ↓
                           Update Database
```

This gives you reliability + real-time with guaranteed processing.

---

### **Option 3: Server-Sent Events (SSE)**
For notifying your frontend of real-time changes:

```python
from fastapi.responses import StreamingResponse

@router.get("/events/users")
async def subscribe_to_user_events(current_user: TokenData = Depends(require_role("admin"))):
    """Real-time user update stream"""
    async def event_generator():
        channel = get_redis_channel("user_updates")
        async for message in channel.listen():
            yield f"data: {json.dumps(message)}\n\n"
    
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream"
    )
```

Frontend:
```javascript
const eventSource = new EventSource("/api/events/users");
eventSource.onmessage = (event) => {
  const update = JSON.parse(event.data);
  // Update UI immediately
  console.log("User updated:", update);
};
```

---

### **Option 4: WebSockets**
For two-way real-time communication:

```python
from fastapi import WebSocket

@router.websocket("/ws/users/sync")
async def websocket_user_sync(websocket: WebSocket):
    await websocket.accept()
    
    async def listen_for_updates():
        while True:
            # Listen for Asgardeo webhook events
            update = await get_next_user_update()  # from Redis/event bus
            await websocket.send_json(update)
    
    await listen_for_updates()
```

---

## My Recommendation

**Use Webhooks + Message Queue:**

1. **Asgardeo sends webhook** → Your `/webhooks/asgardeo/user-updated` endpoint
2. **Your endpoint publishes event** → Message queue (Redis/RabbitMQ)
3. **Background worker consumes** → Updates database immediately
4. **Optional: Broadcast to clients** → WebSocket/SSE for live UI updates

This gives you:
- ✅ True real-time sync
- ✅ Reliability (queue ensures no missed events)
- ✅ Scalability (horizontal scaling of workers)
- ✅ Auditability (all events logged)

Would you like me to implement the webhook handler and message queue integration for your Asgardeo client?
