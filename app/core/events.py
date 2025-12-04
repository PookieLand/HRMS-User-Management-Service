from datetime import datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class EventType(str, Enum):
    USER_CREATED = "user.created"
    USER_UPDATED = "user.updated"
    USER_DELETED = "user.deleted"
    USER_SUSPENDED = "user.suspended"
    USER_ACTIVATED = "user.activated"
    USER_ROLE_CHANGED = "user.role.changed"


class EventMetadata(BaseModel):
    source_service: str = "user-management-service"
    correlation_id: str = Field(default_factory=lambda: str(uuid4()))
    causation_id: str | None = None
    user_id: str | None = None
    trace_id: str | None = None


class EventEnvelope(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    event_type: EventType
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    version: str = "1.0"
    data: dict[str, Any]
    metadata: EventMetadata


class UserCreatedEvent(BaseModel):
    user_id: str
    username: str
    email: str
    roles: list[str]
    status: str


class UserUpdatedEvent(BaseModel):
    user_id: str
    updated_fields: dict[str, Any]


class UserDeletedEvent(BaseModel):
    user_id: str
    username: str
    email: str


class UserSuspendedEvent(BaseModel):
    user_id: str
    username: str
    email: str
    reason: str | None = None


class UserActivatedEvent(BaseModel):
    user_id: str
    username: str
    email: str


class UserRoleChangedEvent(BaseModel):
    user_id: str
    username: str
    old_roles: list[str]
    new_roles: list[str]
