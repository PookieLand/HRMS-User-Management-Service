"""
Redis caching module for User Management Service.

Provides caching utilities for dashboard metrics and frequently
accessed data to improve performance and reduce database load.

Cache keys follow the pattern: <service>:<entity>:<identifier>
"""

import json
from datetime import date, datetime
from decimal import Decimal
from typing import Any, Optional

import redis.asyncio as redis

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


# Cache TTL (time-to-live) constants in seconds
CACHE_TTL_SHORT = 60  # 1 minute
CACHE_TTL_MEDIUM = 300  # 5 minutes
CACHE_TTL_LONG = 3600  # 1 hour
CACHE_TTL_DAILY = 86400  # 24 hours


# Cache key prefixes
class CacheKeys:
    """Cache key definitions for consistency across the service."""

    # User metrics
    TOTAL_USERS = "user-service:metrics:total_users"
    ACTIVE_USERS = "user-service:metrics:active_users"
    SUSPENDED_USERS = "user-service:metrics:suspended_users"
    USERS_BY_ROLE = "user-service:metrics:users_by_role"

    # Onboarding metrics
    PENDING_ONBOARDINGS = "user-service:metrics:pending_onboardings"
    COMPLETED_ONBOARDINGS_TODAY = "user-service:metrics:completed_onboardings_today"
    ONBOARDING_STATS = "user-service:metrics:onboarding_stats"

    # HR metrics
    PROBATION_ENDING_COUNT = "user-service:metrics:probation_ending_count"
    CONTRACT_EXPIRING_COUNT = "user-service:metrics:contract_expiring_count"
    REVIEWS_DUE_COUNT = "user-service:metrics:reviews_due_count"

    # User data cache
    USER_PROFILE = "user-service:user:{user_id}:profile"
    USER_PERMISSIONS = "user-service:user:{user_id}:permissions"

    # Invitation cache
    INVITATION_DATA = "user-service:invitation:{token}:data"

    @staticmethod
    def user_profile(user_id: int) -> str:
        """Generate cache key for user profile."""
        return f"user-service:user:{user_id}:profile"

    @staticmethod
    def user_permissions(user_id: int) -> str:
        """Generate cache key for user permissions."""
        return f"user-service:user:{user_id}:permissions"

    @staticmethod
    def invitation(token: str) -> str:
        """Generate cache key for invitation data."""
        return f"user-service:invitation:{token}:data"


def json_serializer(obj: Any) -> Any:
    """Custom JSON serializer for complex types."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, date):
        return obj.isoformat()
    if isinstance(obj, Decimal):
        return float(obj)
    raise TypeError(f"Type {type(obj)} not serializable")


class RedisCache:
    """
    Redis cache client wrapper.

    Provides simple methods for caching operations with
    automatic serialization and error handling.
    """

    def __init__(self):
        """Initialize Redis cache client."""
        self._client: Optional[redis.Redis] = None

    async def get_client(self) -> redis.Redis:
        """Get or create Redis client connection."""
        if self._client is None:
            self._client = await redis.from_url(
                settings.redis_url,
                encoding="utf-8",
                decode_responses=True,
            )
        return self._client

    async def close(self):
        """Close Redis connection."""
        if self._client:
            await self._client.close()
            self._client = None

    async def ping(self) -> bool:
        """Check if Redis is connected."""
        try:
            client = await self.get_client()
            await client.ping()
            return True
        except Exception as e:
            logger.error(f"Redis ping failed: {e}")
            return False

    async def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache.

        Args:
            key: Cache key

        Returns:
            Cached value or None if not found
        """
        try:
            client = await self.get_client()
            value = await client.get(key)
            if value is not None:
                return json.loads(value)
            return None
        except Exception as e:
            logger.warning(f"Cache get failed for key {key}: {e}")
            return None

    async def set(
        self,
        key: str,
        value: Any,
        ttl: int = CACHE_TTL_MEDIUM,
    ) -> bool:
        """
        Set value in cache with TTL.

        Args:
            key: Cache key
            value: Value to cache (will be JSON serialized)
            ttl: Time-to-live in seconds

        Returns:
            True if successful, False otherwise
        """
        try:
            client = await self.get_client()
            json_value = json.dumps(value, default=json_serializer)
            await client.setex(key, ttl, json_value)
            return True
        except Exception as e:
            logger.warning(f"Cache set failed for key {key}: {e}")
            return False

    async def delete(self, key: str) -> bool:
        """
        Delete value from cache.

        Args:
            key: Cache key

        Returns:
            True if deleted, False otherwise
        """
        try:
            client = await self.get_client()
            await client.delete(key)
            return True
        except Exception as e:
            logger.warning(f"Cache delete failed for key {key}: {e}")
            return False

    async def delete_pattern(self, pattern: str) -> int:
        """
        Delete all keys matching pattern.

        Args:
            pattern: Key pattern (e.g., "user-service:user:123:*")

        Returns:
            Number of keys deleted
        """
        try:
            client = await self.get_client()
            keys = []
            async for key in client.scan_iter(match=pattern):
                keys.append(key)

            if keys:
                await client.delete(*keys)
            return len(keys)
        except Exception as e:
            logger.warning(f"Cache delete pattern failed for {pattern}: {e}")
            return 0

    async def increment(self, key: str, amount: int = 1) -> Optional[int]:
        """
        Increment a counter in cache.

        Args:
            key: Cache key
            amount: Amount to increment

        Returns:
            New value or None on error
        """
        try:
            client = await self.get_client()
            return await client.incrby(key, amount)
        except Exception as e:
            logger.warning(f"Cache increment failed for key {key}: {e}")
            return None

    async def decrement(self, key: str, amount: int = 1) -> Optional[int]:
        """
        Decrement a counter in cache.

        Args:
            key: Cache key
            amount: Amount to decrement

        Returns:
            New value or None on error
        """
        try:
            client = await self.get_client()
            return await client.decrby(key, amount)
        except Exception as e:
            logger.warning(f"Cache decrement failed for key {key}: {e}")
            return None

    async def exists(self, key: str) -> bool:
        """
        Check if key exists in cache.

        Args:
            key: Cache key

        Returns:
            True if exists, False otherwise
        """
        try:
            client = await self.get_client()
            return await client.exists(key) > 0
        except Exception as e:
            logger.warning(f"Cache exists check failed for key {key}: {e}")
            return False

    async def get_ttl(self, key: str) -> int:
        """
        Get remaining TTL for a key.

        Args:
            key: Cache key

        Returns:
            TTL in seconds, -1 if no TTL, -2 if key doesn't exist
        """
        try:
            client = await self.get_client()
            return await client.ttl(key)
        except Exception as e:
            logger.warning(f"Cache TTL check failed for key {key}: {e}")
            return -2


# Global cache instance
cache = RedisCache()


# Convenience functions for common caching operations


async def cache_user_metrics(metrics: dict) -> bool:
    """
    Cache dashboard user metrics.

    Args:
        metrics: Dictionary containing user metrics

    Returns:
        True if cached successfully
    """
    success = True

    if "total_users" in metrics:
        success &= await cache.set(
            CacheKeys.TOTAL_USERS,
            metrics["total_users"],
            CACHE_TTL_MEDIUM,
        )

    if "active_users" in metrics:
        success &= await cache.set(
            CacheKeys.ACTIVE_USERS,
            metrics["active_users"],
            CACHE_TTL_MEDIUM,
        )

    if "suspended_users" in metrics:
        success &= await cache.set(
            CacheKeys.SUSPENDED_USERS,
            metrics["suspended_users"],
            CACHE_TTL_MEDIUM,
        )

    if "users_by_role" in metrics:
        success &= await cache.set(
            CacheKeys.USERS_BY_ROLE,
            metrics["users_by_role"],
            CACHE_TTL_MEDIUM,
        )

    return success


async def get_cached_user_metrics() -> Optional[dict]:
    """
    Get cached dashboard user metrics.

    Returns:
        Dictionary with cached metrics or None
    """
    metrics = {}

    total = await cache.get(CacheKeys.TOTAL_USERS)
    if total is not None:
        metrics["total_users"] = total

    active = await cache.get(CacheKeys.ACTIVE_USERS)
    if active is not None:
        metrics["active_users"] = active

    suspended = await cache.get(CacheKeys.SUSPENDED_USERS)
    if suspended is not None:
        metrics["suspended_users"] = suspended

    by_role = await cache.get(CacheKeys.USERS_BY_ROLE)
    if by_role is not None:
        metrics["users_by_role"] = by_role

    return metrics if metrics else None


async def cache_onboarding_stats(stats: dict) -> bool:
    """
    Cache onboarding statistics.

    Args:
        stats: Dictionary containing onboarding stats

    Returns:
        True if cached successfully
    """
    return await cache.set(
        CacheKeys.ONBOARDING_STATS,
        stats,
        CACHE_TTL_MEDIUM,
    )


async def get_cached_onboarding_stats() -> Optional[dict]:
    """
    Get cached onboarding statistics.

    Returns:
        Cached stats or None
    """
    return await cache.get(CacheKeys.ONBOARDING_STATS)


async def cache_user_profile(user_id: int, profile: dict) -> bool:
    """
    Cache user profile data.

    Args:
        user_id: User ID
        profile: User profile dictionary

    Returns:
        True if cached successfully
    """
    return await cache.set(
        CacheKeys.user_profile(user_id),
        profile,
        CACHE_TTL_LONG,
    )


async def get_cached_user_profile(user_id: int) -> Optional[dict]:
    """
    Get cached user profile.

    Args:
        user_id: User ID

    Returns:
        Cached profile or None
    """
    return await cache.get(CacheKeys.user_profile(user_id))


async def invalidate_user_cache(user_id: int) -> int:
    """
    Invalidate all cache entries for a user.

    Args:
        user_id: User ID

    Returns:
        Number of keys invalidated
    """
    pattern = f"user-service:user:{user_id}:*"
    return await cache.delete_pattern(pattern)


async def cache_invitation(token: str, data: dict) -> bool:
    """
    Cache invitation preview data.

    Args:
        token: Invitation token
        data: Invitation data

    Returns:
        True if cached successfully
    """
    return await cache.set(
        CacheKeys.invitation(token),
        data,
        CACHE_TTL_LONG,
    )


async def get_cached_invitation(token: str) -> Optional[dict]:
    """
    Get cached invitation data.

    Args:
        token: Invitation token

    Returns:
        Cached invitation data or None
    """
    return await cache.get(CacheKeys.invitation(token))


async def invalidate_invitation_cache(token: str) -> bool:
    """
    Invalidate cached invitation data.

    Args:
        token: Invitation token

    Returns:
        True if deleted
    """
    return await cache.delete(CacheKeys.invitation(token))
