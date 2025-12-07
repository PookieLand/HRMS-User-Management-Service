"""
User Management Service - Main Application Entry Point.

This service handles:
- User authentication and authorization
- User management (CRUD operations)
- Employee onboarding workflow
- Role-based access control (RBAC)
- Dashboard metrics with Redis caching
- Daily scheduled tasks for HR events
"""

from contextlib import asynccontextmanager

import redis.asyncio as redis
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import Session, func, select

from app.api.auth import router as auth_router
from app.api.onboarding import router as onboarding_router
from app.api.users import router as users_router
from app.core.cache import (
    cache,
    cache_onboarding_stats,
    cache_user_metrics,
    get_cached_onboarding_stats,
    get_cached_user_metrics,
)
from app.core.config import settings
from app.core.database import create_db_and_tables, engine
from app.core.kafka import KafkaProducer
from app.core.logging import get_logger
from app.core.scheduler import daily_scheduler
from app.models.users import OnboardingInvitation, User

logger = get_logger(__name__)


async def get_redis_pool():
    """Initialize and return a Redis connection pool."""
    return await redis.from_url(
        settings.redis_url, encoding="utf-8", decode_responses=True
    )


@asynccontextmanager
async def lifespan(_: FastAPI):
    """
    Application lifespan manager.

    Handles startup and shutdown tasks:
    - Database initialization
    - Redis connection
    - Kafka producer
    - Daily scheduler
    """
    # Startup
    logger.info("Starting User Management Service")
    logger.info(f"Environment: DEBUG={settings.DEBUG}")
    logger.info(f"Database: {settings.DB_HOST}:{settings.DB_PORT}/{settings.DB_NAME}")
    logger.info(f"Redis Cache: {settings.REDIS_HOST}:{settings.REDIS_PORT}")
    logger.info(f"Employee Service: {settings.EMPLOYEE_SERVICE_URL}")
    logger.info(f"Attendance Service: {settings.LEAVE_SERVICE_URL}")
    logger.info(f"Leave Service: {settings.LEAVE_SERVICE_URL}")
    logger.info(f"Notification Service: {settings.NOTIFICATION_SERVICE_URL}")
    logger.info(f"Audit Service: {settings.AUDIT_SERVICE_URL}")
    logger.info(f"Compliance Service: {settings.COMPLIANCE_SERVICE_URL}")

    # Initialize database
    try:
        logger.info("Creating database and tables...")
        create_db_and_tables()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise

    # Initialize Redis
    try:
        logger.info("Connecting to Redis cache...")
        redis_conn = await get_redis_pool()
        await redis_conn.ping()
        logger.info("Connected to Redis successfully")
    except Exception as e:
        logger.error(f"Failed to connect to Redis: {e}")
        raise

    # Initialize Kafka producer
    logger.info("Initializing Kafka producer...")
    await KafkaProducer.start()
    logger.info("Kafka producer initialized successfully")

    # Start daily scheduler for birthday/anniversary/probation checks
    logger.info("Starting daily scheduler...")
    await daily_scheduler.start()
    logger.info("Daily scheduler started")

    logger.info("Application startup complete")

    yield

    # Shutdown
    logger.info("Shutting down User Management Service")

    # Stop scheduler
    await daily_scheduler.stop()
    logger.info("Daily scheduler stopped")

    # Stop Kafka producer
    await KafkaProducer.stop()
    logger.info("Kafka producer stopped")

    # Close Redis connection
    await cache.close()
    logger.info("Redis connection closed")


# Initialize FastAPI application
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="User Management Service for HRMS - Handles user authentication, "
    "authorization, onboarding, and role-based access control",
    lifespan=lifespan,
)


# Configure CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
    allow_methods=settings.CORS_ALLOW_METHODS,
    allow_headers=settings.CORS_ALLOW_HEADERS,
)


# Include routers
app.include_router(auth_router, prefix="/api/v1")
app.include_router(users_router, prefix="/api/v1")
app.include_router(onboarding_router, prefix="/api/v1")


# Health check endpoint
@app.get("/health", tags=["health"])
async def health_check():
    """Health check endpoint for container orchestration."""
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
    }


# Dashboard metrics endpoint with Redis caching
@app.get("/api/v1/dashboard/metrics", tags=["dashboard"])
async def get_dashboard_metrics():
    """
    Get dashboard metrics with Redis caching.

    This endpoint returns user and onboarding statistics
    for the HR dashboard. Results are cached in Redis
    for improved performance.

    Returns:
        Dictionary containing:
        - total_users: Total number of users
        - active_users: Number of active users
        - suspended_users: Number of suspended users
        - users_by_role: Count of users per role
        - onboarding_stats: Onboarding statistics
    """
    # Try to get cached metrics first
    cached_user_metrics = await get_cached_user_metrics()
    cached_onboarding_stats = await get_cached_onboarding_stats()

    if cached_user_metrics and cached_onboarding_stats:
        logger.debug("Returning cached dashboard metrics")
        return {
            **cached_user_metrics,
            "onboarding": cached_onboarding_stats,
            "cached": True,
        }

    # Calculate metrics from database
    logger.info("Calculating dashboard metrics from database")

    with Session(engine) as session:
        # User metrics
        total_users = session.exec(select(func.count(User.id))).one()
        active_users = session.exec(
            select(func.count(User.id)).where(User.status == "active")
        ).one()
        suspended_users = session.exec(
            select(func.count(User.id)).where(User.status == "suspended")
        ).one()

        # Users by role
        users_by_role = {}
        for role in settings.ROLES:
            count = session.exec(
                select(func.count(User.id)).where(User.role == role)
            ).one()
            users_by_role[role] = count

        # Onboarding statistics
        pending_onboardings = session.exec(
            select(func.count(OnboardingInvitation.id)).where(
                OnboardingInvitation.status.in_(
                    ["initiated", "invitation_sent", "asgardeo_user_created"]
                )
            )
        ).one()

        completed_onboardings = session.exec(
            select(func.count(OnboardingInvitation.id)).where(
                OnboardingInvitation.status == "completed"
            )
        ).one()

        cancelled_onboardings = session.exec(
            select(func.count(OnboardingInvitation.id)).where(
                OnboardingInvitation.status == "cancelled"
            )
        ).one()

    # Prepare metrics
    user_metrics = {
        "total_users": total_users,
        "active_users": active_users,
        "suspended_users": suspended_users,
        "users_by_role": users_by_role,
    }

    onboarding_stats = {
        "pending": pending_onboardings,
        "completed": completed_onboardings,
        "cancelled": cancelled_onboardings,
    }

    # Cache metrics
    await cache_user_metrics(user_metrics)
    await cache_onboarding_stats(onboarding_stats)

    return {
        **user_metrics,
        "onboarding": onboarding_stats,
        "cached": False,
    }


# Trigger manual daily checks (for testing/admin purposes)
@app.post("/api/v1/admin/run-daily-checks", tags=["admin"])
async def trigger_daily_checks():
    """
    Manually trigger daily checks.

    This endpoint is for administrative/testing purposes.
    It runs the same checks that run automatically at midnight:
    - Birthday notifications
    - Work anniversary notifications
    - Probation ending notifications
    - Contract expiring notifications
    - Performance review due notifications
    - Salary increment due notifications

    Authorization: Should be restricted to HR_Admin in production
    """
    logger.info("Manual daily checks triggered")
    await daily_scheduler.run_daily_checks()
    return {"message": "Daily checks executed successfully"}


# Invalidate cache endpoint (for admin purposes)
@app.post("/api/v1/admin/invalidate-cache", tags=["admin"])
async def invalidate_all_cache():
    """
    Invalidate all cached dashboard metrics.

    This forces the next dashboard request to fetch
    fresh data from the database.

    Authorization: Should be restricted to HR_Admin in production
    """
    logger.info("Cache invalidation triggered")

    from app.core.cache import CacheKeys

    await cache.delete(CacheKeys.TOTAL_USERS)
    await cache.delete(CacheKeys.ACTIVE_USERS)
    await cache.delete(CacheKeys.SUSPENDED_USERS)
    await cache.delete(CacheKeys.USERS_BY_ROLE)
    await cache.delete(CacheKeys.ONBOARDING_STATS)

    return {"message": "Cache invalidated successfully"}
