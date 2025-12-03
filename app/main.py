from contextlib import asynccontextmanager

import redis.asyncio as redis
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.auth import router as auth_router
from app.api.users import router as users_router
from app.core.config import settings
from app.core.database import create_db_and_tables
from app.core.logging import get_logger

logger = get_logger(__name__)


async def get_redis_pool():
    """Initialize and return a Redis connection pool."""
    return await redis.from_url(
        settings.redis_url,
        encoding="utf-8",
        decode_responses=True
    )


@asynccontextmanager
async def lifespan(_: FastAPI):
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

    try:
        logger.info("Creating database and tables...")
        create_db_and_tables()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise

    try:
        logger.info("Connecting to Redis cache...")
        redis = await get_redis_pool()
        await redis.ping()
        logger.info("Connected to Redis successfully")
    except Exception as e:
        logger.error(f"Failed to connect to Redis: {e}")
        raise

    logger.info("Application startup complete")

    yield

    # Shutdown
    logger.info("Shutting down User Management Service")


# Initialize FastAPI application
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
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


# Health check endpoint
@app.get("/health", tags=["health"])
async def root():
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
    }
