from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.auth import router as auth_router
from app.api.users import router as users_router
from app.core.config import settings
from app.core.database import create_db_and_tables
from app.core.logging import get_logger

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Startup
    logger.info("Starting User Management Service")
    logger.info(f"Environment: DEBUG={settings.DEBUG}")
    logger.info(f"Database: {settings.DB_HOST}:{settings.DB_PORT}/{settings.DB_NAME}")
    logger.info(f"Employee Service: {settings.EMPLOYEE_SERVICE_URL}")
    logger.info(f"Audit Service: {settings.AUDIT_SERVICE_URL}")
    logger.info(f"Compliance Service: {settings.COMPLIANCE_SERVICE_URL}")
    logger.info(f"Notification Service: {settings.NOTIFICATION_SERVICE_URL}")

    try:
        logger.info("Creating database and tables...")
        create_db_and_tables()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
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
        "timestamp": datetime.now().isoformat(),
    }
