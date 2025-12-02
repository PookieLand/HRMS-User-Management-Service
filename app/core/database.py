from typing import Generator

from sqlalchemy import text
from sqlmodel import Session, SQLModel, create_engine

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


def create_database() -> None:
    temp_engine = create_engine(settings.database_url_without_db)

    try:
        with temp_engine.connect() as conn:
            _ = conn.execute(text(f"CREATE DATABASE IF NOT EXISTS {settings.DB_NAME}"))
            conn.commit()
            logger.info(f"Database '{settings.DB_NAME}' ready")
    except Exception as e:
        logger.error(f"Failed to create database: {e}")
        raise
    finally:
        temp_engine.dispose()


def create_db_and_tables() -> None:
    create_database()
    SQLModel.metadata.create_all(engine)
    logger.info("Database tables created successfully")


# Create the database engine
engine = create_engine(
    settings.database_url,
    echo=settings.DEBUG,  # Log SQL queries in debug mode
    pool_pre_ping=True,  # Verify connections before using them
    pool_recycle=3600,  # Recycle connections after 1 hour
)


def get_session() -> Generator[Session, None, None]:
    with Session(engine) as session:
        yield session
