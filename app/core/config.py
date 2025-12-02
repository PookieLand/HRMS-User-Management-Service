from typing import List

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Application Settings
    APP_NAME: str = "User Management Service"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    # Database Settings
    DB_NAME: str = "user_management_db"
    DB_USER: str = "root"
    DB_PASSWORD: str = "root"
    DB_HOST: str = "localhost"
    DB_PORT: int = 3306
    DB_CHARSET: str = "utf8mb4"

    # CORS Settings
    CORS_ORIGINS: str = "https://localhost,http://localhost:3000"
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_ALLOW_METHODS: List[str] = ["*"]
    CORS_ALLOW_HEADERS: List[str] = ["*"]

    # Asgardeo OAuth2 Settings
    ASGARDEO_ORG: str = ""  # REQUIRED: Must be set in .env file
    ASGARDEO_CLIENT_ID: str = ""  # REQUIRED: Must be set in .env file
    JWT_AUDIENCE: str | None = None  # Optional: Set in .env if needed
    JWT_ISSUER: str | None = None  # Optional: Set in .env if needed

    @property
    def jwks_url(self) -> str:
        """Generate JWKS URL from Asgardeo organization."""
        return f"https://api.asgardeo.io/t/{self.ASGARDEO_ORG}/oauth2/jwks"

    @property
    def token_url(self) -> str:
        """Generate token endpoint URL from Asgardeo organization."""
        return f"https://api.asgardeo.io/t/{self.ASGARDEO_ORG}/oauth2/token"

    @property
    def issuer(self) -> str:
        """Get JWT issuer, fallback to token URL if not explicitly set."""
        if self.JWT_ISSUER:
            return self.JWT_ISSUER
        return self.token_url

    @property
    def cors_origins_list(self) -> List[str]:
        """Parse CORS_ORIGINS from comma-separated string."""
        if isinstance(self.CORS_ORIGINS, str):
            return [origin.strip() for origin in self.CORS_ORIGINS.split(",")]
        return [self.CORS_ORIGINS]

    # Service URLs for Integration
    EMPLOYEE_SERVICE_URL: str = "http://employee-service:8001"
    ATTENDANCE_SERVICE_URL: str = "http://employee-service:8002"
    LEAVE_SERVICE_URL: str = "http://employee-service:8003"
    NOTIFICATION_SERVICE_URL: str = "http://notification-service:8004"
    AUDIT_SERVICE_URL: str = "http://audit-service:8005"
    COMPLIANCE_SERVICE_URL: str = "http://compliance-service:8006"

    # Service Integration Settings
    SERVICE_REQUEST_TIMEOUT: int = 30  # seconds
    SERVICE_RETRY_COUNT: int = 3
    SERVICE_RETRY_DELAY: int = 1  # seconds

    # Role Definitions
    ROLES: List[str] = ["HR_Admin", "HR_Manager", "manager", "employee"]
    DEFAULT_ROLE: str = "employee"

    # User Status Definitions
    USER_STATUSES: List[str] = ["active", "suspended", "deleted"]
    DEFAULT_STATUS: str = "active"

    # Password Requirements
    MIN_PASSWORD_LENGTH: int = 8
    REQUIRE_UPPERCASE: bool = True
    REQUIRE_NUMBERS: bool = True
    REQUIRE_SPECIAL_CHARS: bool = True

    @property
    def database_url(self) -> str:
        """Generate MySQL database URL."""
        return f"mysql+mysqldb://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}?charset={self.DB_CHARSET}"

    @property
    def database_url_without_db(self) -> str:
        """Generate MySQL URL without database name (for initial connection)."""
        return f"mysql+mysqldb://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}?charset={self.DB_CHARSET}"

    class Config:
        env_file = ".env.development"
        case_sensitive = True


# Create global settings instance
settings = Settings()
