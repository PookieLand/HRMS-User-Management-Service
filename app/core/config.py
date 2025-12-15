from typing import List

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Application Settings
    APP_NAME: str = "User Management Service"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    # Database Settings
    DB_NAME: str = "hrms_db"
    DB_USER: str = ""
    DB_PASSWORD: str = ""
    DB_HOST: str = "localhost"
    DB_PORT: int = 3306
    DB_CHARSET: str = "utf8"

    # Redis Configuration for Caching
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: str = ""
    REDIS_DB: int = 0

    # Kafka Settings
    KAFKA_BOOTSTRAP_SERVERS: str = "localhost:9092"
    KAFKA_ENABLED: bool = True

    # Frontend URL for invitation links
    FRONTEND_URL: str = "http://localhost:3000"

    # CORS Settings
    CORS_ORIGINS: str = "https://localhost,http://localhost:3000"
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_ALLOW_METHODS: List[str] = ["*"]
    CORS_ALLOW_HEADERS: List[str] = ["*"]

    # Asgardeo OAuth2 Settings
    # ASGARDEO_ORG: str = ""  # REQUIRED: Must be set in .env file
    # ASGARDEO_CLIENT_ID: str = ""  # REQUIRED: Must be set in .env file
    # ASGARDEO_CLIENT_SECRET: str = ""  # REQUIRED: Must be set in .env file

    ASGARDEO_ORG: str = "pookieland"
    ASGARDEO_CLIENT_ID: str = "O1swhn0zfcjJGAfxIKIfuAyoApAa"
    ASGARDEO_CLIENT_SECRET: str = "5MurGc7axd60Gg5Y0QrnrlLmlsu5yvbJhqtbl0aN_W8a"

    # Asgardeo Group IDs (Optional fallback when group read permissions are not available)
    # These are used when M2M app doesn't have permission to list/read groups
    # Find group IDs in Asgardeo Console under User Management > Groups
    ASGARDEO_GROUP_ID_HR_ADMIN: str | None = None
    ASGARDEO_GROUP_ID_HR_MANAGER: str | None = None
    ASGARDEO_GROUP_ID_MANAGER: str | None = None
    ASGARDEO_GROUP_ID_EMPLOYEE: str | None = None

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
    # Ports: user=8000, employee=8001, attendance=8002, leave=8003, audit=8004, notification=8005, compliance=8006
    EMPLOYEE_SERVICE_URL: str = "http://employee-service:8001"
    ATTENDANCE_SERVICE_URL: str = "http://attendance-service:8002"
    LEAVE_SERVICE_URL: str = "http://leave-service:8003"
    AUDIT_SERVICE_URL: str = "http://audit-service:8004"
    NOTIFICATION_SERVICE_URL: str = "http://notification-service:8005"
    COMPLIANCE_SERVICE_URL: str = "http://compliance-service:8006"

    # Service Integration Settings
    SERVICE_REQUEST_TIMEOUT: int = 30  # seconds
    SERVICE_RETRY_COUNT: int = 3
    SERVICE_RETRY_DELAY: int = 1  # seconds

    # Role Definitions
    ROLES: List[str] = ["HR_Admin", "HR_Manager", "manager", "employee"]
    DEFAULT_ROLE: str = "employee"

    @property
    def VALID_ROLES(self) -> List[str]:
        """Alias for ROLES for backward compatibility."""
        return self.ROLES

    # Role Hierarchy (higher number = more privileges)
    ROLE_HIERARCHY: dict = {
        "employee": 1,
        "manager": 2,
        "HR_Manager": 3,
        "HR_Admin": 4,
        "admin": 4,  # Alias for HR_Admin
    }

    # Permission Definitions by Role
    ROLE_PERMISSIONS: dict = {
        "employee": [
            "profile:read",
            "profile:update",
            "leave:create",
            "leave:read:own",
            "attendance:read:own",
            "attendance:checkin",
            "attendance:checkout",
        ],
        "manager": [
            "profile:read",
            "profile:update",
            "leave:create",
            "leave:read:own",
            "leave:read:team",
            "leave:approve:team",
            "leave:reject:team",
            "attendance:read:own",
            "attendance:read:team",
            "attendance:checkin",
            "attendance:checkout",
            "employees:read:team",
            "reports:read:team",
        ],
        "HR_Manager": [
            "profile:read",
            "profile:update",
            "users:read",
            "users:create",
            "users:update",
            "employees:read",
            "employees:create",
            "employees:update",
            "leave:read",
            "leave:approve",
            "leave:reject",
            "attendance:read",
            "reports:read",
            "departments:read",
            "departments:create",
            "departments:update",
        ],
        "HR_Admin": [
            "profile:read",
            "profile:update",
            "users:read",
            "users:create",
            "users:update",
            "users:delete",
            "users:suspend",
            "users:activate",
            "roles:manage",
            "employees:read",
            "employees:create",
            "employees:update",
            "employees:delete",
            "employees:manage",
            "leave:read",
            "leave:approve",
            "leave:reject",
            "leave:delete",
            "attendance:read",
            "attendance:update",
            "attendance:delete",
            "reports:read",
            "reports:create",
            "departments:read",
            "departments:create",
            "departments:update",
            "departments:delete",
            "settings:read",
            "settings:update",
            "audit:read",
        ],
    }

    # Asgardeo Group Mapping
    # Using underscore format to match actual Asgardeo group names
    # NOTE: Updated to use current group names in Asgardeo: 'Managers' (not 'Team_Managers')
    ASGARDEO_GROUP_MAPPING: dict = {
        "HR_Admin": "HR_Administrators",
        "HR_Manager": "HR_Managers",
        "Manager": "Managers",
        "manager": "Managers",
        "Employee": "Employees",
        "employee": "Employees",
    }

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

    @property
    def redis_url(self) -> str:
        """Generate Redis connection URL with authentication."""
        if self.REDIS_PASSWORD:
            return f"redis://:{self.REDIS_PASSWORD}@{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"

    # Onboarding constants
    INVITATION_EXPIRY_DAYS: int = 7
    # Notify 7 days before probation ends
    PROBATION_END_NOTIFICATION_DAYS: int = 7

    class Config:
        env_file = ".env"
        case_sensitive = True


# Create global settings instance
settings = Settings()
