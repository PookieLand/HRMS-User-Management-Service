FROM python:3.13-slim AS builder

# Install system dependencies for mysqlclient and confluent-kafka (librdkafka v2.12.1+)
RUN apt-get update && apt-get install -y --no-install-recommends \
    default-libmysqlclient-dev \
    pkg-config \
    gcc \
    curl \
    gnupg \
    && curl -fsSL https://packages.confluent.io/deb/7.9/archive.key | gpg --dearmor -o /usr/share/keyrings/confluent-archive-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/confluent-archive-keyring.gpg] https://packages.confluent.io/deb/7.9 stable main" > /etc/apt/sources.list.d/confluent.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends librdkafka-dev \
    && rm -rf /var/lib/apt/lists/*

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Copy the application into the container
COPY . /app
WORKDIR /app

# Setup the working directory
WORKDIR /app
# Install the application dependencies.
RUN uv sync --frozen

# Strip binaries to reduce size
RUN find /app/.venv -type f -name "*.so" -exec strip {} \; 2>/dev/null || true

# Remove __pycache__ and .pyc files
RUN find /app/.venv -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true && \
    find /app/.venv -type f -name "*.pyc" -delete && \
    find /app/.venv -type f -name "*.pyo" -delete

# Remove test directories from packages
RUN find /app/.venv/lib/python3.13/site-packages -type d -name "tests" -exec rm -rf {} + 2>/dev/null || true && \
    find /app/.venv/lib/python3.13/site-packages -type d -name "test" -exec rm -rf {} + 2>/dev/null || true

# Remove unnecessary package metadata and documentation
RUN find /app/.venv/lib/python3.13/site-packages -type f \( -name "*.md" -o -name "*.rst" -o -name "*.txt" \) ! -name "LICENSE*" -delete 2>/dev/null || true && \
    find /app/.venv/lib/python3.13/site-packages -name "*.pyi" -delete && \
    find /app/.venv/lib/python3.13/site-packages -type d -name "*.dist-info" -exec rm -f {}/RECORD {}/WHEEL \; 2>/dev/null || true

# Remove pip and setuptools from venv (not needed at runtime)
RUN rm -rf /app/.venv/lib/python3.13/site-packages/pip /app/.venv/lib/python3.13/site-packages/setuptools /app/.venv/lib/python3.13/site-packages/wheel 2>/dev/null || true

# Runtime stage
FROM python:3.13-slim

# Install only runtime dependencies (not build tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
    mariadb-client \
    libmariadb3 \
    libstdc++6 \
    ca-certificates \
    librdkafka1 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /usr/sbin/nologin -M appuser

# Copy virtual environment from builder
COPY --from=builder --chown=appuser:appgroup /app/.venv /app/.venv

# Copy only necessary application files (exclude unnecessary directories)
COPY --chown=appuser:appgroup app/ /app/app/
COPY --chown=appuser:appgroup pyproject.toml uv.lock /app/

WORKDIR /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the application
CMD ["/app/.venv/bin/fastapi", "run", "app/main.py", "--port", "8000", "--host", "0.0.0.0"]
