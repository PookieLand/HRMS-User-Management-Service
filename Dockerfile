FROM python:3.13-alpine3.22 AS builder

# Install build dependencies only in builder stage
RUN apk add --no-cache \
    pkgconfig \
    gcc \
    musl-dev \
    mariadb-dev \
    mariadb-connector-c-dev

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Copy the application into the container
COPY . /app
WORKDIR /app

# Install the application dependencies using uv sync
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
FROM python:3.13-alpine3.22

# Install only runtime dependencies (not build tools)
RUN apk add --no-cache \
    mariadb-connector-c \
    libstdc++ \
    ca-certificates

# Create non-root user for security
RUN addgroup -g 10001 appgroup && \
    adduser -u 10001 -G appgroup -s /sbin/nologin -D appuser

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
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD /app/.venv/bin/python -c "import httpx; r = httpx.get('http://localhost:8000/health'); exit(0 if r.status_code == 200 else 1)" || exit 1

# Run the application
CMD ["/app/.venv/bin/fastapi", "run", "app/main.py", "--port", "8000", "--host", "0.0.0.0"]

