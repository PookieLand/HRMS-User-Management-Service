FROM python:3.13-alpine3.22

# Install system dependencies
RUN apk add --no-cache pkgconfig gcc musl-dev mariadb-dev mariadb-connector-c-dev

# Install uv.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Copy the application into the container.
COPY . /app

# Setup the working directory
WORKDIR /app
# Install the application dependencies.
RUN uv sync --frozen

# Expose port
EXPOSE 8000

# Run the application.
CMD ["/app/.venv/bin/fastapi", "run", "app/main.py", "--port", "8000", "--host", "0.0.0.0"]

