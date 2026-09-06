FROM python:3.11-slim

LABEL org.opencontainers.image.title="OpenShomer" \
      org.opencontainers.image.description="Autonomous Agentic Security Engineer for LLM prompts, agent configs, and MCP servers" \
      org.opencontainers.image.url="https://github.com/kavix/OpenShomer" \
      org.opencontainers.image.source="https://github.com/kavix/OpenShomer" \
      org.opencontainers.image.licenses="MIT"

COPY --from=ghcr.io/astral-sh/uv:0.12.7 /uv /uvx /bin/

WORKDIR /app

# Install git, curl, and essential runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install project dependencies first (for layer caching)
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# Copy repository source files
COPY . .

# Install project and CLI binaries into virtualenv
RUN uv sync --frozen --no-dev

# Ensure entrypoint is executable
RUN chmod +x /app/docker-entrypoint.sh

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    OPENSHOMER_ENV=production

EXPOSE 8000

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["api"]
