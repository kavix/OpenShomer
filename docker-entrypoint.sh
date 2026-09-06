#!/bin/sh
set -e

# If first argument is 'api' or 'serve', launch FastAPI API server
if [ "$1" = "api" ] || [ "$1" = "serve" ]; then
    shift
    exec uvicorn app.main:app --host 0.0.0.0 --port 8000 "$@"

# If first argument is 'mcp', run the Model Context Protocol server
elif [ "$1" = "mcp" ]; then
    shift
    exec python -m app.mcp.server "$@"

# If first argument is an openshomer CLI subcommand, delegate to openshomer CLI
elif [ "$1" = "scan" ] || [ "$1" = "fix" ] || [ "$1" = "auto-pr" ] || [ "$1" = "mulerun" ] || [ "$1" = "tui" ] || [ "$1" = "version" ]; then
    exec openshomer "$@"

# If no arguments provided, default to starting the API server
elif [ -z "$1" ]; then
    exec uvicorn app.main:app --host 0.0.0.0 --port 8000

# Otherwise pass through any custom command (e.g. bash, pytest, uv)
else
    exec "$@"
fi
