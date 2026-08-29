# Developer Setup Guide

Standard instructions for setting up the OpenShomer development environment.

---

## Prerequisites
- Python 3.10+
- [uv](https://docs.astral.sh/uv/) (Astral Python package manager)
- Docker (for sandbox and container validation)

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/kavix/OpenShomer.git
cd OpenShomer

# Synchronize virtual environment and dependencies
uv sync

# Run complete test suite
uv run pytest -v

# Start development server
uv run uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```
