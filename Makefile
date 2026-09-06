.PHONY: install test lint format run scan tui auto-pr docker-build docker-run clean

install:
	uv sync

test:
	uv run pytest -v

lint:
	uv run ruff check .
	uv run ruff format --check .

format:
	uv run ruff format .
	uv run ruff check --fix .

run:
	uv run uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

scan:
	uv run openshomer scan $(TARGET)

tui:
	uv run openshomer tui $(TARGET)

auto-pr:
	uv run openshomer auto-pr $(TARGET)

docker-build:
	docker build -t openshomer:latest .

docker-run:
	docker-compose up --build

clean:
	rm -rf .pytest_cache __pycache__ */__pycache__ */*/__pycache__ .venv
