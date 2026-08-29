.PHONY: install test lint run docker-build docker-run clean

install:
	uv sync

test:
	uv run pytest -v

run:
	uv run uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

docker-build:
	docker build -t openshomer:latest .

docker-run:
	docker-compose up --build

clean:
	rm -rf .pytest_cache __pycache__ */__pycache__ */*/__pycache__ .venv
