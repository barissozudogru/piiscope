.PHONY: help install lint test demo build up down logs clean

help:
	@echo "Available targets:"
	@echo "  help    - Show this help message"
	@echo "  install - Install package for development (pip install -e '.[dev,parquet]')"
	@echo "  lint    - Run ruff checks (ruff check .)"
	@echo "  test    - Run pytest (pytest -q)"
	@echo "  demo    - Run piiscope scan on samples (piiscope scan samples/customers.csv)"
	@echo "  build   - Build package (python -m build)"
	@echo "  up      - Start docker-compose environment"
	@echo "  down    - Stop docker-compose environment"
	@echo "  logs    - Show docker-compose logs"
	@echo "  clean   - Remove build artifacts, dist, *.egg-info, caches"

install:
	pip install -e ".[dev,parquet]"

lint:
	ruff check .

test:
	pytest -q

demo:
	piiscope scan samples/customers.csv

build:
	python -m build

up:
	docker compose -f deploy/docker-compose.yml --env-file .env up --build -d

down:
	docker compose -f deploy/docker-compose.yml --env-file .env down

logs:
	docker compose -f deploy/docker-compose.yml --env-file .env logs -f

clean:
	rm -rf build/ dist/ *.egg-info/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type d -name .pytest_cache -exec rm -rf {} +
	find . -type d -name .ruff_cache -exec rm -rf {} +
