.PHONY: install install-frontend dev dev-backend dev-frontend demo-reset test lint format format-check typecheck secret-scan check golden-path knowledge-rag demo-e2e autonomous-e2e live-model-smoke contest-preflight contest-demo-evidence migrate downgrade

install:
	uv sync --all-groups

install-frontend:
	npm --prefix frontend install

dev:
	./scripts/dev.sh

dev-backend:
	uv run uvicorn app.main:app --app-dir backend --reload --host 127.0.0.1 --port 8000

dev-frontend:
	npm --prefix frontend run dev -- --host 127.0.0.1

demo-reset:
	curl --fail --silent --show-error -X POST -H 'X-Demo-Role: ADMIN' http://127.0.0.1:8000/api/v1/replay/reset

test:
	uv run pytest

lint:
	uv run ruff check backend scripts
	npm --prefix frontend run lint

format:
	uv run ruff format backend scripts
	npm --prefix frontend run format

format-check:
	uv run ruff format --check backend scripts
	npm --prefix frontend run format:check

typecheck:
	uv run mypy backend/app
	npm --prefix frontend run typecheck

secret-scan:
	uv run python scripts/secret_scan.py

check: test lint format-check typecheck secret-scan

golden-path:
	PYTHONPATH=backend uv run python scripts/run_golden_path_backend.py

knowledge-rag:
	PYTHONPATH=backend uv run python scripts/run_knowledge_report.py

demo-e2e:
	npm --prefix frontend run e2e

autonomous-e2e:
	npm --prefix frontend run e2e:autonomous

contest-preflight:
	PYTHONPATH=backend uv run python scripts/contest_preflight.py
	npm --prefix frontend run e2e:contest

contest-demo-evidence:
	npm --prefix frontend run e2e:contest

live-model-smoke:
	PYTHONPATH=backend uv run python scripts/live_model_smoke.py

migrate:
	uv run alembic upgrade head

downgrade:
	uv run alembic downgrade base
