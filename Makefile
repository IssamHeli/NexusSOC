.PHONY: up dev down logs build test lint typecheck migrate seed clean ps help

COMPOSE = docker compose
API_SRC = ai_agent_src
VENV    = .venv

# ── Stack ──────────────────────────────────────────────────────────────────────

up:         ## Start full stack (build if needed)
	$(COMPOSE) up --build -d

dev:        ## Hot-reload mode (mounts src volumes)
	$(COMPOSE) -f docker-compose.yml -f docker-compose.dev.yml up -d

down:       ## Stop all containers
	$(COMPOSE) down --remove-orphans

logs:       ## Follow API + worker logs
	$(COMPOSE) logs -f ai-agent-api worker

build:      ## Rebuild images without cache
	$(COMPOSE) build --no-cache

ps:         ## Show container status
	$(COMPOSE) ps

# ── DB ─────────────────────────────────────────────────────────────────────────

migrate:    ## Run Alembic migrations inside running API container
	$(COMPOSE) exec ai-agent-api alembic upgrade head

seed:       ## Seed demo data via shuffle simulation
	$(COMPOSE) exec ai-agent-api python shuffle_simulation.py

# ── Quality ────────────────────────────────────────────────────────────────────

$(VENV):
	python3 -m venv $(VENV)
	$(VENV)/bin/pip install --quiet \
	  -r $(API_SRC)/requirements.txt \
	  ruff mypy bandit pytest pytest-asyncio

lint: $(VENV)      ## Ruff lint + Bandit security scan
	$(VENV)/bin/ruff check $(API_SRC)/
	$(VENV)/bin/bandit -r $(API_SRC)/ -ll --exclude $(API_SRC)/migrations -q

typecheck: $(VENV) ## mypy type-check (no strict)
	$(VENV)/bin/mypy $(API_SRC)/ --ignore-missing-imports --no-strict-optional

test: $(VENV)      ## Run pytest suite
	@[ -d $(API_SRC)/tests ] && \
	  $(VENV)/bin/pytest $(API_SRC)/tests/ -v || \
	  echo "No tests yet — create ai_agent_src/tests/"

# ── Cleanup ────────────────────────────────────────────────────────────────────

clean:      ## Stop stack and wipe ALL volumes  ⚠ DATA LOSS
	@echo "WARNING: deletes postgres, prometheus, grafana volumes."
	@read -p "Type 'yes' to confirm: " c && [ "$$c" = "yes" ] || exit 1
	$(COMPOSE) down -v --remove-orphans

# ── Help ───────────────────────────────────────────────────────────────────────

help:       ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?##' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
