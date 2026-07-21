SHELL := /bin/bash
.DEFAULT_GOAL := help

ENV_FILE := .env
COMPOSE := docker compose --env-file $(ENV_FILE)
MIGRATIONS_DIR := database/migrations
MIGRATE_NETWORK := vms-net
MIGRATE_IMAGE := migrate/migrate:v4.19.1

# Pulls POSTGRES_USER, POSTGRES_DB, REDIS_PASSWORD, DATABASE_URL, etc. in as
# real Make variables (not shell-escaped lookups) so recipes below can just
# reference $(VAR). DATABASE_URL uses the Docker-internal "postgres" hostname,
# which is why migrate-* run inside a container on $(MIGRATE_NETWORK) rather
# than as a host-installed binary — the hostname wouldn't resolve on the host.
-include $(ENV_FILE)

.PHONY: help init up down restart logs ps build \
	migrate-up migrate-down migrate-create migrate-status \
	db-shell redis-cli seed \
	backend-dev backend-test backend-lint \
	frontend-dev frontend-build frontend-lint \
	secrets-gen tls-gen license-gen \
	clean fmt

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

init: ## First-time setup: copy .env, generate secrets + dev TLS cert
	@test -f $(ENV_FILE) || cp .env.example $(ENV_FILE)
	@$(MAKE) secrets-gen
	@$(MAKE) tls-gen
	@mkdir -p data/recordings
	@echo "Edit .env with real values, then run 'make up'."

secrets-gen: ## Generate JWT RS256 keypair + placeholder license public key (dev only)
	@mkdir -p secrets
	@test -f secrets/jwt_private.pem || openssl genrsa -out secrets/jwt_private.pem 4096
	@test -f secrets/jwt_public.pem || openssl rsa -in secrets/jwt_private.pem -pubout -out secrets/jwt_public.pem
	@test -f secrets/license_public.pem || cp secrets/jwt_public.pem secrets/license_public.pem
	@chmod 600 secrets/jwt_private.pem
	@echo "Dev secrets generated in ./secrets (gitignored). Replace license_public.pem with the real vendor key before production."

tls-gen: ## Generate a self-signed dev TLS certificate for nginx (dev only)
	@mkdir -p nginx/tls
	@test -f nginx/tls/privkey.pem || openssl req -x509 -nodes -newkey rsa:2048 \
		-keyout nginx/tls/privkey.pem -out nginx/tls/fullchain.pem -days 365 \
		-subj "/CN=localhost" \
		-addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
	@echo "Self-signed dev TLS cert generated in ./nginx/tls (gitignored — browsers will warn, that's expected). Replace with a real cert before production."

up: ## Start all services in the background
	$(COMPOSE) up -d

down: ## Stop all services
	$(COMPOSE) down

restart: down up ## Restart all services

logs: ## Tail logs for all services (use s=<service> for one)
	$(COMPOSE) logs -f --tail=200 $(s)

ps: ## Show running services
	$(COMPOSE) ps

build: ## Rebuild all images
	$(COMPOSE) build --no-cache

migrate-up: ## Apply all pending migrations (runs golang-migrate in a container on the vms-net network)
	docker run --rm --network $(MIGRATE_NETWORK) \
		-v "$(CURDIR)/$(MIGRATIONS_DIR):/migrations" \
		$(MIGRATE_IMAGE) -path=/migrations -database "$(DATABASE_URL)" up

migrate-down: ## Roll back the last migration
	docker run --rm --network $(MIGRATE_NETWORK) \
		-v "$(CURDIR)/$(MIGRATIONS_DIR):/migrations" \
		$(MIGRATE_IMAGE) -path=/migrations -database "$(DATABASE_URL)" down 1

migrate-create: ## Create a new migration pair: make migrate-create name=add_foo
	@test -n "$(name)" || (echo "usage: make migrate-create name=<snake_case_name>" && exit 1)
	docker run --rm -v "$(CURDIR)/$(MIGRATIONS_DIR):/migrations" \
		$(MIGRATE_IMAGE) create -ext sql -dir /migrations -seq $(name)

migrate-status: ## Show current migration version
	docker run --rm --network $(MIGRATE_NETWORK) \
		-v "$(CURDIR)/$(MIGRATIONS_DIR):/migrations" \
		$(MIGRATE_IMAGE) -path=/migrations -database "$(DATABASE_URL)" version

db-shell: ## Open a psql shell in the running postgres container
	$(COMPOSE) exec postgres psql -U $(POSTGRES_USER) -d $(POSTGRES_DB)

redis-cli: ## Open a redis-cli shell in the running redis container
	$(COMPOSE) exec redis redis-cli -a $(REDIS_PASSWORD) --no-auth-warning

seed: ## Load development seed data into the running postgres container
	$(COMPOSE) exec -T postgres psql -U $(POSTGRES_USER) -d $(POSTGRES_DB) < database/seed.sql

backend-dev: ## Run the Go backend locally with hot reload (requires air)
	cd backend && air

backend-test: ## Run Go backend test suite
	cd backend && go test ./... -race -cover

backend-lint: ## Lint the Go backend
	cd backend && golangci-lint run ./...

frontend-dev: ## Run the Vite dev server
	cd frontend && npm run dev

frontend-build: ## Production build of the frontend
	cd frontend && npm run build

frontend-lint: ## Lint the frontend
	cd frontend && npm run lint

fmt: ## Format Go and frontend code
	cd backend && gofmt -l -w .
	cd frontend && npm run format

clean: ## Stop services and remove volumes (DESTRUCTIVE: wipes DB/redis/recordings data)
	$(COMPOSE) down -v
