# TraceTramp Makefile
.PHONY: build run dev setup doctor test migrate sqlx-prepare sqlx-check docker deploy clean lab-smoke

# Variables
CARGO := cargo
DOCKER := docker
DOCKER_COMPOSE := docker-compose
KUBECTL := kubectl

# Build the project
build:
	$(CARGO) build --release

# Run in development mode
dev:
	$(CARGO) run

run:
	$(CARGO) run

setup:
	$(CARGO) run -- setup

doctor:
	$(CARGO) run -- doctor

# Run tests
test:
	$(CARGO) test

# Run database migrations
migrate:
	$(CARGO) sqlx migrate run

sqlx-prepare:
	SQLX_OFFLINE=true $(CARGO) sqlx prepare -- --all-targets --all-features

sqlx-check:
	SQLX_OFFLINE=true $(CARGO) sqlx prepare --check -- --all-targets --all-features

# Create new migration
new-migration:
	$(CARGO) sqlx migrate add $(name)

# Docker commands
docker-build:
	$(DOCKER) build -t tracetramp:latest .

docker-up:
	$(DOCKER_COMPOSE) up -d

# Host I/O smoke (requires `docker compose up` — see docker-compose.yml ports 19741/19742/19735).
lab-smoke:
	bash scripts/smoke_lab_io.sh

docker-down:
	$(DOCKER_COMPOSE) down

docker-logs:
	$(DOCKER_COMPOSE) logs -f tracetramp

# Full stack with monitoring
docker-up-full:
	$(DOCKER_COMPOSE) --profile monitoring --profile with-ollama up -d

# Kubernetes commands
k8s-deploy:
	$(KUBECTL) apply -f k8s/

k8s-delete:
	$(KUBECTL) delete -f k8s/

k8s-status:
	$(KUBECTL) get pods -l app=tracetramp

# Generate API documentation
api-docs:
	@echo "API documentation available in README.md"
	@echo "Swagger/OpenAPI spec generation not yet implemented"

# Code formatting and linting
fmt:
	$(CARGO) fmt

clippy:
	$(CARGO) clippy -- -D warnings

# Clean build artifacts
clean:
	$(CARGO) clean
	$(DOCKER_COMPOSE) down -v

# Quick start - build and run with docker-compose
quickstart:
	$(MAKE) docker-build
	$(MAKE) docker-up
	@echo "TraceTramp is running!"
	@echo "Data Plane: http://localhost:9741"
	@echo "Management Plane: http://localhost:9742"

# Production build with optimizations
production:
	$(CARGO) build --release --bin tracetramp
	strip target/release/tracetramp
