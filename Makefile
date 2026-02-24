# Connector-OSS — Build & Test Infrastructure
#
# Quick start:
#   make all          # build + test everything
#   make rust         # build + test Rust kernel + engine + server
#   make python       # build vac-ffi (PyO3) + install Python SDK
#   make server       # build + run connector-server
#   make docker       # build scratch container (~5MB)

.PHONY: all rust python server docker clean check fmt

# =============================================================================
# Paths
# =============================================================================

VAC_DIR        := vac
AAPI_DIR       := aapi
CONNECTOR_DIR  := connector
FFI_DIR        := $(VAC_DIR)/crates/vac-ffi
PY_SDK_DIR     := sdks/python
TS_SDK_DIR     := sdks/typescript

# =============================================================================
# Top-level targets
# =============================================================================

all: rust python
	@echo "✅ All builds and tests passed"

check: rust-test
	@echo "✅ All tests passed"

# =============================================================================
# Rust kernel + engine + server
# =============================================================================

rust: rust-build rust-test

rust-build:
	@echo "🔨 Building VAC kernel..."
	cd $(VAC_DIR) && cargo build --release
	@echo "🔨 Building AAPI..."
	cd $(AAPI_DIR) && cargo build --release
	@echo "🔨 Building Connector (engine + api + server)..."
	cd $(CONNECTOR_DIR) && cargo build --release

rust-test:
	@echo "🧪 Testing VAC kernel..."
	cd $(VAC_DIR) && cargo test --release -- --skip vac_ffi
	@echo "🧪 Testing AAPI..."
	cd $(AAPI_DIR) && cargo test --release
	@echo "🧪 Testing Connector..."
	cd $(CONNECTOR_DIR) && cargo test --release

# =============================================================================
# Python: vac-ffi (PyO3) → Python SDK
# =============================================================================

python: vac-ffi python-install
	@echo "✅ Python SDK ready: from connector import Connector"

vac-ffi:
	@echo "🐍 Building vac-ffi (PyO3 → Python wheel)..."
	cd $(FFI_DIR) && maturin develop --release
	@echo "✅ vac_ffi installed into current Python env"

python-install:
	@echo "📦 Installing Python SDK..."
	pip install -e $(PY_SDK_DIR)

# =============================================================================
# Server
# =============================================================================

server:
	@echo "🚀 Starting connector-server on :8080..."
	cd $(CONNECTOR_DIR) && cargo run --release -p connector-server

# =============================================================================
# Docker
# =============================================================================

docker:
	@echo "🐳 Building scratch container (~5MB, 0 CVEs)..."
	docker build -t connector-oss/connector:latest .
	@echo "✅ Image: connector-oss/connector:latest"
	@docker images connector-oss/connector:latest --format "Size: {{.Size}}"

docker-run:
	docker run -p 8080:8080 \
		-e CONNECTOR_LLM_PROVIDER=openai \
		-e CONNECTOR_LLM_MODEL=gpt-4o \
		-e CONNECTOR_LLM_API_KEY=$${CONNECTOR_LLM_API_KEY} \
		connector-oss/connector:latest

docker-compose:
	docker compose up -d
	@echo "✅ Stack running:"
	@echo "  Connector: http://localhost:8080"
	@echo "  Prometheus: http://localhost:9090"
	@echo "  Grafana: http://localhost:3000 (admin/connector)"

# =============================================================================
# Clean
# =============================================================================

clean:
	cd $(VAC_DIR) && cargo clean
	cd $(AAPI_DIR) && cargo clean
	cd $(CONNECTOR_DIR) && cargo clean

# =============================================================================
# Dev helpers
# =============================================================================

fmt:
	cd $(VAC_DIR) && cargo fmt
	cd $(AAPI_DIR) && cargo fmt
	cd $(CONNECTOR_DIR) && cargo fmt

clippy:
	cd $(VAC_DIR) && cargo clippy --release -- -D warnings
	cd $(AAPI_DIR) && cargo clippy --release -- -D warnings
	cd $(CONNECTOR_DIR) && cargo clippy --release -- -D warnings
