.PHONY: build run test clean check fmt clippy help

# Default target
help:
	@echo "Available commands:"
	@echo "  build      - Build the project"
	@echo "  run        - Run the OAuth2 mock server (with templates)"
	@echo "  run-config - Run with user configuration file"
	@echo "  test       - Run tests"
	@echo "  check      - Check code without building"
	@echo "  fmt        - Format code"
	@echo "  clippy     - Run clippy linter"
	@echo "  clean      - Clean build artifacts"
	@echo "  test-client - Run the Python test client"

# Build the project
build:
	cargo build

# Run the OAuth2 mock server
run:
	cargo run

# Run with custom user configuration
run-config:
	cargo run -- --config config/users.toml

# Run tests
test:
	cargo test

# Check code without building
check:
	cargo check

# Format code
fmt:
	cargo fmt

# Run clippy linter
clippy:
	cargo clippy

# Clean build artifacts
clean:
	cargo clean

# Run the Python test client
test-client:
	@echo "Running Python test client..."
	@if command -v python3 >/dev/null 2>&1; then \
		python3 examples/test_client.py; \
	elif command -v python >/dev/null 2>&1; then \
		python examples/test_client.py; \
	else \
		echo "Python not found. Please install Python 3."; \
		exit 1; \
	fi

# Run the shell test script
test-shell:
	@echo "Running shell test script..."
	@if [ -f examples/test_oauth2.sh ]; then \
		./examples/test_oauth2.sh; \
	else \
		echo "Test script not found: examples/test_oauth2.sh"; \
		exit 1; \
	fi

# Quick test of all endpoints
quick-test:
	@echo "Testing OAuth2 endpoints..."
	@echo "1. Testing home page..."
	@curl -s http://127.0.0.1:3000/ | grep -q "OAuth2 Mock Server" && echo "✅ Home page OK" || echo "❌ Home page failed"
	@echo "2. Testing OpenID Connect configuration..."
	@curl -s http://127.0.0.1:3000/.well-known/openid_configuration | grep -q "issuer" && echo "✅ OpenID config OK" || echo "❌ OpenID config failed"
	@echo "3. Testing authorization endpoint..."
	@curl -s "http://127.0.0.1:3000/authorize?response_type=code&client_id=test&redirect_uri=http://localhost/callback" | grep -q "Authorization Code Generated" && echo "✅ Authorization endpoint OK" || echo "❌ Authorization endpoint failed"
	@echo "✅ Quick test completed!"
