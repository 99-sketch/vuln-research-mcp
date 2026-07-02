.PHONY: install test lint format build clean publish test-publish help

help:
	@echo "Available commands:"
	@echo "  make install      - Install dependencies"
	@echo "  make test         - Run tests"
	@echo "  make lint         - Run code linting (black, isort, mypy)"
	@echo "  make format       - Format code (black, isort)"
	@echo "  make build        - Build package"
	@echo "  make clean        - Clean build artifacts"
	@echo "  make publish      - Publish to PyPI (requires TWINE_PASSWORD)"
	@echo "  make test-publish - Publish to Test PyPI"

install:
	pip install -e ".[dev]"

test:
	pytest tests/ -v

lint:
	black --check src/ tests/
	isort --check-only src/ tests/
	mypy src/

format:
	black src/ tests/
	isort src/ tests/

build: clean
	python -m build

clean:
	rm -rf build/ dist/ *.egg-info __pycache__ .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type d -name .pytest_cache -exec rm -rf {} +
	find . -name "*.pyc" -delete

publish: build
	@test -n "$(TWINE_PASSWORD)" || (echo "Error: TWINE_PASSWORD not set" && exit 1)
	python -m twine upload dist/*

test-publish: build
	@test -n "$(TWINE_PASSWORD)" || (echo "Error: TWINE_PASSWORD not set" && exit 1)
	python -m twine upload --repository testpypi dist/*

# Development helpers
dev-install: install
	pip install -e .

run:
	python src/server.py

# Check if package is ready for publishing
check: lint test build
	@echo "✓ All checks passed! Package is ready for publishing."

# Create a new version tag (usage: make tag VERSION=0.2.0)
tag:
	@test -n "$(VERSION)" || (echo "Error: VERSION not set. Usage: make tag VERSION=x.y.z" && exit 1)
	@echo "Creating tag v$(VERSION)..."
	git tag -a "v$(VERSION)" -m "Release v$(VERSION)"
	git push origin "v$(VERSION)"
	@echo "Tag v$(VERSION) created and pushed. GitHub Actions will handle the release."

.PHONY: help install test lint format build clean publish test-publish dev-install run check tag
