# Makefile for DarkCoder
# Quick reference for common development tasks

.PHONY: help setup install build build-all build-dev test test-watch lint lint-fix format preflight clean start debug typecheck doctor

help:
	@echo "╔════════════════════════════════════════════════════════════╗"
	@echo "║          DarkCoder - Development Make Commands            ║"
	@echo "╚════════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "SETUP & INSTALLATION"
	@echo "  make setup              - First-time setup (install + build)"
	@echo "  make install            - Install npm dependencies"
	@echo "  make doctor             - Run diagnostic health check"
	@echo ""
	@echo "BUILDING"
	@echo "  make build              - Build the main project"
	@echo "  make build-all          - Build CLI + sandbox + VS Code extension"
	@echo "  make build-dev          - Fast build for development (no optimization)"
	@echo ""
	@echo "DEVELOPMENT"
	@echo "  make start              - Start the CLI"
	@echo "  make debug              - Start CLI in debug mode"
	@echo "  make test               - Run all tests"
	@echo "  make test-watch         - Run tests in watch mode"
	@echo "  make typecheck          - Run TypeScript type checking"
	@echo ""
	@echo "CODE QUALITY"
	@echo "  make lint               - Check code style"
	@echo "  make lint-fix           - Fix code style issues automatically"
	@echo "  make format             - Format code with prettier"
	@echo "  make preflight          - Run full checks (lint + test + build)"
	@echo ""
	@echo "CLEANUP"
	@echo "  make clean              - Remove build artifacts"
	@echo "  make clean-all          - Clean everything (node_modules, cache, etc)"
	@echo ""
	@echo "DOCS"
	@echo "  View SETUP.md for detailed setup instructions"
	@echo "  View BUILD.md for build troubleshooting"
	@echo ""

# Setup & Installation
setup: install build
	@echo "✓ Setup complete! Run 'make start' to launch DarkCoder."

install:
	@echo "Installing dependencies..."
	npm install

doctor:
	@echo "Running diagnostic check..."
	npm run doctor

# Building
build:
	@echo "Building DarkCoder (standard)..."
	npm run build

build-all:
	@echo "Building all artifacts (CLI + sandbox + VS Code extension)..."
	npm run build:all

build-dev:
	@echo "Building DarkCoder (fast development build)..."
	npm run build:managed

# Development
start:
	@echo "Starting DarkCoder CLI..."
	npm start

debug:
	@echo "Starting DarkCoder in debug mode..."
	npm run debug

# Testing
test:
	@echo "Running test suite..."
	npm test

test-watch:
	@echo "Running tests in watch mode..."
	npm test -- --watch

typecheck:
	@echo "Checking TypeScript types..."
	npm run typecheck

# Code Quality
lint:
	@echo "Linting code..."
	npm run lint

lint-fix:
	@echo "Fixing linting issues..."
	npm run lint:fix

format:
	@echo "Formatting code..."
	npm run format

preflight:
	@echo "Running full preflight checks..."
	npm run preflight

# Cleanup
clean:
	@echo "Cleaning build artifacts..."
	npm run clean

clean-all: clean
	@echo "Removing all generated files..."
	rm -rf node_modules package-lock.json
	@echo "✓ Cleanup complete. Run 'make install' to reinstall."
