# Convenience development targets for this repository. Run from the repo root.
# See BuildSupport/Makefile for the full FFI build graph.

.DEFAULT_GOAL := help

SCRIPTS := Scripts

.PHONY: help init-ffi rebuild-ffi reset-ffi swift-build test-offline

help:
	@echo "Convenience targets (repo root):"
	@echo "  make init-ffi              ./$(SCRIPTS)/init-local-ffi.sh"
	@echo "  make rebuild-ffi           ./$(SCRIPTS)/rebuild-local-ffi.sh (default: ios-sim)"
	@echo "  make rebuild-ffi REBUILD_TARGET=ios-device"
	@echo "  make rebuild-ffi REBUILD_TARGET=macos"
	@echo "  make reset-ffi             ./$(SCRIPTS)/reset-local-ffi.sh"
	@echo "  make swift-build           swift build"
	@echo "  make test-offline          swift test --filter OfflineTests"

# Initialize the local FFI development environment
init-ffi:
	./$(SCRIPTS)/init-local-ffi.sh

REBUILD_TARGET ?= ios-sim
# Rebuild the local FFI development environment
rebuild-ffi:
	./$(SCRIPTS)/rebuild-local-ffi.sh $(REBUILD_TARGET)

# Reset the local FFI development environment
reset-ffi:
	./$(SCRIPTS)/reset-local-ffi.sh

# Build the Swift package
swift-build:
	swift build

# Run offline Swift tests
test-offline:
	swift test --filter OfflineTests
