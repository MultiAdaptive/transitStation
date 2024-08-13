# Define the Go command and the target binary name
GO := go
TARGET := build/transitStation

# Define source directories and files
SRC_DIR := cmd
SRC_FILE := $(SRC_DIR)/main.go

# Detect the operating system
UNAME_S := $(shell uname -s)

# Default target: auto-detect OS and build accordingly
.PHONY: all
all: auto-build

# Auto-build based on OS
.PHONY: auto-build
auto-build:
ifeq ($(UNAME_S),Linux)
	$(MAKE) build-linux
else ifeq ($(UNAME_S),Darwin)
	$(MAKE) build-macos
else
	@echo "Unsupported OS: $(UNAME_S)"
	@exit 1
endif

# Build the target binary
build: FORCE $(SRC_FILE)
	@mkdir -p build
	$(GO) build -o $(TARGET) $(SRC_FILE)

# Clean the build artifacts
.PHONY: clean
clean:
	@rm -rf build

# Cross-compilation for Linux
.PHONY: build-linux
build-linux:
	GOOS=linux GOARCH=amd64 $(MAKE) build

# Cross-compilation for macOS
.PHONY: build-macos
build-macos:
	GOOS=darwin GOARCH=amd64 $(MAKE) build

# Force target to always execute
.PHONY: FORCE
FORCE:
