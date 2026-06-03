# GhostFS Makefile
# Usage:
#   make normal        — build Normal mode (release)
#   make cybersec      — build Cybersec mode (release)
#   make normal-debug  — build Normal mode (debug)
#   make test          — run tests for both modes
#   make install       — install to /usr/local/bin
#   make clean         — clean build artifacts

INSTALL_DIR ?= /usr/local/bin
CARGO       ?= cargo

.PHONY: all normal cybersec normal-debug cybersec-debug test install clean fmt check

all: normal

# ── Release builds ──────────────────────────────────────────────────────────

normal:
	@echo "▶ Building GhostFS Normal (release)..."
	$(CARGO) build --release --features normal,zstd,lz4
	@echo "✓ Binary: target/release/ghostfs"

cybersec:
	@echo "▶ Building GhostFS Cybersec (release)..."
	$(CARGO) build --no-default-features --release --features cybersec,zstd,lz4
	@echo "✓ Binary: target/release/ghostfs  [CYBERSEC MODE]"

# ── Debug builds ────────────────────────────────────────────────────────────

normal-debug:
	$(CARGO) build --features normal,zstd,lz4

cybersec-debug:
	$(CARGO) build --no-default-features --features cybersec,zstd,lz4

# ── Tests ───────────────────────────────────────────────────────────────────

test:
	@echo "▶ Testing Normal mode..."
	$(CARGO) test --features normal,zstd,lz4
	@echo "▶ Testing Cybersec mode..."
	$(CARGO) test --no-default-features --features cybersec,zstd,lz4

# ── Install ─────────────────────────────────────────────────────────────────

install: normal
	install -m 755 target/release/ghostfs $(INSTALL_DIR)/ghostfs
	@echo "✓ Installed to $(INSTALL_DIR)/ghostfs"

install-cybersec: cybersec
	install -m 755 target/release/ghostfs $(INSTALL_DIR)/ghostfs-cybersec
	@echo "✓ Installed to $(INSTALL_DIR)/ghostfs-cybersec"

# ── Code quality ────────────────────────────────────────────────────────────

fmt:
	$(CARGO) fmt --all

check:
	$(CARGO) check --features normal,zstd,lz4
	$(CARGO) check --no-default-features --features cybersec,zstd,lz4
	$(CARGO) clippy --features normal,zstd,lz4 -- -D warnings

# ── Clean ───────────────────────────────────────────────────────────────────

clean:
	$(CARGO) clean
