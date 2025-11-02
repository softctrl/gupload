# GuardUpload Makefile

CARGO ?= cargo

.PHONY: default build fmt clippy test check lint clean

default: check

build:
	$(CARGO) build

fmt:
	$(CARGO) fmt --all

clippy:
	$(CARGO) clippy --all-targets --all-features -- -D warnings

test:
	$(CARGO) test --all-targets --all-features

check: fmt clippy test

lint: fmt clippy

clean:
	$(CARGO) clean
