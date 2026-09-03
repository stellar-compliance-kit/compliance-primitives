.PHONY: test doctest clippy fmt fmt-check lint build check-wasm-size check-accessibility

# Mirrors the "cargo test" CI job (.github/workflows/ci.yml).
test:
	cargo test --workspace --verbose

# Mirrors the "Run doc tests" CI step.
doctest:
	cargo test --workspace --doc --verbose

# Mirrors the "cargo clippy" CI job.
clippy:
	cargo clippy --workspace --all-targets -- -D warnings

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

# Full local lint pass: clippy (as run in CI) plus a formatting check.
lint: clippy fmt-check

# Mirrors the "wasm32v1-none build" CI job.
build:
	cargo build --workspace --target wasm32v1-none --release

# Mirrors the "wasm size budget" CI job.
check-wasm-size:
	bash scripts/check-wasm-size.sh

# Mirrors the "accessibility audit (web/)" CI job. Run `npm install` once
# first (downloads Puppeteer's bundled Chromium).
check-accessibility:
	node scripts/check-accessibility.mjs
