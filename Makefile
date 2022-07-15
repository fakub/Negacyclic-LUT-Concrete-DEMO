# run with default settings in Cargo.toml
run:
	RUSTFLAGS="-C target-cpu=native" cargo run --release
# build-only
build:
	RUSTFLAGS="-C target-cpu=native" cargo build --release
