.PHONY: build test sample

build:
	cargo build --release --locked

test: build
	cargo test --release --locked

sample: build
	mkdir -p docs site
	target/release/s3-policy-audit examples > docs/sample-output.txt; true
	target/release/s3-policy-audit examples --tsv > docs/sample-output.tsv; true
	python3 scripts/site.py docs/sample-output.tsv site/index.html "s3-policy-audit" "Audits AWS S3 bucket policies and bucket configuration exports for public principals, wildcard actions, missing TLS enforcement, public access block gaps and open ACLs. Rust." "Synthetic data."
