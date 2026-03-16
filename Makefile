.PHONY: setup lint type test check verify-release demo

setup:
	python3 -m venv .venv
	.venv/bin/pip install -e '.[dev]'

lint:
	./scripts/run_tests.sh lint

type:
	./scripts/run_tests.sh type

test:
	./scripts/run_tests.sh test -q

check:
	./scripts/run_tests.sh check

verify-release:
	./scripts/run_tests.sh check
	.venv/bin/pip install --quiet cyclonedx-bom
	mkdir -p dist
	.venv/bin/cyclonedx-py environment --of JSON --output-file dist/sbom-python.cdx.json
	./scripts/validate_sbom.py --cyclonedx dist/sbom-python.cdx.json
	@if [ -f sbom-docker.spdx.json ]; then \
		./scripts/validate_sbom.py --spdx sbom-docker.spdx.json; \
	else \
		echo "ℹ️  No local docker SBOM file found (sbom-docker.spdx.json)."; \
		echo "    Docker SBOM is validated in release-docker workflow."; \
	fi

demo:
	.venv/bin/skillscan scan examples/suspicious_skill --fail-on never
