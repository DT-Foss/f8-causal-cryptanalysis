.PHONY: install test smoke quick anchors audit reproduce reproduce-full reproduce-causal reproduce-atlas reproduce-fullround-transfers reproduce-shake-extended reproduce-shake-solver verify-vectors casi build clean

install:
	python3 -m pip install -e '.[dev]'

test:
	python3 -m pytest

quick:
	./scripts/reproduce_quick.sh

anchors:
	./scripts/verify_anchors.sh

audit:
	python3 scripts/check_publication.py

verify-vectors:
	python3 -m arx_carry_leak verify-vectors

smoke:
	python3 -m arx_carry_leak run --profile quick --output results/generated/quick.json

reproduce: test verify-vectors smoke

reproduce-full:
	python3 -m arx_carry_leak run --profile full --output results/generated/full.json

reproduce-causal:
	./scripts/reproduce_causal_mechanisms.sh

reproduce-atlas:
	./scripts/reproduce_multi_cipher_atlas.sh

reproduce-fullround-transfers:
	./scripts/reproduce_fullround_transfers.sh

reproduce-shake-extended:
	./scripts/reproduce_shake_native_extended.sh

reproduce-shake-solver:
	./scripts/reproduce_shake_solver_frontier.sh

casi:
	python3 -m arx_carry_leak casi --target speck32_64 --samples 1000 --seeds 3

build:
	python3 -m build

clean:
	rm -rf build dist .pytest_cache .ruff_cache src/*.egg-info
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
