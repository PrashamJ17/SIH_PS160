# IPsec Sentinel — single entry point for every verification.
#
# Tool resolution: prefer the project virtualenv when present (local dev), otherwise
# fall back to PATH (CI, where deps are installed into the runner's environment).
VENV   := .venv/bin
RUFF   := $(shell [ -x $(VENV)/ruff ]   && echo $(VENV)/ruff   || echo ruff)
MYPY   := $(shell [ -x $(VENV)/mypy ]   && echo $(VENV)/mypy   || echo mypy)
PYTEST := $(shell [ -x $(VENV)/pytest ] && echo $(VENV)/pytest || echo pytest)

.PHONY: lint fmt type test test-unit test-int cov verify verify-all clean

# scripts is included because mypy already checks it. Linting three of the four trees
# meant the milestone check scripts accumulated lint that `make verify` never saw.
lint:
	$(RUFF) check src tests testbed scripts
	$(RUFF) format --check src tests testbed scripts

fmt:
	$(RUFF) format src tests testbed scripts
	$(RUFF) check --fix src tests testbed scripts

type:
	$(MYPY)

test-unit:
	$(PYTEST) tests/unit -m "not integration" -n auto

test-int:
	$(PYTEST) tests/integration -m integration

test:
	$(PYTEST) -m "not integration" -n auto

cov:
	$(PYTEST) -m "not integration" --cov=ipsec_sentinel --cov-report=term-missing --cov-fail-under=80

# Run before EVERY commit
verify: lint type test

# Run at EVERY milestone
verify-all: lint type cov test-int

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
