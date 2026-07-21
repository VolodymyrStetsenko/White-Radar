.PHONY: install init doctor test lint typecheck secrets check

install:
	python -m pip install -e ".[dev]"

init:
	white-radar init

doctor:
	white-radar doctor

test:
	python -m unittest discover -s tests -v

lint:
	ruff check .

typecheck:
	mypy src

secrets:
	python scripts/check_secrets.py

check: secrets lint typecheck test
	python -m compileall -q src
