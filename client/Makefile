
.PHONY: setup setup-dev dev check test syntax test_contracts

setup:
	pip install --upgrade pip --progress-bar off
	pip install -e . --progress-bar off
	python -c "from zklay.core.contracts import install_sol; \
                install_sol()"

check: syntax test
syntax: ${PROTOBUF_OUTPUT}
	flake8 `git ls-files '**.py'`
	mypy -p zklay
	mypy -p tests
	mypy -p test_commands
	pylint zklay.core zklay.cli tests test_commands


