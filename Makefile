.PHONY: test demo serve verify init clean e2e coverage check browser-install browser-e2e check-all dev

PYTHON ?= python3

test:
	$(PYTHON) -m unittest discover -s tests -v

e2e:
	$(PYTHON) scripts/e2e.py

coverage:
	$(PYTHON) -m coverage run --source=secure_vote -m unittest discover -s tests
	$(PYTHON) -m coverage report --fail-under=90

# Fast, dependency-free gate: unit/integration + HTTP lifecycle.
check: coverage e2e

browser-install:
	$(PYTHON) -m pip install -r requirements-browser.txt
	$(PYTHON) -m playwright install --with-deps chromium

browser-e2e:
	$(PYTHON) scripts/browser_e2e.py

# Full CI-equivalent gate; run browser-install once first.
check-all: check browser-e2e

dev:
	$(PYTHON) -m pip install -r requirements-dev.txt

demo:
	$(PYTHON) -m secure_vote demo

serve:
	$(PYTHON) -m secure_vote serve

init:
	$(PYTHON) -m secure_vote init

verify:
	$(PYTHON) -m secure_vote verify

clean:
	rm -rf data .coverage
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
