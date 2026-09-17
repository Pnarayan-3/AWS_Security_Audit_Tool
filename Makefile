PYTHON := python
PIP := $(PYTHON) -m pip
PYTEST := $(PYTHON) -m pytest

.PHONY: install test scan audit security-gate clean

install:
$(PIP) install -r requirements.txt

test:
$(PYTEST) -v

scan:
$(PYTHON) audit.py scan

security-gate:
$(PYTHON) audit.py scan --security-gate

clean:
rm -rf **pycache**
rm -rf .pytest_cache
rm -rf */**pycache**
rm -rf reports/*.json
rm -rf reports/*.html
rm -rf reports/*.sarif
