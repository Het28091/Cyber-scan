PYTHON ?= $(shell test ! -x .venv/bin/python || echo .venv/bin/python)
ifeq ($(strip $(PYTHON)),)
PYTHON = python3
endif
.PHONY: setup doctor demo demo-web demo-internet up down test bundle
setup:
	bash setup.sh
doctor:
	$(PYTHON) -m secaudit doctor --config config/offline.json
demo:
	$(PYTHON) -m secaudit scan --config config/offline.json
demo-web:
	$(PYTHON) demo/server.py
up:
	$(PYTHON) -m secaudit dashboard
down:
	@echo 'The dashboard runs in the foreground. Press Ctrl+C in its terminal to stop it.'
test:
	$(PYTHON) -m unittest discover -s tests -v
bundle:
	$(PYTHON) -m secaudit bundle prepare --output offline-bundle

demo-internet:
	$(PYTHON) -m secaudit scan --config config/internet.json
