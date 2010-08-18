PYTHON       = $(BIN)/python
SETUP        = $(PYTHON) setup.py
BUILD_NUMBER ?= 0000INVALID

.PHONY: goldengate/_version.py

sdist:
	$(SETUP) sdist

version: goldengate/_version.py

goldengate/_version.py: goldengate/_version.py.m4
	m4 -D__BUILD__=$(BUILD_NUMBER) $^ > $@

