PYTHON       ?= python3
MYPY         ?= mypy
MYPY_TARGETS ?= impl tests

.PHONY: all test lint fuzz template vectors clean bip-shrincs

all: test lint template vectors

fuzz:
	./run_tests.sh fuzz

lint:
	$(MYPY) $(MYPY_TARGETS)

template:
	./pydoc_insert.py

vectors:
	./gen_test_vectors.py

clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf .mypy_cache

bip-shrincs: template
	rm -rf bips
	mkdir -p bips/bip-XXXX
	cp SHRINCS.md bips/bip-XXXX.md
	cp -r impl docs img bips/bip-XXXX
	find bips/bip-XXXX -type d -name __pycache__ -prune -exec rm -rf {} +
	sed -i 's_\bimg/_bip-XXXX/img/_g' bips/bip-XXXX.md
	sed -i 's_\bimpl/_bip-XXXX/impl/_g' bips/bip-XXXX.md
	sed -i 's_\./docs/_\./bip-XXXX/docs/_g' bips/bip-XXXX.md
