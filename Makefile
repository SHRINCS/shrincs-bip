PYTHON       ?= python3
MYPY         ?= mypy
MYPY_TARGETS ?= impl tests

.PHONY: all test unit fuzz integration lint template vectors clean

all: test lint template vectors

test: unit integration fuzz

unit:
	./run_tests.sh unit

integration:
	./run_tests.sh integration

fuzz:
	./run_tests.sh fuzz

lint:
	$(MYPY) $(MYPY_TARGETS) --check-untyped-defs

template:
	./pydoc_insert.py

vectors:
	./gen_test_vectors.py

clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -f SHRINCS.new.md
	rm -rf .mypy_cache
