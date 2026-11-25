PYTHON       ?= python3
MYPY         ?= mypy
MYPY_TARGETS ?= impl tests

.PHONY: all test mypy template vectors clean

all: test mypy template vectors

fuzz:
	./run_tests.sh fuzz

mypy:
	$(MYPY) $(MYPY_TARGETS)

template:
	./pydoc_insert.py

vectors:
	./gen_test_vectors.py

clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf .mypy_cache
