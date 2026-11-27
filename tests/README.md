# SHRINCS tests

Tests for the reference implementation in [`impl/shrincs.py`](../impl/shrincs.py),
organized by category:

- [`unit/`](./unit): individual pieces of the implementation (address serialization, type annotations, low-level primitives).
- [`integration/`](./integration): the highest-level API (`shrincs_keygen`, `shrincs_sign`, `shrincs_verify`) end to end.
- [`fuzz/`](./fuzz): generated data thrown at `shrincs_keygen`, `shrincs_sign`, `shrincs_verify`, and `base_2b` to see if and how they break. Each test is a `@fuzz(cases=N)` method whose body contains only input generation and assertions; the decorator, in [`fuzz/fuzz_case.py`](./fuzz/fuzz_case.py), provides a seeded RNG per case and labels every failure with its index and seed, so any break found is reproducible.

The test suite depends only on the Python standard library.

## Running

From the repository root:

```sh
./run_tests.sh            # all tests
./run_tests.sh fuzz       # one category (unit | integration | fuzz)
./run_tests.sh -k keygen  # tests whose id matches a pattern
./run_tests.sh -v         # verbose
```

Or, equivalently, with plain `unittest` from the repository root:

```sh
python3 -m unittest discover -s tests -t .
```

A single module:

```sh
python3 -m unittest tests.unit.test_addresses
```

Type checking (uses the repository-root `mypy.ini` and its plugin):

```sh
mypy tests
```

[Makefile recipes](../Makefile) are provided for the primary test entry points.

## Fuzz knobs

The fuzz tests are deterministic unless configured otherwise:

- Each case draws from its own generator, seeded from `SHRINCS_FUZZ_SEED` (default `0x5eed`), the test id, and the case index. Failing cases are labeled with that index and seed, and reproduce two ways: re-run the test with the same `SHRINCS_FUZZ_SEED`, or drive the generation code directly with `random.Random(int(case_seed, 16))`.
- `SHRINCS_FUZZ_ITERS`: multiplier for the number of generated cases in each `@fuzz(cases=N)` test (default `1`). Sweep tests set `cases` to the size of the set they enumerate, and each repeated pass re-randomizes the other inputs (the case index, not the random draw, selects the swept element).

```sh
SHRINCS_FUZZ_SEED=1234 SHRINCS_FUZZ_ITERS=5 ./run_tests.sh fuzz
```
