#!/usr/bin/env bash
#
# Run the SHRINCS test suite.
#
#   ./run_tests.sh                 every test
#   ./run_tests.sh fuzz            one category: unit, integration, fuzz
#   ./run_tests.sh -k keygen       tests whose id matches a pattern
#   ./run_tests.sh fuzz -v         that category, verbose
#
# Any other argument is handed to `python3 -m unittest discover`.

set -e
cd "$(dirname "$0")"

# A leading category name becomes the directory to start discovery in.
start=tests
if [[ -n ${1-} && -d tests/$1 ]]; then
  start="tests/$1"
  shift
fi

# Everything after the category must be an option: `unittest discover` reads
# a positional argument as its start directory, replacing the one set above.
if [[ -n ${1-} && $1 != -* ]]; then
  echo "run_tests.sh: expected a category or an option, got '$1'" >&2
  exit 2
fi

exec python3 -m unittest discover -s "$start" -t . "$@"
