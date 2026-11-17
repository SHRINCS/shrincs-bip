# Shared module for fuzz tests: the `fuzz` decorator and input-generation
# helpers.
#
# The `fuzz` decorator applies per-test boilerplate of seeding generators,
# looping the case count scaled by `SHRINCS_FUZZ_ITERS`, and identifying the
# inputs of a failing case. A fuzz test body is just input generation plus
# assertions:
#
# ```py
# @fuzz(cases=20)
# def test_truncated_signature_never_verifies(self, rng, case: int):
#   sig = rng.choice([self.sf_sig, self.sl_sig])
#   self.assertFalse(shrincs.shrincs_verify(
#     MESSAGE, sig[:rng.randrange(len(sig))], b"", self.pk
#   ))
# ```
#
# Every case should sample random inputs only from its own RNG.

import os
import random
from collections.abc import Callable
from functools import wraps
from typing import Any

from impl import shrincs

FUZZ_SEED = int(os.environ.get("SHRINCS_FUZZ_SEED", "0x5eed"), 0)
FUZZ_ITERS = int(os.environ.get("SHRINCS_FUZZ_ITERS", "1"))

def derive_seed(base: int, label: str) -> int:
  digest = shrincs.sha256(base.to_bytes(8, "big") + label.encode())
  return int.from_bytes(digest[:8], "big")

def rand_bytes(rng: random.Random, length: int) -> bytes:
  return bytes(rng.getrandbits(8) for _ in range(length))

def flip_byte(data: bytes, index: int) -> bytes:
  mutated = bytearray(data)
  mutated[index] ^= 0x1 << (index % 8)
  return bytes(mutated)

def fuzz(cases: int) -> Callable:
  """
  Turn a test method taking `(self, rng, case)` into a fuzz test.
  `cases` is the number of generated cases, scaled by `SHRINCS_FUZZ_ITERS`.
  Each case runs inside `subTest` labeled with its index and generator seed.
  """
  def decorator(body: Callable) -> Callable:
    @wraps(body)
    def wrapper(self, *args: Any) -> None:
      test_seed = derive_seed(FUZZ_SEED, self.id())
      for case in range(cases * FUZZ_ITERS):
        case_seed = derive_seed(test_seed, f"case {case}")
        with self.subTest(case=case, case_seed=hex(case_seed)):
          body(self, random.Random(case_seed), case)
    return wrapper
  return decorator
