# Fuzz tests for `base_2b`, the byte-string bit decomposition.
#
# Generated data is checked against an elementary reference implementation.
#
# The decorator (`tests/fuzz/fuzz_case.py`) handles the per-case seeded
# generators. Case loop count can be scaled by setting the env var
# `SHRINCS_FUZZ_ITERS`. Failures print the seed to reproduce the case
# that caused the error.

import unittest

from impl.shrincs import base_2b
from tests.fuzz.fuzz_case import fuzz, rand_bytes


def base_2b_elementary(x: bytes, b: int, out_len: int) -> list[int]:
  """
  Elementary version of `base_2b` for reference. Converts `x` into a string of bits,
  zero-padding the tail if `x` is shorter than `out_len * b` bits, then chunks the bit
  string into `out_len` groups of `b` bits and parses each group as a `b`-bit integer
  big endian. Requires `b > 0` and `out_len > 0`.
  """
  assert b > 0
  assert out_len > 0

  bits = ''.join(f'{byte:08b}' for byte in x)

  # padding
  while len(bits) < out_len * b:
    bits += '0'

  baseb = []
  for offset in range(0, out_len * b, b):
    group = bits[offset : offset + b]
    baseb.append(int(group, 2))
  return baseb


class FuzzBase2bTest(unittest.TestCase):
  # Sweep over every output bit group width from 1 to 16, including byte-aligned and
  # non-byte-aligned. The input bytes and output length are drawn randomly per case.
  @fuzz(cases=len(range(1, 17)) * 12)
  def test_matches_elementary_reference(self, rng, case):
    b = case % 16 + 1
    x = rand_bytes(rng, rng.randrange(0, 9))
    outlen = rng.randrange(1, 20)
    out = base_2b(x, b, outlen)
    self.assertEqual(out, base_2b_elementary(x, b, outlen))
    self.assertTrue(all(0 <= part < 2**b for part in out))


if __name__ == "__main__":
  unittest.main()
