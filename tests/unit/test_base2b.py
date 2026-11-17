"""
Unit tests for `base_2b`, the byte-string bit decomposition.

`base_2b` splits the leading `outlen * b` bits of `x` into groups of `b`
bits parsed big-endian. Missing trailing bits are treated as zero (an
explicit FIPS-205 divergence), and `b` need not divide 8. These tests check
hand-computed values against a straightforward big-integer reference.
"""

import random
import unittest

from impl.shrincs import base_2b


def ref_base_2b(x: bytes, b: int, outlen: int) -> list[int]:
  """Reference implementation: shift to the leading `outlen * b` bits."""
  value = int.from_bytes(x, "big")
  value <<= max(outlen * b - len(x) * 8, 0)  # zero-pad short inputs
  value >>= max(len(x) * 8 - outlen * b, 0)  # drop trailing bits
  return [(value >> (b * (outlen - 1 - i))) % 2**b for i in range(outlen)]


class Base2bTest(unittest.TestCase):
  def test_byte_aligned_nibbles(self):
    self.assertEqual(base_2b(bytes.fromhex("ff00"), 4, 8), [15, 15, 0, 0, 0, 0, 0, 0])

  def test_uses_only_leading_bits(self):
    # b=3: only the leading 6 of the 8 bits are consumed: 0b111_110_00.
    self.assertEqual(base_2b(b"\xff", 3, 2), [7, 7])  # 0b111_111_00
    self.assertEqual(base_2b(b"\xf8", 3, 2), [7, 6])

  def test_short_input_zero_padded(self):
    self.assertEqual(base_2b(b"", 4, 4), [0, 0, 0, 0])
    self.assertEqual(base_2b(b"\x80", 4, 4), [8, 0, 0, 0])
    self.assertEqual(base_2b(b"\x01", 1, 3), [0, 0, 0])  # 0b0000_0001 -> 0b000_000_000 padded

  def test_non_byte_aligned_groups(self):
    # b=5: the leading 30 bits of four 0xFF bytes are all ones.
    self.assertEqual(base_2b(b"\xff\xff\xff\xff", 5, 6), [31] * 6)

  def test_zero_length_output(self):
    self.assertEqual(base_2b(b"\xff\xff", 7, 0), [])

  def test_matches_big_integer_reference(self):
    rng = random.Random(0xB2B)
    for b in (1, 2, 3, 4, 5, 7, 8, 11, 16):
      for _ in range(12):
        x = bytes(rng.getrandbits(8) for _ in range(rng.randrange(0, 9)))
        outlen = rng.randrange(0, 20)
        with self.subTest(b=b, x=x.hex(), outlen=outlen):
          out = base_2b(x, b, outlen)
          self.assertEqual(out, ref_base_2b(x, b, outlen))
          self.assertTrue(all(0 <= part < 2**b for part in out))


if __name__ == "__main__":
  unittest.main()
