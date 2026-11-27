# Unit tests for `base_2b`, the byte-string bit decomposition, using
# various declarative test vectors.

import unittest

from impl.shrincs import base_2b

# name, hex input, b, outlen, expected
Case = tuple[str, str, int, int, list[int]]

# Only the leading out_len * b input bits are consumed, the rest is ignored.
LEADING_BITS: list[Case] = [
  ("all ones",      "ff", 3, 2, [7, 7]),     # 0b111_111_11 -> 0b111_111
  ("low bits zero", "f8", 3, 2, [7, 6]),     # 0b111_110_00 -> 0b111_110
  ("leading zeros", "01", 1, 3, [0, 0, 0]),  # 0b000_000_01 -> 0b000
]

# Inputs shorter than out_len * b bits: the missing trailing bits read zero.
SHORT_INPUT: list[Case] = [
  ("empty input",  "",   4, 4, [0, 0, 0, 0]),
  ("high bit set", "80", 4, 4, [8, 0, 0, 0]),
]

# A single input byte lands in the top of the first group when b exceeds 8.
SINGLE_BYTE_INPUT: list[Case] = [
  ("0x01 at b=32", "01", 32, 1, [0x01000000]),  # 0x01 << 24
  ("0xab at b=16", "ab", 16, 2, [0xab00, 0]),   # 0xab << 8, then padding
  ("0xff at b=16", "ff", 16, 1, [0xff00]),      # 0xff << 8
]

# Widths that divide 8 or are multiples of 8, so groups end on nibble or
# byte boundaries.
ALIGNED_WIDTHS: list[Case] = [
  ("nibbles of ff00", "ff00",                     4,  8, [15, 15, 0, 0, 0, 0, 0, 0]),
  ("nibbles of 8040", "8040",                     4,  5, [8, 0, 4, 0, 0]),
  ("one word",        "070b",                     16, 1, [1803]),
  ("one triplet",     "deadbe",                   24, 1, [0xdeadbe]),
  ("one dword",       "deadbeef",                 32, 1, [0xdeadbeef]),
  ("two dwords",      "b53ecd71a846e29f",         32, 2, [0xb53ecd71, 0xa846e29f]),
  ("three dwords",    "b53ecd71a846e29f5c0df360", 32, 3, [0xb53ecd71, 0xa846e29f, 0x5c0df360]),
  ("four triplets",   "b53ecd71a846e29f5c0df360", 24, 4, [0xb53ecd, 0x71a846, 0xe29f5c, 0xdf360]),
  ("eight bytes",     "b53ecd71a846e29f",         24, 3, [0xb53ecd, 0x71a846, 0xe29f00]),
  ("five bytes",      "b53ecd71a8",               16, 3, [0xb53e, 0xcd71, 0xa800]),
  ("six bytes",       "b53ecd71a846",             16, 4, [0xb53e, 0xcd71, 0xa846, 0]),
]

# The three UNALIGNED_* groups below cover widths that neither divide 8 nor are
# a multiple of 8, so groups straddle byte boundaries.

# Inputs shorter than out_len * b bits: the missing trailing bits read zero.
UNALIGNED_SHORT_INPUT: list[Case] = [
  ("1 byte at b=5",       "80",               5,  5, [16, 0, 0, 0, 0]),
  ("3 bytes at b=11",     "b53ecd",           11, 4, [0x5a9, 0x7b3, 0x200, 0]),
  ("4 bytes for 33 bits", "b53ecd71",         11, 3, [0x5a9, 0x7b3, 0x2e2]),
  ("4 bytes at b=13",     "deadbeef",         13, 5, [0x1bd5, 0x16fb, 0x1780, 0, 0]),
  ("4 bytes at b=17",     "b53ecd71",         17, 4, [0x16a7d, 0x135c4, 0, 0]),
  ("2 bytes at b=18",     "abcd",             18, 3, [0x2af34, 0, 0]),
  ("3 bytes at b=19",     "b53ecd",           19, 5, [0x5a9f6, 0x34000, 0, 0, 0]),
  ("1 byte at b=20",      "ff",               20, 3, [0xff000, 0, 0]),
  ("4 bytes at b=21",     "deadbeef",         21, 4, [0x1bd5b7, 0x1bbc00, 0, 0]),
  ("5 bytes at b=23",     "b53ecd71a8",       23, 4, [0x5a9f66, 0x5c6a00, 0, 0]),
  ("all ones at b=23",    "ffffffffffffffff", 23, 4, [0x7fffff, 0x7fffff, 0x7fffe0, 0]),
]

# Inputs with exactly out_len * b bits: no padding, every group is full.
UNALIGNED_EXACT_INPUT: list[Case] = [
  # last group is 2 bits of 0xe2, then 0x9f5c
  ("9 bytes",  "b53ecd71a846e29f5c",     18, 4, [0x2d4fb, 0xd71a, 0x211b8, 0x29f5c]),

  # last group is 6 bits of 0x5c, then 0x0df3
  ("11 bytes", "b53ecd71a846e29f5c0df3", 22, 4, [0x2d4fb3, 0x171a84, 0x1b8a7d, 0x1c0df3]),

  # five nibbles per group
  ("10 bytes", "b53ecd71a846e29f5c0d",   20, 4, [0xb53ec, 0xd71a8, 0x46e29, 0xf5c0d]),
]

# Inputs longer than out_len * b bits: surplus trailing bits are ignored.
UNALIGNED_LONG_INPUT: list[Case] = [
  # 51 of 80 bits used
  ("10 bytes at b=17", "b53ecd71a846e29f5c0d",     17, 3, [0x16a7d, 0x135c6, 0x14237]),

  # 84 of 96 bits used
  ("12 bytes at b=21", "b53ecd71a846e29f5c0df360", 21, 4, [0x16a7d9, 0x15c6a1, 0x3714f, 0x15c0df]),

  # 69 of 96 bits used
  ("12 bytes at b=23", "b53ecd71a846e29f5c0df360", 23, 3, [0x5a9f66, 0x5c6a11, 0x5c53eb]),

  # 78 of 80 bits used
  ("10 bytes at b=13", "b53ecd71a846e29f5c0d",     13, 6, [0x16a7, 0x1b35, 0x18d4, 0x46e, 0x53e, 0x1703]),

  # The leading 30 bits of four 0xFF bytes are all ones.
  ("all ones at b=5",  "ffffffff",                 5,  6, [0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f]),

  # 30 of 64 bits used
  ("8 bytes at b=5",   "b53ecd71a846e29f",         5,  6, [0x16, 0x14, 0x1f, 0xc, 0x1a, 0x1c]),
]


class Base2bTest(unittest.TestCase):
  def check(self, cases: list[Case]) -> None:
    for name, x, b, out_len, expected in cases:
      with self.subTest(name, b=b, out_len=out_len):
        self.assertEqual(base_2b(bytes.fromhex(x), b, out_len), expected)

  def test_leading_bits(self):
    self.check(LEADING_BITS)

  def test_short_input(self):
    self.check(SHORT_INPUT)

  def test_single_byte_input(self):
    self.check(SINGLE_BYTE_INPUT)

  def test_aligned_widths(self):
    self.check(ALIGNED_WIDTHS)

  def test_unaligned_short_input(self):
    self.check(UNALIGNED_SHORT_INPUT)

  def test_unaligned_exact_input(self):
    self.check(UNALIGNED_EXACT_INPUT)

  def test_unaligned_long_input(self):
    self.check(UNALIGNED_LONG_INPUT)


if __name__ == "__main__":
  unittest.main()
