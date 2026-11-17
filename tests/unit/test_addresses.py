"""Unit tests for the ADRS address classes and their serialization.

Extracted from the former `impl/test.py`. Every one of the twelve concrete
`Address` subclasses must serialize to exactly 22 bytes: the 9-byte common
prefix (`height`, `index`), a one-byte address type flag, and a 12-byte
payload of three 32-bit words, unused fields zeroed.
"""

import unittest

from impl.shrincs import (
  Address, WotsTwHash, WotsTwPrf, WotsTwPk, XmssTree,
  ForsTree, ForsRoots, ForsPrf,
  WotsCHash, WotsCPrf, WotsCPk, WotsCGrind, FxmssTree,
  SL_WOTS_TW_HASH, SL_WOTS_TW_PRF, SL_WOTS_TW_PK, SL_XMSS_TREE,
  SL_FORS_TREE, SL_FORS_ROOTS, SL_FORS_PRF,
  SF_WOTS_C_HASH, SF_WOTS_C_PRF, SF_WOTS_C_PK,
  SF_WOTS_C_GRIND, SF_FXMSS_TREE,
)


class AddressSerializationTest(unittest.TestCase):
  def assert_serializes_to(self, address: Address, address_type: int, payload: bytes):
    self.assertEqual(len(payload), 12)
    expected = (
      address.height.to_bytes(1)
      + address.index.to_bytes(8)
      + address_type.to_bytes(1)
      + payload
    )
    self.assertEqual(address.to_bytes(), expected)
    self.assertEqual(len(address.to_bytes()), 22)

  def test_address_serialization(self):
    height = 7
    index = 0x0102030405060708
    keypair_index = 0x11121314
    chain_index = 0x21222324
    tree_height = 0x21222324
    hash_index = 0x31323334
    tree_index = 0x31323334
    zero_word = bytes(4)

    cases: list[tuple[str, Address, int, bytes]] = [
      (
        "WotsTwHash",
        WotsTwHash(
          height=height,
          index=index,
          keypair_index=keypair_index,
          chain_index=chain_index,
          hash_index=hash_index,
        ),
        SL_WOTS_TW_HASH,
        keypair_index.to_bytes(4) + chain_index.to_bytes(4) + hash_index.to_bytes(4),
      ),
      (
        "WotsTwPrf",
        WotsTwPrf(
          height=height,
          index=index,
          keypair_index=keypair_index,
          chain_index=chain_index,
        ),
        SL_WOTS_TW_PRF,
        keypair_index.to_bytes(4) + chain_index.to_bytes(4) + zero_word,
      ),
      (
        "WotsTwPk",
        WotsTwPk(height=height, index=index, keypair_index=keypair_index),
        SL_WOTS_TW_PK,
        keypair_index.to_bytes(4) + zero_word + zero_word,
      ),
      (
        "XmssTree",
        XmssTree(height=height, index=index, tree_height=tree_height, tree_index=tree_index),
        SL_XMSS_TREE,
        zero_word + tree_height.to_bytes(4) + tree_index.to_bytes(4),
      ),
      (
        "ForsTree",
        ForsTree(
          height=height,
          index=index,
          keypair_index=keypair_index,
          tree_height=tree_height,
          tree_index=tree_index,
        ),
        SL_FORS_TREE,
        keypair_index.to_bytes(4) + tree_height.to_bytes(4) + tree_index.to_bytes(4),
      ),
      (
        "ForsRoots",
        ForsRoots(height=height, index=index, keypair_index=keypair_index),
        SL_FORS_ROOTS,
        keypair_index.to_bytes(4) + zero_word + zero_word,
      ),
      (
        "ForsPrf",
        ForsPrf(height=height, index=index, keypair_index=keypair_index, tree_index=tree_index),
        SL_FORS_PRF,
        keypair_index.to_bytes(4) + zero_word + tree_index.to_bytes(4),
      ),
      (
        "WotsCHash",
        WotsCHash(height=height, index=index, chain_index=chain_index, hash_index=hash_index),
        SF_WOTS_C_HASH,
        zero_word + chain_index.to_bytes(4) + hash_index.to_bytes(4),
      ),
      (
        "WotsCPrf (balanced)",
        WotsCPrf(
          height=height,
          index=index,
          tree_balanced=True,
          tree_depth=0x92,
          chain_index=chain_index,
        ),
        SF_WOTS_C_PRF,
        bytes([True, 0x92]) + bytes(2) + chain_index.to_bytes(4) + zero_word,
      ),
      (
        "WotsCPrf (unbalanced)",
        WotsCPrf(
          height=height,
          index=index,
          tree_balanced=False,
          tree_depth=0x92,
          chain_index=chain_index,
        ),
        SF_WOTS_C_PRF,
        bytes([False, 0x92]) + bytes(2) + chain_index.to_bytes(4) + zero_word,
      ),
      (
        "WotsCPk",
        WotsCPk(height=height, index=index),
        SF_WOTS_C_PK,
        zero_word + zero_word + zero_word,
      ),
      (
        "WotsCGrind",
        WotsCGrind(height=height, index=index),
        SF_WOTS_C_GRIND,
        zero_word + zero_word + zero_word,
      ),
      (
        "FxmssTree",
        FxmssTree(height=height, index=index),
        SF_FXMSS_TREE,
        zero_word + zero_word + zero_word,
      ),
    ]

    for name, address, address_type, payload in cases:
      with self.subTest(address=name):
        self.assert_serializes_to(address, address_type, payload)

  def test_address_types_are_distinguished(self):
    # Two addresses of different classes with identical field values must not
    # collide, i.e. the type flag is part of the serialization.
    common = dict(height=0, index=0)
    self.assertNotEqual(WotsCPk(**common).to_bytes(), WotsCGrind(**common).to_bytes())
    self.assertNotEqual(WotsCGrind(**common).to_bytes(), FxmssTree(**common).to_bytes())
    self.assertNotEqual(WotsCPk(**common).to_bytes(), FxmssTree(**common).to_bytes())

  def test_prefix_fields_encode_big_endian(self):
    # Spot-check that `height` is the first byte and `index` follows as 8
    # big-endian bytes.
    addr = FxmssTree(height=0xAB, index=0x0102030405060708)
    serialized = addr.to_bytes()
    self.assertEqual(serialized[0:1], b"\xAB")
    self.assertEqual(serialized[1:9], bytes(range(1, 9)))
    self.assertEqual(serialized[9], SF_FXMSS_TREE)


if __name__ == "__main__":
  unittest.main()
