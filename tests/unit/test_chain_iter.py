"""
Unit tests for the Winternitz hash chain iterators.

`wots_tw_chain_iter` and `wots_c_chain_iter` walk a tweaked hash chain from
index `start` to index `stop`. The defining property is composition: walking
`start -> stop` directly must equal walking `start -> mid` and then
`mid -> stop`. This is what lets a Winternitz verifier recover a chain tip
from a partial signature.
"""

import random
import unittest

from impl import shrincs
from impl.shrincs import wots_tw_chain_iter, wots_c_chain_iter, WOTS_TW_CHAIN_BITS, WOTS_C_CHAIN_BITS

MAX_TW_INDEX = 2**WOTS_TW_CHAIN_BITS - 1
MAX_C_INDEX = 2**WOTS_C_CHAIN_BITS - 1


class WotsTwChainIterTest(unittest.TestCase):
  def chain(self, node: bytes, start: int, stop: int) -> bytes:
    return wots_tw_chain_iter(
      node, start, stop,
      pk_seed=self.pk_seed, layer=self.layer, tree_address=self.tree_address,
      keypair_index=self.keypair_index, chain_index=self.chain_index,
    )

  def setUp(self):
    rng = random.Random(0x7C075)
    self.node = bytes(rng.getrandbits(8) for _ in range(16))
    self.pk_seed = bytes(rng.getrandbits(8) for _ in range(16))
    self.layer = 3
    self.tree_address = 0x0102030405060708
    self.keypair_index = 9
    self.chain_index = 11

  def test_zero_length_chain_is_identity(self):
    for index in range(MAX_TW_INDEX + 1):
      with self.subTest(index=index):
        self.assertEqual(self.chain(self.node, index, index), self.node)

  def test_chains_compose(self):
    for mid in range(MAX_TW_INDEX + 1):
      partial = self.chain(self.node, 0, mid)
      for stop in range(mid, MAX_TW_INDEX + 1):
        with self.subTest(mid=mid, stop=stop):
          self.assertEqual(
            self.chain(self.node, 0, stop),
            self.chain(partial, mid, stop),
          )

  def test_chain_steps_are_distinct(self):
    tips = {self.chain(self.node, 0, stop) for stop in range(MAX_TW_INDEX + 1)}
    self.assertEqual(len(tips), MAX_TW_INDEX + 1)

  def test_chain_depends_on_tweak(self):
    # Changing any component of the chain address must change the tip.
    base = self.chain(self.node, 0, MAX_TW_INDEX)
    variations = {
      "layer": dict(pk_seed=self.pk_seed, layer=4, tree_address=self.tree_address,
                    keypair_index=self.keypair_index, chain_index=self.chain_index),
      "tree_address": dict(pk_seed=self.pk_seed, layer=self.layer, tree_address=1,
                           keypair_index=self.keypair_index, chain_index=self.chain_index),
      "keypair_index": dict(pk_seed=self.pk_seed, layer=self.layer, tree_address=self.tree_address,
                            keypair_index=10, chain_index=self.chain_index),
      "chain_index": dict(pk_seed=self.pk_seed, layer=self.layer, tree_address=self.tree_address,
                          keypair_index=self.keypair_index, chain_index=12),
      "pk_seed": dict(pk_seed=bytes(16), layer=self.layer, tree_address=self.tree_address,
                      keypair_index=self.keypair_index, chain_index=self.chain_index),
    }
    for name, kwargs in variations.items():
      with self.subTest(component=name):
        self.assertNotEqual(wots_tw_chain_iter(self.node, 0, MAX_TW_INDEX, **kwargs), base)


class WotsCChainIterTest(unittest.TestCase):
  def chain(self, node: bytes, start: int, stop: int) -> bytes:
    return wots_c_chain_iter(
      node, start, stop,
      pk_seed=self.pk_seed, node_height=self.node_height,
      node_index=self.node_index, chain_index=self.chain_index,
    )

  def setUp(self):
    rng = random.Random(0xC0FFEE)
    self.node = bytes(rng.getrandbits(8) for _ in range(16))
    self.pk_seed = bytes(rng.getrandbits(8) for _ in range(16))
    self.node_height = shrincs.FXMSS_HEIGHT - 4
    self.node_index = 5
    self.chain_index = 7

  def test_zero_length_chain_is_identity(self):
    for index in range(MAX_C_INDEX + 1):
      with self.subTest(index=index):
        self.assertEqual(self.chain(self.node, index, index), self.node)

  def test_chains_compose(self):
    for mid in range(MAX_C_INDEX + 1):
      partial = self.chain(self.node, 0, mid)
      for stop in range(mid, MAX_C_INDEX + 1):
        with self.subTest(mid=mid, stop=stop):
          self.assertEqual(
            self.chain(self.node, 0, stop),
            self.chain(partial, mid, stop),
          )

  def test_chain_steps_are_distinct(self):
    tips = {self.chain(self.node, 0, stop) for stop in range(MAX_C_INDEX + 1)}
    self.assertEqual(len(tips), MAX_C_INDEX + 1)


if __name__ == "__main__":
  unittest.main()
