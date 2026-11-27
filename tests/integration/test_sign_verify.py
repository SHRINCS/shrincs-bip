# Integration tests for the highest-level SHRINCS APIs.

import unittest
from typing import Optional
from unittest.mock import patch

from impl import meta
from impl.shrincs import (
  FXMSS_HEIGHT, FXMSS_SHAPE_BALANCED, FXMSS_SHAPE_UNBALANCED, SHRINCS_SL_SIGNATURE_SIZE,
  shrincs_keygen, shrincs_pubkey_from_seckey, shrincs_sign, shrincs_sf_leaf_select,
  shrincs_verify, wots_c_grind_to_constant_sum, wots_c_map_digest,
)

MESSAGE = b"foobar!"
LONG_MESSAGE = 128 * bytes.fromhex(
  "75331f83f2af5d6f53d5e7b4961d17c0"
  "ffafebcecaa6330048ca66936af59eaa"
  "258b6234e3415278d3d5660f3b7de1b5"
  "9149f690ec0ca33e52b39c0734e198f9"
  "1d84fa84fd268e6f0e214df21070ff80"
  "5091d4497987d78ecd7865659e874dfe"
  "29a25b49110bf0b26f4a300f39073386"
  "bc4c7e8d608614d06e21c96ebede8c2e"
)

# Fixed 48-byte seeds. Arbitrary.
SEED1 = bytes.fromhex(
  "ef862b9fa7e16b7e3b8ec18c1a8ce841"
  "00c61a8671657bf28c6588d33122c62e"
  "fa26824bc71423763fd09a9efbc5ba1a"
)
SEED2 = bytes.fromhex(
  "71d12b94c630d48c0c9aba6e5d58e80e"
  "4ccd274030f3b6212548b737697e37eb"
  "c917bbaee87a36ccaa4ca1e096050b92"
)

def flip_byte(data: bytes, index: int) -> bytes:
  mutated = bytearray(data)
  mutated[index] ^= 0x01
  return bytes(mutated)


def stateful_signature_size(sf_structure: bytes, state_ctr: int) -> int:
  leaf = shrincs_sf_leaf_select(sf_structure, state_ctr)
  assert leaf is not None
  leaf_depth = FXMSS_HEIGHT - leaf[1]
  return meta.STATEFUL.signature_size(leaf_depth)


class KeygenTest(unittest.TestCase):
  # Include depth 0 (no stateful signatures) and depth 1, where UXMSS and
  # BXMSS shapes produce the same leaf positions, but must still yield different keys
  # thanks to domain separation.
  def test_distinct_structures_give_distinct_keys(self):
    structures = (
      bytes([FXMSS_SHAPE_UNBALANCED, 0]),
      bytes([FXMSS_SHAPE_UNBALANCED, 1]),
      bytes([FXMSS_SHAPE_UNBALANCED, 2]),
      bytes([FXMSS_SHAPE_UNBALANCED, 3]),
      bytes([FXMSS_SHAPE_UNBALANCED, 16]),
      bytes([FXMSS_SHAPE_UNBALANCED, 255]),
      bytes([FXMSS_SHAPE_BALANCED, 0]),
      bytes([FXMSS_SHAPE_BALANCED, 1]),
      bytes([FXMSS_SHAPE_BALANCED, 2]),
      bytes([FXMSS_SHAPE_BALANCED, 3]),
      bytes([FXMSS_SHAPE_BALANCED, 4]),
    )
    keys = [shrincs_keygen(SEED1, structure) for structure in structures]

    # Compare each unordered pair of keys once.
    for i in range(len(keys)):
      sk_a, pk_a = keys[i]
      for j in range(i + 1, len(keys)):
        sk_b, pk_b = keys[j]
        with self.subTest(a=structures[i].hex(), b=structures[j].hex()):
          self.assertNotEqual(sk_a, sk_b)
          self.assertNotEqual(pk_a, pk_b)

  def test_distinct_seeds_give_distinct_keys(self):
    structure = bytes([FXMSS_SHAPE_UNBALANCED, 2])
    sk_a, pk_a = shrincs_keygen(SEED1, structure)
    sk_b, pk_b = shrincs_keygen(SEED2, structure)
    self.assertNotEqual(pk_a, pk_b)
    self.assertNotEqual(sk_a, sk_b)

  def test_keygen_lengths_and_pubkey_extraction(self):
    sk, pk = shrincs_keygen(SEED1, bytes([FXMSS_SHAPE_BALANCED, 2]))
    self.assertEqual(len(sk), 82)
    self.assertEqual(len(pk), 48)
    self.assertEqual(shrincs_pubkey_from_seckey(sk), pk)


class ExclusiveOwnershipTest(unittest.TestCase):
  # Generate two keypairs with the same sk_seed but distinct stateful structures.
  # The stateful roots differ while the stateless roots match. A stateless
  # signature from either key must be bound to its own key's sf_root - no
  # cross-key replay attacks.
  def test_stateless_signatures_are_bound_to_their_own_pubkey(self):
    sk_a, pk_a = shrincs_keygen(SEED1, bytes([FXMSS_SHAPE_UNBALANCED, 3]))
    sk_b, pk_b = shrincs_keygen(SEED1, bytes([FXMSS_SHAPE_BALANCED, 3]))

    self.assertEqual(pk_a[16:32], pk_b[16:32])    # same stateless root
    self.assertNotEqual(pk_a[32:48], pk_b[32:48]) # different stateful root

    sl_sig_a = shrincs_sign(MESSAGE, b"", sk_a, None, None)
    sl_sig_b = shrincs_sign(MESSAGE, b"", sk_b, None, None)
    assert sl_sig_a is not None and sl_sig_b is not None

    # Correct pubkeys
    self.assertTrue(shrincs_verify(MESSAGE, sl_sig_a, b"", pk_a))
    self.assertTrue(shrincs_verify(MESSAGE, sl_sig_b, b"", pk_b))

    # Swapped pubkeys
    self.assertFalse(shrincs_verify(MESSAGE, sl_sig_a, b"", pk_b))
    self.assertFalse(shrincs_verify(MESSAGE, sl_sig_b, b"", pk_a))

  # A single key's signatures must bind to both complementary roots: changing
  # sf_root rejects the stateless signature, and changing sl_root rejects the
  # stateful one.
  def test_signatures_are_bound_to_both_pubkey_roots(self):
    sk, pk = shrincs_keygen(SEED1, bytes([FXMSS_SHAPE_UNBALANCED, 3]))
    sf_sig = shrincs_sign(MESSAGE, b"", sk, 0, None)
    sl_sig = shrincs_sign(MESSAGE, b"", sk, None, None)
    assert sf_sig is not None and sl_sig is not None

    # Correct pubkey
    self.assertTrue(shrincs_verify(MESSAGE, sf_sig, b"", pk))
    self.assertTrue(shrincs_verify(MESSAGE, sl_sig, b"", pk))

    # Mutated sf_root
    self.assertFalse(shrincs_verify(MESSAGE, sl_sig, b"", flip_byte(pk, 40)))

    # Mutated sl_root
    self.assertFalse(shrincs_verify(MESSAGE, sf_sig, b"", flip_byte(pk, 24)))


class StatefulSigningTest(unittest.TestCase):
  # Exhaust the stateful signature budget of both tree shapes. Parameters:
  # 17 stateful signatures for an unbalanced tree of depth 16,
  # 16 for a balanced tree of depth 4.
  STRUCTURES = [
    (bytes([FXMSS_SHAPE_UNBALANCED, 16]), 17),
    (bytes([FXMSS_SHAPE_BALANCED, 4]), 16),
  ]

  # Exhaust each stateful budget, then check that the next counter produces a
  # verifiable stateless signature.
  def test_all_stateful_signatures_verify(self):
    for sf_structure, signature_count in self.STRUCTURES:
      with self.subTest(sf_structure=sf_structure.hex()):
        sk, pk = shrincs_keygen(SEED1, sf_structure)
        for state_ctr in range(signature_count):
          with self.subTest(state_ctr=state_ctr):
            sig = shrincs_sign(MESSAGE, b"", sk, state_ctr, None)
            self.assertIsNotNone(sig)
            assert sig is not None
            self.assertTrue(shrincs_verify(MESSAGE, sig, b"", pk))
            self.assertEqual(len(sig), stateful_signature_size(sf_structure, state_ctr))

        # Exceeding the stateful budget automatically returns a stateless sig.
        with self.subTest(state_ctr=signature_count):
          sig = shrincs_sign(MESSAGE, b"", sk, signature_count, None)
          self.assertIsNotNone(sig)
          assert sig is not None
          self.assertEqual(len(sig), SHRINCS_SL_SIGNATURE_SIZE)
          self.assertTrue(shrincs_verify(MESSAGE, sig, b"", pk))

  # WOTS+C grinding may use any viable counter, not just the lowest one.
  def test_alternative_grinding_counter_gives_valid_stateful_signature(self):
    sk, pk = shrincs_keygen(SEED1, bytes([FXMSS_SHAPE_UNBALANCED, 3]))

    def grind_from_high_counter(
      pk_seed: bytes,
      digest: bytes,
      node_height: int,
      node_index: int,
    ) -> Optional[tuple[int, list[int]]]:
      lowest = wots_c_grind_to_constant_sum(pk_seed, digest, node_height, node_index)
      assert lowest is not None
      for counter in range(0xF000, 2**16):
        indexes = wots_c_map_digest(pk_seed, digest, node_height, node_index, counter)
        if indexes is not None:
          self.assertGreater(counter, lowest[0])
          return counter, indexes
      return None

    with patch("impl.shrincs.wots_c_grind_to_constant_sum", grind_from_high_counter):
      patched_sig = shrincs_sign(MESSAGE, b"", sk, 0, None)

    regular_sig = shrincs_sign(MESSAGE, b"", sk, 0, None)
    assert patched_sig is not None and regular_sig is not None
    self.assertNotEqual(patched_sig, regular_sig)
    self.assertTrue(shrincs_verify(MESSAGE, patched_sig, b"", pk))
    self.assertTrue(shrincs_verify(MESSAGE, regular_sig, b"", pk))

  # Use a UXMSS-255 key to cover signatures at deep authentication paths.
  def test_uxmss_signing_at_deep_depths(self):
    sf_structure = bytes([FXMSS_SHAPE_UNBALANCED, 255])
    sk, pk = shrincs_keygen(SEED1, sf_structure)
    for state_ctr in (63, 64, 127, 128, 144, 255):
      with self.subTest(state_ctr=state_ctr):
        sig = shrincs_sign(MESSAGE, b"", sk, state_ctr, None)
        self.assertIsNotNone(sig)
        assert sig is not None
        self.assertEqual(len(sig), stateful_signature_size(sf_structure, state_ctr))
        self.assertTrue(shrincs_verify(MESSAGE, sig, b"", pk))


class StatelessSigningTest(unittest.TestCase):
  def test_stateless_signature_basic(self):
    sk, pk = shrincs_keygen(SEED1, bytes([FXMSS_SHAPE_UNBALANCED, 3]))
    sig = shrincs_sign(MESSAGE, b"", sk, None, None)
    self.assertIsNotNone(sig)
    assert sig is not None
    self.assertEqual(len(sig), SHRINCS_SL_SIGNATURE_SIZE)
    self.assertTrue(shrincs_verify(MESSAGE, sig, b"", pk))

    # Test the hedged variant of SPHINCS.
    opt_rand1 = bytes.fromhex("9d6b1c2ef08a4375b26d0f9c81e7a430")
    opt_rand2 = bytes.fromhex("ee4f33b5d72d63654113e2201144f24c")
    sig_randomized_1 = shrincs_sign(MESSAGE, b"", sk, None, opt_rand1)
    sig_randomized_2 = shrincs_sign(MESSAGE, b"", sk, None, opt_rand2)
    assert sig_randomized_1 is not None and sig_randomized_2 is not None
    self.assertNotEqual(sig_randomized_1, sig)
    self.assertNotEqual(sig_randomized_2, sig)
    self.assertNotEqual(sig_randomized_1, sig_randomized_2)
    self.assertEqual(len(sig_randomized_1), SHRINCS_SL_SIGNATURE_SIZE)
    self.assertEqual(len(sig_randomized_2), SHRINCS_SL_SIGNATURE_SIZE)
    self.assertTrue(shrincs_verify(MESSAGE, sig_randomized_1, b"", pk))
    self.assertTrue(shrincs_verify(MESSAGE, sig_randomized_2, b"", pk))

  def test_deterministic_variant_is_reproducible(self):
    sk, pk = shrincs_keygen(SEED1, bytes([FXMSS_SHAPE_UNBALANCED, 3]))
    sig_a = shrincs_sign(MESSAGE, b"", sk, None, None)
    sig_b = shrincs_sign(MESSAGE, b"", sk, None, None)
    self.assertEqual(sig_a, sig_b)

  # A depth-zero tree has no usable leaf, even for state_ctr = 0.
  def test_depth_zero_key_signs_only_statelessly(self):
    sk, pk = shrincs_keygen(SEED1, bytes([FXMSS_SHAPE_BALANCED, 0]))
    sig = shrincs_sign(MESSAGE, b"", sk, 0, None)
    self.assertIsNotNone(sig)
    assert sig is not None
    self.assertEqual(len(sig), SHRINCS_SL_SIGNATURE_SIZE)
    self.assertTrue(shrincs_verify(MESSAGE, sig, b"", pk))


class LongMessageTest(unittest.TestCase):
  def test_stateful_signature_verifies(self):
    sk, pk = shrincs_keygen(SEED1, bytes([FXMSS_SHAPE_UNBALANCED, 3]))
    sig = shrincs_sign(LONG_MESSAGE, b"", sk, 0, None)
    self.assertIsNotNone(sig)
    assert sig is not None
    self.assertTrue(shrincs_verify(LONG_MESSAGE, sig, b"", pk))
    self.assertFalse(shrincs_verify(flip_byte(LONG_MESSAGE, 0), sig, b"", pk))
    self.assertFalse(
      shrincs_verify(flip_byte(LONG_MESSAGE, len(LONG_MESSAGE) - 1), sig, b"", pk)
    )

  def test_stateless_signature_verifies(self):
    sk, pk = shrincs_keygen(SEED1, bytes([FXMSS_SHAPE_UNBALANCED, 3]))
    sig = shrincs_sign(LONG_MESSAGE, b"", sk, None, None)
    self.assertIsNotNone(sig)
    assert sig is not None
    self.assertEqual(len(sig), SHRINCS_SL_SIGNATURE_SIZE)
    self.assertTrue(shrincs_verify(LONG_MESSAGE, sig, b"", pk))
    self.assertFalse(
      shrincs_verify(
        flip_byte(LONG_MESSAGE, len(LONG_MESSAGE) - 1), sig, b"", pk
      )
    )


# Sigs must verify only under the context used by the signer.
class ContextBindingTest(unittest.TestCase):
  def assert_context_binding(self, state_ctr: Optional[int]) -> None:
    sk, pk = shrincs_keygen(SEED1, bytes([FXMSS_SHAPE_UNBALANCED, 3]))
    sig = shrincs_sign(MESSAGE, b"ctx-one", sk, state_ctr, None)
    self.assertIsNotNone(sig)
    assert sig is not None
    self.assertTrue(shrincs_verify(MESSAGE, sig, b"ctx-one", pk))
    self.assertFalse(shrincs_verify(MESSAGE, sig, b"", pk))
    self.assertFalse(shrincs_verify(MESSAGE, sig, b"ctx-two", pk))

  def test_stateful_signature_is_bound_to_context(self):
    self.assert_context_binding(0)

  def test_stateless_signature_is_bound_to_context(self):
    self.assert_context_binding(None)

  def test_context_longer_than_255_bytes_is_rejected(self):
    sk, pk = shrincs_keygen(SEED1, bytes([FXMSS_SHAPE_UNBALANCED, 3]))
    ctx = bytes(range(256))
    for state_ctr in (0, None):
      with self.subTest(state_ctr=state_ctr):
        sig = shrincs_sign(MESSAGE, b"", sk, state_ctr, None)
        self.assertIsNotNone(sig)
        assert sig is not None
        with self.assertRaises(OverflowError):
          shrincs_sign(MESSAGE, ctx, sk, state_ctr, None)
        with self.assertRaises(OverflowError):
          shrincs_verify(MESSAGE, sig, ctx, pk)


class TamperRejectionTest(unittest.TestCase):
  sk: bytes
  pk: bytes
  sf_sig: bytes
  sl_sig: bytes

  # A valid signature must not verify under any mutation of the
  # signature, public key, or message, on both signing paths.
  @classmethod
  def setUpClass(cls):
    cls.sk, cls.pk = shrincs_keygen(SEED1, bytes([FXMSS_SHAPE_UNBALANCED, 3]))
    sf_sig = shrincs_sign(MESSAGE, b"", cls.sk, 0, None)
    sl_sig = shrincs_sign(MESSAGE, b"", cls.sk, None, None)
    assert sf_sig is not None and sl_sig is not None
    cls.sf_sig = sf_sig
    cls.sl_sig = sl_sig

  def signatures(self):
    return ("stateful", self.sf_sig), ("stateless", self.sl_sig)

  def test_tampered_signature_rejected(self):
    for kind, sig in self.signatures():
      for index in (0, 1, len(sig) // 2, len(sig) - 1):
        with self.subTest(kind=kind, sig_index=index):
          self.assertFalse(shrincs_verify(MESSAGE, flip_byte(sig, index), b"", self.pk))

  def test_tampered_pubkey_rejected(self):
    for kind, sig in self.signatures():
      for index in (0, 24, 47):
        with self.subTest(kind=kind, pk_index=index):
          self.assertFalse(
            shrincs_verify(MESSAGE, sig, b"", flip_byte(self.pk, index))
          )

  def test_tampered_message_rejected(self):
    for kind, sig in self.signatures():
      for index in (0, len(MESSAGE) - 1):
        with self.subTest(kind=kind, message_index=index):
          self.assertFalse(
            shrincs_verify(flip_byte(MESSAGE, index), sig, b"", self.pk)
          )


if __name__ == "__main__":
  unittest.main()
