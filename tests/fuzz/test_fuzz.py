# Fuzz tests for the SHRINCS top-level API.
#
# Generated data is thrown at `shrincs_keygen`, `shrincs_sign`, and
# `shrincs_verify` to see if and how they break.
#
# The decorator (`tests/fuzz/fuzz_case.py`) handles the per-case seeded
# generators. Case loop count can be scaled by setting the env var
# `SHRINCS_FUZZ_ITERS`. Failures print the seed to reproduce the case
# that caused the error.

import os
import unittest

from impl import shrincs
from tests.fuzz.fuzz_case import flip_byte, fuzz, rand_bytes

MESSAGE = b"fuzz-me"

ALL_STRUCTURES: list[tuple[int, int]] = [
  (shrincs.FXMSS_SHAPE_UNBALANCED, depth) for depth in [1, 2, 3, 7, 8, 16, 32, 63,
                                                        64, 65, 127, 128, 254, 255]
] + [
  (shrincs.FXMSS_SHAPE_BALANCED, depth) for depth in range(8)
]

# sweep bounds, shared between the exhaustive tests and the oversized ones
SIGNATURE_LENGTH_LIMIT = shrincs.SHRINCS_SL_SIGNATURE_SIZE + 32
PUBKEY_LENGTH_LIMIT = 48 + 16

class FuzzKeygenTest(unittest.TestCase):
  # Key generation must succeed and yield well-formed keys, for each shape
  # and depth in ALL_STRUCTURES, each with a random 48-byte seed.
  @fuzz(cases=len(ALL_STRUCTURES))
  def test_keygen_with_random_seed_all_structures(self, rng, case):
    shape, depth = ALL_STRUCTURES[case]
    seed = rand_bytes(rng, 48)
    sf_structure = bytes([shape, depth])
    keypair = shrincs.shrincs_keygen(seed, sf_structure)
    assert isinstance(keypair, shrincs.Ok), keypair
    sk, pk = keypair.value
    self.assertEqual(len(sk), 82)
    self.assertEqual(len(pk), 48)
    self.assertEqual(shrincs.shrincs_pubkey_from_seckey(sk), pk)

  # The spec requires the shape byte to be one of the FXMSS_SHAPE_* values;
  # keygen over any other shape byte must fail.
  @fuzz(cases=20)
  def test_keygen_rejects_invalid_shape_byte(self, rng, _):
    shape = rng.randrange(2, 256)
    sf_structure = bytes([shape, rng.randrange(0, 8)])
    self.assertEqual(
      shrincs.shrincs_keygen(rand_bytes(rng, 48), sf_structure),
      shrincs.Err(shrincs.InvalidFxmssStructure()),
    )


class FuzzVerifyTest(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    keypair = shrincs.shrincs_keygen(b"\xf0" * 48, bytes([shrincs.FXMSS_SHAPE_UNBALANCED, 3]))
    assert isinstance(keypair, shrincs.Ok), keypair
    sk, cls.pk = keypair.value
    stateful_signature = shrincs.shrincs_sign(MESSAGE, b"", sk, 0, None)
    stateless_signature = shrincs.shrincs_sign(MESSAGE, b"", sk, None, None)
    assert isinstance(stateful_signature, shrincs.Ok), stateful_signature
    assert isinstance(stateless_signature, shrincs.Ok), stateless_signature
    cls.sf_sig = stateful_signature.value
    cls.sl_sig = stateless_signature.value

  # A random blob is essentially never a valid signature.
  @fuzz(cases=SIGNATURE_LENGTH_LIMIT + 1)
  def test_verify_random_signature_of_each_length_never_verifies(self, rng, case):
    self.assertFalse(
      shrincs.shrincs_verify(MESSAGE, rand_bytes(rng, case), b"", self.pk)
    )

  # Beyond the exhaustive range, oversized random blobs must also be rejected.
  @fuzz(cases=20)
  def test_verify_oversized_random_signature_never_verifies(self, rng, _):
    oversized = rng.randrange(SIGNATURE_LENGTH_LIMIT + 1, 20 * shrincs.SHRINCS_SL_SIGNATURE_SIZE)
    self.assertFalse(
      shrincs.shrincs_verify(MESSAGE, rand_bytes(rng, oversized), b"", self.pk)
    )

  # Random public keys must be rejected
  @fuzz(cases=PUBKEY_LENGTH_LIMIT)
  def test_verify_random_pubkey_of_each_length_never_verifies(self, rng, case):
    blob = rand_bytes(rng, case)
    for sig in (self.sf_sig, self.sl_sig):
      self.assertFalse(shrincs.shrincs_verify(MESSAGE, sig, b"", blob))

  # Oversized random pubkeys must also be rejected for both signature kinds.
  @fuzz(cases=100)
  def test_verify_oversized_random_pubkey_never_verifies(self, rng, _):
    blob = rand_bytes(rng, rng.randrange(PUBKEY_LENGTH_LIMIT + 1, 4 * PUBKEY_LENGTH_LIMIT))
    for sig in (self.sf_sig, self.sl_sig):
      self.assertFalse(shrincs.shrincs_verify(MESSAGE, sig, b"", blob))

  # Flipping one bit of a genuine signature (either path) at a random offset
  # must never verify.
  @fuzz(cases=20)
  def test_flipped_bit_in_signature_never_verifies(self, rng, _):
    sig = rng.choice([self.sf_sig, self.sl_sig])
    candidate = flip_byte(sig, rng.randrange(len(sig)))
    self.assertFalse(shrincs.shrincs_verify(MESSAGE, candidate, b"", self.pk))

  # Mutations on the indicator byte and the 16-byte randomizer value should be rejected.
  @fuzz(cases=30)
  def test_flipped_bit_in_indicator_and_r_never_verifies(self, rng, _):
    sig = rng.choice([self.sf_sig, self.sl_sig])
    candidate = flip_byte(sig, rng.randrange(17))
    self.assertFalse(shrincs.shrincs_verify(MESSAGE, candidate, b"", self.pk))

  # Truncating a genuine signature at any point must be rejected.
  @fuzz(cases=300)
  def test_truncated_signature_never_verifies(self, rng, _):
    sig = rng.choice([self.sf_sig, self.sl_sig])
    self.assertFalse(
      shrincs.shrincs_verify(MESSAGE, sig[:rng.randrange(len(sig))], b"", self.pk)
    )

  # Appending random bytes to a genuine signature must be rejected.
  @fuzz(cases=1000)
  def test_extended_signature_never_verifies(self, rng, _):
    sig = rng.choice([self.sf_sig, self.sl_sig])
    candidate = sig + rand_bytes(rng, rng.randrange(1, 8192))
    self.assertFalse(shrincs.shrincs_verify(MESSAGE, candidate, b"", self.pk))

  # Replacing the indicator byte with any other value must be rejected.
  @fuzz(cases=100)
  def test_replaced_indicator_byte_never_verifies(self, rng, _):
    sig = rng.choice([self.sf_sig, self.sl_sig])
    new_indicator = (rng.randrange(1, 256) + sig[0]) % 256
    candidate = bytes([new_indicator]) + sig[1:]
    self.assertFalse(shrincs.shrincs_verify(MESSAGE, candidate, b"", self.pk))

  # A genuine signature must not verify under a random message.
  @fuzz(cases=20)
  def test_signature_under_random_message_never_verifies(self, rng, _):
    sig = rng.choice([self.sf_sig, self.sl_sig])
    message = rand_bytes(rng, rng.randrange(0, 1024))
    self.assertFalse(shrincs.shrincs_verify(message, sig, b"", self.pk))


class FuzzSignTest(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    unbalanced_keypair = shrincs.shrincs_keygen(b"\xf1" * 48, bytes([shrincs.FXMSS_SHAPE_UNBALANCED, 3]))
    balanced_keypair = shrincs.shrincs_keygen(b"\xf2" * 48, bytes([shrincs.FXMSS_SHAPE_BALANCED, 3]))
    assert isinstance(unbalanced_keypair, shrincs.Ok), unbalanced_keypair
    assert isinstance(balanced_keypair, shrincs.Ok), balanced_keypair
    ub_sk, ub_pk = unbalanced_keypair.value
    bal_sk, bal_pk = balanced_keypair.value
    cls.keys = [
      (ub_sk, ub_pk, 4),
      (bal_sk, bal_pk, 8)
    ]

  # On a genuine key of either tree shape, any 64-bit counter within the
  # tree's stateful capacity must yield a stateful signature which verifies.
  @fuzz(cases=12)
  def test_sign_with_random_state_counter_always_verifies(self, rng, case):
    sk, pk, capacity = self.keys[case % len(self.keys)]
    state_ctr = rng.randrange(0, capacity)
    opt_rand = rng.choice([None, rand_bytes(rng, 16)])
    signing_result = shrincs.shrincs_sign(MESSAGE, b"", sk, state_ctr, opt_rand)
    assert isinstance(signing_result, shrincs.Ok), signing_result
    sig = signing_result.value
    self.assertNotEqual(sig[0], shrincs.FXMSS_HEIGHT) # must be stateful sig
    self.assertTrue(shrincs.shrincs_verify(MESSAGE, sig, b"", pk))

  # Counters beyond the tree's capacity, on either tree shape, must fall back
  # to the stateless path.
  @fuzz(cases=6)
  def test_sign_beyond_capacity_falls_back_to_stateless(self, rng, case):
    sk, pk, capacity = self.keys[case % len(self.keys)]
    state_ctr = rng.choice([None, rng.randrange(capacity, 2**64)])
    signing_result = shrincs.shrincs_sign(MESSAGE, b"", sk, state_ctr, None)
    assert isinstance(signing_result, shrincs.Ok), signing_result
    sig = signing_result.value
    self.assertEqual(sig[0], shrincs.FXMSS_HEIGHT) # must be stateless sig
    self.assertTrue(shrincs.shrincs_verify(MESSAGE, sig, b"", pk))


if __name__ == "__main__":
  unittest.main()
