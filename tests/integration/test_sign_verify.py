"""
Integration tests for the highest-level SHRINCS API.

Extracted from (and expanding on) the sign/verify/keygen loop of the former
`impl/test.py`. Covers key generation, the stateful FXMSS signing path for
both tree shapes, the stateless SLH-DSA fallback, context binding, and
rejection of tampered inputs.
"""

import unittest

from impl import shrincs

MESSAGE = b"foobar!"

# Keypairs are relatively expensive to generate, so they are built once per
# process and shared by every test that asks for the same (seed, structure).
_KEYPAIRS: dict[tuple[bytes, bytes], tuple[bytes, bytes]] = {}

def keypair(seed: bytes, sf_structure: bytes) -> tuple[bytes, bytes]:
  cached = _KEYPAIRS.get((seed, sf_structure))
  if cached is None:
    cached = shrincs.shrincs_keygen(seed, sf_structure)
    _KEYPAIRS[(seed, sf_structure)] = cached
  return cached


def flip_byte(data: bytes, index: int) -> bytes:
  mutated = bytearray(data)
  mutated[index] ^= 0x01
  return bytes(mutated)

def make_seed(label: bytes) -> bytes:
  """A valid 48-byte keygen seed derived from a short, readable label."""
  return (label + bytes(48))[:48]


class KeygenTest(unittest.TestCase):
  def test_keygen_is_deterministic(self):
    for structure in (bytes([shrincs.FXMSS_SHAPE_UNBALANCED, 4]),
                      bytes([shrincs.FXMSS_SHAPE_BALANCED, 2])):
      with self.subTest(sf_structure=structure.hex()):
        sk_a, pk_a = shrincs.shrincs_keygen(b"seed" * 12, structure)
        sk_b, pk_b = shrincs.shrincs_keygen(b"seed" * 12, structure)
        self.assertEqual((sk_a, pk_a), (sk_b, pk_b))

  def test_keygen_lengths_and_pubkey_extraction(self):
    sk, pk = keypair(b"\x11" * 48, bytes([shrincs.FXMSS_SHAPE_BALANCED, 2]))
    self.assertEqual(len(sk), 82)
    self.assertEqual(len(pk), 48)
    self.assertEqual(shrincs.shrincs_extract_pubkey(sk), pk)

  def test_distinct_seeds_give_distinct_keys(self):
    structure = bytes([shrincs.FXMSS_SHAPE_UNBALANCED, 2])
    sk_a, pk_a = shrincs.shrincs_keygen(b"\x01" * 48, structure)
    sk_b, pk_b = shrincs.shrincs_keygen(b"\x02" * 48, structure)
    self.assertNotEqual(pk_a, pk_b)
    self.assertNotEqual(sk_a, sk_b)


class StatefulSigningTest(unittest.TestCase):
  # Exhaust the stateful signature budget of both tree shapes. Parameters
  # mirror the original `impl/test.py`: 17 stateful signatures for an
  # unbalanced tree of depth 16, 16 for a balanced tree of depth 4.
  STRUCTURES = [
    (bytes([shrincs.FXMSS_SHAPE_UNBALANCED, 16]), 17),
    (bytes([shrincs.FXMSS_SHAPE_BALANCED, 4]), 16),
  ]

  def test_all_stateful_signatures_verify(self):
    for sf_structure, signature_count in self.STRUCTURES:
      with self.subTest(sf_structure=sf_structure.hex()):
        sk, pk = keypair(make_seed(b"bxmss-stateful-test") + sf_structure[1:], sf_structure)
        for state_ctr in range(signature_count):
          with self.subTest(state_ctr=state_ctr):
            sig = shrincs.shrincs_sign(MESSAGE, b"", sk, state_ctr, None)
            self.assertIsNotNone(sig)
            assert sig is not None
            self.assertTrue(shrincs.shrincs_verify(MESSAGE, sig, b"", pk))
            self.assertGreaterEqual(len(sig), shrincs.SHRINCS_SF_SIGNATURE_SIZE_MIN)
            self.assertLess(len(sig), shrincs.SHRINCS_SL_SIGNATURE_SIZE)


class StatelessSigningTest(unittest.TestCase):
  def test_stateless_signature_verifies_and_has_exact_size(self):
    sk, pk = keypair(b"\x02" * 48, bytes([shrincs.FXMSS_SHAPE_UNBALANCED, 3]))
    sig = shrincs.shrincs_sign(MESSAGE, b"", sk, None, None)
    self.assertIsNotNone(sig)
    assert sig is not None
    self.assertEqual(len(sig), shrincs.SHRINCS_SL_SIGNATURE_SIZE)
    self.assertTrue(shrincs.shrincs_verify(MESSAGE, sig, b"", pk))

  def test_deterministic_variant_is_reproducible(self):
    sk, pk = keypair(b"\x02" * 48, bytes([shrincs.FXMSS_SHAPE_UNBALANCED, 3]))
    sig_a = shrincs.shrincs_sign(MESSAGE, b"", sk, None, None)
    sig_b = shrincs.shrincs_sign(MESSAGE, b"", sk, None, None)
    self.assertEqual(sig_a, sig_b)

  def test_exhausted_state_counter_falls_back_to_stateless(self):
    # An unbalanced tree of depth 3 supports 4 stateful signatures (ctr 0..3);
    # a larger counter must produce a stateless signature instead.
    sk, pk = keypair(b"\x03" * 48, bytes([shrincs.FXMSS_SHAPE_UNBALANCED, 3]))
    for state_ctr in (4, 10**12):
      with self.subTest(state_ctr=state_ctr):
        sig = shrincs.shrincs_sign(MESSAGE, b"", sk, state_ctr, None)
        self.assertIsNotNone(sig)
        assert sig is not None
        self.assertEqual(len(sig), shrincs.SHRINCS_SL_SIGNATURE_SIZE)
        self.assertTrue(shrincs.shrincs_verify(MESSAGE, sig, b"", pk))

  def test_depth_zero_key_signs_only_statelessly(self):
    # A depth-zero tree has no usable leaf, even for state_ctr = 0.
    sk, pk = keypair(b"\x04" * 48, bytes([shrincs.FXMSS_SHAPE_BALANCED, 0]))
    sig = shrincs.shrincs_sign(MESSAGE, b"", sk, 0, None)
    self.assertIsNotNone(sig)
    assert sig is not None
    self.assertEqual(len(sig), shrincs.SHRINCS_SL_SIGNATURE_SIZE)
    self.assertTrue(shrincs.shrincs_verify(MESSAGE, sig, b"", pk))


class ContextBindingTest(unittest.TestCase):
  def test_signature_is_bound_to_context(self):
    sk, pk = keypair(b"\x05" * 48, bytes([shrincs.FXMSS_SHAPE_UNBALANCED, 3]))
    sig = shrincs.shrincs_sign(MESSAGE, b"ctx-one", sk, 0, None)
    self.assertIsNotNone(sig)
    assert sig is not None
    self.assertTrue(shrincs.shrincs_verify(MESSAGE, sig, b"ctx-one", pk))
    self.assertFalse(shrincs.shrincs_verify(MESSAGE, sig, b"", pk))
    self.assertFalse(shrincs.shrincs_verify(MESSAGE, sig, b"ctx-two", pk))


class TamperRejectionTest(unittest.TestCase):
  # A valid signature must stop verifying under any single-byte mutation of
  # the signature, public key, or message, on both signing paths.
  @classmethod
  def setUpClass(cls):
    cls.sk, cls.pk = keypair(b"\x06" * 48, bytes([shrincs.FXMSS_SHAPE_UNBALANCED, 3]))
    cls.sf_sig = shrincs.shrincs_sign(MESSAGE, b"", cls.sk, 0, None)
    cls.sl_sig = shrincs.shrincs_sign(MESSAGE, b"", cls.sk, None, None)
    assert cls.sf_sig is not None and cls.sl_sig is not None

  def signatures(self):
    return ("stateful", self.sf_sig), ("stateless", self.sl_sig)

  def test_tampered_signature_rejected(self):
    for kind, sig in self.signatures():
      for index in (0, 1, len(sig) // 2, len(sig) - 1):
        with self.subTest(kind=kind, sig_index=index):
          self.assertFalse(shrincs.shrincs_verify(MESSAGE, flip_byte(sig, index), b"", self.pk))

  def test_tampered_pubkey_rejected(self):
    for kind, sig in self.signatures():
      for index in (0, 24, 47):
        with self.subTest(kind=kind, pk_index=index):
          self.assertFalse(
            shrincs.shrincs_verify(MESSAGE, sig, b"", flip_byte(self.pk, index))
          )

  def test_tampered_message_rejected(self):
    for kind, sig in self.signatures():
      for index in (0, len(MESSAGE) - 1):
        with self.subTest(kind=kind, message_index=index):
          self.assertFalse(
            shrincs.shrincs_verify(flip_byte(MESSAGE, index), sig, b"", self.pk)
          )


if __name__ == "__main__":
  unittest.main()
