"""Unit tests for the specification-level type annotations.

Extracted from the former `impl/test.py`. The `LEN` and `UINT` annotations in
`impl/shrincs.py` carry bounds as runtime metadata; these tests assert the
documented bit widths and return sizes of the public API, so an accidental
change to the specification shows up as a test failure even though the
annotations have no runtime effect.
"""

import unittest
from typing import Any, get_args, get_type_hints

from impl.shrincs import (
  LEN, UINT, SHRINCS_SL_SIGNATURE_SIZE, SPHX_SIGNATURE_SIZE,
  shrincs_sign, wots_tw_chain_iter, wots_c_chain_iter,
)


def find_metadata(annotation: Any, metadata_type: type) -> list[Any]:
  """Recursively collect annotations of `metadata_type` from a type hint."""
  if isinstance(annotation, metadata_type):
    return [annotation]
  return [
    metadata
    for argument in get_args(annotation)
    for metadata in find_metadata(argument, metadata_type)
  ]


class ChainIteratorAnnotationTest(unittest.TestCase):
  def test_chain_iter_arguments_are_32_bit(self):
    for chain_iterator in (wots_tw_chain_iter, wots_c_chain_iter):
      with self.subTest(function=chain_iterator.__name__):
        annotations = get_type_hints(chain_iterator, include_extras=True)
        for argument in ("start", "stop"):
          bounds = find_metadata(annotations[argument], UINT)
          self.assertEqual(len(bounds), 1)
          self.assertEqual(bounds[0].bits, 32)


class SignReturnAnnotationTest(unittest.TestCase):
  def test_sign_can_return_stateless_sized_signature(self):
    return_annotation = get_type_hints(shrincs_sign, include_extras=True)["return"]
    lengths = find_metadata(return_annotation, LEN)
    self.assertTrue(
      any(length.size == SHRINCS_SL_SIGNATURE_SIZE for length in lengths),
      "shrincs_sign must be able to return a SHRINCS_SL_SIGNATURE_SIZE-byte signature",
    )

  def test_sign_cannot_return_bare_sphincs_signature(self):
    return_annotation = get_type_hints(shrincs_sign, include_extras=True)["return"]
    lengths = find_metadata(return_annotation, LEN)
    self.assertFalse(
      any(length.size == SPHX_SIGNATURE_SIZE for length in lengths),
      "shrincs_sign must not return a bare SPHX_SIGNATURE_SIZE-byte signature "
      "(the SHRINCS stateless signature carries an indicator byte)",
    )


if __name__ == "__main__":
  unittest.main()
