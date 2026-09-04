from random import randbytes
from typing import get_args, get_type_hints
from shrincs import shrincs_sign, shrincs_keygen, shrincs_verify
from shrincs import FXMSS_SHAPE_UNBALANCED, FXMSS_SHAPE_BALANCED, FXMSS_HEIGHT
from shrincs import LEN, UINT, SHRINCS_SL_SIGNATURE_SIZE, SPHX_SIGNATURE_SIZE
from shrincs import wots_c_chain_iter, wots_tw_chain_iter


def find_metadata(annotation, metadata_type):
  if isinstance(annotation, metadata_type):
    return [annotation]
  return [
    metadata
    for argument in get_args(annotation)
    for metadata in find_metadata(argument, metadata_type)
  ]

if __name__ == "__main__":
  for chain_iterator in (wots_tw_chain_iter, wots_c_chain_iter):
    annotations = get_type_hints(chain_iterator, include_extras=True)
    assert find_metadata(annotations['start'], UINT)[0].bits == 32
    assert find_metadata(annotations['steps'], UINT)[0].bits == 32

  return_lengths = find_metadata(
    get_type_hints(shrincs_sign, include_extras=True)['return'], LEN
  )
  assert any(length.size == SHRINCS_SL_SIGNATURE_SIZE for length in return_lengths)
  assert not any(length.size == SPHX_SIGNATURE_SIZE for length in return_lengths)

  structures = [
    (bytes([FXMSS_SHAPE_BALANCED, 4]), 16),
    (bytes([FXMSS_SHAPE_UNBALANCED, 16]), 17)
  ]
  for (i, (sf_structure, stateful_signature_count)) in enumerate(structures):
    sk, pk = shrincs_keygen(randbytes(48), sf_structure)

    msg = b"foobar!"
    for j in range(stateful_signature_count):
      sig = shrincs_sign(msg, b"", sk, j, None)
      assert shrincs_verify(msg, sig, b"", pk)
    print(f'verified all stateful signatures for structure {sf_structure.hex()}')

    if i == len(structures) - 1:
      sig = shrincs_sign(msg, b"", sk, None, None)
      assert shrincs_verify(msg, sig, b"", pk)
      assert len(sig) == SHRINCS_SL_SIGNATURE_SIZE
      print(f'verified stateless signature')
