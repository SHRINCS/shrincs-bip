from random import randbytes
from typing import get_args, get_type_hints
from shrincs import shrincs_sign, shrincs_keygen, shrincs_verify
from shrincs import FXMSS_SHAPE_UNBALANCED, FXMSS_SHAPE_BALANCED, FXMSS_HEIGHT
from shrincs import LEN, UINT, SHRINCS_SL_SIGNATURE_SIZE, SPHX_SIGNATURE_SIZE
from shrincs import wots_c_chain_iter, wots_tw_chain_iter
from shrincs import Address, WotsTwHash, WotsTwPrf, WotsTwPk, XmssTree
from shrincs import ForsTree, ForsRoots, ForsPrf
from shrincs import WotsCHash, WotsCPrf, WotsCPk, WotsCGrind, FxmssTree
from shrincs import SL_WOTS_TW_HASH, SL_WOTS_TW_PRF, SL_WOTS_TW_PK, SL_XMSS_TREE
from shrincs import SL_FORS_TREE, SL_FORS_ROOTS, SL_FORS_PRF
from shrincs import SF_WOTS_C_HASH, SF_WOTS_C_PRF, SF_WOTS_C_PK
from shrincs import SF_WOTS_C_GRIND, SF_FXMSS_TREE


def find_metadata(annotation, metadata_type):
  if isinstance(annotation, metadata_type):
    return [annotation]
  return [
    metadata
    for argument in get_args(annotation)
    for metadata in find_metadata(argument, metadata_type)
  ]


def assert_address_serializes_to(address: Address, address_type: int, payload: bytes):
  assert len(payload) == 12
  expected = (
    address.height.to_bytes(1)
    + address.index.to_bytes(8)
    + address_type.to_bytes(1)
    + payload
  )
  assert address.to_bytes() == expected


def verify_address_serialization():
  height = 7
  index = 0x0102030405060708
  keypair_index = 0x11121314
  chain_index = 0x21222324
  tree_height = 0x21222324
  hash_index = 0x31323334
  tree_index = 0x31323334
  zero_word = bytes(4)

  assert_address_serializes_to(
    WotsTwHash(
      height=height,
      index=index,
      keypair_index=keypair_index,
      chain_index=chain_index,
      hash_index=hash_index,
    ),
    SL_WOTS_TW_HASH,
    keypair_index.to_bytes(4) + chain_index.to_bytes(4) + hash_index.to_bytes(4),
  )

  assert_address_serializes_to(
    WotsTwPrf(
      height=height,
      index=index,
      keypair_index=keypair_index,
      chain_index=chain_index,
    ),
    SL_WOTS_TW_PRF,
    keypair_index.to_bytes(4) + chain_index.to_bytes(4) + zero_word,
  )

  assert_address_serializes_to(
    WotsTwPk(height=height, index=index, keypair_index=keypair_index),
    SL_WOTS_TW_PK,
    keypair_index.to_bytes(4) + zero_word + zero_word,
  )

  assert_address_serializes_to(
    XmssTree(height=height, index=index, tree_height=tree_height, tree_index=tree_index),
    SL_XMSS_TREE,
    zero_word + tree_height.to_bytes(4) + tree_index.to_bytes(4),
  )

  assert_address_serializes_to(
    ForsTree(
      height=height,
      index=index,
      keypair_index=keypair_index,
      tree_height=tree_height,
      tree_index=tree_index,
    ),
    SL_FORS_TREE,
    keypair_index.to_bytes(4) + tree_height.to_bytes(4) + tree_index.to_bytes(4),
  )

  assert_address_serializes_to(
    ForsRoots(height=height, index=index, keypair_index=keypair_index),
    SL_FORS_ROOTS,
    keypair_index.to_bytes(4) + zero_word + zero_word,
  )

  assert_address_serializes_to(
    ForsPrf(height=height, index=index, keypair_index=keypair_index, tree_index=tree_index),
    SL_FORS_PRF,
    keypair_index.to_bytes(4) + zero_word + tree_index.to_bytes(4),
  )

  assert_address_serializes_to(
    WotsCHash(height=height, index=index, chain_index=chain_index, hash_index=hash_index),
    SF_WOTS_C_HASH,
    zero_word + chain_index.to_bytes(4) + hash_index.to_bytes(4),
  )

  tree_depth = 0x92
  assert_address_serializes_to(
    WotsCPrf(
      height=height,
      index=index,
      tree_balanced=True,
      tree_depth=tree_depth,
      chain_index=chain_index,
    ),
    SF_WOTS_C_PRF,
    bytes([True, tree_depth]) + bytes(2) + chain_index.to_bytes(4) + zero_word,
  )

  assert_address_serializes_to(
    WotsCPrf(
      height=height,
      index=index,
      tree_balanced=False,
      tree_depth=tree_depth,
      chain_index=chain_index,
    ),
    SF_WOTS_C_PRF,
    bytes([False, tree_depth]) + bytes(2) + chain_index.to_bytes(4) + zero_word,
  )

  assert_address_serializes_to(
    WotsCPk(height=height, index=index),
    SF_WOTS_C_PK,
    zero_word + zero_word + zero_word,
  )

  assert_address_serializes_to(
    WotsCGrind(height=height, index=index),
    SF_WOTS_C_GRIND,
    zero_word + zero_word + zero_word,
  )

  assert_address_serializes_to(
    FxmssTree(height=height, index=index),
    SF_FXMSS_TREE,
    zero_word + zero_word + zero_word,
  )


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

  verify_address_serialization()

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
