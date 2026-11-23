from random import randbytes
from typing import get_args, get_type_hints
from unittest import TestCase
from unittest.mock import call, patch
from shrincs import shrincs_sign, shrincs_keygen, shrincs_verify
from shrincs import FXMSS_SHAPE_UNBALANCED, FXMSS_SHAPE_BALANCED, FXMSS_HEIGHT
from shrincs import BXMSS_MAX_DEPTH, H, shrincs_sf_leaf_select, wots_c_pubkey_gen
from shrincs import WOTS_C_CHAINS_SIZE, fxmss_pubkey_from_sig
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


def verify_fxmss_structure_limits() -> None:
  with (
    patch('shrincs.xmss_node') as stateless_root,
    patch('shrincs.fxmss_node') as stateful_root,
  ):
    for sf_structure in (bytes([2, 1]), bytes([FXMSS_SHAPE_BALANCED, BXMSS_MAX_DEPTH + 1])):
      assert shrincs_keygen(bytes(48), sf_structure) is None
      invalid_key = bytes(64) + sf_structure + bytes(16)
      for state_ctr in (0, None):
        assert shrincs_sign(b'foobar!', b'', invalid_key, state_ctr, None) is None
    stateless_root.assert_not_called()
    stateful_root.assert_not_called()

  # Use a real WOTS+C leaf with fixed sibling hashes in place of the large subtrees.
  depth = BXMSS_MAX_DEPTH
  leaf_height = FXMSS_HEIGHT - depth
  balanced_64 = bytes([FXMSS_SHAPE_BALANCED, depth])
  last_index = int.from_bytes(b'\xff' * 8)
  assert shrincs_sf_leaf_select(bytes([FXMSS_SHAPE_BALANCED, depth - 1]), last_index) is None
  assert shrincs_sf_leaf_select(balanced_64, None) is None

  seed = bytes(range(48))
  sk_seed, pk_seed = seed[:16], seed[32:48]
  sibling = bytes(16)
  root = wots_c_pubkey_gen(sk_seed, pk_seed, leaf_height, last_index, True, depth)
  expected_calls = [call(sk_seed, 0, FXMSS_HEIGHT, pk_seed, True, depth)]
  for level in range(depth):
    parent_index = 2**(depth - level - 1) - 1
    root = H(pk_seed, FxmssTree(leaf_height + level + 1, parent_index), sibling + root)
    expected_calls.append(call(sk_seed, 2 * parent_index, leaf_height + level, pk_seed, True, depth))

  with (
    patch('shrincs.xmss_node', return_value=bytes(16)),
    patch('shrincs.fxmss_node', side_effect=[root] + [sibling] * depth) as tree_node,
  ):
    keypair = shrincs_keygen(seed, balanced_64)
    assert keypair is not None
    sk, pk = keypair
    sig = shrincs_sign(b'foobar!', b'', sk, last_index, None)
    assert tree_node.call_args_list == expected_calls
  assert sig is not None
  assert sig[17:25] == last_index.to_bytes(8)
  assert shrincs_verify(b'foobar!', sig, b'', pk)


def verify_fxmss_leaf_selection() -> None:
  structure = bytes([FXMSS_SHAPE_UNBALANCED, 4])
  expected_positions = [(1, 254), (1, 253), (1, 252), (1, 251), (0, 251), None, None]
  for counter, expected in enumerate(expected_positions):
    assert shrincs_sf_leaf_select(structure, counter) == expected

  for shape in (FXMSS_SHAPE_BALANCED, FXMSS_SHAPE_UNBALANCED):
    assert shrincs_sf_leaf_select(bytes([shape, 0]), 0) is None


def verify_fxmss_verifier_checks() -> None:
  depth_one_signature = bytes(2 + WOTS_C_CHAINS_SIZE + 16)
  digest, pk_seed = bytes(32), bytes(16)
  test_case = TestCase()

  with test_case.assertRaises(AssertionError):
    fxmss_pubkey_from_sig(2, FXMSS_HEIGHT - 1, depth_one_signature, digest, pk_seed)
  with test_case.assertRaises(AssertionError):
    fxmss_pubkey_from_sig(0, FXMSS_HEIGHT - 2, depth_one_signature, digest, pk_seed)


def verify_deep_uxmss_signature() -> None:
  depth = 65
  structure = bytes([FXMSS_SHAPE_UNBALANCED, depth])
  with patch('shrincs.xmss_node', return_value=bytes(16)):
    keypair = shrincs_keygen(bytes(range(48)), structure)
  assert keypair is not None
  sk, pk = keypair

  message = b'foobar!'
  signature = shrincs_sign(message, b'', sk, depth, None)
  assert signature is not None
  assert signature[0] == FXMSS_HEIGHT - depth
  assert signature[17:25] == bytes(8)
  assert len(signature) == 17 + 8 + 2 + WOTS_C_CHAINS_SIZE + 16 * depth
  assert shrincs_verify(message, signature, b'', pk)


if __name__ == "__main__":
  for chain_iterator in (wots_tw_chain_iter, wots_c_chain_iter):
    annotations = get_type_hints(chain_iterator, include_extras=True)
    assert find_metadata(annotations['start'], UINT)[0].bits == 32
    assert find_metadata(annotations['stop'], UINT)[0].bits == 32

  return_lengths = find_metadata(
    get_type_hints(shrincs_sign, include_extras=True)['return'], LEN
  )
  assert any(length.size == SHRINCS_SL_SIGNATURE_SIZE for length in return_lengths)
  assert not any(length.size == SPHX_SIGNATURE_SIZE for length in return_lengths)

  verify_address_serialization()
  verify_fxmss_structure_limits()
  verify_fxmss_leaf_selection()
  verify_fxmss_verifier_checks()
  verify_deep_uxmss_signature()

  structures = [
    (bytes([FXMSS_SHAPE_BALANCED, 4]), 16),
    (bytes([FXMSS_SHAPE_UNBALANCED, 16]), 17)
  ]
  for (i, (sf_structure, stateful_signature_count)) in enumerate(structures):
    keypair = shrincs_keygen(randbytes(48), sf_structure)
    assert keypair is not None
    sk, pk = keypair

    msg = b"foobar!"
    for j in range(stateful_signature_count):
      sig = shrincs_sign(msg, b"", sk, j, None)
      assert shrincs_verify(msg, sig, b"", pk)
      if sf_structure == bytes([FXMSS_SHAPE_BALANCED, 4]) and j == 0:
        invalid_index_sig = sig[:17] + bytes([16]) + sig[18:]
        assert not shrincs_verify(msg, invalid_index_sig, b"", pk)
    print(f'verified all stateful signatures for structure {sf_structure.hex()}')

    if i == len(structures) - 1:
      sig = shrincs_sign(msg, b"", sk, None, None)
      assert shrincs_verify(msg, sig, b"", pk)
      assert len(sig) == SHRINCS_SL_SIGNATURE_SIZE
      print(f'verified stateless signature')
