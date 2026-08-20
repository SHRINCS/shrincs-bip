from random import randbytes
from shrincs import shrincs_sign, shrincs_keygen, shrincs_verify
from shrincs import FXMSS_SHAPE_UNBALANCED, FXMSS_SHAPE_BALANCED, FXMSS_HEIGHT
from shrincs import xmss_node, xmss_sign, xmss_leaf_cache_gen, xmss_node_from_cache, xmss_sign_from_cache
from shrincs import SPHX_LAYER_COUNT, SPHX_XMSS_HEIGHT
from shrincs import fxmss_sign, shrincs_sf_leaf_select
from shrincs import uxmss_cache_gen, uxmss_auth_path, fxmss_sign_from_auth_path

def top_tree_adrs() -> bytearray:
  """Returns a fresh ADRS locating the top-layer XMSS tree in the hypertree."""
  ADRS = bytearray(22)
  ADRS[0] = SPHX_LAYER_COUNT - 1
  return ADRS

def test_shrincs():
  structures = [
    bytes([FXMSS_SHAPE_BALANCED, 4]),
    bytes([FXMSS_SHAPE_UNBALANCED, 16])
  ]
  for (i, sf_structure) in enumerate(structures):
    sk, pk = shrincs_keygen(randbytes(48), sf_structure)

    msg = b"foobar!"
    for j in range(16):
      sig = shrincs_sign(msg, b"", sk, j, None)
      assert shrincs_verify(msg, sig, b"", pk)
    print(f'verified all stateful signatures for structure {sf_structure.hex()}')

    if i == len(structures) - 1:
      sig = shrincs_sign(msg, b"", sk, None, None)
      assert shrincs_verify(msg, sig, b"", pk)
      print(f'verified stateless signature')

def test_xmss_leaf_cache():
  seed = randbytes(48)
  sk_seed, pk_seed = seed[0:16], seed[32:48]

  leaf_cache = xmss_leaf_cache_gen(sk_seed, pk_seed, top_tree_adrs())

  # Cached leaves must match the naively computed leaves.
  for leaf_index in (0, 1, 2**SPHX_XMSS_HEIGHT - 1):
    assert leaf_cache[leaf_index] == xmss_node(sk_seed, leaf_index, 0, pk_seed, top_tree_adrs())

  # The root computed from the cache must match the naively computed root.
  root_naive = xmss_node(sk_seed, 0, SPHX_XMSS_HEIGHT, pk_seed, top_tree_adrs())
  root_cached = xmss_node_from_cache(leaf_cache, 0, SPHX_XMSS_HEIGHT, pk_seed, top_tree_adrs())
  assert root_cached == root_naive

  # Cached signing must produce byte-identical XMSS signatures.
  for keypair_index in (0, 137):
    msg = randbytes(16)
    sig_naive = xmss_sign(msg, sk_seed, keypair_index, pk_seed, top_tree_adrs())
    sig_cached = xmss_sign_from_cache(msg, sk_seed, leaf_cache, keypair_index, pk_seed, top_tree_adrs())
    assert sig_cached == sig_naive
  print('verified stateless leaf cache equivalence')

def test_uxmss_cache():
  for tree_depth in (1, 2, 16, 255):
    sf_structure = bytes([FXMSS_SHAPE_UNBALANCED, tree_depth])
    seed = randbytes(48)
    sk_seed, pk_seed = seed[0:16], seed[32:48]

    cache = uxmss_cache_gen(sk_seed, pk_seed, sf_structure)
    assert len(cache) == tree_depth + 1

    # Cached signing must produce byte-identical FXMSS signatures for every state counter
    # TODO: runtime of the test is annoying; instead of comparing against a freshly built reference 
    # signature, we can feed each cached signature to the normative verifier. 
    for state_ctr in range(tree_depth + 1):
      leaf_index, leaf_height = shrincs_sf_leaf_select(sf_structure, state_ctr)
      digest = randbytes(32)
      sig_naive = fxmss_sign(digest, sk_seed, leaf_index, leaf_height, pk_seed, sf_structure)
      auth_path = uxmss_auth_path(cache, leaf_index, leaf_height, pk_seed, sf_structure)
      sig_cached = fxmss_sign_from_auth_path(digest, sk_seed, leaf_index, leaf_height, pk_seed, sf_structure, auth_path)
      assert sig_cached == sig_naive
    assert shrincs_sf_leaf_select(sf_structure, tree_depth + 1) is None
  print('verified UXMSS cache equivalence')

if __name__ == "__main__":
  test_shrincs()
  test_xmss_leaf_cache()
  test_uxmss_cache()
