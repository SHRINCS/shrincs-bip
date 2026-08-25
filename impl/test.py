from random import randbytes
from shrincs import shrincs_sign, shrincs_keygen, shrincs_verify
from shrincs import FXMSS_SHAPE_UNBALANCED, FXMSS_SHAPE_BALANCED, FXMSS_HEIGHT
from shrincs import SPHX_LAYER_COUNT, SPHX_XMSS_HEIGHT
from shrincs import xmss_node, xmss_sign, fxmss_node, fxmss_sign, fxmss_pubkey_from_sig, shrincs_sf_leaf_select
from caches import xmss_leaf_cache_gen, xmss_node_from_cache, xmss_sign_from_cache
from caches import uxmss_cache_gen, uxmss_auth_path, fxmss_sign_from_auth_path
from caches import bds_state_init, bds_auth_path, bds_state_update

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

    sf_root = fxmss_node(sk_seed, 0, FXMSS_HEIGHT, pk_seed, sf_structure, bytearray(22))

    # Every signature is validated with the normal verifier against the root.
    for state_ctr in range(tree_depth + 1):
      leaf_index, leaf_height = shrincs_sf_leaf_select(sf_structure, state_ctr)
      digest = randbytes(32)
      auth_path = uxmss_auth_path(cache, leaf_index, leaf_height, pk_seed, sf_structure)
      sig_cached = fxmss_sign_from_auth_path(digest, sk_seed, leaf_index, leaf_height, pk_seed, sf_structure, auth_path)
      assert fxmss_pubkey_from_sig(leaf_index, leaf_height, sig_cached, digest, pk_seed) == sf_root
      if tree_depth <= 16:
        assert sig_cached == fxmss_sign(digest, sk_seed, leaf_index, leaf_height, pk_seed, sf_structure)
    assert shrincs_sf_leaf_select(sf_structure, tree_depth + 1) is None
  print('verified UXMSS cache equivalence')

def bds_node_count(bds_state):
  """Counts the 16-byte nodes held by a BDS state."""
  treehash_nodes = sum((th['node'] is not None) + len(th['stack']) for th in bds_state['treehash'])
  return len(bds_state['auth']) + len(bds_state['keep']) + len(bds_state['retain']) + treehash_nodes

def test_bds():
  for (tree_depth, bds_k) in ((2, 2), (4, 2), (4, 4), (6, 2), (8, 2), (8, 4)):
    sf_structure = bytes([FXMSS_SHAPE_BALANCED, tree_depth])
    seed = randbytes(48)
    sk_seed, pk_seed = seed[0:16], seed[32:48]

    bds_state = bds_state_init(sk_seed, pk_seed, sf_structure, bds_k)
    assert len(bds_state['retain']) == 2**bds_k - bds_k - 1
    sf_root = fxmss_node(sk_seed, 0, FXMSS_HEIGHT, pk_seed, sf_structure, bytearray(22))

    # Walk the entire signing budget. Every signature is validated with the normal verifier against the root
    max_nodes = bds_node_count(bds_state)
    for state_ctr in range(2**tree_depth):
      assert bds_state['state_ctr'] == state_ctr
      leaf_index, leaf_height = shrincs_sf_leaf_select(sf_structure, state_ctr)
      digest = randbytes(32)
      sig_bds = fxmss_sign_from_auth_path(digest, sk_seed, leaf_index, leaf_height, pk_seed, sf_structure, bds_auth_path(bds_state))
      assert fxmss_pubkey_from_sig(leaf_index, leaf_height, sig_bds, digest, pk_seed) == sf_root
      if tree_depth <= 6:
        assert sig_bds == fxmss_sign(digest, sk_seed, leaf_index, leaf_height, pk_seed, sf_structure)
      bds_state_update(bds_state, sk_seed, pk_seed, sf_structure)
      max_nodes = max(max_nodes, bds_node_count(bds_state))

    # The BDS storage bound must hold throughout the walk: auth + keep + retain + one completed node and stack per treehash instance.
    bound = tree_depth + tree_depth//2 + (2**bds_k - bds_k - 1) + \
            max(0, tree_depth - bds_k) + max(0, tree_depth - bds_k - 1)
    assert max_nodes <= bound, (tree_depth, bds_k, max_nodes, bound)
  print('verified BXMSS BDS traversal equivalence')

if __name__ == "__main__":
  test_shrincs()
  test_xmss_leaf_cache()
  test_uxmss_cache()
  test_bds()
