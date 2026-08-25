# SHRINCS signer cache implementation
#
# Optional, signer-side cache constructions for SHRINCS signers, specified in
# docs/CACHE_MANAGEMENT.md. Caching is not consensus-relevant: it changes
# neither the signatures a keypair produces, nor their encoding, nor the
# verifier. Every function here is validated against the naive algorithms in
# shrincs.py by test.py.

try:
  from .shrincs import * # imported as part of the impl package (e.g. by pydoc_insert.py)
except ImportError:
  from shrincs import * # imported as a sibling module (e.g. by test.py)


def xmss_leaf_cache_gen(sk_seed: bytes, pk_seed: bytes, ADRS: bytearray) -> list[bytes]:
  """
  The XMSS cache generation function. Computes the WOTS-TW public keys of every leaf in the XMSS tree
  at the location prefilled in `ADRS`, for reuse across signatures as a leaf cache.

  - Inputs:
    - `sk_seed`: a 16-byte secret.
    - `pk_seed`: a 16-byte salt.
    - `ADRS`: a 22-byte address.
  - Output:
    - a list of `2**SPHX_XMSS_HEIGHT` 16-byte WOTS-TW public key hashes, ordered by leaf index.

  This function is only used in the stateless path, and only by the signer.
  """
  leaf_cache = [b''] * 2**SPHX_XMSS_HEIGHT
  for leaf_index in range(2**SPHX_XMSS_HEIGHT):
    ADRS[10:14] = leaf_index.to_bytes(4)
    leaf_cache[leaf_index] = wots_tw_pubkey_gen(sk_seed, pk_seed, ADRS)
  return leaf_cache

def xmss_node_from_cache(leaf_cache: list[bytes], node_index: int, node_height: int, pk_seed: bytes, ADRS: bytearray) -> bytes:
  """
  The cached XMSS node calculation function. Similar to `xmss_node`, but reads WOTS-TW public
  keys from `leaf_cache` instead of regenerating them, and requires no secret key.

  - Inputs:
    - `leaf_cache`: the WOTS-TW public keys of the tree, from `xmss_leaf_cache_gen`.
    - `node_index`: a 32-bit unsigned integer, the index (from the left) of the node in the XMSS layer.
    - `node_height`: a 32-bit unsigned integer, the height (from the bottom) of the node in the XMSS layer.
    - `pk_seed`: a 16-byte salt.
    - `ADRS`: a 22-byte address.
  - Output:
    - a 16-byte XMSS node hash.

  This function is only used in the stateless path, and only by the signer.
  """
  if node_height == 0: # Bottom layer: read the WOTS-TW pubkey hash from the cache.
    return leaf_cache[node_index]

  # Recursively derive the left/right child nodes.
  lchild_index = 2 * node_index
  child_height = node_height - 1
  lchild = xmss_node_from_cache(leaf_cache, lchild_index, child_height, pk_seed, ADRS)
  rchild = xmss_node_from_cache(leaf_cache, lchild_index + 1, child_height, pk_seed, ADRS)

  # Compute and return the parent node.
  ADRS[9] = SL_XMSS_TREE
  ADRS[10:14] = zeros(4)
  ADRS[14:18] = node_height.to_bytes(4)
  ADRS[18:22] = node_index.to_bytes(4)
  return H(pk_seed, ADRS, lchild + rchild)

def xmss_sign_from_cache(message: bytes, sk_seed: bytes, leaf_cache: list[bytes], keypair_index: int, pk_seed: bytes, ADRS: bytearray) -> bytes:
  """
  XMSS signing from cache. Equivalent to `xmss_sign`, but computes the Merkle
  authentication path from `leaf_cache` instead of regenerating every WOTS-TW leaf.

  - Inputs:
    - `message`: a 16-byte message to sign.
    - `sk_seed`: a 16-byte secret.
    - `leaf_cache`: the WOTS-TW public keys of the tree, from `xmss_leaf_cache_gen`.
    - `keypair_index`: a 32-bit unsigned integer, the index of the WOTS-TW keypair to sign with.
    - `pk_seed`: a 16-byte salt.
    - `ADRS`: a 22-byte address.
  - Output:
    - a `SPHX_XMSS_SIGNATURE_SIZE`-byte signature.

  This function is only used in the stateless path, and only by the signer.
  """
  # Sign the message with WOTS-TW.
  ADRS[10:14] = keypair_index.to_bytes(4)
  sig = wots_tw_sign(message, sk_seed, pk_seed, ADRS)

  # Append the Merkle authentication path.
  for j in range(SPHX_XMSS_HEIGHT):
    sibling_index = (keypair_index >> j) ^ 1
    sig += xmss_node_from_cache(leaf_cache, sibling_index, j, pk_seed, ADRS)

  return sig

def uxmss_cache_gen(sk_seed: bytes, pk_seed: bytes, sf_structure: bytes) -> dict[tuple[int, int], bytes]:
  """
  The UXMSS cache generation function. Computes the WOTS+C public keys of every leaf in a UXMSS tree.

  - Inputs:
    - `sk_seed`: a 16-byte secret.
    - `pk_seed`: a 16-byte salt.
    - `sf_structure`: a 2-byte identifier describing the FXMSS tree structure.
  - Output:
    - a dictionary mapping `(node_index, node_height)` positions to 16-byte WOTS+C public key hashes: `depth + 1` leaves in total.

  This function is only used in the stateful path, and only by the signer.
  """
  tree_shape, tree_depth = sf_structure[0], sf_structure[1]
  assert tree_shape == FXMSS_SHAPE_UNBALANCED
  assert tree_depth >= 1

  cache = {}
  ADRS = bytearray(22)

  # The deepest layer holds two WOTS+C leaves; every layer above holds one, as the right sibling of the spine.
  deepest_height = FXMSS_HEIGHT - tree_depth
  cache[(0, deepest_height)] = fxmss_node(sk_seed, 0, deepest_height, pk_seed, sf_structure, ADRS)
  for node_height in range(deepest_height, FXMSS_HEIGHT):
    cache[(1, node_height)] = fxmss_node(sk_seed, 1, node_height, pk_seed, sf_structure, ADRS)

  return cache

def uxmss_auth_path(uxmss_cache: dict[tuple[int, int], bytes], leaf_index: int, leaf_height: int, pk_seed: bytes, sf_structure: bytes) -> list[bytes]:
  """
  Computes the Merkle authentication path from a cache. Every path node is read from there,
  except the leaf's sibling on the spine, which is recombined from the cached leaves below it.

  - Inputs:
    - `uxmss_cache`: a leaf cache from `uxmss_cache_gen`.
    - `leaf_index`: a 64-bit unsigned integer, the index of the signing leaf in the FXMSS layer.
    - `leaf_height`: an 8-bit unsigned integer, the height of the signing leaf in the FXMSS tree.
    - `pk_seed`: a 16-byte salt.
    - `sf_structure`: a 2-byte identifier describing the FXMSS tree structure.
  - Output:
    - a list of `FXMSS_HEIGHT - leaf_height` 16-byte authentication path nodes, ordered from the leaf's sibling upwards.

  This function is only used in the stateful path, and only by the signer.
  """
  tree_shape, tree_depth = sf_structure[0], sf_structure[1]
  assert tree_shape == FXMSS_SHAPE_UNBALANCED
  deepest_height = FXMSS_HEIGHT - tree_depth
  leaf_depth = FXMSS_HEIGHT - leaf_height

  ADRS = bytearray(22)
  ADRS[9] = SF_FXMSS_TREE

  # The leaf's sibling: a cached leaf on the deepest layer, or a spine node recombined from the cached leaves below it.
  if leaf_height == deepest_height:
    sibling = uxmss_cache[(leaf_index ^ 1, leaf_height)]
  else:
    sibling = uxmss_cache[(0, deepest_height)]
    for node_height in range(deepest_height + 1, leaf_height + 1):
      ADRS[0] = node_height
      sibling = H(pk_seed, ADRS, sibling + uxmss_cache[(1, node_height - 1)])

  # Every node above the sibling is a cached leaf.
  auth_path = [sibling]
  for j in range(1, leaf_depth):
    auth_path.append(uxmss_cache[(1, leaf_height + j)])
  return auth_path

def fxmss_sign_from_auth_path(message_digest: bytes, sk_seed: bytes, leaf_index: int, leaf_height: int, pk_seed: bytes, sf_structure: bytes, auth_path: list[bytes]) -> Optional[bytes]:
  """
  FXMSS signing from a precomputed authentication path. Equivalent to `fxmss_sign`, but
  appends the given `auth_path` instead of regenerating its nodes with `fxmss_node`.

  - Inputs:
    - `message_digest`: a 32-byte message digest.
    - `sk_seed`: a 16-byte secret.
    - `leaf_index`: a 64-bit unsigned integer, the index of the signing leaf in the FXMSS layer.
    - `leaf_height`: an 8-bit unsigned integer, the height of the signing leaf in the FXMSS tree.
    - `pk_seed`: a 16-byte salt.
    - `sf_structure`: a 2-byte identifier describing the FXMSS tree structure.
    - `auth_path`: a list of `FXMSS_HEIGHT - leaf_height` 16-byte authentication path nodes, ordered from the leaf's sibling upwards.
  - Output:
    - a `2 + 16 * (WOTS_C_CHAIN_COUNT + FXMSS_HEIGHT - leaf_height)`-byte signature, or null.

  This function is only used in the stateful path, and only by the signer.
  """
  leaf_depth = FXMSS_HEIGHT - leaf_height
  assert len(auth_path) == leaf_depth

  # Validate the leaf is positioned correctly for the specified tree structure.
  tree_shape, tree_depth = sf_structure[0], sf_structure[1]
  if tree_shape == FXMSS_SHAPE_UNBALANCED:
    assert leaf_index == 1 or leaf_depth == tree_depth
  if tree_shape == FXMSS_SHAPE_BALANCED:
    assert leaf_depth == tree_depth

  ADRS = bytearray(22)
  ADRS[0] = leaf_height
  ADRS[1:9] = leaf_index.to_bytes(8)
  ADRS[10:14] = sf_structure + zeros(2)
  sig = wots_c_sign(message_digest, sk_seed, pk_seed, ADRS)
  if sig is None:
    return None

  # Append the precomputed Merkle authentication path.
  return sig + concat(auth_path)

def bds_state_init(sk_seed: bytes, pk_seed: bytes, sf_structure: bytes, bds_k: int) -> dict:
  """
  The BDS state initialization function. Computes the starting traversal state for a BXMSS
  tree: the authentication path of leaf zero, one treehash instance per lower layer
  holding the next right node of that layer, and the retained right nodes of the top
  `bds_k - 1` layers below the root.

  - Inputs:
    - `sk_seed`: a 16-byte secret.
    - `pk_seed`: a 16-byte salt.
    - `sf_structure`: a 2-byte identifier describing the FXMSS tree structure. Its shape byte must be `FXMSS_SHAPE_BALANCED`.
    - `bds_k`: the memory/time trade-off parameter: `2 <= bds_k <= depth`, with `depth - bds_k` even.
  - Output:
    - a BDS state: a dictionary with the fields
      - `state_ctr`: the state counter whose authentication path `auth` currently holds.
      - `bds_k`: the parameter `bds_k`.
      - `auth`: the current authentication path, one node per layer, from the leaf's sibling upwards.
      - `keep`: nodes remembered to compute upcoming left authentication nodes, keyed by layer.
      - `retain`: precomputed right nodes of the top layers, keyed by `(node_index, layer)`.
      - `treehash`: one instance per layer `j < depth - bds_k`: a completed `node`, the
        `next_leaf` it will consume, and a `stack` of partial subtree roots paired with their layers.

  This function is only used in the stateful path, and only by the signer.

  Layers are counted relative to the BXMSS tree: layer `j` sits at FXMSS height
  `FXMSS_HEIGHT - depth + j`, so layer 0 holds the WOTS+C leaves and layer `depth` the root.
  The initial state consists of nodes computed during key generation anyway, so
  implementations may fill it as a byproduct of `shrincs_keygen`.
  """
  tree_shape, tree_depth = sf_structure[0], sf_structure[1]
  assert tree_shape == FXMSS_SHAPE_BALANCED
  assert 2 <= bds_k <= tree_depth
  assert (tree_depth - bds_k) % 2 == 0

  leaf_layer = FXMSS_HEIGHT - tree_depth
  ADRS = bytearray(22)

  # The authentication path of leaf zero.
  auth = [b''] * tree_depth
  for j in range(tree_depth):
    auth[j] = fxmss_node(sk_seed, 1, leaf_layer + j, pk_seed, sf_structure, ADRS)

  # One treehash instance per layer below the retained layers.
  treehash = [None] * (tree_depth - bds_k)
  for j in range(tree_depth - bds_k):
    treehash[j] = {
      'node': fxmss_node(sk_seed, 3, leaf_layer + j, pk_seed, sf_structure, ADRS),
      'next_leaf': None,
      'stack': [],
    }

  # Retain every future right node of the top bds_k - 1 layers below the root.
  retain = {}
  for j in range(tree_depth - bds_k, tree_depth - 1):
    for node_index in range(3, 2**(tree_depth - j), 2):
      retain[(node_index, j)] = fxmss_node(sk_seed, node_index, leaf_layer + j, pk_seed, sf_structure, ADRS)

  return {'state_ctr': 0, 'bds_k': bds_k, 'auth': auth, 'keep': {}, 'retain': retain, 'treehash': treehash}

def bds_auth_path(bds_state: dict) -> list[bytes]:
  """
  The BDS authentication path read function. Returns the Merkle authentication path of the
  WOTS+C leaf at index `state_ctr` of the BDS state, for use with `fxmss_sign_from_auth_path`.

  - Inputs:
    - `bds_state`: a BDS state from `bds_state_init`.
  - Output:
    - a list of `depth` 16-byte authentication path nodes, from the leaf's sibling upwards.

  This function is only used in the stateful path, and only by the signer.
  """
  return list(bds_state['auth'])

def bds_treehash_update(bds_state: dict, sk_seed: bytes, pk_seed: bytes, sf_structure: bytes) -> None:
  """
  The BDS treehash scheduling function. Performs a single treehash update: picks the active
  instance whose lowest stacked node sits on the lowest layer, consumes that instance's next
  leaf, and merges it up the stack. An instance completes once the merged node reaches its target layer.

  - Inputs:
    - `bds_state`: a BDS state from `bds_state_init`.
    - `sk_seed`: a 16-byte secret.
    - `pk_seed`: a 16-byte salt.
    - `sf_structure`: a 2-byte identifier describing the FXMSS tree structure.
  - Output:
    - none.

  This function is only used in the stateful path, and only by the signer.
  """
  tree_depth = sf_structure[1]
  leaf_layer = FXMSS_HEIGHT - tree_depth

  # Pick the instance to receive this update.
  best, best_low = None, None
  for j in range(len(bds_state['treehash'])):
    th = bds_state['treehash'][j]
    if th['next_leaf'] is None:
      continue # instance is completed, or was never started
    low = min((layer for (layer, _) in th['stack']), default=j)
    if best is None or low < best_low:
      best, best_low = j, low
  if best is None:
    return # no active instances remain

  # Consume the instance's next leaf and merge it up the stack.
  th = bds_state['treehash'][best]
  leaf_index = th['next_leaf']
  ADRS = bytearray(22)
  node = fxmss_node(sk_seed, leaf_index, leaf_layer, pk_seed, sf_structure, ADRS)
  node_layer = 0
  while th['stack'] and th['stack'][-1][0] == node_layer:
    (_, lchild) = th['stack'].pop()
    node_layer += 1
    ADRS[0] = leaf_layer + node_layer
    ADRS[1:9] = (leaf_index >> node_layer).to_bytes(8)
    ADRS[9] = SF_FXMSS_TREE
    ADRS[10:22] = zeros(12)
    node = H(pk_seed, ADRS, lchild + node)

  if node_layer == best:
    th['node'] = node
    th['next_leaf'] = None # instance completed
  else:
    th['stack'].append((node_layer, node))
    th['next_leaf'] = leaf_index + 1

def bds_state_update(bds_state: dict, sk_seed: bytes, pk_seed: bytes, sf_structure: bytes) -> None:
  """
  The BDS state update function. Advances the state by one leaf: computes the authentication
  path of the next leaf from the stored nodes, refreshes `keep` and restarts the consumed
  treehash instances.

  - Inputs:
    - `bds_state`: a BDS state from `bds_state_init`.
    - `sk_seed`: a 16-byte secret.
    - `pk_seed`: a 16-byte salt.
    - `sf_structure`: a 2-byte identifier describing the FXMSS tree structure.
  - Output:
    - none.

  This function is only used in the stateful path, and only by the signer.
  """
  tree_depth = sf_structure[1]
  leaf_layer = FXMSS_HEIGHT - tree_depth
  bds_k = bds_state['bds_k']
  s = bds_state['state_ctr']

  bds_state['state_ctr'] = s + 1
  if s + 1 >= 2**tree_depth:
    return # the stateful signing budget is exhausted; there is no next leaf

  # The layer of the first left-turn on the path from leaf s to the root: the
  # lowest layer whose authentication path node is about to change to a left
  # node. Equals the number of trailing one bits of s.
  tau = 0
  while (s >> tau) & 1 == 1:
    tau += 1

  # If the authentication node on layer tau sits below a left node, remember
  # it: it is the right child from which that left node will later be computed.
  if tau < tree_depth - 1 and (s >> (tau + 1)) & 1 == 0:
    bds_state['keep'][tau] = bds_state['auth'][tau]

  ADRS = bytearray(22)

  if tau == 0:
    # Leaf s is a left child: it becomes the bottom authentication node.
    bds_state['auth'][0] = fxmss_node(sk_seed, s, leaf_layer, pk_seed, sf_structure, ADRS)
  else:
    # The left node entering the path on layer tau is the parent of the old
    # authentication node below it and the node remembered in keep.
    lchild = bds_state['auth'][tau - 1]
    rchild = bds_state['keep'].pop(tau - 1)
    ADRS[0] = leaf_layer + tau
    ADRS[1:9] = (s >> tau).to_bytes(8)
    ADRS[9] = SF_FXMSS_TREE
    ADRS[10:22] = zeros(12)
    bds_state['auth'][tau] = H(pk_seed, ADRS, lchild + rchild)

    # Below tau, fresh right nodes enter the path: from the treehash instances
    # on the lower layers, and from retain on the top layers.
    for j in range(tau):
      if j < tree_depth - bds_k:
        th = bds_state['treehash'][j]
        assert th['next_leaf'] is None and th['node'] is not None
        bds_state['auth'][j] = th['node']
        th['node'] = None
      else:
        needed_index = ((s + 1) >> j) ^ 1
        bds_state['auth'][j] = bds_state['retain'].pop((needed_index, j))

    # Restart the consumed treehash instances on the next right node of their
    # layer, unless that node lies beyond the edge of the tree.
    for j in range(min(tau, tree_depth - bds_k)):
      if s + 1 + 3 * 2**j < 2**tree_depth:
        bds_state['treehash'][j]['next_leaf'] = s + 1 + 3 * 2**j

  # Distribute the round's budget of treehash updates.
  for _ in range((tree_depth - bds_k) // 2):
    bds_treehash_update(bds_state, sk_seed, pk_seed, sf_structure)
