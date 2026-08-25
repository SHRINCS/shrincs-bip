# Cache Management for SHRINCS Signers

This document specifies three optional cache constructions for components of the SHRINCS signature. Caching is only a signer-side technique to speed-up the signature generation, it doesn't affect the verification functions.

| Signature Type | Cache | Cache Size | Signing Cost in SHA256 Compressions |
|-|-|-|-|
| Stateless | [Stateless Cache](#the-stateless-cache) | <!-- CONST START SL_LEAF_CACHE_SIZE -->8192<!-- CONST END SL_LEAF_CACHE_SIZE --> bytes | <!-- CONST START STATELESS_SIGN_CACHED_COMPRESSIONS -->1414132<!-- CONST END STATELESS_SIGN_CACHED_COMPRESSIONS --> |
| Stateful (UXMSS; depth 255) | [UXMSS Cache](#the-uxmss-cache) | <!-- CONST START UXMSS_255_CACHE_SIZE -->4096<!-- CONST END UXMSS_255_CACHE_SIZE --> bytes | <!-- CONST START UXMSS_255_SIGN_CACHED_COMPRESSIONS_AVG -->417<!-- CONST END UXMSS_255_SIGN_CACHED_COMPRESSIONS_AVG --> (average) |
| Stateful (BXMSS; depth 10) | [BXMSS Cache](#the-bxmss-cache); `bds_k = 2` | <!-- CONST START BXMSS_10_BDS_STATE_SIZE -->496<!-- CONST END BXMSS_10_BDS_STATE_SIZE --> bytes | <!-- CONST START BXMSS_10_BDS_SIGN_COMPRESSIONS -->2907<!-- CONST END BXMSS_10_BDS_SIGN_COMPRESSIONS --> (average) |
| Stateful (BXMSS; depth 20) | [BXMSS Cache](#the-bxmss-cache); `bds_k = 2` | <!-- CONST START BXMSS_20_BDS_STATE_SIZE -->1056<!-- CONST END BXMSS_20_BDS_STATE_SIZE --> bytes | <!-- CONST START BXMSS_20_BDS_SIGN_COMPRESSIONS -->5527<!-- CONST END BXMSS_20_BDS_SIGN_COMPRESSIONS --> (average) |

The pseudocode below is generated from the reference implementation by [`pydoc_insert.py`](../pydoc_insert.py), like the specification itself, so code and documentation cannot drift apart.

## The Stateless Cache

Every stateless signature contains a top-layer tree signature. A cold signer regenerates this tree for each stateless signature: `2**SPHX_XMSS_HEIGHT` WOTS-TW leaves.

The stateless cache stores the WOTS-TW public keys of the top-layer tree: `2**SPHX_XMSS_HEIGHT` hashes of 16 bytes each, or <!-- CONST START SL_LEAF_CACHE_SIZE -->8192<!-- CONST END SL_LEAF_CACHE_SIZE --> bytes in total. The cache is filled once by `xmss_leaf_cache_gen`.

To use the cache, the signer substitutes `xmss_sign_from_cache` for `xmss_sign` at the top layer of `hypertree_sign` (that is, when `j == SPHX_LAYER_COUNT - 1`). The internal Merkle nodes above the cached leaves are recomputed on demand by `xmss_node_from_cache`. This reduces the cost of signing the top layer from <!-- CONST START XMSS_SIGN_COMPRESSIONS -->291839<!-- CONST END XMSS_SIGN_COMPRESSIONS --> to at most <!-- CONST START STATELESS_XMSS_SIGN_CACHED_COMPRESSIONS -->1017<!-- CONST END STATELESS_XMSS_SIGN_CACHED_COMPRESSIONS --> compressions, and the total cost of a stateless signature from <!-- CONST START STATELESS_SIGN_COMPRESSIONS -->1704954<!-- CONST END STATELESS_SIGN_COMPRESSIONS --> to <!-- CONST START STATELESS_SIGN_CACHED_COMPRESSIONS -->1414132<!-- CONST END STATELESS_SIGN_CACHED_COMPRESSIONS --> compressions - a speedup of <!-- CONST START STATELESS_SIGN_CACHED_SPEED_RATIO -->1.21<!-- CONST END STATELESS_SIGN_CACHED_SPEED_RATIO -->x.

### `xmss_leaf_cache_gen(...)`

<!-- DOC START xmss_leaf_cache_gen -->
The XMSS cache generation function. Computes the WOTS-TW public keys of every leaf in the XMSS tree
at the location prefilled in `ADRS`, for reuse across signatures as a leaf cache.

- Inputs:
  - `sk_seed`: a 16-byte secret.
  - `pk_seed`: a 16-byte salt.
  - `ADRS`: a 22-byte address.
- Output:
  - a list of `2**SPHX_XMSS_HEIGHT` 16-byte WOTS-TW public key hashes, ordered by leaf index.

This function is only used in the stateless path, and only by the signer.

```py
def xmss_leaf_cache_gen(sk_seed: bytes, pk_seed: bytes, ADRS: bytearray) -> list[bytes]:
  leaf_cache = [b''] * 2**SPHX_XMSS_HEIGHT
  for leaf_index in range(2**SPHX_XMSS_HEIGHT):
    ADRS[10:14] = leaf_index.to_bytes(4)
    leaf_cache[leaf_index] = wots_tw_pubkey_gen(sk_seed, pk_seed, ADRS)
  return leaf_cache
```
<!-- DOC END xmss_leaf_cache_gen -->

### `xmss_node_from_cache(...)`

<!-- DOC START xmss_node_from_cache -->
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

```py
def xmss_node_from_cache(leaf_cache: list[bytes], node_index: int, node_height: int, pk_seed: bytes, ADRS: bytearray) -> bytes:
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
```
<!-- DOC END xmss_node_from_cache -->

### `xmss_sign_from_cache(...)`

<!-- DOC START xmss_sign_from_cache -->
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

```py
def xmss_sign_from_cache(message: bytes, sk_seed: bytes, leaf_cache: list[bytes], keypair_index: int, pk_seed: bytes, ADRS: bytearray) -> bytes:
  ADRS[10:14] = keypair_index.to_bytes(4)
  sig = wots_tw_sign(message, sk_seed, pk_seed, ADRS)

  # Append the Merkle authentication path.
  for j in range(SPHX_XMSS_HEIGHT):
    sibling_index = (keypair_index >> j) ^ 1
    sig += xmss_node_from_cache(leaf_cache, sibling_index, j, pk_seed, ADRS)

  return sig
```
<!-- DOC END xmss_sign_from_cache -->

## The UXMSS Cache

A UXMSS tree of depth `d` requires calculating `2*d + 1` nodes in total: one WOTS+C leaf per layer (an exception is the deepest layer), joined by the internal spine nodes. Every authentication path is included in this set: for the signing leaf at depth `k`, it is the leaf's sibling on the spine followed by the leaf public keys at depths `k - 1` through `1`.

The UXMSS cache stores the `d + 1` leaf public keys: <!-- CONST START UXMSS_255_CACHE_SIZE -->4096<!-- CONST END UXMSS_255_CACHE_SIZE --> bytes at the recommended maximum depth `d = FXMSS_HEIGHT`, or <!-- CONST START UXMSS_31_CACHE_SIZE -->512<!-- CONST END UXMSS_31_CACHE_SIZE --> bytes at depth 31. The cache is filled once by `uxmss_cache_gen`.

To sign, `uxmss_auth_path` computes the authentication path from the cache and `fxmss_sign_from_auth_path` assembles the signature. At depth 255 this costs between <!-- CONST START UXMSS_SIGN_CACHED_COMPRESSIONS_MIN -->291<!-- CONST END UXMSS_SIGN_CACHED_COMPRESSIONS_MIN --> and <!-- CONST START UXMSS_255_SIGN_CACHED_COMPRESSIONS_MAX -->545<!-- CONST END UXMSS_255_SIGN_CACHED_COMPRESSIONS_MAX --> SHA256 compressions per signature (<!-- CONST START UXMSS_255_SIGN_CACHED_COMPRESSIONS_AVG -->417<!-- CONST END UXMSS_255_SIGN_CACHED_COMPRESSIONS_AVG --> on average) instead of <!-- CONST START UXMSS_255_SIGN_COMPRESSIONS_AVG -->133146<!-- CONST END UXMSS_255_SIGN_COMPRESSIONS_AVG --> - roughly <!-- CONST START UXMSS_255_SIGN_CACHED_SPEED_RATIO -->319<!-- CONST END UXMSS_255_SIGN_CACHED_SPEED_RATIO -->x faster.

### `uxmss_cache_gen(...)`

<!-- DOC START uxmss_cache_gen -->
The UXMSS cache generation function. Computes the WOTS+C public keys of every leaf in a UXMSS tree.

- Inputs:
  - `sk_seed`: a 16-byte secret.
  - `pk_seed`: a 16-byte salt.
  - `sf_structure`: a 2-byte identifier describing the FXMSS tree structure.
- Output:
  - a dictionary mapping `(node_index, node_height)` positions to 16-byte WOTS+C public key hashes: `depth + 1` leaves in total.

This function is only used in the stateful path, and only by the signer.

```py
def uxmss_cache_gen(sk_seed: bytes, pk_seed: bytes, sf_structure: bytes) -> dict[tuple[int, int], bytes]:
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
```
<!-- DOC END uxmss_cache_gen -->

### `uxmss_auth_path(...)`

<!-- DOC START uxmss_auth_path -->
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

```py
def uxmss_auth_path(uxmss_cache: dict[tuple[int, int], bytes], leaf_index: int, leaf_height: int, pk_seed: bytes, sf_structure: bytes) -> list[bytes]:
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
```
<!-- DOC END uxmss_auth_path -->

### `fxmss_sign_from_auth_path(...)`

<!-- DOC START fxmss_sign_from_auth_path -->
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

```py
def fxmss_sign_from_auth_path(message_digest: bytes, sk_seed: bytes, leaf_index: int, leaf_height: int, pk_seed: bytes, sf_structure: bytes, auth_path: list[bytes]) -> Optional[bytes]:
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
```
<!-- DOC END fxmss_sign_from_auth_path -->

## The BXMSS Cache

A BXMSS tree of depth `d` has `2**d` WOTS+C leaves, so caching it in the full form costs `16 * 2**d` bytes - 16 MiB at depth 20 (while the naive signer instead regenerates most of the tree for every signature). Because BXMSS consumes leaves strictly left to right, computing successive authentication paths cheaply is the classic Merkle tree traversal problem, and we adopt its standard solution: the BDS algorithm[^bds], also used by XMSS implementations[^xmss].

BDS rests on three observations. 
1. Authentication paths overlap: moving to the next leaf, only the nodes up to the path's first left-turn change. 
2. Every left node entering a path is the parent of two nodes the signer held shortly before: the BDS state remembers the required right child in `keep`, so each left node costs a single call to `H`. 
3. Every right node entering a path can be built gradually in advance: a treehash instance per layer assembles the next right node of that layer a few leaves at a time, while the right nodes of the top `bds_k - 1` layers are computed once at key generation and held in `retain` forever.

Per signature, the signer then computes at most `(d - bds_k)/2 + 1` WOTS+C leaves and about `3 * (d - bds_k)/2` compression calls, while storing at most `3*d + d/2 - 3*bds_k - 2 + 2**bds_k` nodes of 16 bytes each. The parameter `bds_k` trades memory for time: it must satisfy `2 <= bds_k <= d` with `d - bds_k` even, and each increment of 2 removes one leaf computation per signature while roughly quadrupling the retained nodes.

| Stateful Structure | `bds_k` | BDS State Size | Signing Cost with BDS (avg) | Naive Signing Cost (avg) |
|-|-|-|-|-|
| BXMSS; depth 5 | 3 | <!-- CONST START BXMSS_5_BDS_STATE_SIZE -->224<!-- CONST END BXMSS_5_BDS_STATE_SIZE --> bytes | <!-- CONST START BXMSS_5_BDS_SIGN_COMPRESSIONS -->1335<!-- CONST END BXMSS_5_BDS_SIGN_COMPRESSIONS --> | <!-- CONST START BXMSS_5_SIGN_COMPRESSIONS -->16468<!-- CONST END BXMSS_5_SIGN_COMPRESSIONS --> |
| BXMSS; depth 8 | 2 | <!-- CONST START BXMSS_8_BDS_STATE_SIZE -->384<!-- CONST END BXMSS_8_BDS_STATE_SIZE --> bytes | <!-- CONST START BXMSS_8_BDS_SIGN_COMPRESSIONS -->2383<!-- CONST END BXMSS_8_BDS_SIGN_COMPRESSIONS --> | <!-- CONST START BXMSS_8_SIGN_COMPRESSIONS -->133393<!-- CONST END BXMSS_8_SIGN_COMPRESSIONS --> |
| BXMSS; depth 10 | 2 | <!-- CONST START BXMSS_10_BDS_STATE_SIZE -->496<!-- CONST END BXMSS_10_BDS_STATE_SIZE --> bytes | <!-- CONST START BXMSS_10_BDS_SIGN_COMPRESSIONS -->2907<!-- CONST END BXMSS_10_BDS_SIGN_COMPRESSIONS --> | <!-- CONST START BXMSS_10_SIGN_COMPRESSIONS -->534287<!-- CONST END BXMSS_10_SIGN_COMPRESSIONS --> |
| BXMSS; depth 12 | 2 | <!-- CONST START BXMSS_12_BDS_STATE_SIZE -->608<!-- CONST END BXMSS_12_BDS_STATE_SIZE --> bytes | <!-- CONST START BXMSS_12_BDS_SIGN_COMPRESSIONS -->3431<!-- CONST END BXMSS_12_BDS_SIGN_COMPRESSIONS --> | <!-- CONST START BXMSS_12_SIGN_COMPRESSIONS -->2137869<!-- CONST END BXMSS_12_SIGN_COMPRESSIONS --> |
| BXMSS; depth 16 | 2 | <!-- CONST START BXMSS_16_BDS_STATE_SIZE -->832<!-- CONST END BXMSS_16_BDS_STATE_SIZE --> bytes | <!-- CONST START BXMSS_16_BDS_SIGN_COMPRESSIONS -->4479<!-- CONST END BXMSS_16_BDS_SIGN_COMPRESSIONS --> | <!-- CONST START BXMSS_16_SIGN_COMPRESSIONS -->34209545<!-- CONST END BXMSS_16_SIGN_COMPRESSIONS --> |
| BXMSS; depth 20 | 2 | <!-- CONST START BXMSS_20_BDS_STATE_SIZE -->1056<!-- CONST END BXMSS_20_BDS_STATE_SIZE --> bytes | <!-- CONST START BXMSS_20_BDS_SIGN_COMPRESSIONS -->5527<!-- CONST END BXMSS_20_BDS_SIGN_COMPRESSIONS --> | <!-- CONST START BXMSS_20_SIGN_COMPRESSIONS -->547356421<!-- CONST END BXMSS_20_SIGN_COMPRESSIONS --> |

At depth 20, one kilobyte of BDS state makes stateful signing roughly <!-- CONST START BXMSS_20_BDS_SIGN_SPEED_RATIO -->99033<!-- CONST END BXMSS_20_BDS_SIGN_SPEED_RATIO -->x faster.

The signer builds the initial state with `bds_state_init`, reads the current authentication path with `bds_auth_path`, generates the signature with `fxmss_sign_from_auth_path`, and then advances the state with `bds_state_update`. The update must run exactly once per stateful signature: the state's `state_ctr` field mirrors the keypair's state counter, and the two must always agree, as discussed in [On Managing Caches](../SHRINCS.md#on-managing-caches).

### `bds_state_init(...)`

<!-- DOC START bds_state_init -->
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

```py
def bds_state_init(sk_seed: bytes, pk_seed: bytes, sf_structure: bytes, bds_k: int) -> dict:
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
```
<!-- DOC END bds_state_init -->

### `bds_auth_path(...)`

<!-- DOC START bds_auth_path -->
The BDS authentication path read function. Returns the Merkle authentication path of the
WOTS+C leaf at index `state_ctr` of the BDS state, for use with `fxmss_sign_from_auth_path`.

- Inputs:
  - `bds_state`: a BDS state from `bds_state_init`.
- Output:
  - a list of `depth` 16-byte authentication path nodes, from the leaf's sibling upwards.

This function is only used in the stateful path, and only by the signer.

```py
def bds_auth_path(bds_state: dict) -> list[bytes]:
  return list(bds_state['auth'])
```
<!-- DOC END bds_auth_path -->

### `bds_treehash_update(...)`

<!-- DOC START bds_treehash_update -->
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

```py
def bds_treehash_update(bds_state: dict, sk_seed: bytes, pk_seed: bytes, sf_structure: bytes) -> None:
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
```
<!-- DOC END bds_treehash_update -->

### `bds_state_update(...)`

<!-- DOC START bds_state_update -->
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

```py
def bds_state_update(bds_state: dict, sk_seed: bytes, pk_seed: bytes, sf_structure: bytes) -> None:
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
```
<!-- DOC END bds_state_update -->

## References

[^bds]: https://doi.org/10.1007/978-3-540-88403-3_5 - "Merkle Tree Traversal Revisited" by Buchmann, Dahmen, and Schneider.
[^xmss]: https://www.rfc-editor.org/rfc/rfc8391.html
