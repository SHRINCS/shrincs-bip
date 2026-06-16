from math import ceil, floor
import hashlib

#  Helper functions

def repeat(b, n):
  return [b for _ in range(n)]

def concat(array):
  assert len(array) > 0
  acc = array[0]
  for items in array[1:]:
    acc += items
  return acc

def xor(s1, s2):
  """
  Returns the XOR of two arrays of integers which must have equal length.
  """
  assert len(s1) == len(s2)
  return bytes([b1 ^ b2 for (b1, b2) in zip(s1, s2)])

def base_2b(x, b, outlen):
  """
  Decomposes a byte string `x` into `outlen` groups of `b` bits which are each
  parsed as an integer in the range `[0, 2**b)`. The leading `outlen * b` bits
  of `x` are parsed, and so `x` must have accordingly sufficient length.
  """
  assert len(x) >= ceil(outlen * b / 8)

  baseb = [None] * outlen # output array
  j = 0                   # counts the bytes read from the input x.
  acc = 0                 # accumulator, collects bits from x
  bits_filled = 0         # counts the bits accumulated

  for i in range(outlen):
    while bits_filled < b:
      acc = (acc << 8) + x[j]
      j += 1
      bits_filled += 8

    bits_filled -= b
    baseb[i] = acc >> bits_filled
    acc %= 2**bits_filled # prevent accumulator from overflowing

  return baseb


#  Constants
WOTS_C_CHAIN_BITS    = 4
WOTS_TW_CHAIN_BITS   = 4
WOTS_C_CHAIN_COUNT   = 32
WOTS_TW_CHAIN_COUNT1 = 32
WOTS_TW_CHAIN_COUNT2 = 3
WOTS_TW_CHAIN_COUNT  = 35
WOTS_TW_CHECKSUM_MAX = 480
WOTS_C_CONSTANT_SUM  = 240
SPHX_LAYER_COUNT     = 5
SPHX_XMSS_HEIGHT    = 9
SPHX_FORS_HEIGHT     = 13
SPHX_FORS_COUNT      = 10
FXMSS_HEIGHT         = 255


#  ADRS type flags
SL_WOTS_TW_HASH = 0
SL_WOTS_TW_PK   = 1
SL_XMSS_TREE   = 2
SL_FORS_TREE    = 3
SL_FORS_ROOTS   = 4
SL_WOTS_TW_PRF  = 5
SL_FORS_PRF     = 6
SF_WOTS_C_HASH  = 16
SF_WOTS_C_PK    = 17
SF_FXMSS_TREE   = 18
SF_WOTS_C_PRF   = 21
SF_WOTS_C_GRIND = 22


#  Primitive cryptographic functions

def sha256(message):
  return list(hashlib.sha256(bytes(message)).digest())

def hmac_sha256(key, msg):
  padded_key = repeat(0, 64)
  padded_key[:len(key)] = key
  inner = sha256(xor(padded_key, [0x36] * 64) + msg)
  return sha256(xor(padded_key, [0x5C] * 64) + inner)


# Tweaked hash functions

def T_sl(pk_seed, ADRS, M_l):
  """
  Hashes an input `M_l`, which is a sequence of `WOTS_TW_CHAIN_COUNT` hashes, each 16 bytes long,
  concatenated together. This function will be used to compress Winternitz chain tips to a single
  hash in SPHINCS.
  """
  return sha256(pk_seed + repeat(0, 48) + ADRS + M_l)[:16]

def T_sf(pk_seed, ADRS, M_l):
  """
  Hashes an input `M_l`, which is a sequence of `WOTS_C_CHAIN_COUNT` hashes, each 16 bytes long,
  concatenated together. This function will be used to compress Winternitz chain tips to a single
  hash in FXMSS.
  """
  return sha256(pk_seed + repeat(0, 48) + ADRS + M_l)[:16]

def F(pk_seed, ADRS, M_1):
  """
  Hashes an input `M_1`, which is a single 16-byte hash. This function will be used to generate
  and iterate Winternitz hash chains and to hash FORS leaves.
  """
  return sha256(pk_seed + repeat(0, 48) + ADRS + M_1)[:16]

def H(pk_seed, ADRS, M_2):
  """
  Hashes an input `M_2`, which is a pair of 16-byte hashes, concatenated together. This function
  will be used to combine pairs of merkle nodes, to construct merkle trees in XMSS and FORS.
  """
  return sha256(pk_seed + repeat(0, 48) + ADRS + M_2)[:16]

def H_grind(pk_seed, position, digest, counter):
  """
  Hashes a 32-byte message `digest` and a grinding `counter`. This function will be used to
  map `digest` into a constant-sum message space for WOTS+C.
  """
  assert counter <= 0xFFFF
  return sha256(pk_seed + repeat(0, 48) + position + digest + repeat(0, 4) + counter.to_bytes(2))[:16]

def PRF(pk_seed, sk_seed, ADRS):
  """
  Hashes `sk_seed` with an `ADRS` to derive secret preimage values needed for signing and key
  generation.
  """
  return sha256(pk_seed + repeat(0, 48) + ADRS + sk_seed)[:16]

def H_msg_sl(R, pk_seed, root, M):
  """
  Hashes a _randomizer_ `R`, the `pk_seed`, a merkle root `root`, and an arbitrary-length message
  bytestring `M`. It will be used to produce a digest for signing in the stateless path.
  """
  return sha256(R + pk_seed + sha256(R + pk_seed + root + M) + repeat(0, 4))

def H_msg_sf(R, pk_seed, root, position, M):
  """
  Hashes a _randomizer_ `R`, the `pk_seed`, a merkle root `root`, and an arbitrary-length message
  bytestring `M`. It will be used to produce a digest for signing in the stateful path.
  """
  return sha256(R + pk_seed + position + sha256(R + pk_seed + root + position + M))

def PRF_msg(sk_prf, opt_rand, M):
  """
  Uses HMAC-SHA256 to hash `sk_prf`, randomness `opt_rand`, and an arbitrary-length message `M`.
  This function will be used to derive a _randomizer_ (salt) for the given message.
  """
  return hmac_sha256(key=sk_prf, msg=opt_rand + M)[:16]


#  Winternitz algorithms

def wots_chain_iter(node, start, steps, pk_seed, ADRS):
  """
  The WOTS hash chain iteration function. Takes in a 16-byte hash `node` at a given `start` index
  in a hash chain. This method iterates the hash chain by `steps` iterations, returning the hash
  chain node at index `start+steps`. The `ADRS` must be prefilled to ensure the hashes are properly
  tweaked.
  """
  for j in range(start, start+steps):
    ADRS[18:22] = j.to_bytes(4)
    node = F(pk_seed, ADRS, node)
  return node

def wots_tw_message_to_indexes(message):
  """
  The WOTS-TW message map function. Converts a 16-byte `message` to a checksummed array
  of `WOTS_TW_CHAIN_COUNT` WOTS hash chain indexes in the range `[0, 2**WOTS_TW_CHAIN_BITS)`.
  """
  msg_indexes = base_2b(message, WOTS_TW_CHAIN_BITS, WOTS_TW_CHAIN_COUNT1)
  checksum = WOTS_TW_CHECKSUM_MAX - sum(msg_indexes)

  checksum_indexes = [None] * WOTS_TW_CHAIN_COUNT2
  for i in range(WOTS_TW_CHAIN_COUNT2):
    checksum_indexes[WOTS_TW_CHAIN_COUNT2 - 1 - i] = checksum % (2**WOTS_TW_CHAIN_BITS)
    checksum >>= WOTS_TW_CHAIN_BITS

  return msg_indexes + checksum_indexes

def wots_tw_message_to_indexes_alt(message):
  """
  Alternative implementation, equivalent to `wots_tw_message_to_indexes` but using the
  more complex FIPS-205 algorithm.
  """
  SPHX_WOTS_CHECKSUM_SHIFT = (8 - (WOTS_TW_CHAIN_BITS * WOTS_TW_CHAIN_COUNT2) % 8) % 8
  SPHX_WOTS_CHECKSUM_BYTE_LEN = ceil(WOTS_TW_CHAIN_COUNT2 * WOTS_TW_CHAIN_BITS / 8)
  msg_indexes = base_2b(message, WOTS_TW_CHAIN_BITS, WOTS_TW_CHAIN_COUNT1)
  checksum = (WOTS_TW_CHECKSUM_MAX - sum(msg_indexes)) << SPHX_WOTS_CHECKSUM_SHIFT
  checksum_bytes = checksum.to_bytes(SPHX_WOTS_CHECKSUM_BYTE_LEN)
  checksum_indexes = base_2b(checksum_bytes, WOTS_TW_CHAIN_BITS, WOTS_TW_CHAIN_COUNT2)
  return msg_indexes + checksum_indexes

def wots_tw_pubkey_gen(sk_seed, pk_seed, ADRS):
  """
  The WOTS-TW public key generation function. Takes in the secret `sk_seed`, the `pk_seed`,
  and an `ADRS`. The `ADRS` should be prefilled with the location of the WOTS keypair being used.
  """
  wots_pk = [None] * WOTS_TW_CHAIN_COUNT
  for i in range(WOTS_TW_CHAIN_COUNT):
    ADRS[9] = SL_WOTS_TW_PRF
    ADRS[14:18] = i.to_bytes(4) # chain index
    ADRS[18:22] = repeat(0, 4) # zero hash index
    sk = PRF(pk_seed, sk_seed, ADRS)
    ADRS[9] = SL_WOTS_TW_HASH
    wots_pk[i] = wots_chain_iter(sk, 0, 2**WOTS_TW_CHAIN_BITS - 1, pk_seed, ADRS)

  ADRS[9] = SL_WOTS_TW_PK
  ADRS[14:22] = repeat(0, 8)
  wots_pk_hash = T_sl(pk_seed, ADRS, concat(wots_pk))
  return wots_pk_hash

def wots_tw_sign(message, sk_seed, pk_seed, ADRS):
  """
  The WOTS-TW signing function. Takes in a 16-byte `message`, the `sk_seed` and `pk_seed`,
  and an `ADRS`. The `ADRS` should be prefilled with the location of the WOTS keypair being used.
  """
  indexes = wots_tw_message_to_indexes(message)
  signature = [None] * WOTS_TW_CHAIN_COUNT
  for i in range(WOTS_TW_CHAIN_COUNT):
    ADRS[9] = SL_WOTS_TW_PRF
    ADRS[14:18] = i.to_bytes(4)  # chain index
    ADRS[18:22] = repeat(0, 4) # zero hash index
    sk = PRF(pk_seed, sk_seed, ADRS)
    ADRS[9] = SL_WOTS_TW_HASH
    signature[i] = wots_chain_iter(sk, 0, indexes[i], pk_seed, ADRS)
  return concat(signature)

def wots_tw_pubkey_from_sig(signature, message, pk_seed, ADRS):
  """
  The WOTS-TW verification procedure. Recovers a WOTS-TW public key from a `signature` on a given
  16-byte `message`. Takes in the `pk_seed`. The `ADRS` should be prefilled with the location of
  the WOTS keypair being used.
  """
  indexes = wots_tw_message_to_indexes(message)
  wots_pk = [None] * WOTS_TW_CHAIN_COUNT
  ADRS[9] = SL_WOTS_TW_HASH
  for i in range(WOTS_TW_CHAIN_COUNT):
    ADRS[14:18] = i.to_bytes(4)
    steps = 2**WOTS_TW_CHAIN_BITS - 1 - indexes[i]
    wots_pk[i] = wots_chain_iter(signature[i*16 : (i+1)*16], indexes[i], steps, pk_seed, ADRS)

  ADRS[9] = SL_WOTS_TW_PK
  ADRS[14:22] = repeat(0, 8)
  wots_pk_hash = T_sl(pk_seed, ADRS, concat(wots_pk))
  return wots_pk_hash

def wots_c_grind_to_constant_sum(pk_seed, message_digest, ADRS):
  """
  The WOTS+C grinding function. Takes in a `message_digest`, the `pk_seed`, and an `ADRS`, and
  grinds - up to a maximum of 2<sup>16</sup> attempts - until we find a counter that maps to a
  constant sum index-set. Returns the lowest valid integer counter and the corresponding array
  of constant-sum hash chain indexes. The `ADRS` should be prefilled with the location of the
  WOTS+C key which will be used to sign the resulting indexes.
  """
  ADRS[9] = SF_WOTS_C_GRIND
  for i in range(2**16):
    hashed = H_grind(pk_seed, ADRS[:10], message_digest, i)
    indexes = base_2b(hashed, WOTS_C_CHAIN_BITS, WOTS_C_CHAIN_COUNT)
    if sum(indexes) == WOTS_C_CONSTANT_SUM:
      return (i, indexes)

  return None # practically impossible

def wots_c_map_digest(pk_seed, message_digest, ADRS, counter):
  """
  The WOTS+C digest validation function. Takes in a `message_digest`, the `pk_seed`, an `ADRS`,
  and a `counter` parsed from a WOTS+C signature. This evaluates the grinding counter and attempts
  to map the digest to a constant sum set of hash chain indexes. If the `counter` is valid, this
  function returns the constant sum index-set. Otherwise, it returns null.
  """
  ADRS[9] = SF_WOTS_C_GRIND
  hashed = H_grind(pk_seed, ADRS[:10], message_digest, counter)
  indexes = base_2b(hashed, WOTS_C_CHAIN_BITS, WOTS_C_CHAIN_COUNT)
  if sum(indexes) == WOTS_C_CONSTANT_SUM:
    return indexes
  else:
    return None

def wots_c_pubkey_gen(sk_seed, pk_seed, ADRS):
  """
  The WOTS+C public key generation function. Takes in the secret `sk_seed`, the `pk_seed`, and an
  `ADRS`. The `ADRS` should be prefilled with the location of the WOTS keypair being used.
  """
  wots_pk = [None] * WOTS_C_CHAIN_COUNT
  ADRS[10:14] = repeat(0, 4) # zeros reserved
  for i in range(WOTS_C_CHAIN_COUNT):
    ADRS[9] = SF_WOTS_C_PRF
    ADRS[14:18] = i.to_bytes(4) # chain index
    ADRS[18:22] = repeat(0, 4) # zero hash index
    sk = PRF(pk_seed, sk_seed, ADRS)
    ADRS[9] = SF_WOTS_C_HASH
    wots_pk[i] = wots_chain_iter(sk, 0, 2**WOTS_C_CHAIN_BITS - 1, pk_seed, ADRS)

  ADRS[9] = SF_WOTS_C_PK
  ADRS[14:22] = repeat(0, 8)
  wots_pk_hash = T_sf(pk_seed, ADRS, concat(wots_pk))
  return wots_pk_hash

def wots_c_sign(message_digest, sk_seed, pk_seed, ADRS):
  """
  The WOTS+C signing function. Takes in a 32-byte `message_digest`, the `sk_seed` and `pk_seed`,
  and an `ADRS`. The `ADRS` should be prefilled with the location of the WOTS keypair being used.
  """
  counter, indexes = wots_c_grind_to_constant_sum(pk_seed, message_digest, ADRS)
  signature = [None] * WOTS_C_CHAIN_COUNT

  ADRS[10:14] = repeat(0, 4) # zeros reserved
  for i in range(WOTS_C_CHAIN_COUNT):
    ADRS[9] = SF_WOTS_C_PRF
    ADRS[14:18] = i.to_bytes(4)  # chain index
    ADRS[18:22] = repeat(0, 4) # zero hash index
    sk = PRF(pk_seed, sk_seed, ADRS)
    ADRS[9] = SF_WOTS_C_HASH
    signature[i] = wots_chain_iter(sk, 0, indexes[i], pk_seed, ADRS)
  return (concat(signature), counter)

def wots_c_pubkey_from_sig(signature, counter, message_digest, pk_seed, ADRS):
  """
  The WOTS+C verification procedure. Recovers a WOTS+C public key from a `signature` on a given
  32-byte `message_digest`. Takes in a grinding `counter`, the `pk_seed`, and an `ADRS`. The `ADRS`
  should be prefilled with the location of the WOTS keypair being used.
  """
  indexes = wots_c_map_digest(pk_seed, message_digest, ADRS, counter)

  # Reject if counter doesn't satisfy the constant-sum requirement.
  if indexes is None:
    return None

  wots_pk = [None] * WOTS_C_CHAIN_COUNT
  ADRS[9] = SF_WOTS_C_HASH
  ADRS[10:14] = repeat(0, 4) # zeros reserved
  for i in range(WOTS_C_CHAIN_COUNT):
    ADRS[14:18] = i.to_bytes(4)
    steps = 2**WOTS_C_CHAIN_BITS - 1 - indexes[i]
    wots_pk[i] = wots_chain_iter(signature[i*16 : (i+1)*16], indexes[i], steps, pk_seed, ADRS)

  ADRS[9] = SF_WOTS_C_PK
  ADRS[14:22] = repeat(0, 8)
  wots_pk_hash = T_sf(pk_seed, ADRS, concat(wots_pk))
  return wots_pk_hash

def xmss_node(sk_seed, node_index, node_height, pk_seed, ADRS):
  """
  The XMSS internal node computation helper function. This is a recursive function which takes
  in the `sk_seed`, a target `node_index`, a `node_height`, the `pk_seed`, and an `ADRS`.
  """
  if node_height == 0: # Bottom layer: return the WOTS-TW pubkey hash.
    ADRS[10:14] = node_index.to_bytes(4)
    return wots_tw_pubkey_gen(sk_seed, pk_seed, ADRS)

  # Recursively derive the left/right child nodes
  lchild_index = 2 * node_index
  lchild_height = node_height - 1
  lchild = xmss_node(sk_seed, lchild_index, lchild_height, pk_seed, ADRS)
  rchild = xmss_node(sk_seed, lchild_index + 1, lchild_height, pk_seed, ADRS)

  # Compute & return the parent node.
  ADRS[9] = SL_XMSS_TREE
  ADRS[10:14] = repeat(0, 4)
  ADRS[14:18] = node_height.to_bytes(4)
  ADRS[18:22] = node_index.to_bytes(4)
  return H(pk_seed, ADRS, lchild + rchild)

def xmss_sign(message, sk_seed, keypair_index, pk_seed, ADRS):
  """
  The XMSS signing procedure. This function produces a deterministic WOTS-TW signature using a
  specific leaf of a XMSS tree, and appends a merkle authentication path to form a XMSS
  signature. Takes in the `message` to sign, the `sk_seed`, the `keypair_index` to sign with,
  the `pk_seed`, and an `ADRS` which contains a pre-filled WOTS-TW keypair index.
  """
  # Sign the message with WOTS-TW
  ADRS[10:14] = keypair_index.to_bytes(4)
  sig = wots_tw_sign(message, sk_seed, pk_seed, ADRS)

  # Append the Merkle authentication path
  for j in range(SPHX_XMSS_HEIGHT):
    sibling_index = (keypair_index >> j) ^ 1
    sig += xmss_node(sk_seed, sibling_index, j, pk_seed, ADRS)

  return sig

def xmss_pubkey_from_sig(keypair_index, signature, message, pk_seed, ADRS):
  """
  The XMSS verification function. Recovers an XMSS public key from a `signature` on a given
  16-byte `message`. Takes in the `pk_seed`, and an `ADRS`. The exact position of the WOTS-TW
  signing leaf is given by the `keypair_index` argument.
  """
  wots_sig = signature[0 : WOTS_TW_CHAIN_COUNT*16]
  xmss_auth = signature[WOTS_TW_CHAIN_COUNT*16 : (WOTS_TW_CHAIN_COUNT+SPHX_XMSS_HEIGHT)*16]

  ADRS[10:14] = keypair_index.to_bytes(4) # AKA keypair address
  node = wots_tw_pubkey_from_sig(wots_sig, message, pk_seed, ADRS)

  ADRS[9] = SL_XMSS_TREE
  ADRS[10:14] = repeat(0, 4)

  for k in range(SPHX_XMSS_HEIGHT):
    ADRS[14:18] = k.to_bytes(4)
    ADRS[18:22] = (keypair_index >> (k+1)).to_bytes(4)
    sibling = xmss_auth[k*16 : (k+1)*16]
    if (keypair_index >> k) & 1 == 1:
      node = H(pk_seed, ADRS, sibling + node)
    else:
      node = H(pk_seed, ADRS, node + sibling)

  return node


def fxmss_node(sk_seed, node_index, node_height, pk_seed, structure, ADRS):
  ...

def fxmss_sign(message_digest, sk_seed, keypair_index, pk_seed, structure, ADRS):
  ...

def fxmss_pubkey_from_sig(node_index, signature, counter, message_digest, pk_seed, ADRS):
  """
  The FXMSS verification function. Recovers an FXMSS public key from a `signature` on a given
  32-byte `message_digest`. Takes in a grinding `counter`, the `pk_seed`, and an `ADRS`.

  The length of the `signature` implies the depth of the WOTS+C signing leaf. The exact
  left/right position of the WOTS+C signing leaf within its layer is given explicitly by the
  `node_index` argument.
  """
  wots_sig = signature[0 : WOTS_C_CHAIN_COUNT*16]
  xmss_auth = signature[WOTS_C_CHAIN_COUNT*16 : len(signature)]

  node_depth = floor(len(xmss_auth) / 16)

  # Ensure node_index describes a valid position in the FXMSS tree.
  assert node_index < 2 ** min(64, node_depth)

  node_height = FXMSS_HEIGHT - node_depth

  ADRS[0] = node_height
  ADRS[1:9] = node_index.to_bytes(8)
  node = wots_c_pubkey_from_sig(wots_sig, counter, message_digest, pk_seed, ADRS)
  if node is None:
    return None

  ADRS[9] = SF_FXMSS_TREE
  ADRS[10:22] = repeat(0, 12)

  for k in range(0, node_depth):
    ADRS[0] += 1
    ADRS[1:9] = (node_index >> (k+1)).to_bytes(8)
    sibling = xmss_auth[k*16 : (k+1)*16]
    if (node_index >> k) & 1 == 1:
      node = H(pk_seed, ADRS, sibling + node)
    else:
      node = H(pk_seed, ADRS, node + sibling)

  return node
