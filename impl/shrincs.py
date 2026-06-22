from math import ceil, floor
import hashlib
from typing import Optional

#  Helper functions

def repeat(b: int, n: int) -> bytes:
  return bytes((b for _ in range(n)))

def zeros(n: int) -> bytes:
  return repeat(0, n)

def concat(array: list[bytes]) -> bytes:
  return b''.join(array)

def xor(s1: bytes, s2: bytes) -> bytes:
  """
  Returns the XOR of two arrays of bytes which must have equal length.
  """
  assert len(s1) == len(s2)
  return bytes((b1 ^ b2 for (b1, b2) in zip(s1, s2)))

def base_2b(x: bytes, b: int, outlen: int) -> list[int]:
  """
  Decomposes a byte string `x` into `outlen` groups of `b` bits which are each
  parsed as an integer in the range `[0, 2**b)`. The leading `outlen * b` bits
  of `x` are parsed, and so `x` must have accordingly sufficient length.
  """
  assert len(x) >= ceil(outlen * b / 8)

  baseb = [0] * outlen # output array
  j = 0                # counts the bytes read from the input x.
  acc = 0              # accumulator, collects bits from x
  bits_filled = 0      # counts the bits accumulated

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
SPHX_XMSS_HEIGHT     = 9
SPHX_FORS_HEIGHT     = 13
SPHX_FORS_COUNT      = 10
FXMSS_HEIGHT         = 255

#  FXMSS structure types
FXMSS_SHAPE_UNBALANCED = 0
FXMSS_SHAPE_BALANCED   = 1

#  ADRS type flags
SL_WOTS_TW_HASH = 0
SL_WOTS_TW_PK   = 1
SL_XMSS_TREE    = 2
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

def sha256(message: bytes) -> bytes:
  return hashlib.sha256(bytes(message)).digest()

def hmac_sha256(key: bytes, msg: bytes) -> bytes:
  assert len(key) <= 64
  padded_key = key + zeros(64 - len(key))
  inner = sha256(xor(padded_key, repeat(0x36, 64)) + msg)
  return sha256(xor(padded_key, repeat(0x5C, 64)) + inner)


# Tweaked hash functions

def T_sl(pk_seed: bytes, ADRS: bytearray, M_l: bytes) -> bytes:
  """
  Hashes an input `M_l`, which is a sequence of `WOTS_TW_CHAIN_COUNT` hashes, each 16 bytes long,
  concatenated together. This function will be used to compress Winternitz chain tips to a single
  hash in SPHINCS.

  - Inputs:
    - `pk_seed`: a 16-byte salt.
    - `ADRS`: a 22-byte address.
    - `M_l`: an array of `WOTS_TW_CHAIN_COUNT * 16` bytes.
  - Output:
    - A 16-byte hash.

  This function is only used in the stateless path.
  """
  return sha256(pk_seed + zeros(48) + ADRS + M_l)[:16]

def T_sf(pk_seed: bytes, ADRS: bytearray, M_l: bytes) -> bytes:
  """
  Hashes an input `M_l`, which is a sequence of `WOTS_C_CHAIN_COUNT` hashes, each 16 bytes long,
  concatenated together. This function will be used to compress Winternitz chain tips to a single
  hash in FXMSS.

  - Inputs:
    - `pk_seed`: a 16-byte salt.
    - `ADRS`: a 22-byte address.
    - `M_l`: an array of `WOTS_C_CHAIN_COUNT * 16` bytes.
  - Output:
    - A 16-byte hash.

  This function is only used in the stateful path.
  """
  return sha256(pk_seed + zeros(48) + ADRS + M_l)[:16]

def F(pk_seed: bytes, ADRS: bytearray, M_1: bytes) -> bytes:
  """
  Hashes an input `M_1`, which is a single 16-byte hash. This function will be used to generate
  and iterate Winternitz hash chains and to hash FORS leaves.

  - Inputs:
    - `pk_seed`: a 16-byte salt.
    - `ADRS`: a 22-byte address.
    - `M_1`: a 16-byte hash.
  - Output:
    - A 16-byte hash.

  This function is used in both stateful and stateless paths.
  """
  return sha256(pk_seed + zeros(48) + ADRS + M_1)[:16]

def H(pk_seed: bytes, ADRS: bytearray, M_2: bytes) -> bytes:
  """
  Hashes an input `M_2`, which is a pair of 16-byte hashes, concatenated together. This function
  will be used to combine pairs of merkle nodes, to construct merkle trees in XMSS and FORS.

  - Inputs:
    - `pk_seed`: a 16-byte salt.
    - `ADRS`: a 22-byte address.
    - `M_2`: an array of 32 bytes.
  - Output:
    - A 16-byte hash.

  This function is used in both stateful and stateless paths.
  """
  return sha256(pk_seed + zeros(48) + ADRS + M_2)[:16]

def H_grind(pk_seed: bytes, ADRS: bytearray, digest: bytes, counter: int) -> bytes:
  """
  Hashes a 32-byte message `digest` and a grinding `counter`. This function will be used to
  map `digest` into a constant-sum message space for WOTS+C. Also takes in `pk_seed` and
  a WOTS+C leaf `ADRS`.


  - Inputs:
    - `pk_seed`: a 16-byte salt.
    - `ADRS`: a 22-byte address.
    - `digest`: an array of 32 bytes.
    - `counter`: a 16-bit unsigned integer.
  - Output:
    - A 16-byte hash.

  This function is only used in the stateful path.
  """
  assert counter <= 0xFFFF
  return sha256(pk_seed + zeros(48) + ADRS[:10] + digest + zeros(4) + counter.to_bytes(2))[:16]

def PRF(pk_seed: bytes, sk_seed: bytes, ADRS: bytearray) -> bytes:
  """
  Hashes `sk_seed` with an `ADRS` to derive secret preimage values needed for signing and key
  generation.

  - Inputs:
    - `pk_seed`: a 16-byte salt.
    - `sk_seed`: a 16-byte secret.
    - `ADRS`: a 22-byte address.
  - Output:
    - A 16-byte hash.

  This function is used in both stateful and stateless paths, but only by the signing algorithm.
  """
  return sha256(pk_seed + zeros(48) + ADRS + sk_seed)[:16]

def H_msg_sl(R: bytes, pk_seed: bytes, root: bytes, M: bytes) -> bytes:
  """
  Hashes a _randomizer_ `R`, the `pk_seed`, a merkle root `root`, and an arbitrary-length message
  bytestring `M`. It will be used to produce a digest for signing in the stateless path.

  - Inputs:
    - `R`: a 16-byte randomizer.
    - `pk_seed`: a 16-byte salt.
    - `root`: a 16-byte hash.
    - `M`: an arbitrary-length bytestring (TODO).
  - Output:
    - A 32-byte hash.

  This function is only used in the stateless path.

  Note that `pk_seed` is not padded in this tweaked hash function.
  """
  return sha256(R + pk_seed + sha256(R + pk_seed + root + M) + zeros(4))

def H_msg_sf(R: bytes, pk_seed: bytes, root: bytes, ADRS: bytearray, M: bytes) -> bytes:
  """
  Hashes a _randomizer_ `R`, the `pk_seed`, a WOTS+C leaf `ADRS`, a merkle root `root`,
  and an arbitrary-length message bytestring `M`. It will be used to produce a digest for
  signing in the stateful path.

  TODO: can `position` be used only once?

  - Inputs:
    - `R`: a 16-byte randomizer.
    - `pk_seed`: a 16-byte salt.
    - `root`: a 16-byte hash.
    - `ADRS`: a 22-byte address.
    - `M`: an arbitrary-length bytestring (TODO).
  - Output:
    - A 32-byte hash.

  This function is only used in the stateful path.

  Note that `pk_seed` is not padded in this tweaked hash function.
  """
  return sha256(R + pk_seed + ADRS[:9] + sha256(R + pk_seed + root + ADRS[:9] + M))

def PRF_msg(sk_prf: bytes, opt_rand: bytes, M: bytes) -> bytes:
  """
  Uses HMAC-SHA256 to hash `sk_prf`, randomness `opt_rand`, and an arbitrary-length message `M`.
  This function will be used to derive a _randomizer_ (salt) for the given message.

  - Inputs:
    - `sk_prf`: a 16-byte secret.
    - `opt_rand`: a 16-byte salt.
    - `M`: an arbitrary-length bytestring (TODO).
  - Output:
    - A 16-byte hash.

  This function is used in both stateful and stateless paths, but only by the signing algorithm.

  In the stateless path, `opt_rand` is set to either `pk_seed` (giving the "deterministic variant"
  of SLH-DSA[^slhdsa]), or a 16-byte salt sampled from a secure RNG (the "hedged variant" of SLH-DSA,
  resistant to side-channel attacks).

  In the stateful path, `opt_rand` is set to `ADRS[0:9] + zeros(7)`.
  """
  return hmac_sha256(key=sk_prf, msg=opt_rand + M)[:16]


#  Winternitz algorithms

def wots_chain_iter(node: bytes, start: int, steps: int, pk_seed: bytes, ADRS: bytearray) -> bytes:
  """
  The WOTS hash chain iteration function. Takes in a 16-byte hash `node` at a given `start` index
  in a hash chain. This method iterates the hash chain by `steps` iterations, returning the hash
  chain node at index `start+steps`. The `ADRS` must be prefilled to ensure the hashes are properly
  tweaked.

  - Inputs:
    - `node`: a 16-byte hash.
    - `start`: an unsigned integer indicating the index of `node` in the hash chain.
    - `steps`: an unsigned integer indicating how many steps to take up the hash chain.
    - `pk_seed`: a 16-byte salt.
    - `ADRS`: a 22-byte address.
  - Output:
    - A 16-byte hash at index `start + steps`.

  This function is used very heavily by both stateful and stateless paths and is the core target
  for optimization and parallelization.
  """
  for j in range(start, start+steps):
    ADRS[18:22] = j.to_bytes(4)
    node = F(pk_seed, ADRS, node)
  return node

def wots_tw_message_to_indexes(message: bytes) -> list[int]:
  """
  The WOTS-TW message map function. Converts a 16-byte `message` to a checksummed array
  of `WOTS_TW_CHAIN_COUNT` WOTS hash chain indexes in the range `[0, 2**WOTS_TW_CHAIN_BITS)`.

  - Inputs:
    - `message`: a 16-byte hash
  - Output:
    - An checksummed array of `WOTS_TW_CHAIN_BITS`-bit integers of length `WOTS_TW_CHAIN_COUNT`.
  """
  msg_indexes = base_2b(message, WOTS_TW_CHAIN_BITS, WOTS_TW_CHAIN_COUNT1)
  checksum = WOTS_TW_CHECKSUM_MAX - sum(msg_indexes)

  checksum_indexes = [0] * WOTS_TW_CHAIN_COUNT2
  for i in range(WOTS_TW_CHAIN_COUNT2):
    checksum_indexes[WOTS_TW_CHAIN_COUNT2 - 1 - i] = checksum % (2**WOTS_TW_CHAIN_BITS)
    checksum >>= WOTS_TW_CHAIN_BITS

  return msg_indexes + checksum_indexes

def wots_tw_message_to_indexes_alt(message: bytes) -> list[int]:
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

def wots_tw_pubkey_gen(sk_seed: bytes, pk_seed: bytes, ADRS: bytearray) -> bytes:
  """
  The WOTS-TW public key generation function. Takes in the secret `sk_seed`, the `pk_seed`,
  and an `ADRS`. The `ADRS` should be prefilled with the location of the WOTS keypair being used.

  - Inputs:
    - `sk_seed`: a 16-byte secret.
    - `pk_seed`: a 16-byte salt.
    - `ADRS`: a 22-byte address.
  - Output:
    - A 16-byte hash representing the WOTS-TW public key.

  This algorithm is used only by the signer.
  """
  wots_pk = [b''] * WOTS_TW_CHAIN_COUNT
  for i in range(WOTS_TW_CHAIN_COUNT):
    ADRS[9] = SL_WOTS_TW_PRF
    ADRS[14:18] = i.to_bytes(4) # chain index
    ADRS[18:22] = zeros(4) # zero hash index
    sk = PRF(pk_seed, sk_seed, ADRS)
    ADRS[9] = SL_WOTS_TW_HASH
    wots_pk[i] = wots_chain_iter(sk, 0, 2**WOTS_TW_CHAIN_BITS - 1, pk_seed, ADRS)

  ADRS[9] = SL_WOTS_TW_PK
  ADRS[14:22] = zeros(8)
  wots_pk_hash = T_sl(pk_seed, ADRS, concat(wots_pk))
  return wots_pk_hash

def wots_tw_sign(message: bytes, sk_seed: bytes, pk_seed: bytes, ADRS: bytearray) -> bytes:
  """
  The WOTS-TW signing function. Takes in a 16-byte `message`, the `sk_seed` and `pk_seed`,
  and an `ADRS`. The `ADRS` should be prefilled with the location of the WOTS keypair being used.

  - Inputs:
    - `message`: a 16-byte message to sign.
    - `sk_seed`: a 16-byte secret.
    - `pk_seed`: a 16-byte salt.
    - `ADRS`: a 22-byte address.
  - Output:
    - A WOTS signature composed of `WOTS_TW_CHAIN_COUNT * 16` bytes.

  This algorithm is used only by the signer.
  """
  indexes = wots_tw_message_to_indexes(message)
  signature = [b''] * WOTS_TW_CHAIN_COUNT
  for i in range(WOTS_TW_CHAIN_COUNT):
    ADRS[9] = SL_WOTS_TW_PRF
    ADRS[14:18] = i.to_bytes(4)  # chain index
    ADRS[18:22] = zeros(4) # zero hash index
    sk = PRF(pk_seed, sk_seed, ADRS)
    ADRS[9] = SL_WOTS_TW_HASH
    signature[i] = wots_chain_iter(sk, 0, indexes[i], pk_seed, ADRS)
  return concat(signature)

def wots_tw_pubkey_from_sig(signature: bytes, message: bytes, pk_seed: bytes, ADRS: bytearray) -> bytes:
  """
  The WOTS-TW verification procedure. Recovers a WOTS-TW public key from a `signature` on a given
  16-byte `message`. Takes in the `pk_seed`. The `ADRS` should be prefilled with the location of
  the WOTS keypair being used.

  - Inputs:
    - `signature`: a string of `WOTS_TW_CHAIN_COUNT * 16` bytes.
    - `message`: a 16-byte message.
    - `pk_seed`: a 16-byte salt.
    - `ADRS`: a 22-byte address.
  - Output:
    - A 16-byte hash representing the WOTS-TW public key.

  This algorithm is used by both signers and verifiers.
  """
  indexes = wots_tw_message_to_indexes(message)
  wots_pk = [b''] * WOTS_TW_CHAIN_COUNT
  ADRS[9] = SL_WOTS_TW_HASH
  for i in range(WOTS_TW_CHAIN_COUNT):
    ADRS[14:18] = i.to_bytes(4)
    steps = 2**WOTS_TW_CHAIN_BITS - 1 - indexes[i]
    wots_pk[i] = wots_chain_iter(signature[i*16 : (i+1)*16], indexes[i], steps, pk_seed, ADRS)

  ADRS[9] = SL_WOTS_TW_PK
  ADRS[14:22] = zeros(8)
  wots_pk_hash = T_sl(pk_seed, ADRS, concat(wots_pk))
  return wots_pk_hash

def wots_c_grind_to_constant_sum(pk_seed: bytes, message_digest: bytes, ADRS: bytearray) -> tuple[int, list[int]]:
  """
  The WOTS+C grinding function. Takes in a `message_digest`, the `pk_seed`, and an `ADRS`, and
  grinds - up to a maximum of 2<sup>16</sup> attempts - until we find a counter that maps to a
  constant sum index-set. Returns the lowest valid integer counter and the corresponding array
  of constant-sum hash chain indexes. The `ADRS` should be prefilled with the location of the
  WOTS+C key which will be used to sign the resulting indexes.

  - Inputs:
    - `pk_seed`: a 16-byte salt.
    - `message_digest`: a 32-byte intermediate message digest (from `H_msg_sf`).
    - `ADRS`: a 22-byte address.
  - Outputs:
    - The smallest possible valid counter.
    - The corresponding constant-sum set of hash chain indexes.

  This algorithm is used only by the signer.
  """
  ADRS[9] = SF_WOTS_C_GRIND
  for i in range(2**16):
    hashed = H_grind(pk_seed, ADRS, message_digest, i)
    indexes = base_2b(hashed, WOTS_C_CHAIN_BITS, WOTS_C_CHAIN_COUNT)
    if sum(indexes) == WOTS_C_CONSTANT_SUM:
      return (i, indexes)

  raise RuntimeError("Unreachable") # practically impossible

def wots_c_map_digest(pk_seed: bytes, message_digest: bytes, ADRS: bytearray, counter: int) -> Optional[list[int]]:
  """
  The WOTS+C digest validation function. Takes in a `message_digest`, the `pk_seed`, an `ADRS`,
  and a `counter` parsed from a WOTS+C signature. This evaluates the grinding counter and attempts
  to map the digest to a constant sum set of hash chain indexes. If the `counter` is valid, this
  function returns the constant sum index-set. Otherwise, it returns null.

  - Inputs:
    - `pk_seed`: a 16-byte salt.
    - `message_digest`: a 32-byte intermediate message digest (from `H_msg_sf`).
    - `ADRS`: a 22-byte address.
    - `counter`: an unsigned integer.
  - Output:
    - A constant-sum set of hash chain indexes, or null.

  This algorithm is used only by the verifier.
  """
  ADRS[9] = SF_WOTS_C_GRIND
  hashed = H_grind(pk_seed, ADRS, message_digest, counter)
  indexes = base_2b(hashed, WOTS_C_CHAIN_BITS, WOTS_C_CHAIN_COUNT)
  if sum(indexes) == WOTS_C_CONSTANT_SUM:
    return indexes
  else:
    return None

def wots_c_pubkey_gen(sk_seed: bytes, pk_seed: bytes, ADRS: bytearray) -> bytes:
  """
  The WOTS+C public key generation function. Takes in the secret `sk_seed`, the `pk_seed`, and an
  `ADRS`. The `ADRS` should be prefilled with the location of the WOTS keypair being used.

  - Inputs:
    - `sk_seed`: a 16-byte secret.
    - `pk_seed`: a 16-byte salt.
    - `ADRS`: a 22-byte address.
  - Output:
    - A 16-byte hash representing the WOTS+C public key.

  This algorithm is used only by the signer.
  """
  wots_pk = [b''] * WOTS_C_CHAIN_COUNT
  ADRS[10:14] = zeros(4) # zeros reserved
  for i in range(WOTS_C_CHAIN_COUNT):
    ADRS[9] = SF_WOTS_C_PRF
    ADRS[14:18] = i.to_bytes(4) # chain index
    ADRS[18:22] = zeros(4) # zero hash index
    sk = PRF(pk_seed, sk_seed, ADRS)
    ADRS[9] = SF_WOTS_C_HASH
    wots_pk[i] = wots_chain_iter(sk, 0, 2**WOTS_C_CHAIN_BITS - 1, pk_seed, ADRS)

  ADRS[9] = SF_WOTS_C_PK
  ADRS[14:22] = zeros(8)
  wots_pk_hash = T_sf(pk_seed, ADRS, concat(wots_pk))
  return wots_pk_hash

def wots_c_sign(message_digest: bytes, sk_seed: bytes, pk_seed: bytes, ADRS: bytearray) -> bytes:
  """
  The WOTS+C signing function. Takes in a 32-byte `message_digest`, the `sk_seed` and `pk_seed`,
  and an `ADRS`. The `ADRS` should be prefilled with the location of the WOTS keypair being used.

  - Inputs:
    - `message_digest`: a 32-byte message digest to sign.
    - `sk_seed`: a 16-byte secret.
    - `pk_seed`: a 16-byte salt.
    - `ADRS`: a 22-byte address.
  - Outputs:
    - A WOTS signature composed of `2 + WOTS_C_CHAIN_COUNT * 16` bytes.

  This algorithm is used only by the signer.
  """
  counter, indexes = wots_c_grind_to_constant_sum(pk_seed, message_digest, ADRS)
  signature = [b''] * WOTS_C_CHAIN_COUNT

  ADRS[10:14] = zeros(4) # zeros reserved
  for i in range(WOTS_C_CHAIN_COUNT):
    ADRS[9] = SF_WOTS_C_PRF
    ADRS[14:18] = i.to_bytes(4)  # chain index
    ADRS[18:22] = zeros(4) # zero hash index
    sk = PRF(pk_seed, sk_seed, ADRS)
    ADRS[9] = SF_WOTS_C_HASH
    signature[i] = wots_chain_iter(sk, 0, indexes[i], pk_seed, ADRS)
  return counter.to_bytes(2) + concat(signature)

def wots_c_pubkey_from_sig(signature: bytes, message_digest: bytes, pk_seed: bytes, ADRS: bytearray) -> Optional[bytes]:
  """
  The WOTS+C verification procedure. Recovers a WOTS+C public key from a `signature` on a given
  32-byte `message_digest`. Takes in the `pk_seed`, and an `ADRS`. The `ADRS`
  should be prefilled with the location of the WOTS keypair being used.

  - Inputs:
    - `signature`: a string of `2 + WOTS_C_CHAIN_COUNT * 16` bytes.
    - `message_digest`: a 32-byte message digest.
    - `pk_seed`: a 16-byte salt.
    - `ADRS`: a 22-byte address.
  - Output:
    - A 16-byte hash representing the WOTS+C public key, or null.

  This algorithm is used by both signers and verifiers.
  """
  counter = int.from_bytes(signature[0:2])
  indexes = wots_c_map_digest(pk_seed, message_digest, ADRS, counter)

  # Reject if counter doesn't satisfy the constant-sum requirement.
  if indexes is None:
    return None

  wots_pk = [b''] * WOTS_C_CHAIN_COUNT
  ADRS[9] = SF_WOTS_C_HASH
  ADRS[10:14] = zeros(4) # zeros reserved
  for i in range(WOTS_C_CHAIN_COUNT):
    ADRS[14:18] = i.to_bytes(4)
    steps = 2**WOTS_C_CHAIN_BITS - 1 - indexes[i]
    wots_pk[i] = wots_chain_iter(signature[2+i*16 : 2+(i+1)*16], indexes[i], steps, pk_seed, ADRS)

  ADRS[9] = SF_WOTS_C_PK
  ADRS[14:22] = zeros(8)
  wots_pk_hash = T_sf(pk_seed, ADRS, concat(wots_pk))
  return wots_pk_hash


#  XMSS algorithms

def xmss_node(sk_seed: bytes, node_index: int, node_height: int, pk_seed: bytes, ADRS: bytearray) -> bytes:
  """
  The XMSS internal node computation helper function. This is a recursive function which takes
  in the `sk_seed`, a target `node_index`, a `node_height`, the `pk_seed`, and an `ADRS`.

  - Inputs:
    - `sk_seed`: a 16-byte secret.
    - `node_index`: An unsigned integer indicating the index (from the left) of the desired node in the XMSS layer.
    - `node_height`: An unsigned integer indicating the height (from the bottom) of the desired node in the XMSS layer.
    - `pk_seed`: a 16-byte salt.
    - `ADRS`: a 22-byte address.
  - Outputs:
    - A 16-byte XMSS node hash

  This algorithm is used only by the signer.
  """
  if node_height == 0: # Bottom layer: return the WOTS-TW pubkey hash.
    ADRS[10:14] = node_index.to_bytes(4)
    return wots_tw_pubkey_gen(sk_seed, pk_seed, ADRS)

  # Recursively derive the left/right child nodes
  lchild_index = 2 * node_index
  child_height = node_height - 1
  lchild = xmss_node(sk_seed, lchild_index, child_height, pk_seed, ADRS)
  rchild = xmss_node(sk_seed, lchild_index + 1, child_height, pk_seed, ADRS)

  # Compute & return the parent node.
  ADRS[9] = SL_XMSS_TREE
  ADRS[10:14] = zeros(4)
  ADRS[14:18] = node_height.to_bytes(4)
  ADRS[18:22] = node_index.to_bytes(4)
  return H(pk_seed, ADRS, lchild + rchild)

def xmss_sign(message: bytes, sk_seed: bytes, keypair_index: int, pk_seed: bytes, ADRS: bytearray) -> bytes:
  """
  The XMSS signing procedure. This function produces a deterministic WOTS-TW signature using a
  specific leaf of a XMSS tree, and appends a merkle authentication path to form a XMSS
  signature. Takes in the `message` to sign, the `sk_seed`, the `keypair_index` to sign with,
  the `pk_seed`, and an `ADRS`.

  - Inputs:
    - `message`: a 16-byte message to sign.
    - `sk_seed`: a 16-byte secret.
    - `keypair_index`: The index of the WOTS-TW keypair to sign with.
    - `pk_seed`: a 16-byte salt.
    - `ADRS`: a 22-byte address.
  - Outputs:
    - A XMSS signature consisting of `16 * (SPHX_XMSS_HEIGHT + WOTS_TW_CHAIN_COUNT)` bytes.

  This algorithm is used only by the signer.
  """
  # Sign the message with WOTS-TW
  ADRS[10:14] = keypair_index.to_bytes(4)
  sig = wots_tw_sign(message, sk_seed, pk_seed, ADRS)

  # Append the Merkle authentication path
  for j in range(SPHX_XMSS_HEIGHT):
    sibling_index = (keypair_index >> j) ^ 1
    sig += xmss_node(sk_seed, sibling_index, j, pk_seed, ADRS)

  return sig

def xmss_pubkey_from_sig(keypair_index: int, signature: bytes, message: bytes, pk_seed: bytes, ADRS: bytearray) -> bytes:
  """
  The XMSS verification function. Recovers an XMSS public key from a `signature` on a given
  16-byte `message`. Takes in the `pk_seed`, and an `ADRS`. The exact position of the WOTS-TW
  signing leaf is given by the `keypair_index` argument.

  - Inputs:
    - `keypair_index`: a 32-bit unsigned integer, the index of the WOTS-TW keypair to sign with.
    - `signature`: an XMSS signature consisting of `16 * (WOTS_TW_CHAIN_COUNT + SPHX_XMSS_HEIGHT)` bytes.
    - `message`: a 16-byte message.
    - `pk_seed`: a 16-byte salt.
    - `ADRS`: a 22-byte address.
  - Output:
    - a 16-byte XMSS root node hash

  This algorithm is used only by the signer.
  """
  wots_sig = signature[0 : WOTS_TW_CHAIN_COUNT*16]
  xmss_auth = signature[WOTS_TW_CHAIN_COUNT*16 : (WOTS_TW_CHAIN_COUNT+SPHX_XMSS_HEIGHT)*16]

  ADRS[10:14] = keypair_index.to_bytes(4) # AKA keypair address
  node = wots_tw_pubkey_from_sig(wots_sig, message, pk_seed, ADRS)

  ADRS[9] = SL_XMSS_TREE
  ADRS[10:14] = zeros(4)

  for k in range(SPHX_XMSS_HEIGHT):
    ADRS[14:18] = (k + 1).to_bytes(4)
    ADRS[18:22] = (keypair_index >> (k+1)).to_bytes(4)
    sibling = xmss_auth[k*16 : (k+1)*16]
    if (keypair_index >> k) & 1 == 1:
      node = H(pk_seed, ADRS, sibling + node)
    else:
      node = H(pk_seed, ADRS, node + sibling)

  return node


#  FXMSS algorithms

def fxmss_node(sk_seed: bytes, node_index: int, node_height: int, pk_seed: bytes, structure: bytes, ADRS: bytearray) -> bytes:
  """
  The FXMSS internal node computation helper function. This is a recursive function which takes
  in the `sk_seed`, a target `node_index`, a `node_height`, the `pk_seed`, an FXMSS tree
  `structure` identifier, and an `ADRS`.

  - Inputs:
    - `sk_seed`: a 16-byte secret.
    - `node_index`: A 64-bit unsigned integer indicating the index (from the left) of the desired node in the FXMSS layer.
    - `node_height`: An 8-bit unsigned integer indicating the height (from the bottom) of the desired node in the FXMSS tree.
    - `pk_seed`: a 16-byte salt.
    - `structure`: a 2-byte identifier describing the FXMSS tree structure.
    - `ADRS`: a 22-byte address.
  - Outputs:
    - A 16-byte FXMSS node hash

  This algorithm is used only by the signer.
  """
  node_depth = FXMSS_HEIGHT - node_height
  tree_shape, tree_depth = structure[0], structure[1]

  is_uxmss_leaf = tree_shape == FXMSS_SHAPE_UNBALANCED and (node_index == 1 or node_depth == tree_depth)
  is_bxmss_leaf = tree_shape == FXMSS_SHAPE_BALANCED and node_depth == tree_depth

  if is_uxmss_leaf or is_bxmss_leaf:
    ADRS[0] = node_height
    ADRS[1:9] = node_index.to_bytes(8)
    return wots_c_pubkey_gen(sk_seed, pk_seed, ADRS)

  # Catch and throw if control would enter an infinite resursive loop.
  if tree_shape == FXMSS_SHAPE_UNBALANCED:
    assert node_index == 0
  elif tree_shape == FXMSS_SHAPE_BALANCED:
    assert node_depth < tree_depth

  # Recursively derive the left/right child nodes
  lchild_index = 2 * node_index
  child_height = node_height - 1
  lchild = fxmss_node(sk_seed, lchild_index, child_height, pk_seed, structure, ADRS)
  rchild = fxmss_node(sk_seed, lchild_index + 1, child_height, pk_seed, structure, ADRS)

  # Compute & return the parent node.
  ADRS[0] = node_height
  ADRS[1:9] = node_index.to_bytes(8)
  ADRS[9] = SF_FXMSS_TREE
  ADRS[10:22] = zeros(12)
  return H(pk_seed, ADRS, lchild + rchild)

def fxmss_sign(message_digest: bytes, sk_seed: bytes, leaf_index: int, leaf_height: int, pk_seed: bytes, structure: bytes, ADRS: bytearray) -> bytes:
  """
  The FXMSS signing procedure. This function produces a deterministic WOTS+C signature using a
  specific leaf of an FXMSS tree, and appends a merkle authentication path to form an FXMSS
  signature. Takes in a `message_digest` to sign, the `sk_seed`, the WOTS+C leaf position
  described by `leaf_index` and `leaf_height`, the `pk_seed`, the tree `structure`, and an `ADRS`.

  - Inputs:
    - `message_digest`: a 32-byte message digest.
    - `sk_seed`: a 16-byte secret.
    - `leaf_index`: A 64-bit unsigned integer indicating the index (from the left) of the signing leaf in the FXMSS layer.
    - `leaf_height`: An 8-bit unsigned integer indicating the height (from the bottom) of the signing leaf in the FXMSS tree.
    - `pk_seed`: a 16-byte salt.
    - `structure`: a 2-byte identifier describing the FXMSS tree structure.
    - `ADRS`: a 22-byte address.
  - Outputs:
    - An FXMSS signature, a byte string with length `2 + 16 * (WOTS_C_CHAIN_COUNT + FXMSS_HEIGHT - leaf_height)`

  This algorithm is used only by the signer.
  """
  leaf_depth = FXMSS_HEIGHT - leaf_height

  # Validate the leaf is positioned correctly for the specified tree structure.
  tree_shape, tree_depth = structure[0], structure[1]
  if tree_shape == FXMSS_SHAPE_UNBALANCED:
    assert leaf_index == 1 or leaf_depth == tree_depth
  if tree_shape == FXMSS_SHAPE_BALANCED:
    assert leaf_depth == tree_depth

  ADRS[0] = leaf_height
  ADRS[1:9] = leaf_index.to_bytes(8)
  sig = wots_c_sign(message_digest, sk_seed, pk_seed, ADRS)

  # Append the Merkle authentication path
  for j in range(leaf_depth):
    sibling_index = (leaf_index >> j) ^ 1
    sibling_height = leaf_height + j
    sig += fxmss_node(sk_seed, sibling_index, sibling_height, pk_seed, structure, ADRS)

  return sig

def fxmss_pubkey_from_sig(node_index: int, signature: bytes, message_digest: bytes, pk_seed: bytes, ADRS: bytearray) -> Optional[bytes]:
  """
  The FXMSS verification function. Recovers an FXMSS public key from a `signature` on a given
  32-byte `message_digest`. Takes in the `pk_seed`, and an `ADRS`.

  The length of the `signature` implies the depth of the WOTS+C signing leaf. The exact
  left/right position of the WOTS+C signing leaf within its layer is given explicitly by the
  `node_index` argument.

  - Inputs:
    - `node_index`: a 64-bit unsigned integer.
    - `signature`: a variable-length FXMSS signature.
      - Must be at least `2 + 16 * WOTS_C_CHAIN_COUNT` bytes long.
      - Must be no longer than `2 + 16 * (WOTS_C_CHAIN_COUNT + FXMSS_HEIGHT)` bytes long.
      - Byte length must be 2 more than a multiple of 16.
    - `message_digest`: a 32-byte message digest.
    - `pk_seed`: a 16-byte salt.
    - `ADRS`: a 22-byte address.
  - Output:
    - a 16-byte FXMSS root node hash, or null
  """
  wots_sig = signature[0 : 2+WOTS_C_CHAIN_COUNT*16]
  xmss_auth = signature[2+WOTS_C_CHAIN_COUNT*16 : len(signature)]

  node_depth = floor(len(xmss_auth) / 16)

  # Ensure node_index describes a valid position in the FXMSS tree.
  assert node_index < 2 ** min(64, node_depth)

  node_height = FXMSS_HEIGHT - node_depth

  ADRS[0] = node_height
  ADRS[1:9] = node_index.to_bytes(8)
  node = wots_c_pubkey_from_sig(wots_sig, message_digest, pk_seed, ADRS)
  if node is None:
    return None

  ADRS[9] = SF_FXMSS_TREE
  ADRS[10:22] = zeros(12)

  for k in range(node_depth):
    ADRS[0] += 1
    ADRS[1:9] = (node_index >> (k+1)).to_bytes(8)
    sibling = xmss_auth[k*16 : (k+1)*16]
    if (node_index >> k) & 1 == 1:
      node = H(pk_seed, ADRS, sibling + node)
    else:
      node = H(pk_seed, ADRS, node + sibling)

  return node


#  FORS algorithms

def fors_sk_gen(sk_seed: bytes, pk_seed: bytes, ADRS: bytearray, tree_index: int) -> bytes:
  """
  The FORS secret preimage generation function. Generates a secret 16-byte preimage from `sk_seed`.
  Takes in `pk_seed`, an `ADRS`, and the `tree_index` to indicate the position of the FORS leaf
  in the forest.

  - Inputs:
    - `sk_seed`: a 16-byte secret.
    - `pk_seed`: a 16-byte salt.
    - `ADRS`: a 22-byte address.
    - `tree_index`: a `SPHX_FORS_HEIGHT`-bit unsigned integer.
  - Output:
    - A 16-byte preimage.

  This algorithm is used only by the signer.

  Note the `tree_index` of a FORS leaf or node is _indexed across the entire forest,_ not just
  within a single tree. The index of leaf `l` in tree `t` is `t * 2**SPHX_FORS_HEIGHT + l`.
  """
  ADRS[9] = SL_FORS_PRF
  ADRS[14:18] = zeros(4)
  ADRS[18:22] = tree_index.to_bytes(4)
  return PRF(pk_seed, sk_seed, ADRS)

def fors_node(sk_seed: bytes, node_index: int, node_height: int, pk_seed: bytes, ADRS: bytearray) -> bytes:
  """
  The FORS internal merkle node computation helper function. This is a recursive function which
  takes in the `sk_seed`, `pk_seed`, an `ADRS`, and integers `node_height`, `node_index` which
  describe the position of the FORS node in the forest of merkle trees.

  - Inputs:
    - `sk_seed`: a 16-byte secret.
    - `pk_seed`: a 16-byte salt.
    - `ADRS`: a 22-byte address.
    - `tree_index`: a `SPHX_FORS_HEIGHT`-bit unsigned integer.
  - Output:
    - A 16-byte FORS node hash.

  This function is used only by the signer.

  Note the `tree_index` of a FORS leaf or node is _indexed across the entire forest,_ not just
  within a single tree. The index of leaf `l` in tree `t` is `t * 2**SPHX_FORS_HEIGHT + l`.
  """
  if node_height == 0:
    preimage = fors_sk_gen(sk_seed, pk_seed, ADRS, node_index)
    ADRS[9] = SL_FORS_TREE
    ADRS[14:18] = zeros(4)
    ADRS[18:22] = node_index.to_bytes(4)
    return F(pk_seed, ADRS, preimage)

  lchild_index = 2 * node_index
  child_height = node_height - 1
  lchild = fors_node(sk_seed, lchild_index, child_height, pk_seed, ADRS)
  rchild = fors_node(sk_seed, lchild_index + 1, child_height, pk_seed, ADRS)

  ADRS[9] = SL_FORS_TREE
  ADRS[14:18] = node_height.to_bytes(4)
  ADRS[18:22] = node_index.to_bytes(4)
  return H(pk_seed, ADRS, lchild + rchild)

def fors_sign():
  """
  TODO
  """
  ...

def fors_pubkey_from_sig():
  """
  TODO
  """
  ...
