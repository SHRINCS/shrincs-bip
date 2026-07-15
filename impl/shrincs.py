from math import ceil, floor
import hashlib
from typing import Optional, Tuple

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
  Decomposes the bytes `x` into `outlen` groups of `b` bits which are each
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
  """
  The `sha256` hash function.

  - Inputs:
    - `message`: a message of at most `2**61 - 1` bytes.
  - Output:
    - a 32-byte hash.
  """
  return hashlib.sha256(bytes(message)).digest()

def hmac_sha256(key: bytes, message: bytes) -> bytes:
  """
  The `hmac_sha256` keyed hash function.

  - Inputs:
    - `key`: a key of at most 64 bytes.
    - `message`: a message of at most `2**61 - 1 - 64` bytes.
  - Output:
    - a 32-byte hash.
  """
  assert len(key) <= 64
  padded_key = key + zeros(64 - len(key))
  inner = sha256(xor(padded_key, repeat(0x36, 64)) + message)
  return sha256(xor(padded_key, repeat(0x5C, 64)) + inner)


# Tweaked hash functions

def T_sl(pk_seed: bytes, ADRS: bytearray, M_l: bytes) -> bytes:
  """
  The `T_sl` tweaked hash function. Compresses `WOTS_TW_CHAIN_COUNT` Winternitz chain tips into a
  single 16-byte hash.

  - Inputs:
    - `pk_seed`: a 16-byte salt.
    - `ADRS`: a 22-byte address.
    - `M_l`: a `WOTS_TW_CHAIN_COUNT * 16`-byte concatenation of chain tips.
  - Output:
    - a 16-byte hash.

  This function is only used in the stateless path, and by both the signer and the verifier.
  """
  return sha256(pk_seed + zeros(48) + ADRS + M_l)[:16]

def T_sf(pk_seed: bytes, ADRS: bytearray, M_l: bytes) -> bytes:
  """
  The `T_sf` tweaked hash function. Compresses `WOTS_C_CHAIN_COUNT` Winternitz chain tips into a
  single 16-byte hash.

  - Inputs:
    - `pk_seed`: a 16-byte salt.
    - `ADRS`: a 22-byte address.
    - `M_l`: a `WOTS_C_CHAIN_COUNT * 16`-byte concatenation of chain tips.
  - Output:
    - a 16-byte hash.

  This function is only used in the stateful path, and by both the signer and the verifier.
  """
  return sha256(pk_seed + zeros(48) + ADRS + M_l)[:16]

def T_k(pk_seed: bytes, ADRS: bytearray, M_k: bytes) -> bytes:
  """
  The `T_k` tweaked hash function. Compresses `SPHX_FORS_COUNT` FORS tree roots into a single
  16-byte hash.

  - Inputs:
    - `pk_seed`: a 16-byte salt.
    - `ADRS`: a 22-byte address.
    - `M_k`: a `SPHX_FORS_COUNT * 16`-byte concatenation of FORS tree roots.
  - Output:
    - a 16-byte hash.

  This function is only used in the stateless path, and by both the signer and the verifier.
  """
  return sha256(pk_seed + zeros(48) + ADRS + M_k)[:16]

def F(pk_seed: bytes, ADRS: bytearray, M_1: bytes) -> bytes:
  """
  The `F` tweaked hash function. Hashes a single 16-byte input, to generate and iterate Winternitz
  hash chains and to hash FORS leaves.

  - Inputs:
    - `pk_seed`: a 16-byte salt.
    - `ADRS`: a 22-byte address.
    - `M_1`: a 16-byte hash.
  - Output:
    - a 16-byte hash.

  This function is used in both stateful and stateless paths, and by both the signer and the verifier.
  """
  return sha256(pk_seed + zeros(48) + ADRS + M_1)[:16]

def H(pk_seed: bytes, ADRS: bytearray, M_2: bytes) -> bytes:
  """
  The `H` tweaked hash function. Combines a pair of 16-byte Merkle child nodes into their 16-byte
  parent, building the Merkle trees in XMSS and FORS.

  - Inputs:
    - `pk_seed`: a 16-byte salt.
    - `ADRS`: a 22-byte address.
    - `M_2`: a 32-byte concatenation of two child node hashes.
  - Output:
    - a 16-byte hash.

  This function is used in both stateful and stateless paths, and by both the signer and the verifier.
  """
  return sha256(pk_seed + zeros(48) + ADRS + M_2)[:16]

def H_grind(pk_seed: bytes, ADRS: bytearray, digest: bytes, counter: int) -> bytes:
  """
  The `H_grind` tweaked hash function. Maps a 32-byte `digest` and grinding `counter` into the
  constant-sum message space for WOTS+C.

  - Inputs:
    - `pk_seed`: a 16-byte salt.
    - `ADRS`: a 22-byte address.
    - `digest`: a 32-byte digest.
    - `counter`: a 16-bit unsigned integer.
  - Output:
    - a 16-byte hash.

  This function is only used in the stateful path, and by both the signer and the verifier.
  """
  assert counter <= 0xFFFF
  return sha256(pk_seed + zeros(48) + ADRS[:10] + digest + zeros(4) + counter.to_bytes(2))[:16]

def PRF(pk_seed: bytes, sk_seed: bytes, ADRS: bytearray) -> bytes:
  """
  The `PRF` pseudorandom function. Derives a secret 16-byte preimage from `sk_seed`, for signing
  and key generation.

  - Inputs:
    - `pk_seed`: a 16-byte salt.
    - `sk_seed`: a 16-byte secret.
    - `ADRS`: a 22-byte address.
  - Output:
    - a 16-byte hash.

  This function is used in both stateful and stateless paths, but only by the signer.
  """
  return sha256(pk_seed + zeros(48) + ADRS + sk_seed)[:16]

def H_msg_sl(R: bytes, pk_seed: bytes, root: bytes, M: bytes) -> bytes:
  """
  The `H_msg_sl` message hash function. Produces the 32-byte signing digest for the stateless path.

  - Inputs:
    - `R`: a 16-byte randomizer.
    - `pk_seed`: a 16-byte salt.
    - `root`: a 16-byte hash.
    - `M`: a variable-length message.
  - Output:
    - a 32-byte hash.

  This function is only used in the stateless path, and by both the signer and the verifier.

  Note that `pk_seed` is not padded in this keyed hash function.
  """
  return sha256(R + pk_seed + sha256(R + pk_seed + root + M) + zeros(4))

def H_msg_sf(R: bytes, ADRS: bytearray, pk_seed: bytes, root: bytes, M: bytes) -> bytes:
  """
  The `H_msg_sf` message hash function. Produces the 32-byte signing digest for the stateful path.

  - Inputs:
    - `R`: a 16-byte randomizer.
    - `pk_seed`: a 16-byte salt.
    - `root`: a 16-byte hash.
    - `ADRS`: a 22-byte address.
    - `M`: a variable-length message.
  - Output:
    - a 32-byte hash.

  This function is only used in the stateful path, and by both the signer and the verifier.

  Note that `pk_seed` is not padded in this tweakable hash function.
  """
  return sha256(R + ADRS[:9] + pk_seed + sha256(R + ADRS[:9] + pk_seed + root + M))

def PRF_msg_sl(sk_prf: bytes, opt_rand: bytes, M: bytes) -> bytes:
  """
  The `PRF_msg_sl` pseudorandom function. Derives the per-message randomizer (salt) for the stateless path via
  HMAC-SHA256.

  - Inputs:
    - `sk_prf`: a 16-byte secret.
    - `opt_rand`: a 16-byte salt.
    - `M`: a variable-length message.
  - Output:
    - a 16-byte hash.

  This function is only used in the stateless path, and only by the signer.

  `opt_rand` is set to either `pk_seed` (giving the "deterministic variant" of SLH-DSA[^slhdsa]),
  or a 16-byte salt sampled from a secure RNG (the "hedged variant" of SLH-DSA, which increases
  resistance to side-channel attacks).
  """
  return hmac_sha256(key=sk_prf, message=opt_rand + M)[:16]

def PRF_msg_sf(sk_prf: bytes, pk_seed: bytes, ADRS: bytearray, M: bytes) -> bytes:
  """
  The `PRF_msg_sf` function. Derives the per-message randomizer (salt) for the stateful path via
  HMAC-SHA256.

  - Inputs:
    - `sk_prf`: a 16-byte secret.
    - `pk_seed`: a 16-byte salt.
    - `ADRS`: a 22-byte address.
    - `M`: a variable-length message.
  - Output:
    - a 16-byte hash.

  This function is only used in the stateful path, and only by the signer.
  """
  return hmac_sha256(key=sk_prf + repeat(0xFF, 48), message=pk_seed + ADRS[:9] + M)[:16]


#  Winternitz algorithms

def wots_chain_iter(node: bytes, start: int, steps: int, pk_seed: bytes, ADRS: bytearray) -> bytes:
  """
  The WOTS hash chain iteration function. Iterates the hash chain from index `start` by `steps`
  steps, returning the node at index `start + steps`. The `ADRS` must be prefilled so the hashes
  are correctly tweaked.

  - Inputs:
    - `node`: a 16-byte hash.
    - `start`: a 32-bit unsigned integer, the index of `node` in its hash chain.
    - `steps`: a 32-bit unsigned integer, the number of steps to take up the chain; `start + steps` must not exceed `2**32`.
    - `pk_seed`: a 16-byte salt.
    - `ADRS`: a 22-byte address.
  - Output:
    - a 16-byte hash at index `start + steps`.

  This function is used in both stateful and stateless paths, and by both the signer and the verifier.
  """
  for j in range(start, start+steps):
    ADRS[18:22] = j.to_bytes(4)
    node = F(pk_seed, ADRS, node)
  return node

def wots_tw_message_to_indexes(message: bytes) -> list[int]:
  """
  The WOTS-TW message map function. Converts a 16-byte `message` into a checksummed array of
  `WOTS_TW_CHAIN_COUNT` chain indexes in `[0, 2**WOTS_TW_CHAIN_BITS)`.

  - Inputs:
    - `message`: a 16-byte hash.
  - Output:
    - a checksummed array of `WOTS_TW_CHAIN_COUNT` `WOTS_TW_CHAIN_BITS`-bit unsigned integers.

  This function is only used in the stateless path, and by both the signer and the verifier.
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
  The WOTS-TW public key generation function. Computes the 16-byte WOTS-TW public key at the
  keypair location prefilled in `ADRS`.

  - Inputs:
    - `sk_seed`: a 16-byte secret.
    - `pk_seed`: a 16-byte salt.
    - `ADRS`: a 22-byte address.
  - Output:
    - a 16-byte hash representing the WOTS-TW public key.

  This function is only used in the stateless path, and only by the signer.
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
  The WOTS-TW signing function. Produces a WOTS-TW signature on a 16-byte `message`, at the keypair
  location prefilled in `ADRS`.

  - Inputs:
    - `message`: a 16-byte message to sign.
    - `sk_seed`: a 16-byte secret.
    - `pk_seed`: a 16-byte salt.
    - `ADRS`: a 22-byte address.
  - Output:
    - a `WOTS_TW_CHAIN_COUNT * 16`-byte signature.

  This function is only used in the stateless path, and only by the signer.
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
  The WOTS-TW verification function. Recovers a WOTS-TW public key from a `signature` on a 16-byte
  `message`.

  - Inputs:
    - `signature`: a `WOTS_TW_CHAIN_COUNT * 16`-byte signature.
    - `message`: a 16-byte message.
    - `pk_seed`: a 16-byte salt.
    - `ADRS`: a 22-byte address.
  - Output:
    - a 16-byte hash representing the WOTS-TW public key.

  This function is only used in the stateless path, and by both the signer and the verifier.
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
  The WOTS+C grinding function. Grinds up to 2^16 counters until one maps `message_digest` to a
  constant-sum index set, returning the lowest such counter and its index set.

  - Inputs:
    - `pk_seed`: a 16-byte salt.
    - `message_digest`: a 32-byte intermediate message digest (from `H_msg_sf`).
    - `ADRS`: a 22-byte address.
  - Output:
    - a tuple `(counter, indexes)`: the smallest valid 16-bit `counter` and the corresponding
      constant-sum set of hash chain indexes (of length `WOTS_C_CHAIN_COUNT`).

  This function is only used in the stateful path, and only by the signer.
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
  The WOTS+C digest validation function. Evaluates a signature's grinding `counter` and returns the
  constant-sum index set it yields, or null if the counter is invalid.

  - Inputs:
    - `pk_seed`: a 16-byte salt.
    - `message_digest`: a 32-byte intermediate message digest (from `H_msg_sf`).
    - `ADRS`: a 22-byte address.
    - `counter`: a 16-bit unsigned integer.
  - Output:
    - a constant-sum set of hash chain indexes (of length `WOTS_C_CHAIN_COUNT`), or null.

  This function is only used in the stateful path, and only by the verifier.
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
  The WOTS+C public key generation function. Computes the 16-byte WOTS+C public key at the keypair
  location prefilled in `ADRS`.

  - Inputs:
    - `sk_seed`: a 16-byte secret.
    - `pk_seed`: a 16-byte salt.
    - `ADRS`: a 22-byte address.
  - Output:
    - a 16-byte hash representing the WOTS+C public key.

  This function is only used in the stateful path, and only by the signer.
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
  The WOTS+C signing function. Produces a WOTS+C signature on a 32-byte `message_digest`, at the
  keypair location prefilled in `ADRS`.

  - Inputs:
    - `message_digest`: a 32-byte message digest to sign.
    - `sk_seed`: a 16-byte secret.
    - `pk_seed`: a 16-byte salt.
    - `ADRS`: a 22-byte address.
  - Output:
    - a `2 + WOTS_C_CHAIN_COUNT * 16`-byte signature.

  This function is only used in the stateful path, and only by the signer.
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
  The WOTS+C verification function. Recovers a WOTS+C public key from a `signature` on a 32-byte
  `message_digest`.

  - Inputs:
    - `signature`: a `2 + WOTS_C_CHAIN_COUNT * 16`-byte signature.
    - `message_digest`: a 32-byte message digest.
    - `pk_seed`: a 16-byte salt.
    - `ADRS`: a 22-byte address.
  - Output:
    - a 16-byte hash representing the WOTS+C public key, or null.

  This function is only used in the stateful path, and only by the verifier.
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
  The XMSS internal node computation function. Recursively computes the XMSS node at the given
  `node_index` and `node_height`. The `ADRS` must be prefilled with the location of the XMSS tree
  in the hypertree to ensure the hashes are properly tweaked.

  - Inputs:
    - `sk_seed`: a 16-byte secret.
    - `node_index`: a 32-bit unsigned integer, the index (from the left) of the node in the XMSS layer.
    - `node_height`: a 32-bit unsigned integer, the height (from the bottom) of the node in the XMSS layer.
    - `pk_seed`: a 16-byte salt.
    - `ADRS`: a 22-byte address.
  - Output:
    - a 16-byte XMSS node hash.

  This function is only used in the stateless path, and only by the signer.
  """
  if node_height == 0: # Bottom layer: return the WOTS-TW pubkey hash.
    ADRS[10:14] = node_index.to_bytes(4)
    return wots_tw_pubkey_gen(sk_seed, pk_seed, ADRS)

  # Recursively derive the left/right child nodes.
  lchild_index = 2 * node_index
  child_height = node_height - 1
  lchild = xmss_node(sk_seed, lchild_index, child_height, pk_seed, ADRS)
  rchild = xmss_node(sk_seed, lchild_index + 1, child_height, pk_seed, ADRS)

  # Compute and return the parent node.
  ADRS[9] = SL_XMSS_TREE
  ADRS[10:14] = zeros(4)
  ADRS[14:18] = node_height.to_bytes(4)
  ADRS[18:22] = node_index.to_bytes(4)
  return H(pk_seed, ADRS, lchild + rchild)

def xmss_sign(message: bytes, sk_seed: bytes, keypair_index: int, pk_seed: bytes, ADRS: bytearray) -> bytes:
  """
  The XMSS signing function. Produces a deterministic WOTS-TW signature at leaf `keypair_index` and
  appends the Merkle authentication path to form an XMSS signature. The `ADRS` must be prefilled with
  the location of the XMSS tree in the hypertree to ensure the hashes are properly tweaked.

  - Inputs:
    - `message`: a 16-byte message to sign.
    - `sk_seed`: a 16-byte secret.
    - `keypair_index`: a 32-bit unsigned integer, the index of the WOTS-TW keypair to sign with.
    - `pk_seed`: a 16-byte salt.
    - `ADRS`: a 22-byte address.
  - Output:
    - a `16 * (SPHX_XMSS_HEIGHT + WOTS_TW_CHAIN_COUNT)`-byte signature.

  This function is only used in the stateless path, and only by the signer.
  """
  # Sign the message with WOTS-TW.
  ADRS[10:14] = keypair_index.to_bytes(4)
  sig = wots_tw_sign(message, sk_seed, pk_seed, ADRS)

  # Append the Merkle authentication path.
  for j in range(SPHX_XMSS_HEIGHT):
    sibling_index = (keypair_index >> j) ^ 1
    sig += xmss_node(sk_seed, sibling_index, j, pk_seed, ADRS)

  return sig

def xmss_pubkey_from_sig(keypair_index: int, signature: bytes, message: bytes, pk_seed: bytes, ADRS: bytearray) -> bytes:
  """
  The XMSS verification function. Recovers an XMSS root from a `signature` on a 16-byte `message`
  at leaf `keypair_index`. The `ADRS` must be prefilled with the location of the XMSS tree in the
  hypertree to ensure the hashes are properly tweaked.

  - Inputs:
    - `keypair_index`: a 32-bit unsigned integer, the index of the WOTS-TW keypair to sign with.
    - `signature`: a `16 * (WOTS_TW_CHAIN_COUNT + SPHX_XMSS_HEIGHT)`-byte signature.
    - `message`: a 16-byte message.
    - `pk_seed`: a 16-byte salt.
    - `ADRS`: a 22-byte address.
  - Output:
    - a 16-byte XMSS root node hash.

  This function is only used in the stateless path, and by both the signer and the verifier.
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


#  Hypertree algorithms

def hypertree_sign(message: bytes, sk_seed: bytes, pk_seed: bytes, tree_index: int, leaf_index: int) -> bytes:
  """
  The hypertree signing function. Signs a 16-byte `message` through a hypertree of XMSS trees.

  - Inputs:
    - `message`: a 16-byte message to sign.
    - `sk_seed`: a 16-byte secret.
    - `pk_seed`: a 16-byte salt.
    - `tree_index`: a 64-bit unsigned integer, the index (from the left) of the bottom-layer XMSS tree to sign with.
    - `leaf_index`: a 32-bit unsigned integer, the index (from the left) of the WOTS-TW key in the bottom-layer XMSS tree to sign with.
  - Output:
    - a `16 * SPHX_LAYER_COUNT * (SPHX_XMSS_HEIGHT + WOTS_TW_CHAIN_COUNT)`-byte signature.

  This function is only used in the stateless path, and only by the signer.
  """
  ADRS = bytearray(22)

  sig = b""
  for j in range(SPHX_LAYER_COUNT):
    ADRS[0] = j
    ADRS[1:9] = tree_index.to_bytes(8)
    layer_sig = xmss_sign(message, sk_seed, leaf_index, pk_seed, ADRS)
    if j < SPHX_LAYER_COUNT - 1:
      message = xmss_pubkey_from_sig(leaf_index, layer_sig, message, pk_seed, ADRS)
      leaf_index = tree_index % (2**SPHX_XMSS_HEIGHT)
      tree_index >>= SPHX_XMSS_HEIGHT
    sig += layer_sig

  return sig

def hypertree_verify(message: bytes, signature: bytes, pk_seed: bytes, tree_index: int, leaf_index: int, sl_root: bytes) -> bool:
  """
  The hypertree verification function. Recovers the hypertree root from a `signature` and compares
  it against `sl_root`.

  - Inputs:
    - `message`: a 16-byte message.
    - `signature`: a `16 * SPHX_LAYER_COUNT * (SPHX_XMSS_HEIGHT + WOTS_TW_CHAIN_COUNT)`-byte signature.
    - `pk_seed`: a 16-byte salt.
    - `tree_index`: a 64-bit unsigned integer, the index (from the left) of the bottom-layer XMSS tree to sign with.
    - `leaf_index`: a 32-bit unsigned integer, the index (from the left) of the WOTS-TW key in the bottom-layer XMSS tree to sign with.
    - `sl_root`: the 16-byte root hash of the stateless root tree.
  - Output:
    - a boolean indicating if the signature is valid.

  This function is only used in the stateless path, and only by the verifier.
  """
  ADRS = bytearray(22)

  offset = 0
  for j in range(SPHX_LAYER_COUNT):
    ADRS[0] = j
    ADRS[1:9] = tree_index.to_bytes(8)
    layer_sig = signature[offset : offset+16*(SPHX_XMSS_HEIGHT+WOTS_TW_CHAIN_COUNT)]
    message = xmss_pubkey_from_sig(leaf_index, layer_sig, message, pk_seed, ADRS)
    if j < SPHX_LAYER_COUNT - 1:
      leaf_index = tree_index % (2**SPHX_XMSS_HEIGHT)
      tree_index >>= SPHX_XMSS_HEIGHT
      offset += len(layer_sig)
  return message == sl_root


#  FXMSS algorithms

def fxmss_node(sk_seed: bytes, node_index: int, node_height: int, pk_seed: bytes, structure: bytes, ADRS: bytearray) -> bytes:
  """
  The FXMSS internal node computation function. Recursively computes the FXMSS node at the given
  `node_index` and `node_height` for the tree `structure`.

  - Inputs:
    - `sk_seed`: a 16-byte secret.
    - `node_index`: a 64-bit unsigned integer, the index (from the left) of the node in the FXMSS layer.
    - `node_height`: an 8-bit unsigned integer, the height (from the bottom) of the node in the FXMSS tree.
    - `pk_seed`: a 16-byte salt.
    - `structure`: a 2-byte identifier describing the FXMSS tree structure.
    - `ADRS`: a 22-byte address.
  - Output:
    - a 16-byte FXMSS node hash.

  This function is only used in the stateful path, and only by the signer.
  """
  node_depth = FXMSS_HEIGHT - node_height
  tree_shape, tree_depth = structure[0], structure[1]

  is_uxmss_leaf = tree_shape == FXMSS_SHAPE_UNBALANCED and (node_index == 1 or node_depth == tree_depth)
  is_bxmss_leaf = tree_shape == FXMSS_SHAPE_BALANCED and node_depth == tree_depth

  if is_uxmss_leaf or is_bxmss_leaf:
    ADRS[0] = node_height
    ADRS[1:9] = node_index.to_bytes(8)
    return wots_c_pubkey_gen(sk_seed, pk_seed, ADRS)

  # Catch and throw if control would enter an infinite recursive loop.
  if tree_shape == FXMSS_SHAPE_UNBALANCED:
    assert node_index == 0
  elif tree_shape == FXMSS_SHAPE_BALANCED:
    assert node_depth < tree_depth

  # Recursively derive the left/right child nodes.
  lchild_index = 2 * node_index
  child_height = node_height - 1
  lchild = fxmss_node(sk_seed, lchild_index, child_height, pk_seed, structure, ADRS)
  rchild = fxmss_node(sk_seed, lchild_index + 1, child_height, pk_seed, structure, ADRS)

  # Compute and return the parent node.
  ADRS[0] = node_height
  ADRS[1:9] = node_index.to_bytes(8)
  ADRS[9] = SF_FXMSS_TREE
  ADRS[10:22] = zeros(12)
  return H(pk_seed, ADRS, lchild + rchild)

def fxmss_sign(message_digest: bytes, sk_seed: bytes, leaf_index: int, leaf_height: int, pk_seed: bytes, structure: bytes) -> bytes:
  """
  The FXMSS signing function. Produces a deterministic WOTS+C signature at the leaf given by
  `leaf_index`/`leaf_height` and appends the Merkle authentication path to form an FXMSS signature.

  - Inputs:
    - `message_digest`: a 32-byte message digest.
    - `sk_seed`: a 16-byte secret.
    - `leaf_index`: a 64-bit unsigned integer, the index (from the left) of the signing leaf in the FXMSS layer.
    - `leaf_height`: an 8-bit unsigned integer, the height (from the bottom) of the signing leaf in the FXMSS tree.
    - `pk_seed`: a 16-byte salt.
    - `structure`: a 2-byte identifier describing the FXMSS tree structure.
  - Output:
    - a `2 + 16 * (WOTS_C_CHAIN_COUNT + FXMSS_HEIGHT - leaf_height)`-byte signature.

  This function is only used in the stateful path, and only by the signer.
  """
  leaf_depth = FXMSS_HEIGHT - leaf_height

  # Validate the leaf is positioned correctly for the specified tree structure.
  tree_shape, tree_depth = structure[0], structure[1]
  if tree_shape == FXMSS_SHAPE_UNBALANCED:
    assert leaf_index == 1 or leaf_depth == tree_depth
  if tree_shape == FXMSS_SHAPE_BALANCED:
    assert leaf_depth == tree_depth

  ADRS = bytearray(22)
  ADRS[0] = leaf_height
  ADRS[1:9] = leaf_index.to_bytes(8)
  sig = wots_c_sign(message_digest, sk_seed, pk_seed, ADRS)

  # Append the Merkle authentication path.
  for j in range(leaf_depth):
    sibling_index = (leaf_index >> j) ^ 1
    sibling_height = leaf_height + j
    sig += fxmss_node(sk_seed, sibling_index, sibling_height, pk_seed, structure, ADRS)

  return sig

def fxmss_pubkey_from_sig(leaf_index: int, signature: bytes, message_digest: bytes, pk_seed: bytes) -> Optional[bytes]:
  """
  The FXMSS verification function. Recovers an FXMSS root from a `signature` on a 32-byte
  `message_digest`. The signature length implies the leaf depth; `leaf_index` gives its
  left-to-right position.

  - Inputs:
    - `leaf_index`: a 64-bit unsigned integer, the left-to-right position of the WOTS+C signing leaf.
    - `signature`: a variable-length signature of `2 + 16 * (WOTS_C_CHAIN_COUNT + 1)` to `2 + 16 * (WOTS_C_CHAIN_COUNT + FXMSS_HEIGHT)` bytes, with length 2 more than a multiple of 16.
    - `message_digest`: a 32-byte message digest.
    - `pk_seed`: a 16-byte salt.
  - Output:
    - a 16-byte FXMSS root node hash, or null.

  This function is only used in the stateful path, and only by the verifier.
  """
  wots_sig = signature[0 : 2+WOTS_C_CHAIN_COUNT*16]
  xmss_auth = signature[2+WOTS_C_CHAIN_COUNT*16 : len(signature)]

  leaf_depth = floor(len(xmss_auth) / 16)

  # Ensure leaf_index describes a valid position in the FXMSS tree.
  assert leaf_index < 2 ** min(64, leaf_depth)

  leaf_height = FXMSS_HEIGHT - leaf_depth

  ADRS = bytearray(22)
  ADRS[0] = leaf_height
  ADRS[1:9] = leaf_index.to_bytes(8)
  node = wots_c_pubkey_from_sig(wots_sig, message_digest, pk_seed, ADRS)
  if node is None:
    return None

  ADRS[9] = SF_FXMSS_TREE
  ADRS[10:22] = zeros(12)

  for k in range(leaf_depth):
    ADRS[0] += 1
    ADRS[1:9] = (leaf_index >> (k+1)).to_bytes(8)
    sibling = xmss_auth[k*16 : (k+1)*16]
    if (leaf_index >> k) & 1 == 1:
      node = H(pk_seed, ADRS, sibling + node)
    else:
      node = H(pk_seed, ADRS, node + sibling)

  return node


#  FORS algorithms

def fors_sk_gen(sk_seed: bytes, pk_seed: bytes, ADRS: bytearray, node_index: int) -> bytes:
  """
  The FORS secret preimage generation function. Generates the secret 16-byte preimage of the FORS
  leaf at forest-wide index `node_index`. The `ADRS` must be prefilled with the location of the FORS
  keypair to ensure the hashes are properly tweaked.

  - Inputs:
    - `sk_seed`: a 16-byte secret.
    - `pk_seed`: a 16-byte salt.
    - `ADRS`: a 22-byte address.
    - `node_index`: a 32-bit unsigned integer, a forest-wide leaf index in `[0, SPHX_FORS_COUNT * 2**SPHX_FORS_HEIGHT)`.
  - Output:
    - a 16-byte preimage.

  This function is only used in the stateless path, and only by the signer.

  Note the `node_index` of a FORS leaf or node is _indexed across the entire forest,_ not just
  within a single tree. The index of leaf `l` in tree `t` is `t * 2**SPHX_FORS_HEIGHT + l`.
  """
  ADRS[9] = SL_FORS_PRF
  ADRS[14:18] = zeros(4)
  ADRS[18:22] = node_index.to_bytes(4)
  return PRF(pk_seed, sk_seed, ADRS)

def fors_node(sk_seed: bytes, node_index: int, node_height: int, pk_seed: bytes, ADRS: bytearray) -> bytes:
  """
  The FORS internal node computation function. Recursively computes the FORS node at the forest-wide
  `node_index` and `node_height`. The `ADRS` must be prefilled with the location of the FORS keypair
  to ensure the hashes are properly tweaked.

  - Inputs:
    - `sk_seed`: a 16-byte secret.
    - `pk_seed`: a 16-byte salt.
    - `ADRS`: a 22-byte address.
    - `node_index`: a 32-bit unsigned integer, a forest-wide node index in `[0, SPHX_FORS_COUNT * 2**(SPHX_FORS_HEIGHT - node_height))`.
    - `node_height`: a 32-bit unsigned integer, a node height in `[0, SPHX_FORS_HEIGHT]`.
  - Output:
    - a 16-byte FORS node hash.

  This function is only used in the stateless path, and only by the signer.

  Note the `node_index` of a FORS leaf or node is _indexed across the entire forest,_ not just
  within a single tree. The index of node `l` in tree `t` at height `h` is
  `t * 2**(SPHX_FORS_HEIGHT - h) + l`.
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

def fors_sign(message_digest: bytes, sk_seed: bytes, pk_seed: bytes, ADRS: bytearray) -> bytes:
  """
  The FORS signing function. Produces a FORS signature on a `message_digest`. The `ADRS` must be
  prefilled with the location of the FORS keypair to ensure the hashes are properly tweaked.

  - Inputs:
    - `message_digest`: a `ceil(SPHX_FORS_COUNT * SPHX_FORS_HEIGHT / 8)`-byte message digest.
    - `sk_seed`: a 16-byte secret.
    - `pk_seed`: a 16-byte salt.
    - `ADRS`: a 22-byte address.
  - Output:
    - a `16 * SPHX_FORS_COUNT * (SPHX_FORS_HEIGHT + 1)`-byte signature.

  This function is only used in the stateless path, and only by the signer.
  """
  sig = b""
  index_set = base_2b(message_digest, SPHX_FORS_HEIGHT, SPHX_FORS_COUNT)
  for i in range(SPHX_FORS_COUNT):
    leaf_index = i * 2**SPHX_FORS_HEIGHT + index_set[i]
    sig += fors_sk_gen(sk_seed, pk_seed, ADRS, leaf_index)
    for j in range(SPHX_FORS_HEIGHT):
      sibling_index = i * 2**(SPHX_FORS_HEIGHT - j) + ((index_set[i] >> j) ^ 1)
      sig += fors_node(sk_seed, sibling_index, j, pk_seed, ADRS)
  return sig

def fors_pubkey_from_sig(signature: bytes, message_digest: bytes, pk_seed: bytes, ADRS: bytearray) -> bytes:
  """
  The FORS verification function. Recovers a FORS public key from a `signature` on a
  `message_digest`. The `ADRS` must be prefilled with the location of the FORS keypair to ensure
  the hashes are properly tweaked.

  - Inputs:
    - `signature`: a `16 * SPHX_FORS_COUNT * (SPHX_FORS_HEIGHT + 1)`-byte signature.
    - `message_digest`: a `ceil(SPHX_FORS_COUNT * SPHX_FORS_HEIGHT / 8)`-byte message digest.
    - `pk_seed`: a 16-byte salt.
    - `ADRS`: a 22-byte address.
  - Output:
    - a 16-byte hash of the FORS public key.

  This function is only used in the stateless path, and by both the signer and the verifier.
  """
  index_set = base_2b(message_digest, SPHX_FORS_HEIGHT, SPHX_FORS_COUNT)

  offset = 0
  roots = b""
  for i in range(SPHX_FORS_COUNT):
    preimage = signature[offset : offset+16]
    offset += 16
    tree_index = i * 2**SPHX_FORS_HEIGHT + index_set[i]

    ADRS[9] = SL_FORS_TREE
    ADRS[14:18] = zeros(4)
    ADRS[18:22] = tree_index.to_bytes(4)
    node = F(pk_seed, ADRS, preimage)
    for j in range(SPHX_FORS_HEIGHT):
      ADRS[14:18] = (j + 1).to_bytes(4)
      ADRS[18:22] = (tree_index >> (j+1)).to_bytes(4)

      sibling = signature[offset : offset+16]
      offset += 16

      if (index_set[i] >> j) & 1 == 1:
        node = H(pk_seed, ADRS, sibling + node)
      else:
        node = H(pk_seed, ADRS, node + sibling)
    roots += node

  ADRS[9] = SL_FORS_ROOTS
  ADRS[14:22] = zeros(8)
  return T_k(pk_seed, ADRS, roots)


#  SLH-DSA algorithms

def slh_dsa_digest_message(R: bytes, pk_seed: bytes, sl_root: bytes, message: bytes) -> Tuple[bytes, int, int]:
  """
  The SLH-DSA message hashing function. Derives the FORS message digest, bottom-layer XMSS tree
  index, and FORS leaf index from `message` under `H_msg_sl`.

  - Inputs:
    - `R`: a 16-byte randomizer.
    - `pk_seed`: a 16-byte salt.
    - `sl_root`: the 16-byte root hash of the stateless root tree.
    - `message`: a variable-length message.
  - Outputs:
    - a `ceil(SPHX_FORS_COUNT * SPHX_FORS_HEIGHT / 8)`-byte message digest, ready for use by FORS.
    - a pseudorandomly selected index of a bottom-layer XMSS tree, in `[0, 2**(SPHX_XMSS_HEIGHT * (SPHX_LAYER_COUNT - 1)))`.
    - a pseudorandomly selected index of a FORS key within an XMSS tree, in `[0, 2**SPHX_XMSS_HEIGHT)`.

  This function is only used in the stateless path, and by both the signer and the verifier.
  """
  digest = H_msg_sl(R, pk_seed, sl_root, message)

  fors_digest = digest[:ceil(SPHX_FORS_HEIGHT * SPHX_FORS_COUNT / 8)]
  offset = len(fors_digest)

  tree_index_digest = digest[offset : offset + ceil(SPHX_XMSS_HEIGHT * (SPHX_LAYER_COUNT - 1) / 8)]
  offset += len(tree_index_digest)

  leaf_index_digest = digest[offset : offset + ceil(SPHX_XMSS_HEIGHT / 8)]

  tree_index = int.from_bytes(tree_index_digest) % (2**(SPHX_XMSS_HEIGHT * (SPHX_LAYER_COUNT - 1)))
  leaf_index = int.from_bytes(leaf_index_digest) % (2**SPHX_XMSS_HEIGHT)
  return (fors_digest, tree_index, leaf_index)


def slh_dsa_sign_internal(message: bytes, sk_seed: bytes, sk_prf: bytes, pk_seed: bytes, sl_root: bytes, opt_rand: Optional[bytes]) -> bytes:
  """
  The SLH-DSA internal signing function. Signs `message` with `sk_seed`, salting all hashes with
  `pk_seed`, deriving the randomizer from `sk_prf`/`opt_rand`, and binding the signature to
  `sl_root`.

  The optional additional data `opt_rand` is used to further salt the randomizer. If omitted,
  the algorithm uses `pk_seed` in its place, resulting in the _deterministic variant_ of SLH-DSA.

  The resulting signature is composed of (1) a randomizer, (2) a FORS signature, and (3) a
  hypertree signature, all concatenated together.

  - Inputs:
    - `message`: a variable-length message.
    - `sk_seed`: a 16-byte secret.
    - `sk_prf`: a 16-byte secret.
    - `pk_seed`: a 16-byte salt.
    - `sl_root`: the 16-byte root hash of the stateless root tree.
    - `opt_rand`: an optional 16-byte salt for the randomizer.
  - Output:
    - a `16 * (1 + SPHX_FORS_COUNT * (SPHX_FORS_HEIGHT + 1) + SPHX_LAYER_COUNT * (WOTS_TW_CHAIN_COUNT + SPHX_XMSS_HEIGHT))`-byte signature.

  This function is only used in the stateless path, and only by the signer.
  """
  if opt_rand is None:
    opt_rand = pk_seed # deterministic mode

  R = PRF_msg_sl(sk_prf, opt_rand, message)
  fors_digest, tree_index, leaf_index = slh_dsa_digest_message(R, pk_seed, sl_root, message)

  ADRS = bytearray(22)
  ADRS[1:9] = tree_index.to_bytes(8)
  ADRS[10:14] = leaf_index.to_bytes(4)

  fors_signature = fors_sign(fors_digest, sk_seed, pk_seed, ADRS)
  fors_pubkey = fors_pubkey_from_sig(fors_signature, fors_digest, pk_seed, ADRS)
  hypertree_signature = hypertree_sign(fors_pubkey, sk_seed, pk_seed, tree_index, leaf_index)

  return R + fors_signature + hypertree_signature

def slh_dsa_verify_internal(message: bytes, signature: bytes, pk_seed: bytes, sl_root: bytes) -> bool:
  """
  The SLH-DSA internal verification function. Recovers the root-tree root from a `signature` on
  `message` and checks it against `sl_root`.

  - Inputs:
    - `message`: a variable-length message.
    - `signature`: a `16 * (1 + SPHX_FORS_COUNT * (SPHX_FORS_HEIGHT + 1) + SPHX_LAYER_COUNT * (WOTS_TW_CHAIN_COUNT + SPHX_XMSS_HEIGHT))`-byte signature.
    - `pk_seed`: a 16-byte salt.
    - `sl_root`: the 16-byte root hash of the stateless root tree.
  - Output:
    - a boolean indicating if the signature is valid.

  This function is only used in the stateless path, and only by the verifier.
  """
  if len(signature) != 16 * (1 + SPHX_FORS_COUNT * (SPHX_FORS_HEIGHT + 1) + SPHX_LAYER_COUNT * (WOTS_TW_CHAIN_COUNT + SPHX_XMSS_HEIGHT)):
    return False

  R = signature[0:16]
  fors_signature = signature[16 : 16 * (1 + SPHX_FORS_COUNT * (SPHX_FORS_HEIGHT + 1))]
  offset = 16 + len(fors_signature)
  hypertree_signature = signature[offset : offset + 16 * SPHX_LAYER_COUNT * (WOTS_TW_CHAIN_COUNT + SPHX_XMSS_HEIGHT)]

  fors_digest, tree_index, leaf_index = slh_dsa_digest_message(R, pk_seed, sl_root, message)

  ADRS = bytearray(22)
  ADRS[1:9] = tree_index.to_bytes(8)
  ADRS[10:14] = leaf_index.to_bytes(4)

  fors_pubkey = fors_pubkey_from_sig(fors_signature, fors_digest, pk_seed, ADRS)
  return hypertree_verify(fors_pubkey, hypertree_signature, pk_seed, tree_index, leaf_index, sl_root)

def slh_dsa_sign(message: bytes, ctx: bytes, sk_seed: bytes, sk_prf: bytes, pk_seed: bytes, sl_root: bytes, opt_rand: Optional[bytes]) -> bytes:
  """
  The SLH-DSA external signing function. Signs `message` with `sk_seed`, prepending the context
  `ctx`; salts all hashes with `pk_seed`, derives the randomizer from `sk_prf`/`opt_rand`, and
  binds to `sl_root`.

  - Inputs:
    - `message`: a variable-length message.
    - `ctx`: a context of at most 255 bytes.
    - `sk_seed`: a 16-byte secret.
    - `sk_prf`: a 16-byte secret.
    - `pk_seed`: a 16-byte salt.
    - `sl_root`: the 16-byte root hash of the stateless root tree.
    - `opt_rand`: an optional 16-byte salt for the randomizer.
  - Output:
    - a `16 * (1 + SPHX_FORS_COUNT * (SPHX_FORS_HEIGHT + 1) + SPHX_LAYER_COUNT * (WOTS_TW_CHAIN_COUNT + SPHX_XMSS_HEIGHT))`-byte signature.

  This function is only used in the stateless path, and only by the signer.

  This is a simple wrapper around `slh_dsa_sign_internal` which prepends an optional context
  `ctx` to every message. Verifiers must use `slh_dsa_verify` with the same `ctx`.
  """
  assert len(ctx) < 256
  contextualized_msg = (0).to_bytes(1) + len(ctx).to_bytes(1) + ctx + message
  return slh_dsa_sign_internal(contextualized_msg, sk_seed, sk_prf, pk_seed, sl_root, opt_rand)

def slh_dsa_verify(message: bytes, signature: bytes, ctx: bytes, pk_seed: bytes, sl_root: bytes) -> bool:
  """
  The SLH-DSA verification function. Recovers the root-tree root from a `signature` on `message`
  (with context `ctx`) and checks it against `sl_root`.

  - Inputs:
    - `message`: a variable-length message.
    - `signature`: a `16 * (1 + SPHX_FORS_COUNT * (SPHX_FORS_HEIGHT + 1) + SPHX_LAYER_COUNT * (WOTS_TW_CHAIN_COUNT + SPHX_XMSS_HEIGHT))`-byte signature.
    - `ctx`: a context of at most 255 bytes.
    - `pk_seed`: a 16-byte salt.
    - `sl_root`: the 16-byte root hash of the stateless root tree.
  - Output:
    - a boolean indicating if the signature is valid.

  This function is only used in the stateless path, and only by the verifier.

  This is a simple wrapper around `slh_dsa_verify_internal` which prepends an optional context
  `ctx` to every message. Signatures must be produced via `slh_dsa_sign` with the same `ctx`.
  """
  assert len(ctx) < 256
  contextualized_msg = (0).to_bytes(1) + len(ctx).to_bytes(1) + ctx + message
  return slh_dsa_verify_internal(contextualized_msg, signature, pk_seed, sl_root)


#  SHRINCS algorithms

def shrincs_keygen(seed: bytes, sf_structure: bytes) -> Tuple[bytes, bytes]:
  """
  The SHRINCS key generation function. Computes the secret and public keys from a 48-byte `seed`
  and the stateful tree `sf_structure`.

  - Inputs:
    - `seed`: a 48-byte random seed. Must be sampled from a CSRNG.
    - `sf_structure`: a 2-byte identifier describing the shape and depth of the stateful FXMSS tree.
  - Outputs:
    - an 82-byte SHRINCS secret key.
    - a 48-byte SHRINCS public key.

  This function is used only during key generation.

  > [!WARNING]
  > The `sf_structure` argument must come from a trusted source or else be validated.
  > If an adversary can control `sf_structure` they may cause key-generation to fail, or hang
  > consuming compute resources by making the implementation generate a very large BXMSS tree.
  """
  assert len(seed) == 48
  assert len(sf_structure) == 2

  sk_seed = seed[0:16]
  sk_prf  = seed[16:32]
  pk_seed = seed[32:48]

  ADRS = bytearray(22)
  ADRS[0] = SPHX_LAYER_COUNT - 1
  sl_root = xmss_node(sk_seed, 0, SPHX_XMSS_HEIGHT, pk_seed, ADRS)
  sf_root = fxmss_node(sk_seed, 0, FXMSS_HEIGHT, pk_seed, sf_structure, bytearray(22))

  shrincs_seckey = sk_seed + sk_prf + pk_seed + sl_root + sf_structure + sf_root
  shrincs_pubkey = pk_seed + sl_root + sf_root
  return (shrincs_seckey, shrincs_pubkey)

def shrincs_sf_leaf_select(structure: bytes, state_ctr: int) -> Optional[Tuple[int, int]]:
  """
  The SHRINCS stateful-path leaf-selection function. Computes the position `(index, height)` of the
  next WOTS+C leaf for the given `structure` and `state_ctr`.

  - Inputs:
    - `structure`: a 2-byte identifier describing the FXMSS tree structure.
    - `state_ctr`: a signed integer, the number of stateful signatures the keypair has
      previously issued (a negative value is explicitly invalid).
  - Outputs:
    - a 64-bit unsigned integer, the left-to-right index of the next WOTS+C leaf in the FXMSS tree.
    - an 8-bit unsigned integer, the bottom-to-top height of the next WOTS+C leaf in the FXMSS tree.

  Returns `None` if `state_ctr` is set to any negative number, or if `state_ctr + 1` exceeds the
  number of WOTS+C leaves in the FXMSS tree (as defined by its structure).

  This function is only used in the stateful path, and only by the signer.
  """
  tree_shape, tree_depth = structure[0], structure[1]
  if tree_shape == FXMSS_SHAPE_UNBALANCED:
    if state_ctr == tree_depth and tree_depth > 0:
      return (0, FXMSS_HEIGHT - tree_depth)
    if state_ctr >= 0 and state_ctr < tree_depth + 1:
      return (1, FXMSS_HEIGHT - 1 - state_ctr)

  elif tree_shape == FXMSS_SHAPE_BALANCED:
    if state_ctr >= 0 and state_ctr < 2**tree_depth and tree_depth > 0:
      return (state_ctr, FXMSS_HEIGHT - tree_depth)

  # - unknown FXMSS tree shape
  # - depth-zero tree
  # - no more signatures left
  # - state is negative (explicitly invalid)
  return None

def shrincs_sign(message: bytes, shrincs_seckey: bytes, state_ctr: int, opt_rand: Optional[bytes]) -> bytes:
  """
  The SHRINCS signing function. Signs `message` with the serialized secret key `shrincs_seckey`:
  uses the stateful FXMSS path when `state_ctr` is valid for the key's tree structure, otherwise
  falls back to the stateless SLH-DSA path.

  - Inputs:
    - `message`: a message of at most `2**61 - 128` bytes.
    - `shrincs_seckey`: an 82-byte SHRINCS secret key.
    - `state_ctr`: a signed integer, the number of stateful signatures the keypair has
      previously issued (a negative value is explicitly invalid).
    - `opt_rand`: an optional 16-byte salt for the randomizer in SLH-DSA (unused in the stateful path;
      if omitted, the stateless path uses the deterministic variant of SLH-DSA).
  - Output:
    - a variable-length SHRINCS signature.

  This function is used only by the signer.

  > [!CAUTION]
  > Using the same key to sign different `message` values with the same `state_ctr` is
  > a security vulnerability. SHRINCS implementations must wrap `shrincs_sign` with code
  > which increments and saves the state counter as `state_ctr + 1` on a persistent,
  > non-recoverable storage medium before the signature is returned to the caller.
  >
  > The only exception is for invalid (i.e. negative) values of `state_ctr`, which
  > explicitly trigger use of the stateful path.
  """
  sk_seed      = shrincs_seckey[0:16]
  sk_prf       = shrincs_seckey[16:32]
  pk_seed      = shrincs_seckey[32:48]
  sl_root      = shrincs_seckey[48:64]
  sf_structure = shrincs_seckey[64:66]
  sf_root      = shrincs_seckey[66:82]

  leaf_position = shrincs_sf_leaf_select(sf_structure, state_ctr)

  # Stateless signing path.
  if leaf_position is None:
    # Bind the stateless signature to the stateful keypair.
    return slh_dsa_sign(sf_root + message, b"", sk_seed, sk_prf, pk_seed, sl_root, opt_rand)

  # Stateful signing path.
  leaf_index, leaf_height = leaf_position
  ADRS = bytearray(22)
  ADRS[0] = leaf_height
  ADRS[1:9] = leaf_index.to_bytes(8)
  R = PRF_msg_sf(sk_prf, pk_seed, ADRS, message)

  # Bind the stateful signature to the stateless keypair.
  message_digest = H_msg_sf(R, ADRS, pk_seed, sf_root, sl_root + message)
  fxmss_signature = fxmss_sign(message_digest, sk_seed, leaf_index, leaf_height, pk_seed, sf_structure)

  # TODO: compact encoding for leaf index
  return R + leaf_index.to_bytes(8) + fxmss_signature

def shrincs_verify(message: bytes, signature: bytes, shrincs_pubkey: bytes) -> bool:
  """
  The SHRINCS verification function. Returns true iff `signature` is a valid stateful or stateless
  SHRINCS signature on `message` under `shrincs_pubkey`.

  Based on the length of `signature`, the verifier either recomputes `sf_root`
  (stateful path) or recomputes `sl_root` (stateless path), and compares the result
  against the public key.

  - Inputs:
    - `message`: a message of at most `2**61 - 128` bytes.
    - `signature`: a purported SHRINCS signature of arbitrary length.
    - `shrincs_pubkey`: a 48-byte SHRINCS public key.
  - Output:
    - a boolean indicating if the signature is valid.

  This function is used only by the verifier.
  """
  pk_seed = shrincs_pubkey[0:16]
  sl_root = shrincs_pubkey[16:32]
  sf_root = shrincs_pubkey[32:48]

  # Stateless verification path.
  if len(signature) == 16 * (1 + SPHX_FORS_COUNT * (SPHX_FORS_HEIGHT + 1) + SPHX_LAYER_COUNT * (WOTS_TW_CHAIN_COUNT + SPHX_XMSS_HEIGHT)):
    # Stateless signatures must be bound to the stateful keypair.
    return slh_dsa_verify(sf_root + message, signature, b"", pk_seed, sl_root)

  # Stateful verification path.
  if len(signature) < 24:
    return False

  R = signature[0:16]
  leaf_index = int.from_bytes(signature[16:24])
  fxmss_signature = signature[24:len(signature)]

  # Signature must be at least `2 + 16 * (WOTS_C_CHAIN_COUNT + 1)` bytes.
  if len(fxmss_signature) < 2 + 16 * (WOTS_C_CHAIN_COUNT + 1):
    return False
  # Signature must be no longer than `2 + 16 * (WOTS_C_CHAIN_COUNT + FXMSS_HEIGHT)` bytes.
  elif len(fxmss_signature) > 2 + 16 * (WOTS_C_CHAIN_COUNT + FXMSS_HEIGHT):
    return False
  # Signature length must be 2 more than a multiple of 16.
  elif (len(fxmss_signature) - 2) % 16 != 0:
    return False

  leaf_depth = (len(fxmss_signature) - 2) // 16 - WOTS_C_CHAIN_COUNT
  leaf_height = FXMSS_HEIGHT - leaf_depth

  # Reject a leaf_index that names no position in a tree of this depth.
  if leaf_index >= 2 ** min(64, leaf_depth):
    return False

  ADRS = bytearray(22)
  ADRS[0] = leaf_height
  ADRS[1:9] = leaf_index.to_bytes(8)

  # Stateful signatures must be bound to the stateless keypair.
  message_digest = H_msg_sf(R, ADRS, pk_seed, sf_root, sl_root + message)
  root = fxmss_pubkey_from_sig(leaf_index, fxmss_signature, message_digest, pk_seed)
  return root is not None and root == sf_root
