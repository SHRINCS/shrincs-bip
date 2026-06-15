# SHRINCS

This document fully specifies SHRINCS: _Shrunken SPHINCS._

SHRINCS is a hybrid stateful/stateless signature scheme built using only hash functions. The security of SHRINCS rests on the multi-target collision resistance of the underlying base hash function, for which we use SHA256. A detailed proof of security is not provided here.

This spec serves to describe the keygen, signing, and verification algorithms of SHRINCS.

## Overview

At a high-level, a SHRINCS instance consists of two distinct keypairs joined together into one.

1. The first is a stateful XMSS[^xmss] keypair.
2. The other is a fully stateless SPHINCS+ keypair.

The stateless component is an implementation of SLH-DSA[^slhdsa] with algorithms defined as in FIPS-205, but using a non-standard parameter set. The stateful component is a customized implementation of XMSS adapted to suit Bitcoin's use-cases.

Each of these components individually produces a 16-byte hash as its public key. Both pubkeys, together with a 16-byte seed value, form a 48 byte SHRINCS public key.

```py
PK = PK.seed || PK.sf_root || PK.sl_root
```

A signature from either one of these two keypairs is sufficient to pass verification, so the signer has a choice of which algorithm to use depending on their needs.


## Parameters

Here follows a table of parameters.
<!--Mike: Should we add the parameters for maximum depth of the stateful XMSS and maximum width of the stateful XMSS (255 and 2^32)? -->
| Parameter | Value | Description |
|:-:|:-:|:-:|
| `WOTS_C_CHAIN_BITS` | 4 | The number of bits encoded by each Winternitz key chain in the stateful XMSS keypair. |
| `WOTS_TW_CHAIN_BITS` | 4 | The number of bits encoded by each Winternitz key chain in the stateless SPHINCS keypair. |
| `WOTS_C_CHAIN_COUNT` | 32 | The number of Winternitz chains in the stateful XMSS keypair. |
| `WOTS_TW_CHAIN_COUNT1` | 32 | The number of Winternitz message chains per WOTS key in the stateless SPHINCS keypair. |
| `WOTS_TW_CHAIN_COUNT2` | 3 | The number of Winternitz checksum chains per WOTS key in the stateless SPHINCS keypair. |
| `WOTS_TW_CHAIN_COUNT` | 35 | The overall number of Winternitz chains per WOTS key in the stateless SPHINCS keypair. |
| `WOTS_TW_CHECKSUM_MAX` | 480 | The maximum possible sum of Winternitz hash chain indexes in the stateless SPHINCS keypair. |
| `WOTS_C_CONSTANT_SUM` | 240 | The most likely sum for Winternitz hash chain indexes in the stateful XMSS keypair. |
| `SPHX_LAYER_COUNT` | 5 | The number of XMSS layers in the SPHINCS hypertree. |
| `SPHX_XMSS_HEIGHT` | 9 | The height of each XMSS layer within the SPHINCS hypertree. |
| `SPHX_FORS_HEIGHT` | 13 | The height of each FORS tree used in the SPHINCS signature. |
| `SPHX_FORS_COUNT` | 10 | The number of FORS trees used in the SPHINCS signature. |
| `FXMSS_HEIGHT` | 255 | The imaginary height of the FXMSS tree, i.e. the maximum depth of a WOTS+C leaf node. |

## Keygen Inputs

Generating a SHRINCS key is straightforward and consists only of generating 48 random bytes. This is then split into 3 x 16-byte seeds.

- `SK.seed` is the core component of the secret key. Exposing this compromises the security of the keypair.
- `SK.prf` is bonus randomness used for deriving per-message salt values. This is a hedge against faulty signing-time RNG.
- `PK.seed` is a salt value which is appended to the public key.

Note this is the bare minimum needed to generate a full SHRINCS public key. More performant (but larger) secret key representations are possible.

### Padding

Every SHRINCS keypair contains a randomly generated 16-byte salt value called `PK.seed` which is appended to the public key. This salts every hash function invocation to introduce domain separation between different instances of a signature scheme, to counter offline/precomputation attacks, and to reduce the chance that two hash invocations produce the same outputs for different SHRINCS keypairs.

To save computational effort, `PK.seed` is padded to a length of 64 bytes in most cases. This aligns with the SHA256 block size, so that `PK.seed` can be absorbed into the SHA256 state, and that midstate can be cached & reused.

The padding bytes used depend on whether the `PK.seed` is being used to salt the stateful or stateless signing path of SHRINCS. This serves to separate contexts between stateful and stateless paths. This contextual padding of `PK.seed` is denoted by `pad(PK.seed)`.

- In the stateless path, `pad(PK.seed) = PK.seed || repeat(0x00, 48)`
- In the stateful path, `pad(PK.seed) = PK.seed || repeat(0xFF, 48)`

### Utilities

We make use of the following utility helper functions in specifying SHRINCS.

- `ceil(x)`: rounds `x` up to the nearest whole number.
- `floor(x)`: rounds `x` down to the nearest whole number.
- `sum(x)`: sums a sequence of numbers `x`.
- `log2(x)`: returns the base-2 logarithm of `x` (a float/decimal).
- `repeat(b, n)`: returns a bytestring of length `n` containing only the repeated byte `b`.
- `range(start, end)`: returns the ascending sequence of all integers `i` such that `start <= i < end`.
- `be_bytes(i, n)`: returns the big-endian encoding of the unsigned integer `i`, serialized as a string of `n` bytes.
- `be_decode(b)`: returns the integer represented by the given big-endian-encoded bytes `b`.
- `concat(array)`: concatenates the elements of the given `array`.

#### `base_2b(...)`

The `base_2b(x, b, outlen)` helper function decomposes a byte string `x` into `outlen` groups of `b` bits which are each parsed as an integer in the range `[0, 2**b)`. The leading `outlen * b` bits of `x` are parsed, and so `x` must have accordingly sufficient length.

```py
def base_2b(x, b, outlen):
  assert len(x) >= ceil(outlen * b / 8)

  baseb = []      # output array
  j = 0           # counts the bytes read from the input x.
  acc = 0         # accumulator, collects bits from x
  bits_filled = 0 # counts the bits accumulated

  for i in range(0, outlen):
    while bits_filled < b:
      acc = (acc << 8) + x[j]
      j += 1
      bits_filled += 8

    bits_filled -= b
    baseb[i] = acc >> bits_filled
    acc %= 2**bits_filled # prevent accumulator from overflowing

  return baseb
```

# Building Blocks

SHRINCS is a high-level construction built out of many smaller sub-schemes. To fully specify SHRINCS we start by defining the lowest level building blocks - addresses and _tweakable hash functions_ - followed by the one-time signature schemes WOTS-TW and WOTS+C, and then the few-time signature scheme FORS, and finally we will move on to the higher-level constructions like XMSS and SPHINCS, which together form SHRINCS.

```
     ADRS
        \
      tweakable hash
        functions
        /         \
       /         /   \
      /         /      \
   WOTS+C   WOTS-TW   FORS
    /           \      /
   /             \    /
 XMSS      SPHINCS+ (SLH-DSA)
    \             /
     \           /
      \         /
        SHRINCS
```

## ADRS

A critical security property of SHRINCS and its components is that every hash function invocation used in the verification algorithm must be _unique,_ so that inputs used in one hash function cannot be reused to produce the same output in another hash function.

To accomplish this goal, we will use _tweakable hash functions_ (explained below) which modify a hash function with some context-dependent location information. This unambiguously specifies the exact instance of the hash function in the signing/verification algorithms where the hash function is being used. This location is called an _address_ and we encode it into a 22-byte array, often called an `ADRS`.[^adrs]

### ADRS Format
<!--Mike: I think the presentation of ADRS format should be done a bit differently. We can have to tables. One for the stateless and for the stateful. Then we write the purpose of bytes for stateless and stateful there. This way we can also have different names for the fields. -->
| `ADRS` Field | Size | Purpose |
|:-:|:-:|:-:|
| `layer` | 1 byte | In the stateful path, this specifies depth in the XMSS tree. <br> In the stateless path, this specifies the layer in the SPHINCS hypertree. |
| `tree_address` | 8 bytes | A 64-bit integer serialized with big-endian encoding. <br> In the stateful path, this specifies the node index within a layer of the XMSS tree. <br> In the stateless path, this specifies the node index within a layer of the SPHINCS hypertree. |
| `type` | 1 byte | A context-dependent flag which gives meaning to the remaining 12 bytes. |
| `payload` | 12 bytes | <br> Usage depends on the `type` field. <br> <br> |

### ADRS Types

| `ADRS` Type | Value | Purpose | Signing Path |
|:-:|:-:|:-:|:-:|
| `SL_WOTS_TW_HASH` | 0 | Used when iterating WOTS-TW hash chains. | Stateless |
| `SL_WOTS_TW_PK`  | 1 | Used when compressing WOTS-TW public keys. | Stateless |
| `SL_XMSS_TREE` | 2 | Used when combining merkle nodes in the SPHINCS hypertree. | Stateless |
| `SL_FORS_TREE` | 3 | Used when combining merkle nodes in FORS trees. | Stateless |
| `SL_FORS_ROOTS` | 4 | Used when compressing FORS merkle roots together. | Stateless |
| `SL_WOTS_TW_PRF` | 5 | Used when generating WOTS-TW secret preimages. | Stateless |
| `SL_FORS_PRF` | 6 | Used when generating FORS secret preimages. | Stateless |
| `SF_WOTS_C_HASH` | 16 | Used when iterating WOTS+C hash chains. | Stateful |
| `SF_WOTS_C_PK`  | 17 | Used when compressing WOTS+C public keys. | Stateful |
| `SF_FXMSS_TREE` | 18 | Used when combining merkle nodes in the stateful FXMSS tree. | Stateful |
| `SF_WOTS_C_PRF` | 21 | Used when generating WOTS+C secret preimages. | Stateless |
| `SF_WOTS_C_GRIND` | 22 | Used when grinding WOTS+C message digests. | Stateful |

### ADRS Payloads

Each `ADRS` type gives different contextual meaning to the 12 bytes of the ADRS `payload` field. The following table describes how they are used under each ADRS type flag.
| `ADRS` Type | Payload Format |
|:-:|-|
| `SL_WOTS_TW_HASH` | 4 bytes: key pair index <br> 4 bytes: chain index <br> 4 bytes: hash index |
| `SL_WOTS_TW_PK` | 4 bytes: key pair index <br> 8 bytes: zero padding |
| `SL_XMSS_TREE` | 4 bytes: zero padding <br> 4 bytes: tree height <br> 4 bytes: tree index |
| `SL_FORS_TREE` | 4 bytes: key pair index <br> 4 bytes: tree height <br> 4 bytes: tree index |
| `SL_FORS_ROOTS` | 4 bytes: key pair index <br> 8 bytes: zero padding |
| `SL_WOTS_TW_PRF` | 4 bytes: key pair index <br> 4 bytes: chain index <br> 4 bytes: zero padding |
| `SL_FORS_PRF` | 4 bytes: key pair index <br> 4 bytes: zero padding <br> 4 bytes: tree index |
| `SF_WOTS_C_HASH` | 4 bytes: zero padding <br> 4 bytes: chain index <br> 4 bytes: hash index |
| `SF_WOTS_C_PK` | 12 bytes: zero padding |
| `SF_FXMSS_TREE` | 12 bytes: zero padding |
| `SF_WOTS_C_PRF` | 4 bytes: zero padding <br> 4 bytes: chain index <br> 4 bytes: zero padding |
| `SF_WOTS_C_GRIND` | 10 bytes: zero padding <br> 2 bytes: grinding counter |

<!--Mike: How does the SL_XMSS_TREE payload work with the stateful branch. Is not it already specified in (layer + tree_address)? Oh, I see. It is only used in the stateless path. But I think my confusion is a good argument for separating the stateful and stateless ADRS structure into two parts.-->
TODO: make this more visual and explain each field better in context.

## Tweakable Hash Functions

At the core of both SPHINCS and XMSS is the concept of _tweakable hash functions._ A tweakable hash function can be thought of as a hash function which supports additional independent parameters that can be used to scope the hash function to a specific role. This makes security easier to prove.

In SHRINCS, we construct tweakable hash functions using SHA256 as the base hash function. This we invoke as the primitive function `sha256(x)` which returns a 32-byte array.

In one case, we use HMAC-SHA256[^hmac], which we invoke as the function `hmac_sha256(key, msg)`.

```py
def hmac_sha256(key, msg):
  padded_key = repeat(0x00, 64)
  padded_key[0:len(key)] = key
  inner = sha256(xor(padded_key, 0x36) || msg)
  return sha256(xor(padded_key, 0x5C) || inner)
```

SHA256 and HMAC outputs are often truncated, which we denote using Pythonic list-slicing notation: `sha256(x)[:16]`

The following sections describe tweaked hash functions to fill different roles.


### `T_sl(...)`

The tweaked hash function `T_sl` hashes an input `M_l`, which is a sequence of `WOTS_TW_CHAIN_COUNT` hashes, each 16 bytes long, concatenated together. This function will be used to compress Winternitz chain tips to a single hash in SPHINCS.

```py
T_sl(PK.seed, ADRS, M_l) = sha256(pad(PK.seed) || ADRS || M_l)[:16]
```

- Inputs:
  - `PK.seed`: a 16-byte salt.
  - `ADRS`: a 22-byte address.
  - `M_l`: an array of `WOTS_TW_CHAIN_COUNT * 16` bytes.
- Output:
  - A 16-byte hash.

This function is only used in the stateless path.


### `T_sf(...)`

The tweaked hash function `T_sf` hashes an input `M_l`, which is a sequence of `WOTS_C_CHAIN_COUNT` hashes, each 16 bytes long, concatenated together. This function will be used to compress Winternitz chain tips to a single hash in XMSS.

```py
T_sf(PK.seed, ADRS, M_l) = sha256(pad(PK.seed) || ADRS || M_l)[:16]
```

- Inputs:
  - `PK.seed`: a 16-byte salt.
  - `ADRS`: a 22-byte address.
  - `M_l`: an array of `WOTS_C_CHAIN_COUNT * 16` bytes.
- Output:
  - A 16-byte hash.

This function is only used in the stateful path.


### `F(...)`

The tweaked hash function `F` hashes an input `M_1`, which is a single 16-byte hash. This function will be used to generate and iterate Winternitz hash chains and to hash FORS leaves.

```py
F(PK.seed, ADRS, M_1) = sha256(pad(PK.seed) || ADRS || M_1)[:16]
```

- Inputs:
  - `PK.seed`: a 16-byte salt.
  - `ADRS`: a 22-byte address.
  - `M_1`: a 16-byte hash.
- Output:
  - A 16-byte hash.

This function is used in both stateful and stateless paths.


### `H(...)`

The tweaked hash function `H` hashes an input `M_2`, which is a pair of 16-byte hashes, concatenated together. This function will be used to combine pairs of merkle nodes, to construct merkle trees in XMSS and FORS.

```py
H(PK.seed, ADRS, M_2) = sha256(pad(PK.seed) || ADRS || M_2)[:16]
```

- Inputs:
  - `PK.seed`: a 16-byte salt.
  - `ADRS`: a 22-byte address.
  - `M_2`: an array of 32 bytes.
- Output:
  - A 16-byte hash.

This function is used in both stateful and stateless paths.


### `H_grind(...)`

The tweaked hash function `H_grind` hashes a 32-byte message `digest` and a grinding `counter`. This function will be used to map `digest` into a constant-sum message space for WOTS+C.

```py
H_grind(PK.seed, position, digest, counter) =
  sha256(pad(PK.seed) || position || digest || repeat(0x00, 4) || be_bytes(counter, 2))[:16]
```

- Inputs:
  - `PK.seed`: a 16-byte salt.
  - `position`: a 10-byte identifier for the position of the WOTS+C leaf.
  - `digest`: an array of 32 bytes.
  - `counter`: a 16-bit unsigned integer.
- Output:
  - A 16-byte hash.

This function is only used in the stateful path.

The extra 4 bytes of padding before the counter ensures the counter lines up with the SHA256 message schedule boundaries.

### `PRF(...)`

The tweaked hash function `PRF` hashes `SK.seed` with an `ADRS` to derive secret preimage values needed for signing and key generation.

```py
PRF(PK.seed, SK.seed, ADRS) = sha256(pad(PK.seed) || ADRS || SK.seed)[:16]
```

- Inputs:
  - `PK.seed`: a 16-byte salt.
  - `SK.seed`: a 16-byte secret.
  - `ADRS`: a 22-byte address.
- Output:
  - A 16-byte hash.


This function is used in both stateful and stateless paths, but only by the signing algorithm.

Note the order of the arguments passed to `PRF` is _not_ the same order in which those arguments are processed by `sha256`. This aligns with definitions in FIPS-205[^slhdsa].

### `H_msg_sl(...)`

The tweaked hash function `H_msg_sl` hashes a _randomizer_ `R`, the `PK.seed`, a merkle root `root`, and an arbitrary-length (TODO: fixed-length?) message bytestring `M`. It will be used to produce a digest for signing in the stateless path.

```py
H_msg_sl(R, PK.seed, root, M) = sha256(R || PK.seed || sha256(R || PK.seed || root || M) || 0x00000000)
```
- Inputs:
  - `R`: a 16-byte randomizer.
  - `PK.seed`: a 16-byte salt.
  - `root`: a 16-byte hash.
  - `M`: an arbitrary-length bytestring (TODO).
- Output:
  - A 32-byte hash.

This function is only used in the stateless path.

The 4-byte zero-padding at the end of the outer hash input ensures `H_msg_sl` satisfies FIPS-205[^slhdsa], wherein `H_msg_sl` is defined using MGF1-SHA-256[^mgf1].

Note that `PK.seed` is not padded in this tweaked hash function.

### `H_msg_sf(...)`

The tweaked hash function `H_msg_sf` hashes a _randomizer_ `R`, the `PK.seed`, a merkle root `root`, and an arbitrary-length (TODO: fixed-length?) message bytestring `M`. It will be used to produce a digest for signing in the stateful path.

```py
H_msg_sf(R, PK.seed, root, position, M) = sha256(R || PK.seed || position || sha256(R || PK.seed || root || position || M))
```

TODO: can `position` be used only once?

- Inputs:
  - `R`: a 16-byte randomizer.
  - `PK.seed`: a 16-byte salt.
  - `root`: a 16-byte hash.
  - `position`: a 9-byte specifier of the location of the WOTS+C leaf keypair.
  - `M`: an arbitrary-length bytestring (TODO).
- Output:
  - A 32-byte hash.

This function is only used in the stateful path.

Note that `PK.seed` is not padded in this tweaked hash function.

### `PRF_msg(...)`

The tweaked hash function `PRF_msg` uses HMAC-SHA256 to hash `SK.prf`, randomness `opt_rand`, and an arbitrary-length message `M` (TODO: fixed length?). This function will be used to derive a _randomizer_ (salt) for the given message.

```py
PRF_msg(SK.prf, opt_rand, M) = hmac_sha256(SK.prf, opt_rand || M)[:16]
```

- Inputs:
  - `SK.prf`: a 16-byte secret.
  - `opt_rand`: a 16-byte salt.
  - `M`: an arbitrary-length bytestring (TODO).
- Output:
  - A 16-byte hash.

This function is used in both stateful and stateless paths, but only by the signing algorithm.

If deterministic signing is required and an RNG is not available, `opt_rand` will be set to `PK.seed`.

TODO: domain separate between stateful/stateless.

### Implementation Notes

- The only difference between `T_sf`, `T_sl`, `F`, and `H` is the byte-length of the third input parameter. They are defined as different hash functions for security.
- `PRF_msg` may be replaced with an XOF such as MGF1-SHA-256 or SHAKE256, from which the caller can sample multiple randomizers for the purposes of grinding to implement hypertree pruning[^pruning] more efficiently. For security, the XOF itself needs to provide the required security guarantees of a PRF, and the XOF should absorb the same inputs as `PRF_msg`.
- `F(...)` is the most performance-critical hash function to optimize, as it dominates the runtime of signing, keygen, and verification.
- The padded `PK.seed` should be absorbed into a SHA256 midstate which is cached and reused. **This doubles performance.**
- These tweaked hash functions often handle secret inputs like `SK.seed`, so implementations should be free of control flows which branch and leak side-channel information based on potentially-secret data. Inputs should not be copied in memory unless securely erased afterwards.
- Many of these hash functions are invoked on independent data, and so can be run in parallel. Platforms with access to vectorized (SIMD) instruction sets on x86[^simd_x86] or ARM[^simd_arm] CPUs may utilize them to parallelize SHA256[^sha256x8] to improve performance significantly: a factor of 4 or more in some cases.
- Implementors can use SHA2 hardware acceleration[^sha_ni], though this is best used to accelerate verification, not signing or keygen[^sha_ni_bench].


## WOTS Schemes

A _one-time signature_ (OTS) scheme restricts signers to creating at most one signature per keypair. If this assumption is broken by publishing distinct signatures, then adversaries will be capable of forging new ones. While limited in their practical utility, hash-based OTS schemes are a crucial building block to construct more advanced hash-based signature schemes.

The following two sections describe a pair of related one-time signature schemes: WOTS-TW and WOTS+C.

- WOTS+C is used for the stateful signing path.
- WOTS-TW is used for the stateless signing path.

Both WOTS-TW and WOTS+C are variants of the original _Winternitz one-time signature scheme_ (WOTS).[^merkle]

### Informal Description

Here follows an intuitive description of Winternitz OTS (WOTS) schemes in general.

A WOTS private key is an array of secret preimages. Each preimage is hashed, and the output is then hashed again, and so on, forming a _chain_ of hashes. After some prescribed number of steps in the chain (iterating the hash function) we reach the _tip_ of the hash chain. The _tips_ of those hash chains form the Winternitz public key.

To sign, the key holder maps an approved message to a set of integers which each index a node in a hash chain, and reveals the hashes at those indexes as the Winternitz signature.

The verifier maps the message to those same integers as the signer did, and finishes computing the hash chains. If the signer revealed the correct nodes, then the verifier will have recomputed the same hash chain tips that compose the signer's public key.

<img src="img/wots-diagram-generic.svg">

<sup>This diagram illustrates a simplified example of WOTS, using 4 hash chains of length 4 to sign an 8-bit message.</sup>

As written this would be insecure: Adversaries could forge signatures by finding a message which maps to a higher set of indexes. WOTS-TW and WOTS+C differ only in their solutions to this problem: WOTS-TW appends additional "checksum" hash chains, while WOTS+C appends a small salt which the signer must grind to find a set of indexes which sum to a specific constant.

## WOTS Algorithm

Both WOTS schemes make use of the following common hash-chaining algorithm.

### `wots_chain_iter(...)`

The WOTS hash chain iteration function. Takes in a 16-byte hash `node` at a given `start` index in a hash chain. This method iterates the hash chain by `steps` iterations, returning the hash chain node at index `start+steps`. The `ADRS` must be prefilled to ensure the hashes are properly tweaked.

```py
def wots_chain_iter(node, start, steps, PK.seed, ADRS):
  for j in range(start, start+steps):
    ADRS[18:22] = be_bytes(j, 4)
    node = F(PK.seed, ADRS, node)
  return node
```

- Inputs:
  - `node`: a 16-byte hash.
  - `start`: an unsigned integer indicating the index of `node` in the hash chain.
  - `steps`: an unsigned integer indicating how many steps to take up the hash chain.
  - `PK.seed`: a 16-byte salt.
  - `ADRS`: a 22-byte address.
- Output:
  - A 16-byte hash at index `start + steps`.

This function is used very heavily by both stateful and stateless paths and is the core target for optimization and parallelization.

## WOTS-TW

WOTS-TW is the classic variant of Winternitz one-time signatures[^merkle] which uses a checksum to prevent forgeries. In WOTS-TW, a 128-bit message is mapped directly into an array of `WOTS_TW_CHAIN_COUNT1` hash chain indexes, and the checksum is simply the negation of the sum of those indexes. This checksum is then encoded into `WOTS_TW_CHAIN_COUNT2` hash chain indexes which are appended to the message indexes before signing and verification.

This process starts by breaking a 128-bit message into `WOTS_TW_CHAIN_COUNT1` integers of `WOTS_TW_CHAIN_BITS` bits each in the range `[0, 2**WOTS_TW_CHAIN_BITS)`. The maximum possible sum of those indexes would be if every index was equal to `2**WOTS_TW_CHAIN_BITS - 1`, so the maximum sum is

```py
WOTS_TW_CHECKSUM_MAX = WOTS_TW_CHAIN_COUNT1 * (2**WOTS_TW_CHAIN_BITS - 1)
```

This constant is defined explicitly in the earlier [table of constants](#Parameters).

Given an array of `msg_indexes`, the checksum can be computed by:

```py
checksum = WOTS_TW_CHECKSUM_MAX - sum(msg_indexes)
```

This checksum is then converted into `WOTS_TW_CHAIN_COUNT2` integers of `WOTS_TW_CHAIN_BITS` bits each, which are appended to the original `msg_indexes`.

### `wots_tw_message_to_indexes(...)`

The WOTS-TW message map function.

Converts a 16-byte `message` to a checksummed array of `WOTS_TW_CHAIN_COUNT` WOTS hash chain indexes in the range `[0, 2**WOTS_TW_CHAIN_BITS)`.

```py
def wots_tw_message_to_indexes(message):
  msg_indexes = base_2b(message, WOTS_TW_CHAIN_BITS, WOTS_TW_CHAIN_COUNT1)
  checksum = WOTS_TW_CHECKSUM_MAX - sum(msg_indexes)

  checksum_indexes = []
  for i in range(0, WOTS_TW_CHAIN_COUNT2):
    checksum_indexes[WOTS_TW_CHAIN_COUNT2 - 1 - i] = checksum % (2**WOTS_TW_CHAIN_BITS)
    checksum >>= WOTS_TW_CHAIN_BITS

  return msg_indexes || checksum_indexes
```

```py
# Alternate definition from FIPS-205 (algorithm 7); The above algorithm is equivalent to this.
SPHX_WOTS_CHECKSUM_SHIFT = (8 - (WOTS_TW_CHAIN_BITS * WOTS_TW_CHAIN_COUNT2) % 8) % 8
SPHX_WOTS_CHECKSUM_BYTE_LEN = ceil(WOTS_TW_CHAIN_COUNT2 * WOTS_TW_CHAIN_BITS / 8)
def wots_tw_message_to_indexes_alt(message):
  msg_indexes = base_2b(message, WOTS_TW_CHAIN_BITS, WOTS_TW_CHAIN_COUNT1)
  checksum = (WOTS_TW_CHECKSUM_MAX - sum(msg_indexes)) << SPHX_WOTS_CHECKSUM_SHIFT
  checksum_bytes = be_bytes(checksum, SPHX_WOTS_CHECKSUM_BYTE_LEN)
  checksum_indexes = base_2b(checksum_bytes, WOTS_TW_CHAIN_BITS, WOTS_TW_CHAIN_COUNT2)
  return msg_indexes || checksum_indexes
```

- Inputs:
  - `message`: a 16-byte hash
- Output:
  - An checksummed array of `WOTS_TW_CHAIN_BITS`-bit integers of length `WOTS_TW_CHAIN_COUNT`.

This algorithm is used by both signer and verifier, and **it is security-critical for both implementations to match.** Note especially how the bits of the checksum are sliced off and appended to the very end of the final encoding; The checksum bits are NOT appended directly to the message indexes.

#### Example

Consider the following message indexes:

```py
msg = [10, 11, 2, 2, 3, 12, 15, 8, 1, 2, 8, 2, 2, 10, 9, 13, 10, 11, 2, 2, 3, 12, 15, 8, 1, 2, 8, 2, 2, 10, 9, 13]
```

The checksum of these message indexes is:

```py
checksum = WOTS_TW_CHECKSUM_MAX - sum(msg)
         = 260
         = 0b100000100
```

The original message has a binary representation:

```
1010 1011 0010 ... 1010 1001 1101
```


After appending the checksum, the final checksummed index sequence should look like this:

```
1010 1011 0010 ... 1010 1001 1101 0001 0000 0100
                                  ^^^^^^^^^^^^^^
                                     checksum
```


### `wots_tw_pubkey_gen(...)`

The WOTS-TW public key generation function. Takes in the secret `SK.seed`, the `PK.seed`, and an `ADRS`. The `ADRS` should be prefilled with the location of the WOTS keypair being used.

```py
def wots_tw_pubkey_gen(SK.seed, PK.seed, ADRS):
  wots_pk = []
  for i in range(0, WOTS_TW_CHAIN_COUNT):
    ADRS[9] = SL_WOTS_TW_PRF
    ADRS[14:18] = be_bytes(i, 4)  # chain index
    ADRS[18:22] = repeat(0x00, 4) # zero hash index
    sk = PRF(PK.seed, SK.seed, ADRS)
    ADRS[9] = SL_WOTS_TW_HASH
    wots_pk[i] = wots_chain_iter(sk, 0, 2**WOTS_TW_CHAIN_BITS - 1, PK.seed, ADRS)

  ADRS[9] = SL_WOTS_TW_PK
  ADRS[14:22] = repeat(0x00, 8)
  wots_pk_hash = T_sl(PK.seed, ADRS, concat(wots_pk))
  return wots_pk_hash
```

- Inputs:
  - `SK.seed`: a 16-byte secret.
  - `PK.seed`: a 16-byte salt.
  - `ADRS`: a 22-byte address.
- Output:
  - A 16-byte hash representing the WOTS-TW public key.

This algorithm is used only by the signer.


### `wots_tw_sign(...)`

The WOTS-TW signing function. Takes in a 16-byte `message`, the `SK.seed` and `PK.seed`, and an `ADRS`. The `ADRS` should be prefilled with the location of the WOTS keypair being used.

```py
def wots_tw_sign(message, SK.seed, PK.seed, ADRS):
  indexes = wots_tw_message_to_indexes(message)
  signature = []
  for i in range(0, WOTS_TW_CHAIN_COUNT):
    ADRS[9] = SL_WOTS_TW_PRF
    ADRS[14:18] = be_bytes(i, 4)  # chain index
    ADRS[18:22] = repeat(0x00, 4) # zero hash index
    sk = PRF(PK.seed, SK.seed, ADRS)
    ADRS[9] = SL_WOTS_TW_HASH
    signature[i] = wots_chain_iter(sk, 0, indexes[i], PK.seed, ADRS)
  return concat(signature)
```

- Inputs:
  - `message`: a 16-byte message to sign.
  - `SK.seed`: a 16-byte secret.
  - `PK.seed`: a 16-byte salt.
  - `ADRS`: a 22-byte address.
- Output:
  - A WOTS signature composed of `WOTS_TW_CHAIN_COUNT * 16` bytes.

This algorithm is used only by the signer.


### `wots_tw_pubkey_from_sig(...)`

The WOTS-TW verification procedure. Recovers a WOTS-TW public key from a `signature` on a given 16-byte `message`. Takes in the `PK.seed`. The `ADRS` should be prefilled with the location of the WOTS keypair being used.

```py
def wots_tw_pubkey_from_sig(signature, message, PK.seed, ADRS):
  indexes = wots_tw_message_to_indexes(message)
  wots_pk = []
  ADRS[9] = SL_WOTS_TW_HASH
  for i in range(0, WOTS_TW_CHAIN_COUNT):
    ADRS[14:18] = be_bytes(i, 4)
    steps = 2**WOTS_TW_CHAIN_BITS - 1 - indexes[i]
    wots_pk[i] = wots_chain_iter(signature[i*16 : (i+1)*16], indexes[i], steps, PK.seed, ADRS)

  ADRS[9] = SL_WOTS_TW_PK
  ADRS[14:22] = repeat(0x00, 8)
  wots_pk_hash = T_sl(PK.seed, ADRS, concat(wots_pk))
  return wots_pk_hash
```

- Inputs:
  - `signature`: a string of `WOTS_TW_CHAIN_COUNT * 16` bytes.
  - `message`: a 16-byte message.
  - `PK.seed`: a 16-byte salt.
  - `ADRS`: a 22-byte address.
- Output:
  - A 16-byte hash representing the WOTS-TW public key.

This algorithm is used by both signers and verifiers.

## WOTS+C

WOTS+C was designed as an improvement to WOTS-TW[^sphincs+c]. It is superior in compactness & performance, but we nonetheless use WOTS-TW for the stateless path to retain compatibility with SLH-DSA[^slhdsa], while WOTS+C is used in the custom stateful component of SHRINCS to reduce signature size.

WOTS+C replaces the checksum in WOTS-TW with a protocol requirement that any message must be mapped to a set of indexes that sum to a fixed constant. This prevents WOTS forgeries because an incremental increase in any index of a hash chain must be balanced out by decrementing a different index. It also ensures a constant-time verifier because the number of hash operations needed to complete every WOTS hash chain is fixed.

The constant-sum parameter `WOTS_C_CONSTANT_SUM` is chosen to maximize the probability that a randomly selected set of indexes will sum to this value. It can be computed by:

```py
WOTS_C_CONSTANT_SUM = floor(WOTS_C_CHAIN_COUNT * (2**WOTS_C_CHAIN_BITS - 1) / 2)
```

Only a subset of index-sets have this "constant-sum" property - about 2<sup>122</sup> out of the possible 2<sup>128</sup> sets of indexes. To map a given message onto this subset, the signer must _grind_ a hash function applied to the message and a rolling integer counter. The hash function ensures the surjective mapping of messages to index-sets is one-way and distributed randomly. If the mapping were not one-way, an attacker could work backwards to find other messages valid under the same signature.

Eventually the signer finds a counter which maps the message to a set of indexes that sum to `WOTS_C_CONSTANT_SUM`. This counter is appended to the WOTS+C signature. The verifier rejects counters which don't map the message to a constant-sum index-set.

### `wots_c_grind_to_constant_sum(...)`

The WOTS+C grinding function. Takes in a `message_digest`, the `PK.seed`, and an `ADRS`, and grinds - up to a maximum of 2<sup>16</sup> attempts - until we find a counter that maps to a constant sum index-set. Returns the lowest valid integer counter and the corresponding array of constant-sum hash chain indexes. The `ADRS` should be prefilled with the location of the WOTS+C key which will be used to sign the resulting indexes.

```py
def wots_c_grind_to_constant_sum(PK.seed, message_digest, ADRS):
  ADRS[9] = SF_WOTS_C_GRIND
  for i in range(0, 2**16):
    hashed = H_grind(PK.seed, ADRS[0:10], message_digest, i)
    indexes = base_2b(hashed, WOTS_C_CHAIN_BITS, WOTS_C_CHAIN_COUNT)
    if sum(indexes) == WOTS_C_CONSTANT_SUM:
      return (i, indexes)

  raise "UNREACHABLE" # practically impossible
```

- Inputs:
  - `PK.seed`: a 16-byte salt.
  - `message_digest`: a 32-byte intermediate message digest (from `H_msg_sf`).
  - `ADRS`: a 22-byte address.
- Outputs:
  - The smallest possible valid counter.
  - The corresponding constant-sum set of hash chain indexes.

This algorithm is used only by the signer.

We max out at 2<sup>16</sup> grinding attempts because the counter is serialized as a 16-bit unsigned integer in the WOTS+C signature encoding - Counters larger than this would not fit into a signature. There is technically a chance that the signer may exhaust all of these attempts without finding a valid counter, however this probability is less than 1 chance in 2<sup>1000</sup>[^wotsgrind] - practically impossible.
<!-- Mike: This estimation is only for this parameter sets. For different parameter sets this can be a worse bound.-->

### `wots_c_map_digest(...)`

The WOTS+C digest validation function. Takes in a `message_digest`, the `PK.seed`, an `ADRS`, and a `counter` parsed from a WOTS+C signature. This evaluates the grinding counter and attempts to map the digest to a constant sum set of hash chain indexes. If the `counter` is valid, this function returns the constant sum index-set. Otherwise, it returns null.

```py
def wots_c_map_digest(PK.seed, message_digest, ADRS, counter):
  ADRS[9] = SF_WOTS_C_GRIND
  hashed = H_grind(PK.seed, ADRS[0:10], message_digest, counter)
  indexes = base_2b(hashed, WOTS_C_CHAIN_BITS, WOTS_C_CHAIN_COUNT)
  if sum(indexes) == WOTS_C_CONSTANT_SUM:
    return indexes
  else:
    return None
```

- Inputs:
  - `PK.seed`: a 16-byte salt.
  - `message_digest`: a 32-byte intermediate message digest (from `H_msg_sf`).
  - `ADRS`: a 22-byte address.
  - `counter`: an unsigned integer.
- Output:
  - A constant-sum set of hash chain indexes, or null.

This algorithm is used only by the verifier.


### `wots_c_pubkey_gen(...)`

The WOTS+C public key generation function. Takes in the secret `SK.seed`, the `PK.seed`, and an `ADRS`. The `ADRS` should be prefilled with the location of the WOTS keypair being used.

```py
def wots_c_pubkey_gen(SK.seed, PK.seed, ADRS):
  wots_pk = []
  ADRS[10:14] = repeat(0x00, 4) # zeros reserved
  for i in range(0, WOTS_C_CHAIN_COUNT):
    ADRS[9] = SF_WOTS_C_PRF
    ADRS[14:18] = be_bytes(i, 4)  # chain index
    ADRS[18:22] = repeat(0x00, 4) # zero hash index
    sk = PRF(PK.seed, SK.seed, ADRS)
    ADRS[9] = SF_WOTS_C_HASH
    wots_pk[i] = wots_chain_iter(sk, 0, 2**WOTS_C_CHAIN_BITS - 1, PK.seed, ADRS)

  ADRS[9] = SF_WOTS_C_PK
  ADRS[14:22] = repeat(0x00, 8)
  wots_pk_hash = T_sf(PK.seed, ADRS, concat(wots_pk))
  return wots_pk_hash
```

- Inputs:
  - `SK.seed`: a 16-byte secret.
  - `PK.seed`: a 16-byte salt.
  - `ADRS`: a 22-byte address.
- Output:
  - A 16-byte hash representing the WOTS+C public key.

This algorithm is used only by the signer.


### `wots_c_sign(...)`

The WOTS+C signing function. Takes in a 32-byte `message_digest`, the `SK.seed` and `PK.seed`, and an `ADRS`. The `ADRS` should be prefilled with the location of the WOTS keypair being used.

```py
def wots_c_sign(message_digest, SK.seed, PK.seed, ADRS):
  counter, indexes = wots_c_grind_to_constant_sum(PK.seed, message_digest, ADRS)
  signature = []

  ADRS[10:14] = repeat(0x00, 4) # zeros reserved
  for i in range(0, WOTS_C_CHAIN_COUNT):
    ADRS[9] = SF_WOTS_C_PRF
    ADRS[14:18] = be_bytes(i, 4)  # chain index
    ADRS[18:22] = repeat(0x00, 4) # zero hash index
    sk = PRF(PK.seed, SK.seed, ADRS)
    ADRS[9] = SF_WOTS_C_HASH
    signature[i] = wots_chain_iter(sk, 0, indexes[i], PK.seed, ADRS)
  return (concat(signature), counter)
```

- Inputs:
  - `message_digest`: a 32-byte message digest to sign.
  - `SK.seed`: a 16-byte secret.
  - `PK.seed`: a 16-byte salt.
  - `ADRS`: a 22-byte address.
- Outputs:
  - A WOTS signature composed of `WOTS_C_CHAIN_COUNT * 16` bytes.
  - A 16-bit integer grinding counter.

This algorithm is used only by the signer.


### `wots_c_pubkey_from_sig(...)`

The WOTS+C verification procedure. Recovers a WOTS+C public key from a `signature` on a given 32-byte `message_digest`. Takes in a grinding `counter`, the `PK.seed`, and an `ADRS`. The `ADRS` should be prefilled with the location of the WOTS keypair being used.

```py
def wots_c_pubkey_from_sig(signature, counter, message_digest, PK.seed, ADRS):
  indexes = wots_c_map_digest(PK.seed, message_digest, ADRS, counter)

  # Reject if counter doesn't satisfy the constant-sum requirement.
  if indexes is None:
    return None

  wots_pk = []
  ADRS[9] = SF_WOTS_C_HASH
  ADRS[10:14] = repeat(0x00, 4) # zeros reserved
  for i in range(0, WOTS_C_CHAIN_COUNT):
    ADRS[14:18] = be_bytes(i, 4)
    steps = 2**WOTS_C_CHAIN_BITS - 1 - indexes[i]
    wots_pk[i] = wots_chain_iter(signature[i*16 : (i+1)*16], indexes[i], steps, PK.seed, ADRS)

  ADRS[9] = SF_WOTS_C_PK
  ADRS[14:22] = repeat(0x00, 8)
  wots_pk_hash = T_sf(PK.seed, ADRS, concat(wots_pk))
  return wots_pk_hash
```

- Inputs:
  - `signature`: a string of `WOTS_C_CHAIN_COUNT * 16` bytes.
  - `counter`: a 16-bit unsigned integer.
  - `message_digest`: a 32-byte message digest.
  - `PK.seed`: a 16-byte salt.
  - `ADRS`: a 22-byte address.
- Output:
  - A 16-byte hash representing the WOTS+C public key, or null.

This algorithm is used by both signers and verifiers.

## XMSS

The _eXtended Merkle Signature Scheme_ (XMSS) is a stateful hash-based signature scheme which can produce signatures on up to a fixed number of messages.

Conceptually, an XMSS keypair is a merkle tree whose leaves are one-time signature (OTS) keypairs. The XMSS public key is the root hash of the merkle tree. An XMSS signature is an OTS signature alongside a merkle tree authentication proof which links the OTS public key to the merkle root hash. The verifier recomputes the OTS public key, and follows the merkle proof to recompute the XMSS public key.

TODO: insert diagram

In SHRINCS, we instantiate XMSS twice, to be used differently in both stateful and stateless components of a SHRINCS keypair.

- In the stateless component, traditional balanced XMSS is used with WOTS-TW as the leaf OTS scheme to certify child layers of the SPHINCS hypertree, and to certify FORS public keys.
- In the stateful component, Flexible XMSS (FXMSS) is used with WOTS+C to sign messages directly.

In XMSS (stateless path), merkle trees are always perfectly balanced, and always have a fixed height `SPHX_XMSS_HEIGHT`. This aligns with FIPS-205 standards.

In FXMSS (stateful path), merkle trees can be balanced or unbalanced, and the WOTS+C leaf keys may be placed up to `FXMSS_HEIGHT` layers deep. This permits more flexible constructions.

Notably for security, XMSS is always used as part of the SPHINCS framework to sign trusted messages generated by the signer, while FXMSS is used as a standalone scheme and so may sign untrusted messages. This means the interfaces of both XMSS and FXMSS are slightly different, and this is a crucial security requirement.

The following sections describe the XMSS and FXMSS algorithms.


## XMSS

These algorithms are used only for the stateless XMSS sub-scheme.


### `xmss_node(...)`

The XMSS internal node computation helper function. This is a recursive function which takes in the `SK.seed`, a target `node_index`, a `node_height`, the `PK.seed`, and an `ADRS`.

```py
def xmss_node(SK.seed, node_index, node_height, PK.seed, ADRS):
  # Bottom layer: return the WOTS-TW pubkey hash.
  if node_height == 0:
    ADRS[10:14] = be_bytes(node_index, 4)
    return wots_tw_pubkey_gen(SK.seed, PK.seed, ADRS)

  # Recursively derive the left/right child nodes
  lchild_index = 2 * node_index
  lchild_height = node_height - 1
  lchild = xmss_node(SK.seed, lchild_index, lchild_height, PK.seed, ADRS)
  rchild = xmss_node(SK.seed, lchild_index + 1, lchild_height, PK.seed, ADRS)

  # Compute & return the parent node.
  ADRS[9] = SL_XMSS_TREE
  ADRS[10:14] = repeat(0x00, 4)
  ADRS[14:18] = be_bytes(node_height)
  ADRS[18:22] = be_bytes(node_index)
  return H(PK.seed, ADRS, lchild || rchild)
```

- Inputs:
  - `SK.seed`: a 16-byte secret.
  - `node_index`: An unsigned integer indicating the index (from the left) of the desired node in the BMXSS layer.
  - `node_height`: An unsigned integer indicating the height (from the bottom) of the desired node in the BMXSS layer.
  - `PK.seed`: a 16-byte salt.
  - `ADRS`: a 22-byte address.
- Outputs:
  - A 16-byte XMSS node hash

This algorithm is used only by the signer.


### `xmss_sign(...)`

The XMSS signing procedure. This function produces a deterministic WOTS-TW signature using a specific leaf of a XMSS tree, and appends a merkle authentication path to form a XMSS signature. Takes in the `message` to sign, the `SK.seed`, the `keypair_index` to sign with, the `PK.seed`, and an `ADRS` which contains a pre-filled WOTS-TW keypair index.

```py
def xmss_sign(message, SK.seed, keypair_index, PK.seed, ADRS):
  # Sign the message with WOTS-TW
  ADRS[10:14] = be_bytes(keypair_index, 4)
  sig = wots_tw_sign(message, SK.seed, PK.seed, ADRS):

  # Append the Merkle authentication path
  for j in range(0, SPHX_XMSS_HEIGHT):
    sibling_index = (keypair_index >> j) ^ 1
    sig = sig || xmss_node(SK.seed, sibling_index, j, PK.seed, ADRS)

  return sig
```

- Inputs:
  - `message`: a 16-byte message to sign.
  - `SK.seed`: a 16-byte secret.
  - `keypair_index`: The index of the WOTS-TW keypair to sign with.
  - `PK.seed`: a 16-byte salt.
  - `ADRS`: a 22-byte address.
- Outputs:
  - A XMSS signature consisting of `16 * (SPHX_XMSS_HEIGHT + WOTS_TW_CHAIN_COUNT)` bytes.

This algorithm is used only by the signer.


### `xmss_pubkey_from_sig(...)`

The XMSS verification function. Recovers an XMSS public key from a `signature` on a given 16-byte `message`. Takes in the `PK.seed`, and an `ADRS`. The exact position of the WOTS-TW signing leaf is given by the `keypair_index` argument.

```py
def xmss_pubkey_from_sig(keypair_index, signature, message, PK.seed, ADRS):
  wots_sig = signature[0 : WOTS_TW_CHAIN_COUNT*16]
  xmss_auth = signature[WOTS_TW_CHAIN_COUNT*16 : (WOTS_TW_CHAIN_COUNT+SPHX_XMSS_HEIGHT)*16]

  ADRS[10:14] = be_bytes(keypair_index, 4) # AKA keypair address
  node = wots_tw_pubkey_from_sig(wots_sig, message, PK.seed, ADRS):

  ADRS[9] = SL_XMSS_TREE
  ADRS[10:14] = repeat(0x00, 4)

  for k in range(0, SPHX_XMSS_HEIGHT):
    ADRS[14:18] = be_bytes(k, 4)
    ADRS[18:22] = be_bytes(keypair_index >> (k+1), 4)
    sibling = xmss_auth[k*16 : (k+1)*16]
    if (keypair_index >> k) & 1:
      node = H(PK.seed, ADRS, sibling || node)
    else:
      node = H(PK.seed, ADRS, node || sibling)

  return node
```

- Inputs:
  - `keypair_index`: a 32-bit unsigned integer.
  - `signature`: an XMSS signature consisting of `16 * (WOTS_TW_CHAIN_COUNT + SPHX_XMSS_HEIGHT)` bytes.
  - `message`: a 16-byte message.
  - `keypair_index`: The index of the WOTS-TW keypair to sign with.
  - `PK.seed`: a 16-byte salt.
  - `ADRS`: a 22-byte address.
- Output:
  - a 16-byte XMSS root node hash


## FXMSS

These algorithms are used only for the stateful FXMSS sub-scheme.


### `fxmss_node(...)`
TODO


### `fxmss_sign(...)`
TODO


### `fxmss_pubkey_from_sig(...)`

The FXMSS verification function. Recovers an FXMSS public key from a `signature` on a given 32-byte `message_digest`. Takes in a grinding `counter`, the `PK.seed`, and an `ADRS`.

The length of the `signature` implies the depth of the WOTS+C signing leaf. The exact left/right position of the WOTS+C signing leaf within its layer is given explicitly by the `node_index` argument.

```py
def fxmss_pubkey_from_sig(node_index, signature, counter, message_digest, PK.seed, ADRS):
  wots_sig = signature[0 : WOTS_C_CHAIN_COUNT*16]
  xmss_auth = signature[WOTS_C_CHAIN_COUNT*16 : len(signature)]

  node_depth = floor(len(xmss_auth) / 16)

  # Ensure node_index describes a valid position in the FXMSS tree.
  assert node_index < 2 ** min(64, node_depth)

  node_height = FXMSS_HEIGHT - node_depth

  ADRS[0] = node_height
  ADRS[1:9] = be_bytes(node_index, 8)
  node = wots_c_pubkey_from_sig(wots_sig, counter, message_digest, PK.seed, ADRS)
  if node is None:
    return None

  ADRS[9] = SF_FXMSS_TREE
  ADRS[10:22] = repeat(0x00, 12)

  for k in range(0, node_depth):
    ADRS[0] += 1
    ADRS[1:9] = be_bytes(node_index >> (k+1), 8)
    sibling = xmss_auth[k*16 : (k+1)*16]
    if (node_index >> k) & 1:
      node = H(PK.seed, ADRS, sibling || node)
    else:
      node = H(PK.seed, ADRS, node || sibling)

  return node
```

- Inputs:
  - `node_index`: a 64-bit unsigned integer.
  - `signature`: a variable-length FXMSS signature.
    - Must be at least `16 * WOTS_C_CHAIN_COUNT` bytes long.
    - Must be no longer than `16 * (WOTS_C_CHAIN_COUNT + FXMSS_HEIGHT)` bytes long.
    - Byte length must be a multiple of 16.
  - `counter`: a 16-bit unsigned integer.
  - `message_digest`: a 32-byte message digest.
  - `PK.seed`: a 16-byte salt.
  - `ADRS`: a 22-byte address.
- Output:
  - a 16-byte FXMSS root node hash


## TODO

- Because SLH-DSA and XMSS have different signature sizes, this means the SHRINCS signature size is variable.
- Mention Vulkan[^vulkan] for signing/keygen.
- Discuss XMSS tree caching
- Consider future-proofing WOTS+C addressing scheme/layout for XMSS^MT.
- Specify which `ADRS` fields should be prefilled and when.
- Add note about how callers cannot accurately depend on tree structures of untrusted parties, due to collision attacks.

[^slhdsa]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
[^adrs]: The 22-byte `ADRS` format aligns with the ADRS<sup>c</sup> format in SLH-DSA and FIPS-205[^slhdsa] for SHA2 parameter sets.
[^xmss]: https://www.rfc-editor.org/rfc/rfc8391.html
[^mgf1]: https://datatracker.ietf.org/doc/html/rfc8017#appendix-B.2.1 - It is possible to restrict ourselves to a single SHA256 invocation to match MGF1-SHA-256, because the SHRINCS parameter set does not require outputs larger than 32 bytes.
[^hmac]: https://datatracker.ietf.org/doc/html/rfc2104
[^simd_x86]: https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html
[^simd_arm]: https://arm-software.github.io/acle/neon_intrinsics/advsimd.html
[^sha_ni]: https://en.wikipedia.org/wiki/SHA_instruction_set
[^sha_ni_bench]: https://conduition.io/code/fast-slh-dsa/#Hardware-Acceleration
[^sha256x8]: https://github.com/sphincs/sphincsplus/blob/7ec789ace6874d875f4bb84cb61b81155398167e/sha2-avx2/sha256avx.c
[^vulkan]: https://conduition.io/code/fast-slh-dsa/#Vulkan-for-SLH-DSA
[^pruning]: https://conduition.io/cryptography/hypertree-pruning/
[^merkle]: https://www.ralphmerkle.com/papers/Certified1979.pdf
[^sphincs+c]: https://eprint.iacr.org/2022/778
[^wotsgrind]: https://gist.github.com/conduition/c19f00d9420eee009c9f33d9cd991bd6
