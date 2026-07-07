# SHRINCS

This document fully specifies SHRINCS: _Shrunken SPHINCS._

SHRINCS is a hybrid stateful/stateless signature scheme built using only hash functions. The security of SHRINCS rests on the multi-target target collision resistance of the underlying base hash function, for which we use SHA256. A detailed proof of security is not provided here.

This spec serves to describe the keygen, signing, and verification algorithms of SHRINCS.


## Templating

This SHRINCS specification includes Python reference code and documentation defined inline at [`impl/shrincs.py`](./impl/shrincs.py). The markdown file you are currently reading uses simple templating to pull Python code and docstrings from `shrincs.py`. If you wish to make changes to the specification of SHRINCS functions inside of a `<!-- DOC START xyz -->` ... `<!-- DOC END xyz -->` templating envelope, please make the changes directly in `shrincs.py` first, and then run the [`pydoc_insert.py` script](./pydoc_insert.py).

>[!WARNING]
> Running the templating script will overwrite SHRINCS.md. Make sure you have saved and committed other important changes first!

```sh
./pydoc_insert.py
```


## Overview

At a high-level, a SHRINCS instance consists of two distinct keypairs joined together into one.

1. The first is a stateful XMSS[^xmss] keypair.
2. The other is a fully stateless SPHINCS+ keypair.

The stateless component is an implementation of SLH-DSA[^slhdsa] with algorithms defined as in FIPS-205, but using a non-standard parameter set. The stateful component is a customized implementation of XMSS adapted to suit Bitcoin's use-cases.

Each of these components individually produces a 16-byte hash as its public key. Both pubkeys, together with a 16-byte seed value, form a 48 byte SHRINCS public key.

```py
PK = PK.seed || PK.sl_root || PK.sf_root
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

To save computational effort, `PK.seed` is padded with zero bytes to a length of 64 bytes in most cases. This aligns with the SHA256 block size, so that `PK.seed` can be absorbed into the SHA256 state, and that midstate can be cached & reused.


## Utilities

We make use of the following utility helper functions in specifying SHRINCS.

- `ceil(x)`: rounds `x` up to the nearest whole number.
- `floor(x)`: rounds `x` down to the nearest whole number.
- `sum(x)`: sums a sequence of numbers `x`.
- `log2(x)`: returns the base-2 logarithm of `x` (a float/decimal).
- `repeat(b, n)`: returns a bytestring of length `n` containing only the repeated byte `b`.
- `zeros(n)`: returns a bytestring of  length `n` containing only repeated zero bytes.
- `range(start, end)`: returns the ascending sequence of all integers `i` such that `start <= i < end`.
- `concat(array)`: concatenates an array of byte strings.


### `base_2b(...)`

<!-- DOC START base_2b -->
Decomposes a byte string `x` into `outlen` groups of `b` bits which are each
parsed as an integer in the range `[0, 2**b)`. The leading `outlen * b` bits
of `x` are parsed, and so `x` must have accordingly sufficient length.

```py
def base_2b(x: bytes, b: int, outlen: int) -> list[int]:
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
```
<!-- DOC END base_2b -->


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
 FXMSS    SPHINCS+ (SLH-DSA)
    \      (contains XMSS)
     \           /
      \         /
       \       /
        SHRINCS
```


## ADRS

A critical security property of SHRINCS and its components is that every hash function invocation used in the verification algorithm must be _unique,_ so that inputs used in one hash function cannot be reused to produce the same output in another hash function.

To accomplish this goal, we will use _tweakable hash functions_ (explained below) which modify a hash function with some context-dependent location information. This unambiguously specifies the exact instance of the hash function in the signing/verification algorithms where the hash function is being used. This location is called an _address_ and we encode it into a 22-byte array, often called an `ADRS`.[^adrs]


### Stateless ADRS Format

| `ADRS` Field | Size | Purpose |
|:-:|:-:|:-:|
| `layer` | 1 byte | Specifies the layer in the SPHINCS hypertree. The topmost layer is at layer `SPHX_LAYER_COUNT`. |
| `tree_address` | 8 bytes | A 64-bit integer serialized with big-endian encoding. Specifies the index of an XMSS tree within a layer of the SPHINCS hypertree. |
| `type` | 1 byte | A context-dependent flag which gives meaning to the remaining 12 bytes. |
| `payload` | 12 bytes | <br> Usage depends on the `type` field. <br> <br> |


### Stateful ADRS Format

| `ADRS` Field | Size | Purpose |
|:-:|:-:|:-:|
| `node_height` | 1 byte | Specifies the height of a node or leaf the FXMSS tree. The root node is at height `FXMSS_HEIGHT`. |
| `node_index` | 8 bytes | A 64-bit integer serialized with big-endian encoding. Specifies the node index (from the left) within a layer of the FXMSS tree. |
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
| `SF_WOTS_C_PRF` | 21 | Used when generating WOTS+C secret preimages. | Stateful |
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
| `SF_WOTS_C_GRIND` | 12 bytes: zero padding |

The following figures show, for each `ADRS` type, how the 22-byte address is laid out: the common `layer`, `tree_address`, and `type` fields, followed by the type-specific interpretation of the 12-byte `payload`. Field widths are drawn proportional to their byte sizes, with byte offsets along the top.

<img src="img/adrs-stateless.svg">

<sup>Stateless (`SL_*`) `ADRS` types, used along the SPHINCS hypertree signing path.</sup>

<img src="img/adrs-stateful.svg">

<sup>Stateful (`SF_*`) `ADRS` types, used along the FXMSS signing path.</sup>


## Tweakable Hash Functions

At the core of both SPHINCS and XMSS is the concept of _tweakable hash functions._ A tweakable hash function can be thought of as a hash function which supports additional independent parameters that can be used to scope the hash function to a specific role. This makes security easier to prove.

In SHRINCS, we construct tweakable hash functions using SHA256 as the base hash function. This we invoke as the primitive function `sha256(x)` which returns a 32-byte array.

In one case, we use HMAC-SHA256[^hmac], which we invoke as the function `hmac_sha256(key, msg)`.

<!-- DOC START hmac_sha256 -->
```py
def hmac_sha256(key: bytes, msg: bytes) -> bytes:
  assert len(key) <= 64
  padded_key = key + zeros(64 - len(key))
  inner = sha256(xor(padded_key, repeat(0x36, 64)) + msg)
  return sha256(xor(padded_key, repeat(0x5C, 64)) + inner)
```
<!-- DOC END hmac_sha256 -->

SHA256 and HMAC outputs are often truncated, which we denote using Pythonic list-slicing notation: `sha256(x)[:16]`

The following sections describe tweaked hash functions to fill different roles.


### `T_sl(...)`

The tweaked hash function `T_sl`.

<!-- DOC START T_sl -->
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

```py
def T_sl(pk_seed: bytes, ADRS: bytearray, M_l: bytes) -> bytes:
  return sha256(pk_seed + zeros(48) + ADRS + M_l)[:16]
```
<!-- DOC END T_sl -->


### `T_sf(...)`

The tweaked hash function `T_sf`.

<!-- DOC START T_sf -->
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

```py
def T_sf(pk_seed: bytes, ADRS: bytearray, M_l: bytes) -> bytes:
  return sha256(pk_seed + zeros(48) + ADRS + M_l)[:16]
```
<!-- DOC END T_sf -->


### `T_k(...)`

The tweaked hash function `T_k`.

<!-- DOC START T_k -->
Hashes an input `M_k`, which is a sequence of `SPHX_FORS_COUNT` hashes, each 16 bytes long,
concatenated together. This function will be used to compress FORS tree roots to a single
hash in the stateless path.

- Inputs:
  - `pk_seed`: a 16-byte salt.
  - `ADRS`: a 22-byte address.
  - `M_k`: an array of `SPHX_FORS_COUNT * 16` bytes.
- Output:
  - A 16-byte hash.

This function is only used in the stateless path.

```py
def T_k(pk_seed: bytes, ADRS: bytearray, M_k: bytes) -> bytes:
  return sha256(pk_seed + zeros(48) + ADRS + M_k)[:16]
```
<!-- DOC END T_k -->


### `F(...)`

The tweaked hash function `F`.

<!-- DOC START F -->
Hashes an input `M_1`, which is a single 16-byte hash. This function will be used to generate
and iterate Winternitz hash chains and to hash FORS leaves.

- Inputs:
  - `pk_seed`: a 16-byte salt.
  - `ADRS`: a 22-byte address.
  - `M_1`: a 16-byte hash.
- Output:
  - A 16-byte hash.

This function is used in both stateful and stateless paths.

```py
def F(pk_seed: bytes, ADRS: bytearray, M_1: bytes) -> bytes:
  return sha256(pk_seed + zeros(48) + ADRS + M_1)[:16]
```
<!-- DOC END F -->


### `H(...)`

The tweaked hash function `H`.

<!-- DOC START H -->
Hashes an input `M_2`, which is a pair of 16-byte hashes, concatenated together. This function
will be used to combine pairs of merkle nodes, to construct merkle trees in XMSS and FORS.

- Inputs:
  - `pk_seed`: a 16-byte salt.
  - `ADRS`: a 22-byte address.
  - `M_2`: an array of 32 bytes.
- Output:
  - A 16-byte hash.

This function is used in both stateful and stateless paths.

```py
def H(pk_seed: bytes, ADRS: bytearray, M_2: bytes) -> bytes:
  return sha256(pk_seed + zeros(48) + ADRS + M_2)[:16]
```
<!-- DOC END H -->


### `H_grind(...)`

The tweaked hash function `H_grind`.

<!-- DOC START H_grind -->
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

```py
def H_grind(pk_seed: bytes, ADRS: bytearray, digest: bytes, counter: int) -> bytes:
  assert counter <= 0xFFFF
  return sha256(pk_seed + zeros(48) + ADRS[:10] + digest + zeros(4) + counter.to_bytes(2))[:16]
```
<!-- DOC END H_grind -->

The extra 4 bytes of padding before the counter ensures the counter lines up with the SHA256 message schedule boundaries.

Notice we only use the first 10 bytes of `ADRS`. This ensures the entire hash input fits inside a single SHA256 compression call. The remaining 12 bytes are always zero padding.


### `PRF(...)`

The tweaked hash function `PRF`.

<!-- DOC START PRF -->
Hashes `sk_seed` with an `ADRS` to derive secret preimage values needed for signing and key
generation.

- Inputs:
  - `pk_seed`: a 16-byte salt.
  - `sk_seed`: a 16-byte secret.
  - `ADRS`: a 22-byte address.
- Output:
  - A 16-byte hash.

This function is used in both stateful and stateless paths, but only by the signing algorithm.

```py
def PRF(pk_seed: bytes, sk_seed: bytes, ADRS: bytearray) -> bytes:
  return sha256(pk_seed + zeros(48) + ADRS + sk_seed)[:16]
```
<!-- DOC END PRF -->

Note the order of the arguments passed to `PRF` is _not_ the same order in which those arguments are processed by `sha256`. This aligns with definitions in FIPS-205[^slhdsa].


### `H_msg_sl(...)`

The tweaked hash function `H_msg_sl`.

<!-- DOC START H_msg_sl -->
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

```py
def H_msg_sl(R: bytes, pk_seed: bytes, root: bytes, M: bytes) -> bytes:
  return sha256(R + pk_seed + sha256(R + pk_seed + root + M) + zeros(4))
```
<!-- DOC END H_msg_sl -->

The 4-byte zero-padding at the end of the outer hash input ensures `H_msg_sl` satisfies FIPS-205[^slhdsa], wherein `H_msg_sl` is defined using MGF1-SHA-256[^mgf1].


### `H_msg_sf(...)`

The tweaked hash function `H_msg_sf`.

<!-- DOC START H_msg_sf -->
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

```py
def H_msg_sf(R: bytes, pk_seed: bytes, root: bytes, ADRS: bytearray, M: bytes) -> bytes:
  return sha256(R + pk_seed + ADRS[:9] + sha256(R + pk_seed + root + ADRS[:9] + M))
```
<!-- DOC END H_msg_sf -->

Notice we only use the first 9 bytes of `ADRS`, because these bytes encode the position of the WOTS+C leaf in the FXMSS tree.

Unlike `H_msg_sl`, this function is a SHRINCS-specific construction and is **not** required to satisfy FIPS-205[^slhdsa]. This accounts for two intentional differences from `H_msg_sl`:

- There is no trailing 4-byte zero-padding on the outer hash. That padding exists only to make `H_msg_sl` match the MGF1-SHA-256[^mgf1] definition mandated by FIPS-205, which does not apply here.
- The WOTS+C leaf position given by `ADRS` is bound into both the inner and outer hash inputs. This domain-separates the stateful digest by the leaf used to sign it.


### `PRF_msg_sl(...)`

The tweaked hash function `PRF_msg_sl`.

<!-- DOC START PRF_msg_sl -->
Uses HMAC-SHA256 to hash `sk_prf`, randomness `opt_rand`, and an arbitrary-length message `M`.
This function will be used to derive a _randomizer_ (salt) for the given message in
the stateless path.

- Inputs:
  - `sk_prf`: a 16-byte secret.
  - `opt_rand`: a 16-byte salt.
  - `M`: an arbitrary-length bytestring (TODO).
- Output:
  - A 16-byte hash.

This function is only used in the stateless path, and only by the signer.

`opt_rand` is set to either `pk_seed` (giving the "deterministic variant" of SLH-DSA[^slhdsa]),
or a 16-byte salt sampled from a secure RNG (the "hedged variant" of SLH-DSA, resistant to
side-channel attacks).

```py
def PRF_msg_sl(sk_prf: bytes, opt_rand: bytes, M: bytes) -> bytes:
  return hmac_sha256(key=sk_prf, msg=opt_rand + M)[:16]
```
<!-- DOC END PRF_msg_sl -->


### `PRF_msg_sf(...)`

The tweaked hash function `PRF_msg_sf`.

<!-- DOC START PRF_msg_sf -->
Uses HMAC-SHA256 to hash `sk_prf`, the `pk_seed`, an `ADRS`, and an arbitrary-length message `M`. This function
will be used to derive a _randomizer_ (salt) for the given message in the stateful path.

- Inputs:
  - `sk_prf`: a 16-byte secret.
  - `pk_seed`: a 16-byte salt.
  - `ADRS`: a 22-byte address.
  - `M`: an arbitrary-length bytestring (TODO).
- Output:
  - A 16-byte hash.

This function is only used in the stateful path, and only by the signer.

```py
def PRF_msg_sf(sk_prf: bytes, pk_seed: bytes, ADRS: bytearray, M: bytes) -> bytes:
  return hmac_sha256(key=sk_prf + repeat(0xFF, 48), msg=pk_seed + ADRS[:9] + M)[:16]
```
<!-- DOC END PRF_msg_sf -->

The `sk_prf` is padded with `0xFF` up until it is 64 bytes long. This ensures domain separation between stateful and stateless paths.

We only use the first 9 bytes of `ADRS`, because these bytes encode the position of the WOTS+C leaf in the FXMSS tree.


### Implementation Notes

- The only difference between `T_sf`, `T_sl`, `T_k`, `F`, and `H` is the byte-length of the third input parameter. They are defined as different hash functions for security.
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

<!-- DOC START wots_chain_iter -->
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

```py
def wots_chain_iter(node: bytes, start: int, steps: int, pk_seed: bytes, ADRS: bytearray) -> bytes:
  for j in range(start, start+steps):
    ADRS[18:22] = j.to_bytes(4)
    node = F(pk_seed, ADRS, node)
  return node
```
<!-- DOC END wots_chain_iter -->


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

<!-- DOC START wots_tw_message_to_indexes -->
The WOTS-TW message map function. Converts a 16-byte `message` to a checksummed array
of `WOTS_TW_CHAIN_COUNT` WOTS hash chain indexes in the range `[0, 2**WOTS_TW_CHAIN_BITS)`.

- Inputs:
  - `message`: a 16-byte hash
- Output:
  - An checksummed array of `WOTS_TW_CHAIN_BITS`-bit integers of length `WOTS_TW_CHAIN_COUNT`.

```py
def wots_tw_message_to_indexes(message: bytes) -> list[int]:
  msg_indexes = base_2b(message, WOTS_TW_CHAIN_BITS, WOTS_TW_CHAIN_COUNT1)
  checksum = WOTS_TW_CHECKSUM_MAX - sum(msg_indexes)

  checksum_indexes = [0] * WOTS_TW_CHAIN_COUNT2
  for i in range(WOTS_TW_CHAIN_COUNT2):
    checksum_indexes[WOTS_TW_CHAIN_COUNT2 - 1 - i] = checksum % (2**WOTS_TW_CHAIN_BITS)
    checksum >>= WOTS_TW_CHAIN_BITS

  return msg_indexes + checksum_indexes
```
<!-- DOC END wots_tw_message_to_indexes -->

<!-- DOC START wots_tw_message_to_indexes_alt -->
Alternative implementation, equivalent to `wots_tw_message_to_indexes` but using the
more complex FIPS-205 algorithm.

```py
def wots_tw_message_to_indexes_alt(message: bytes) -> list[int]:
  SPHX_WOTS_CHECKSUM_SHIFT = (8 - (WOTS_TW_CHAIN_BITS * WOTS_TW_CHAIN_COUNT2) % 8) % 8
  SPHX_WOTS_CHECKSUM_BYTE_LEN = ceil(WOTS_TW_CHAIN_COUNT2 * WOTS_TW_CHAIN_BITS / 8)
  msg_indexes = base_2b(message, WOTS_TW_CHAIN_BITS, WOTS_TW_CHAIN_COUNT1)
  checksum = (WOTS_TW_CHECKSUM_MAX - sum(msg_indexes)) << SPHX_WOTS_CHECKSUM_SHIFT
  checksum_bytes = checksum.to_bytes(SPHX_WOTS_CHECKSUM_BYTE_LEN)
  checksum_indexes = base_2b(checksum_bytes, WOTS_TW_CHAIN_BITS, WOTS_TW_CHAIN_COUNT2)
  return msg_indexes + checksum_indexes
```
<!-- DOC END wots_tw_message_to_indexes_alt -->

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

<!-- DOC START wots_tw_pubkey_gen -->
The WOTS-TW public key generation function. Takes in the secret `sk_seed`, the `pk_seed`,
and an `ADRS`. The `ADRS` should be prefilled with the location of the WOTS keypair being used.

- Inputs:
  - `sk_seed`: a 16-byte secret.
  - `pk_seed`: a 16-byte salt.
  - `ADRS`: a 22-byte address.
- Output:
  - A 16-byte hash representing the WOTS-TW public key.

This algorithm is used only by the signer.

```py
def wots_tw_pubkey_gen(sk_seed: bytes, pk_seed: bytes, ADRS: bytearray) -> bytes:
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
```
<!-- DOC END wots_tw_pubkey_gen -->


### `wots_tw_sign(...)`

<!-- DOC START wots_tw_sign -->
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

```py
def wots_tw_sign(message: bytes, sk_seed: bytes, pk_seed: bytes, ADRS: bytearray) -> bytes:
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
```
<!-- DOC END wots_tw_sign -->


### `wots_tw_pubkey_from_sig(...)`

<!-- DOC START wots_tw_pubkey_from_sig -->
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

```py
def wots_tw_pubkey_from_sig(signature: bytes, message: bytes, pk_seed: bytes, ADRS: bytearray) -> bytes:
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
```
<!-- DOC END wots_tw_pubkey_from_sig -->


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

<!-- DOC START wots_c_grind_to_constant_sum -->
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

```py
def wots_c_grind_to_constant_sum(pk_seed: bytes, message_digest: bytes, ADRS: bytearray) -> tuple[int, list[int]]:
  ADRS[9] = SF_WOTS_C_GRIND
  for i in range(2**16):
    hashed = H_grind(pk_seed, ADRS, message_digest, i)
    indexes = base_2b(hashed, WOTS_C_CHAIN_BITS, WOTS_C_CHAIN_COUNT)
    if sum(indexes) == WOTS_C_CONSTANT_SUM:
      return (i, indexes)

  raise RuntimeError("Unreachable") # practically impossible
```
<!-- DOC END wots_c_grind_to_constant_sum -->

We max out at 2<sup>16</sup> grinding attempts because the counter is serialized as a 16-bit unsigned integer in the WOTS+C signature encoding - Counters larger than this would not fit into a signature. There is technically a chance that the signer may exhaust all of these attempts without finding a valid counter, however this probability is less than 1 chance in 2<sup>1000</sup>[^wotsgrind] - practically impossible.
<!-- Mike: This estimation is only for this parameter sets. For different parameter sets this can be a worse bound.-->


### `wots_c_map_digest(...)`

<!-- DOC START wots_c_map_digest -->
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

```py
def wots_c_map_digest(pk_seed: bytes, message_digest: bytes, ADRS: bytearray, counter: int) -> Optional[list[int]]:
  ADRS[9] = SF_WOTS_C_GRIND
  hashed = H_grind(pk_seed, ADRS, message_digest, counter)
  indexes = base_2b(hashed, WOTS_C_CHAIN_BITS, WOTS_C_CHAIN_COUNT)
  if sum(indexes) == WOTS_C_CONSTANT_SUM:
    return indexes
  else:
    return None
```
<!-- DOC END wots_c_map_digest -->


### `wots_c_pubkey_gen(...)`

<!-- DOC START wots_c_pubkey_gen -->
The WOTS+C public key generation function. Takes in the secret `sk_seed`, the `pk_seed`, and an
`ADRS`. The `ADRS` should be prefilled with the location of the WOTS keypair being used.

- Inputs:
  - `sk_seed`: a 16-byte secret.
  - `pk_seed`: a 16-byte salt.
  - `ADRS`: a 22-byte address.
- Output:
  - A 16-byte hash representing the WOTS+C public key.

This algorithm is used only by the signer.

```py
def wots_c_pubkey_gen(sk_seed: bytes, pk_seed: bytes, ADRS: bytearray) -> bytes:
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
```
<!-- DOC END wots_c_pubkey_gen -->


### `wots_c_sign(...)`

<!-- DOC START wots_c_sign -->
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

```py
def wots_c_sign(message_digest: bytes, sk_seed: bytes, pk_seed: bytes, ADRS: bytearray) -> bytes:
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
```
<!-- DOC END wots_c_sign -->


### `wots_c_pubkey_from_sig(...)`

<!-- DOC START wots_c_pubkey_from_sig -->
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

```py
def wots_c_pubkey_from_sig(signature: bytes, message_digest: bytes, pk_seed: bytes, ADRS: bytearray) -> Optional[bytes]:
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
```
<!-- DOC END wots_c_pubkey_from_sig -->


## XMSS

The _eXtended Merkle Signature Scheme_ (XMSS) is a stateful hash-based signature scheme which can produce signatures on up to a fixed number of messages.

Conceptually, an XMSS keypair is a merkle tree whose leaves are one-time signature (OTS) keypairs. The XMSS public key is the root hash of the merkle tree. An XMSS signature is an OTS signature alongside a merkle tree authentication proof which links the OTS public key to the merkle root hash. The verifier recomputes the OTS public key, and follows the merkle proof to recompute the XMSS public key.

In SHRINCS, we instantiate XMSS twice, to be used differently in both stateful and stateless components of a SHRINCS keypair.

```
      XMSS (balanced)                  |             FXMSS (flexible)

            root                       |                 root
        ___/    \___                   |                /    \
      O            O                   |               O      L
     / \          / \                  |              / \
    O   O        O   O                 |             L   O
   / \ / \      / \ / \                |                / \
  L  L L  L    L  L L  L               |               L   L

                O = inner Merkle node    L = WOTS leaf (OTS keypair)
```

Both schemes are Merkle trees whose leaves are OTS keypairs and whose root is the public key. They differ only in shape: XMSS (stateless path) is always a perfectly balanced tree of fixed height, while FXMSS (stateful path) admits flexible structures, with WOTS+C leaves placed at varying depths.

- In the stateless component, traditional balanced XMSS is used with WOTS-TW as the leaf OTS scheme to certify child layers of the SPHINCS hypertree, and to certify FORS public keys.
- In the stateful component, Flexible XMSS (FXMSS) is used with WOTS+C to sign messages directly.

In XMSS (stateless path), merkle trees are always perfectly balanced, and always have a fixed height `SPHX_XMSS_HEIGHT`. This aligns with FIPS-205 standards.

In FXMSS (stateful path), merkle trees can be balanced or unbalanced, and the WOTS+C leaf keys may be placed up to `FXMSS_HEIGHT` layers deep. This permits more flexible constructions.

Notably for security, XMSS is always used as part of the SPHINCS framework to sign trusted messages generated by the signer, while FXMSS is used as a standalone scheme and so may sign untrusted messages. This means the interfaces of both XMSS and FXMSS are slightly different, and this is a crucial security requirement.

The following sections describe the XMSS and FXMSS algorithms.


## XMSS

These algorithms are used only for the stateless XMSS sub-scheme.


### `xmss_node(...)`

<!-- DOC START xmss_node -->
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

```py
def xmss_node(sk_seed: bytes, node_index: int, node_height: int, pk_seed: bytes, ADRS: bytearray) -> bytes:
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
```
<!-- DOC END xmss_node -->


### `xmss_sign(...)`

<!-- DOC START xmss_sign -->
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

```py
def xmss_sign(message: bytes, sk_seed: bytes, keypair_index: int, pk_seed: bytes, ADRS: bytearray) -> bytes:
  ADRS[10:14] = keypair_index.to_bytes(4)
  sig = wots_tw_sign(message, sk_seed, pk_seed, ADRS)

  # Append the Merkle authentication path
  for j in range(SPHX_XMSS_HEIGHT):
    sibling_index = (keypair_index >> j) ^ 1
    sig += xmss_node(sk_seed, sibling_index, j, pk_seed, ADRS)

  return sig
```
<!-- DOC END xmss_sign -->


### `xmss_pubkey_from_sig(...)`

<!-- DOC START xmss_pubkey_from_sig -->
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

```py
def xmss_pubkey_from_sig(keypair_index: int, signature: bytes, message: bytes, pk_seed: bytes, ADRS: bytearray) -> bytes:
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
```
<!-- DOC END xmss_pubkey_from_sig -->


## FXMSS

FXMSS is the stateful signing path of SHRINCS. FXMSS offers a unique paradigm in the genre of XMSS: Unlike most related schemes, FXMSS allows the signer to pick (almost[^fxmss_node_index]) any arbitrary tree structure. By tree structure, we mean the choice of which positions in the FXMSS tree are used by the signer as WOTS+C leaf nodes.

The FXMSS verifier does not care about the positions of unused WOTS+C leaf nodes - The verifier only cares about the WOTS+C leaf whose signature is attached in the FXMSS signature. This makes the verifier simpler to implement, and frees signers to select their XMSS tree structure at key generation time to suit their use-case.

Because of this flexibility, it is necessary for signers to remember what structure of FXMSS tree they created at key generation time. To encourage interoperability, we define an encoding for FXMSS tree structures which will be stored in the SHRINCS signer's serialized secret key as two additional bytes.

A _tree structure_ for FXMSS is encoded as a tuple of two numbers: ***shape*** and ***depth***.

- ***Shape*** is a flag byte that defines which FXMSS nodes are to be WOTS+C leaves. We will describe two recommended tree shapes below.
- ***Depth*** is an 8-bit unsigned integer describing the height of the FXMSS tree, or more precisely, the distance from the root node to the deepest leaf node.

These two parameters define the _structure_ of the FXMSS stateful path.

The shape and depth bytes will be encoded in the serialized SHRINCS secret key so that implementations which import the key have a clear directive for how to build the same FXMSS tree in the SHRINCS stateful path. Implementations which import SHRINCS keys MUST respect the shape and depth bytes - doing otherwise would be unsafe and may lead to forgeries and theft.


### Tree Shapes

We prescribe and define two FXMSS tree shapes: **Unbalanced XMSS (UXMSS)** and **Balanced XMSS (BXMSS)**. For clarity: We use the terms UXMSS and BXMSS in the context of signing and key-generation, while FXMSS refers more generally to the verifier, which is decoupled from tree shape.

The two shapes are identified by their respective constants.

| Shape Flag | Value | Description |
|:-:|:-:|:-:|
| `FXMSS_SHAPE_UNBALANCED` | 0 | Indicates UXMSS, with a left-leaning unbalanced tree. |
| `FXMSS_SHAPE_BALANCED` | 1 | Indicates BXMSS, with a balanced tree of specific depth. |
| ... | 2...255 | Reserved. |

We leave open the possibility to define new shape flags for new XMSS tree structures, but we encourage signers to utilize the recommended shapes wherever possible, for the sake of security and anonymity.

The following sections describe the usage properties of the two shapes, and we let the variable `depth` represent the depth byte as a parameter of the shape.


#### `FXMSS_SHAPE_UNBALANCED`

When the shape byte is set to `FXMSS_SHAPE_UNBALANCED`, signers use an unbalanced, left-leaning XMSS tree of height `depth`.

```
                   root
                  /    \
                 O    leaf
               /   \
              O   leaf
            /   \
           O   leaf
         /   \
       ...  leaf
       /
      O
    /   \
 leaf   leaf
```

This FXMSS tree shape allows signers to generate very short stateful signatures for the first few initial signatures, since the signer can use the shallowest WOTS+C leaves right away, and these have very short merkle authentication paths.

However, since each WOTS+C leaf can be used only once, subsequent signatures will grow larger at a rate of 16 bytes per signature issued as the merkle authentication path grows in length. Eventually after `depth + 1` signatures, the UXMSS stateful path will be exhausted and unusable, and the last few stateful signatures will be very large.

For most use cases, unless compute power is very limited, we recommend setting `depth = FXMSS_HEIGHT` for UXMSS (the maximum), as even a WOTS+C leaf at maximum depth will still produce a shorter signature than the stateless path. FXMSS depth cannot exceed `FXMSS_HEIGHT = 255` because the FXMSS node height number is encoded into the signature and `ADRS` as a single byte.

#### `FXMSS_SHAPE_BALANCED`

When the shape byte is set to `FXMSS_SHAPE_BALANCED`, signers use a balanced binary XMSS tree, of height `depth`.

```
                  root
              /          \
           /                \
         O                    O
       /   \                /   \
     ...   ...            ...   ...
     /       \            /       \
    O         O          O         O
  /   \     /   \      /   \     /   \
leaf leaf leaf leaf  leaf leaf leaf leaf
```

This FXMSS tree shape allows signers to generate a larger quantity of stateful signatures. Unlike UXMSS, stateful SHRINCS signatures using a BXMSS tree will have a consistent size, up until the stateful path is exhausted (after `2 ** depth` signatures), because all WOTS+C leaves will use the same merkle authentication path length.

The `depth` of the BXMSS tree at key generation time has a significant impact on the performance of the SHRINCS stateful signing path. The exact size of the constant-size signatures is also dictated by `depth`: each step further from the root node we take, we must add 16 bytes to the FXMSS signature. Furthermore, each step doubles the number of leaf nodes, and so doubles the signature budget, but also doubles the amount of computational work needed for BXMSS key generation and/or signing.

Signer implementations may specify any height for BXMSS trees depending on their use-cases, but typical safe defaults range from `depth = 8` (256 signatures, matching the budget of UXMSS) to `depth = 20` (1 million signatures), or more in special circumstances.


#### Custom Shapes

Signers _may_ design custom shapes.[^fxmss_node_index]

For security and privacy we highly recommend signers stick to the two prescribed shapes: BXMSS and UXMSS.


#### Caveats

- Some tree structures are invalid or impractical to generate, such as a balanced tree of height 255.
- Some structures are fungible, such as any tree of depth 0 or depth 1 will be the same regardless of shape.
- Implementations must take care when using SHRINCS secret keys imported from untrusted sources, especially if depending on shape and depth bytes for security-critical logic.


### Algorithms

These algorithms are used only for the stateful FXMSS sub-scheme.


### `fxmss_node(...)`

<!-- DOC START fxmss_node -->
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

```py
def fxmss_node(sk_seed: bytes, node_index: int, node_height: int, pk_seed: bytes, structure: bytes, ADRS: bytearray) -> bytes:
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
```
<!-- DOC END fxmss_node -->


### `fxmss_sign(...)`

<!-- DOC START fxmss_sign -->
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

```py
def fxmss_sign(message_digest: bytes, sk_seed: bytes, leaf_index: int, leaf_height: int, pk_seed: bytes, structure: bytes, ADRS: bytearray) -> bytes:
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
```
<!-- DOC END fxmss_sign -->


### `fxmss_pubkey_from_sig(...)`

<!-- DOC START fxmss_pubkey_from_sig -->
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

```py
def fxmss_pubkey_from_sig(node_index: int, signature: bytes, message_digest: bytes, pk_seed: bytes, ADRS: bytearray) -> Optional[bytes]:
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
```
<!-- DOC END fxmss_pubkey_from_sig -->


## FORS

The stateless signing path of SHRINCS uses Forest Of Random Subsets (FORS), a hash-based _few-time_ signature scheme (FTS), to sign messages.

Compared to one-time signature (OTS) schemes like Winternitz, FTS schemes are characterized by security which resists forgery even when a keypair is reused to sign multiple messages. The degradation in security can be quantified and calibrated using parameters, so that forgery-resistance does not reduce below a target bound. FORS is one such FTS scheme.


### Informal Description

Here follows an informal description of the FORS FTS scheme as it is defined in FIPS-205.[^slhdsa]

A FORS keypair consists of a _forest_ of merkle trees of a fixed size, where each leaf is a hash of a preimage derived by a PRF. We parameterize the number of merkle trees as `SPHX_FORS_COUNT`, and the height of each tree as `SPHX_FORS_HEIGHT`. The FORS public key is a hash of the merkle roots of the entire forest.

When signing, a message is mapped - via a salted hash - to a set of `SPHX_FORS_COUNT` integer indexes, of `SPHX_FORS_HEIGHT` bits each. Each index identifies a specific preimage from each merkle tree which the signer must reveal, along a merkle authentication path. The verifier uses the preimages and merkle paths to recompute the roots of each tree, and finally recomputes the FORS public key to verify the signature.

<img src="img/fors.svg">

<sup>This diagram illustrates a toy FORS keypair, with merkle trees of height 2. Messages are mapped to a set of `k` 2-bit integers which select an index from each tree.</sup>

Each signature reveals one of the preimages in each merkle tree in the forest. Over the course of many signatures, the signer may reuse preimages that have already been revealed in prior signatures, because some messages may map to intersecting index-sets.

Unless he has an efficient way to find preimages, an adversary must hope the signer publishes signatures which admits a forgery by mixing and matching preimages from prior signatures. The adversary _cannot_ control which index-sets the victim signs (because of the salt), and so he cannot trick the signer into exposing specific preimages, even if the adversary can query the signer for arbitrary signatures.

However, the adversary _may_ grind to find a message and salt which maps to an index-set that is a _subset_ of the index-sets signed previously, which would admit a forgery. The probability that this occurs with a randomly sampled index-set can be reduced arbitrarily low by using more and taller trees, or by reducing the limit on the number of signatures the signer is expected to produce. This is formalized as the security notion of _interleaved target-subset resilience._[^sphincs+]


## FORS Algorithms

The following sections describe the algorithms needed for FORS key-generation, signing, and verification.


### `fors_sk_gen(...)`

<!-- DOC START fors_sk_gen -->
The FORS secret preimage generation function. Generates a secret 16-byte preimage from `sk_seed`.
Takes in `pk_seed`, an `ADRS`, and the `tree_index` to indicate the position of the FORS leaf
in the forest.

- Inputs:
  - `sk_seed`: a 16-byte secret.
  - `pk_seed`: a 16-byte salt.
  - `ADRS`: a 22-byte address.
  - `tree_index`: a 32-bit unsigned integer.
- Output:
  - A 16-byte preimage.

This algorithm is used only by the signer.

Note the `tree_index` of a FORS leaf or node is _indexed across the entire forest,_ not just
within a single tree. The index of leaf `l` in tree `t` is `t * 2**SPHX_FORS_HEIGHT + l`.

```py
def fors_sk_gen(sk_seed: bytes, pk_seed: bytes, ADRS: bytearray, tree_index: int) -> bytes:
  ADRS[9] = SL_FORS_PRF
  ADRS[14:18] = zeros(4)
  ADRS[18:22] = tree_index.to_bytes(4)
  return PRF(pk_seed, sk_seed, ADRS)
```
<!-- DOC END fors_sk_gen -->


### `fors_node(...)`

<!-- DOC START fors_node -->
The FORS internal merkle node computation helper function. This is a recursive function which
takes in the `sk_seed`, `pk_seed`, an `ADRS`, and integers `node_height`, `node_index` which
describe the position of the FORS node in the forest of merkle trees.

- Inputs:
  - `sk_seed`: a 16-byte secret.
  - `pk_seed`: a 16-byte salt.
  - `ADRS`: a 22-byte address.
  - `node_index`: a 32-bit unsigned integer.
  - `node_height`: a 32-bit unsigned integer.
- Output:
  - A 16-byte FORS node hash.

This function is only used in the stateless path, and only by the signer.

Note the `node_index` of a FORS leaf or node is _indexed across the entire forest,_ not just
within a single tree. The index of node `l` in tree `t` at height `h` is `t * 2**h + l`.

```py
def fors_node(sk_seed: bytes, node_index: int, node_height: int, pk_seed: bytes, ADRS: bytearray) -> bytes:
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
```
<!-- DOC END fors_node -->


### `fors_sign(...)`

<!-- DOC START fors_sign -->
The FORS signing function. Signs a `message_digest`, using `sk_seed` and `pk_seed`, with the
location of the FORS leaf specified in `ADRS`.

- Inputs:
  - `message_digest`: a digest of a message to sign.
    - Must be exactly `ceil(SPHX_FORS_COUNT * SPHX_FORS_HEIGHT / 8)` bytes long.
  - `sk_seed`: a 16-byte secret.
  - `pk_seed`: a 16-byte salt.
  - `ADRS`: a 22-byte address.
- Output:
  - A FORS signature, a byte string of length `16 * SPHX_FORS_COUNT * (SPHX_FORS_HEIGHT + 1)`.

This function is only used in the stateless path, and only by the signer.

```py
def fors_sign(message_digest: bytes, sk_seed: bytes, pk_seed: bytes, ADRS: bytearray) -> bytes:
  sig = b""
  index_set = base_2b(message_digest, SPHX_FORS_HEIGHT, SPHX_FORS_COUNT)
  for i in range(SPHX_FORS_COUNT):
    leaf_index = i * 2**SPHX_FORS_HEIGHT + index_set[i]
    sig += fors_sk_gen(sk_seed, pk_seed, ADRS, leaf_index)
    for j in range(SPHX_FORS_HEIGHT):
      sibling_index = i * 2**(SPHX_FORS_HEIGHT - j) + ((index_set[i] >> j) ^ 1)
      sig += fors_node(sk_seed, sibling_index, j, pk_seed, ADRS)
  return sig
```
<!-- DOC END fors_sign -->


### `fors_pubkey_from_sig(...)`

<!-- DOC START fors_pubkey_from_sig -->
The FORS verification procedure. Recovers a FORS public key hash from the given `signature` on a
`message_digest`. Takes in a `pk_seed` and `ADRS`.

- Inputs:
  - `signature`: a byte string of length `16 * SPHX_FORS_COUNT * (SPHX_FORS_HEIGHT + 1)`.
  - `message_digest`: a digest of a message to sign.
    - Must be exactly `ceil(SPHX_FORS_COUNT * SPHX_FORS_HEIGHT / 8)` bytes long.
  - `pk_seed`: a 16-byte salt.
  - `ADRS`: a 22-byte address.
- Output:
  - A 16-byte hash of the FORS public key.

This function is only used in the stateless path.

```py
def fors_pubkey_from_sig(signature: bytes, message_digest: bytes, pk_seed: bytes, ADRS: bytearray) -> bytes:
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
```
<!-- DOC END fors_pubkey_from_sig -->


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
[^sphincs+]: https://sphincs.org/data/sphincs+-paper.pdf
[^sphincs+c]: https://eprint.iacr.org/2022/778
[^wotsgrind]: https://gist.github.com/conduition/c19f00d9420eee009c9f33d9cd991bd6
[^fxmss_node_index]: The key requirement for a valid FXMSS tree shape is that the indexes of all nodes must fit in a 64-bit unsigned integer. This means that while FXMSS trees can be up to 255 layers deep, only the leftmost 2<sup>64</sup> nodes in each layer are indexable. This provides plenty of space while maintaining a fixed max-length encoding for node indexes.
