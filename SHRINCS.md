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

| Parameter | Value | Description |
|:-:|:-:|:-:|
| `N` | 16 | The width of the hash function output. Dictates the security level. |
| `XMSS_WOTS_CHAIN_LEN` | 16 | The length of each Winternitz key chain in the stateful XMSS keypair. |
| `SPHX_WOTS_CHAIN_LEN` | 16 | The length of each Winternitz key chain in the stateless SPHINCS keypair. |
| `XMSS_WOTS_CHAIN_COUNT` | 32 | The number of Winternitz chains in the stateful XMSS keypair. |
| `SPHX_WOTS_CHAIN_COUNT` | 35 | The number of Winternitz chains in the stateless SPHINCS keypair. |
| `SPHX_LAYER_COUNT` | 5 | The number of XMSS layers in the SPHINCS hypertree. |
| `SPHX_XMSS_HEIGHT` | 9 | The height of each XMSS layer within the SPHINCS hypertree. |
| `SPHX_FORS_HEIGHT` | 13 | The height of each FORS tree used in the SPHINCS signature. |
| `SPHX_FORS_COUNT` | 10 | The number of FORS trees used in the SPHINCS signature. |
| `XMSS_WOTS_COUNTER_SIZE` | 2 | The size in bytes used to represent the WOTS+C counter in the stateful XMSS signature. |

## Secret Key

Generating a SHRINCS secret key is straightforward and consists only of generating 48 random bytes. This is then split into 3 x 16-byte seeds.

```py
SK = SK.seed || SK.prf || PK.seed
```

- `SK.seed` is the core component of the secret key. Exposing this compromises the security of the keypair.
- `SK.prf` is bonus randomness used for deriving per-message salt values. This is a hedge against faulty signing-time RNG.
- `PK.seed` is a salt value which is appended to the public key.

Note this is the bare minimum needed to generate a full SHRINCS public key. More performant (but larger) secret key representations are possible.

### Padding

Every SHRINCS keypair contains a randomly generated 16-byte salt value called `PK.seed` which is appended to the public key. This salts every hash function invocation when signing or verifying a SHRINCS signature, to reduce the chance that two hash invocations produce the same outputs for different SHRINCS keypairs.

To save computational effort, `PK.seed` is padded to a length of 64 bytes in most cases. This aligns with the SHA256 block size, so that `PK.seed` can be absorbed into the SHA256 state, and that midstate can be cached & reused.

The padding bytes used depend on whether the `PK.seed` is being used to salt the stateful or stateless signing path of SHRINCS. This serves to separate contexts between stateful and stateless paths. This contextual padding of `PK.seed` is denoted by `pad(PK.seed)`.

- In the stateless path, `pad(PK.seed) = PK.seed || repeat(0x00, 48)`
- In the stateful path, `pad(PK.seed) = PK.seed || repeat(0xFF, 48)`

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
| `ADRS` Field | Size | Purpose |
|:-:|:-:|:-:|
| `layer` | 1 byte | In the stateful path, this specifies depth in the XMSS tree. <br> In the stateless path, this specifies the layer in the SPHINCS hypertree. |
| `tree_address` | 8 bytes | A 64-bit integer serialized with big-endian encoding. <br> In the stateful path, this specifies the node index within a layer of the XMSS tree. <br> In the stateless path, this specifies the node index within a layer of the SPHINCS hypertree. |
| `type` | 1 byte | A context-dependent flag which gives meaning to the remaining 12 bytes. |
| (context dependent) | 12 bytes | <br> Usage depends on the `type` field. <br> <br> |


## Tweakable Hash Functions

At the core of both SPHINCS and XMSS is the concept of _tweakable hash functions._ A tweakable hash function can be thought of as a hash function which supports additional independent parameters that can be used to scope the hash function to a specific role. This makes security easier to prove.

In SHRINCS, we construct tweakable hash functions using SHA256 as the base hash function. This we invoke as the primitive function `sha256(x)` which returns a 32-byte array.

In one case, we use HMAC-SHA256[^hmac], which we invoke as the function `hmac_sha256(key, msg)`.

```py
def hmac_sha256(key, msg):
  key = [key[i] for i in range(64) else 0] # pad to 64 bytes
  inner = sha256(xor(key, 0x36) || msg)
  return sha256(xor(key, 0x5C) || inner)
```

SHA256 and HMAC outputs are truncated, often to `N = 16` bytes, which we denote using Pythonic list-slicing notation: `sha256(x)[:N]`

The following sections describe tweaked hash functions to fill different roles.


### `T_sphx(...)`

The tweaked hash function `T_sphx` hashes an input `M_l`, which is a sequence of `SPHX_WOTS_CHAIN_COUNT` hashes, each `N` bytes long, concatenated together. This function will be used to compress Winternitz chain tips to a single hash in SPHINCS.

```py
T_sphx(PK.seed, ADRS, M_l) = sha256(pad(PK.seed) || ADRS || M_l)[:N]
```

- Inputs:
  - `PK.seed`: an `N`-byte salt.
  - `ADRS`: a 22-byte address.
  - `M_l`: an array of `SPHX_WOTS_CHAIN_COUNT * N` bytes.
- Output:
  - An `N`-byte hash.

This function is only used in the stateless path.


### `T_xmss(...)`

The tweaked hash function `T_xmss` hashes an input `M_l`, which is a sequence of `XMSS_WOTS_CHAIN_COUNT` hashes, each `N` bytes long, concatenated together. This function will be used to compress Winternitz chain tips to a single hash in XMSS.

```py
T_xmss(PK.seed, ADRS, M_l) = sha256(pad(PK.seed) || ADRS || M_l)[:N]
```

- Inputs:
  - `PK.seed`: an `N`-byte salt.
  - `ADRS`: a 22-byte address.
  - `M_l`: an array of `XMSS_WOTS_CHAIN_COUNT * N` bytes.
- Output:
  - An `N`-byte hash.

This function is only used in the stateful path.


### `F(...)`

The tweaked hash function `F` hashes an input `M_1`, which is a single `N`-byte hash. This function will be used to generate and iterate Winternitz hash chains and to hash FORS leaves.

```py
F(PK.seed, ADRS, M_1) = sha256(pad(PK.seed) || ADRS || M_1)[:N]
```

- Inputs:
  - `PK.seed`: an `N`-byte salt.
  - `ADRS`: a 22-byte address.
  - `M_1`: an `N`-byte hash.
- Output:
  - An `N`-byte hash.

This function is used in both stateful and stateless paths.


### `H(...)`

The tweaked hash function `H` hashes an input `M_2`, which is a pair of `N`-byte hashes, concatenated together. This function will be used to combine pairs of merkle nodes, to construct merkle trees in XMSS and FORS.

```py
H(PK.seed, ADRS, M_2) = sha256(pad(PK.seed) || ADRS || M_2)[:N]
```

- Inputs:
  - `PK.seed`: an `N`-byte salt.
  - `ADRS`: a 22-byte address.
  - `M_2`: an array of `2 * N` bytes.
- Output:
  - An `N`-byte hash.

This function is used in both stateful and stateless paths.

### `PRF(...)`

The tweaked hash function `PRF` hashes `SK.seed` with an `ADRS` to derive secret preimage values needed for signing and key generation.

```py
PRF(PK.seed, SK.seed, ADRS) = sha256(pad(PK.seed) || ADRS || SK.seed)[:N]
```

- Inputs:
  - `PK.seed`: an `N`-byte salt.
  - `SK.seed`: an `N`-byte secret.
  - `ADRS`: a 22-byte address.
- Output:
  - An `N`-byte hash.


This function is used in both stateful and stateless paths, but only by the signing algorithm.

Note the order of the arguments passed to `PRF` is _not_ the same order in which those arguments are processed by `sha256`. This aligns with definitions in FIPS-205[^slhdsa].

### `H_msg(...)`

The tweaked hash function `H_msg` hashes a _randomizer_ `R`, a merkle root `root`, and an arbitrary-length (TODO: fixed-length?) message bytestring `M`. It will be used to produce a digest for signing.

```py
H_msg(R, PK.seed, root, M) = sha256(R || PK.seed || sha256(R || PK.seed || root || M) || 0x00000000)
```

- Inputs:
  - `R`: an `N`-byte randomizer.
  - `PK.seed`: an `N`-byte salt.
  - `root`: an `N`-byte hash.
  - `M`: an arbitrary-length bytestring (TODO).
- Output:
  - A 32-byte hash (TODO).

TODO: truncate correctly

This function is used in both stateful and stateless paths.

The 4-byte zero-padding at the end of the outer hash input ensures `H_msg` satisfies FIPS-205[^slhdsa], wherein `H_msg` is defined using `MGF1-SHA-256`[^mgf1].

Note that `PK.seed` is not padded in this tweaked hash function. (TODO: make sure to domain separate this between stateful/stateless)

### `PRF_msg(...)`

The tweaked hash function `PRF_msg` uses HMAC-SHA256 to hash `SK.prf`, randomness `opt_rand`, and an arbitrary-length message `M` (TODO: fixed length?). This function will be used to derive a _randomizer_ (salt) for the given message.

```py
PRF_msg(SK.prf, opt_rand, M) = hmac_sha256(SK.prf, opt_rand || M)[:N]
```

- Inputs:
  - `SK.prf`: an `N`-byte secret.
  - `opt_rand`: an `N`-byte salt.
  - `M`: an arbitrary-length bytestring (TODO).
- Output:
  - An `N`-byte hash.

This function is used in both stateful and stateless paths, but only by the signing algorithm.

If deterministic signing is required and an RNG is not available, `opt_rand` will be set to `PK.seed`.

TODO: option for faster hypertree pruning grinding.

### Implementation Notes

- The only difference between `T_xmss`, `T_sphx`, `F`, and `H` is the byte-length of the third input parameter. They are defined as different hash functions for security.
- `F(...)` is the most performance-critical hash function to optimize, as it dominates the runtime of signing, keygen, and verification.
- The padded `PK.seed` should be absorbed into a SHA256 midstate which is cached and reused. **This doubles performance.**
- These tweaked hash functions often handle secret inputs like `SK.seed`, so implementations should be free of control flows which branch and leak side-channel information based on potentially-secret data. Inputs should not be copied in memory unless securely erased afterwards.
- Many of these hash functions are invoked on independent data, and so can be run in parallel. Platforms with access to vectorized (SIMD) instruction sets on x86[^simd_x86] or ARM[^simd_arm] CPUs may utilize them to parallelize SHA256[^sha256x8] to improve performance significantly: a factor of 4 or more in some cases.
- Implementors can use SHA2 hardware acceleration[^sha_ni], though this is best used to accelerate verification, not signing or keygen[^sha_ni_bench].


## TODO

- Because SLH-DSA and XMSS have different signature sizes, this means the SHRINCS signature size is variable.
- Mention Vulkan[^vulkan] for signing/keygen.
- Discuss XMSS tree caching

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
