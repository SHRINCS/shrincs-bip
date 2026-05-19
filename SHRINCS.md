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


### Padding

Every SHRINCS keypair contains a randomly generated 16-byte salt value called `PK.seed` which is appended to the public key. This seed salts every hash function invocation when signing or verifying a SHRINCS signature, to reduce the chance that two hash invocations produce the same outputs for different SHRINCS keypairs.

To save computational effort, `PK.seed` is padded to a length of 64 bytes. This aligns with the SHA256 block size, so that `PK.seed` can be absorbed into the SHA256 state, and that state can be reused.

The padding bytes to use depends on whether the `PK.seed` is being used to salt the stateful or stateless signing path of SHRINCS. This serves to separate contexts between stateful and stateless paths. This contextual padding of `PK.seed` is denoted by `pad(PK.seed)`. TODO

- In the stateless path:



## Building Blocks

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

### ADRS

A key security property of SHRINCS and its components is that every hash function invocation used in the verification algorithm must be _unique,_ so that inputs used in one hash function cannot be reused to produce the same output in another hash function.

To accomplish this goal, we will use _tweakable hash functions_ (explained below) which modify a hash function with some context-dependent location information. This unambiguously specifies the exact instance of the hash function in the signing/verification algorithms where the hash function is being used. This location is called an _address_ and we encode it into a 22-byte array, often called an `ADRS`.[^adrs]

| Field | Size | Purpose |
|:-:|:-:|:-:|
| `layer` | 1 byte | In the stateful path, this specifies depth in the XMSS tree. In the stateless path, this specifies the layer in the SPHINCS hypertree. |
| `tree_address` | 8 bytes | A 64-bit integer serialized with big-endian encoding. In the stateful path, this specifies the node index within a layer of the XMSS tree. In the stateless path, this specifies the node index within a layer of the SPHINCS hypertree. |
| `type` | 1 byte | A context-dependent flag which gives meaning to the remaining 12 bytes. |
| (context dependent) | 12 bytes | Usage depends on the `type` field. |


### Tweakable Hash Functions

At the core of both SPHINCS and XMSS is the concept of _tweakable hash functions._ A tweakable hash function can be thought of as a hash function which supports additional independent parameters that can be used to scope the hash function to a specific role. This makes security easier to prove.

In SHRINCS, we construct tweakable hash functions using SHA256 as the base hash function. This we invoke as the primitive function `sha256(x)`. SHA256 outputs are truncated, often to `N = 16` bytes, which we denote using Pythonic list-slicing notation: `sha256(x)[:N]`

#### `F(...)`

The hash function `F` is used to generate and iterate Winternitz hash chains.

```py
F()
```



## TODO

- Because SLH-DSA and XMSS have different signature sizes, this means the SHRINCS signature size is variable.


[^slhdsa]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
[^adrs]: The 22-byte `ADRS` format aligns with the ADRS<sup>c</sup> format in SLH-DSA and FIPS-205[^slhdsa] for SHA2 parameter sets.
[^xmss]: TODO
