# State Management Guide

This is a supplemental document to the SHRINCS specification, intended as a practical guide for implementors considering usage of the SHRINCS stateful signing component.

For the purposes of this document, we will scope the discussion around Bitcoin wallets, and the word "wallet" will be used interchangeably with the word "implementation".
Many of the principles and techniques we use here extend to other use-cases where SHRINCS' stateful path is applicable too.

## Problems

As a reminder, SHRINCS has a stateful signing component which uses FXMSS.
Each SHRINCS key must track an accompanying *state counter* that is the number of signatures previously issued by that key.
The counter is incremented for every signature issued and stored in some persistent, durable, rollback-resistant and tamper-proof storage medium.
The cryptographic interface of SHRINCS signer detailed in [the reference implementation](./impl/shrincs.py) does not provide any concrete state storage or management solution.
This complexity is instead offloaded to the caller, which in the case of Bitcoin, would be wallet and SDK developers.

The consequences of state misuse are severe: Sign two different messages with the same key and state counter, and an adversary who observed both signatures gains the ability to forge.

State management also creates engineering challenges for low-memory or high-volume signers: If we have a signer who generates `n` SHRINCS keys, it seems like at bare minimum a naive signer must store `n` bits of state - one bit per key to indicate whether the key has been used.
For full utility with UXMSS the signer would more likely want to store at least `n` *bytes* of state, with a 1-byte counter per keypair.

Thankfully there are many defensive engineering measures stateful signers can take to reduce the risks and complexities of managing state.

## Simple Tips

This section contains basic tips for securing wallet software against SHRINCS state reuse.

### Robust Storage

If using a single-storage site, wallets must store state counters only on durable, rollback-resistant storage media, such as secure elements, [TPMs](https://ebrary.net/24775/computer_science/counter_index), or on dedicated signing devices.

Notably, wallets must *not* store state only on standard filesystems, SQL databases, volatile storage (RAM), USB drives, cloud servers, IPFS, Nostr, or on the blockchain itself.
These media are all unsuitable as primary state storage media for one reason or another.

It is possible to combine multiple unsafe state storage media into a cohesive redundant system (see [Redundancy](#redundancy)), but having at least one robust state storage medium is safest, even if that medium only stores a commitment and not the full state itself (see [Offloading](#offloading)).

### Fresh Addresses

**The easiest way for a wallet to avoid state reuse is to avoid address reuse.**

If a consumer wallet only receives one UTXO per address and uses a unique SHRINCS key per address, then state reuse is only possible in rare edgecases when double-signing the same transaction, or RBFing an unconfirmed transaction.
Once that UTXO is spent and confirmed, if no other UTXOs are ever received, the wallet has no more reason to use the stateful path on that key.
Even if state is reused (e.g. by tricking the wallet to sign a different invalid transaction spending the same UTXO), this will have no meaningful economic consequence to the user.

This also has a benefit for wallet performance. If a wallet can safely assume an address will only be used a few times, the program can get away with much shallower FXMSS trees, and can store much smaller state counters too.
For example, if a wallet imposes an artificial limit of 4 stateful signatures per keypair, it only needs to generate 4 WOTS+C leaves per key, and only needs to store 2 bits of state per key.

### Store-then-Sign

To reduce the chance of a state counter being reused, wallets must increment state counters and ensure the change is committed into durable storage *before* invoking SHRINCS' cryptographic signing code.

If the signer creates the signature *before* incrementing the state counter, even if the signer doesn't release the signature outright the signature could still be leaked locally through side-channels or shared memory access.

On the other hand, if the state counter is incremented before the secret key is used, this makes state reuse far less likely even if side channels are considered.

Of course, fault injection attacks on the state storage medium must still be mitigated.
The signer must never create a signature until it is confident the state counter storage cannot be rolled back.

If using multiple storage media (see [Redundancy](#redundancy)) then the counter must be fully committed into all available storage media before the signature is issued.

### Compression

Under typical usage in a Bitcoin wallet, assuming one UXMSS SHRINCS key per address, there could be potentially thousands or millions of used SHRINCS keys whose state must be tracked by the wallet.
This could result in a disk usage blowup as the state size grows linearly with wallet usage.

Thankfully state counters for UXMSS will follow a consistent distribution with most counters staying between 0 and 2 (inclusive).

This means we can use compression algorithms (e.g. [huffman trees](https://en.wikipedia.org/wiki/Huffman_coding)) to losslessly compress a block of many state counters down to a much smaller size.
Even an approach as simple as passing the state counters through the [GZip algorithm](https://en.wikipedia.org/wiki/Gzip) before storing them can reduce their combined size by a factor of \~3x.

More elegant compression algorithms can be optimized specifically to compress UXMSS state counters, and this format could be standardized across wallets.

### Offloading

Storing compressed state counters for many SHRINCS keys is sometimes not an option, e.g. on a secure element with tightly limited storage.
The constrained storage capacity of such devices simply does not permit it.
The signer device could restrict the number of SHRINCS keys the signer can use, commensurate with the maximum number of state counters that the signing device can store securely.
However in the case of Bitcoin hardware wallets, we probably do not want to restrict the number of addresses a wallet can create.

Instead, the hardware wallet can store a **commitment** to the state counters, and offload the raw state counters to an untrusted *host* device.
A simple way to think of this is as a Merkle tree where the leaves are counters.

```
      o
    /   \
   /     \
  o       o
 / \     / \
1   3   5   1
```

When signing, the hardware wallet expects the host to provide the correct counter for the chosen signing key, along with an opening proof to show the state is valid and corresponds to the commitment stored on the hardware wallet.
The hardware wallet must then increment the state and update its commitment in its non-volatile storage *before* creating the signature (see [Store-then-Sign](#store-then-sign)).

Let's say we sign with the third key and use state 5. The host provides the following values to the hardware wallet:

```
      o
    /   \
   /     \
  o       o
         / \
        5   1
```

The hardware wallet can then increment the state counter 5 up to 6, and recalculate a new root using only the proof provided by the host - without being given all the other unchanged state counters.

```
      o
    /   \
   /     \
  o       o
         / \
        6   1
```

This only requires $\log_2(n)$ compute time on the device for storing $n$ SHRINCS key states.
Naively it requires $\log_2(n)$ space as well, but that can be improved via streaming: The host sends the merkle path in discrete chunks, while the device opens the commitment and computes the next updated root in parallel.

<details>
  <summary><h3>Example</h3></summary>

From the device's POV:

- Given the leaf values `5` and `1`, compute two hashes: `x = H(5, 1)` and `x' = H(5+1, 1)`.
- Given the merkle node `y = H(1, 3)` update `x = H(y, x)` and `x' = H(y, x')`.
  - Repeat some number of times.
- Check if `x` matches the commitment stored on the device, and if so update it to `x'`, then sign with the state counter 5.

This approach requires more round trips between the host and device, but needs very little working memory.
</details>

#### Packing

In principle this works, but it is very inefficient, because there is only one state counter per leaf.
A more efficient approach would be to *pack* multiple state counters together into each leaf, so that a hashed leaf takes up the same amount of space as a *packet* of counters.
This reduces the height of the merkle tree from $log_2(n)$ to $log_2(n / p)$ for a *packing rate* of $p$ counters per leaf.

```
                  ----------------  o  ----------------
                 /                                     \
          ----- o -----                          ------ o -----
        /              \                        /              \
      /                  \                    /                  \
[3, 1, 6, ...]     [1, 0, 2, ...]       [9, 0, 3, ...]     [2, 5, 5, ...]
```

As an example, if we have a packing rate of $p = 32$ counters per leaf, a wallet with $2^{32}$ keys would have state proofs consisting of 27 hashes (plus the counter packet).

#### Sparse State Trees

Note that in such a use-case, many SHRINCS keys may have the same state counter, namely zero, so the merkle tree is *sparse*: Many of its leaves are a hash of the same data, e.g. `Z[0] = H(0x000000...)`
This admits an easy host-side optimization because we can recursively compute `Z[i] = H(Z[i - 1] || Z[i - 1])`, where each `Z[i]` is the root of a height-`i` merkle tree whose leaves are all zero state counters.
We can then refer to these roots by referencing an index `i` rather than sending the full hash over the wire between host and device.

Consider a state counter merkle tree like this:

```
                  ----------------  o  ----------------
                 /                                     \
          ----- o -----                          ------ o -----
        /              \                        /              \
      /                  \                    /                  \
[3, 1, 6, ...]     [0, 0, 0, ...]       [0, 0, 0, ...]     [0, 0, 0, ...]
```

Instead of sending `Z[0] = H([0, 0, 0, ...])` and `Z[1] = H(Z[0] || Z[0])` in full over the wire, the host can simply send pointers `0` and `1`.
The hardware wallet can either recompute `Z[0]` and `Z[1]` on the fly with two hash invocations, or pull them from a cache.

### Redundancy

The best state storage medium is not one, but a combination of multiple storage media providing redundancy.

Replicating state in $n$ different storage sites will protect a wallet in the event that up to $n - 1$ state storage sites are compromised or rolled back.
If the signer finds her state storage media disagree on the counter for a given key, the signer cannot tell which is faulty and so she must use the higher of the two counters, or else use the stateless signing path to be very safe.
At least one of these media should be durable and rollback-resistant (e.g. a TPM).

When replicating state to storage media outside the signer's direct control (e.g. a cloud server; a host laptop), the signer should use authenticated encryption or stateless signatures to ensure state counters on the remote storage medium cannot be incremented adversarially.

[Offloading](#offloading) is an example of a simple double redundancy setup, where one medium (the hardware wallet) stores only a commitment while the host computer stores a redundant copy of the full state.
If the two media disagree on the current state (e.g. if the hardware wallet is lost), then the stateful path is not usable anymore.

Note that when signing, the wallet must successfully commit the updated state into *all* storage media before creating the signature (see [Store-then-Sign](#store-then-sign)).

## Wallet Recovery

TODO
- Wallet IDs
- Multi-device pairing

