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

State management also creates engineering challenges for low-memory or high-volume signers: If we have a signer who generates `n` keys, it seems like at bare minimum a naive signer must store `n` bits of state - one bit per key to indicate whether the key has been used.
For full utility the signer would more likely want to store `n` *bytes* of state, with a 1-byte counter per keypair.

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

<!-- TODO diagram -->

When signing, the hardware wallet expects the host to provide the correct counter for the chosen signing key, along with an opening proof to show the state is valid and corresponds to the commitment stored on the hardware wallet.
The hardware wallet must then increment the state and update its commitment in its non-volatile storage *before* creating the signature (see [Store-then-Sign](#store-then-sign)).

### Redundancy

The best state storage medium is not one, but a combination of multiple storage media providing redundancy.
If one medium fails or is rolled back, state can be recovered from the others.

*Double redundancy* (two separate storage locations) will adequately protect a wallet in case either medium is somehow rolled back.
If the signer finds both state storage media disagree on the counter for a given key, the signer cannot tell which is faulty and so she must use the higher of the two counters, or else use the stateless signing path to be very safe.
At least one of these media should be durable and rollback-resistant (e.g. a TPM).

*Triple redundancy* is best.
Three independent storage media allow the signer to reconstruct the correct state when one medium disagrees with the other two.
If the wallet threat model includes a situation where two of the three media have been compromised, then even with triple redundancy the wallet must still assume the highest provided counter is correct.

If state recovery is not a desired goal, and the wallet only wants a boolean yes/no as to whether the state storage media are in agreement, the wallet may store a commitment to the state in the secondary media, while maintaining the full set of counters in just one primary medium.

[Offloading](#offloading) is such an example of a simple double redundancy setup, where one medium (the hardware wallet) stores only a commitment and if the two media disagree on the current state then the stateful path is not usable anymore.

Note that when signing, the wallet must successfully commit the updated state into *all* storage media before creating the signature (see [Store-then-Sign](#store-then-sign)).

## Wallet Recovery

TODO
- Wallet IDs
- Multi-device pairing

