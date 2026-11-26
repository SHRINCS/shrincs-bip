from math import log2
from dataclasses import dataclass

from ..shrincs import ceildiv, SHRINCS_SECURITY_BITS
from .common import num_messages_sum, sha256_compressions


@dataclass(frozen=True)
class StatefulParameterSet:
  log_w: int  # WOTS_C_CHAIN_BITS

  def __str__(self):
    return f"w={2**self.log_w} len={self.chain_count()}"

  def chain_count(self) -> int:
    """Number of WOTS+C chains (WOTS_C_CHAIN_COUNT)."""
    return ceildiv(SHRINCS_SECURITY_BITS, self.log_w)

  def trail_bits(self) -> int:
    """
    Return the number of message bits which are used to define
    (the high order bits of) the trailing WOTS index.
    The trailing index may be less than `log_w` bits if `log_w` does not divide 128.
    """
    return SHRINCS_SECURITY_BITS - (self.chain_count() - 1) * self.log_w

  def count_target_sum_messages(self, target: int) -> int:
    """
    Return the total number of possible messages whose indices sum to `target`.
    """
    w = 2 ** self.log_w

    # The number of padding (low order) bits in the trailing index.
    pad_bits = self.log_w - self.trail_bits()

    # For each possible trailing index `v` in `[0, 1 << pad_bits, 2 << pad_bits, ...]`,
    # count the number of combinations of the first `chains - 1` indices that sum to
    # `target - v`. This gives the total number of valid index sets whose sum is `target`.
    return sum(
      num_messages_sum(w, self.chain_count() - 1, target - (i << pad_bits))
      for i in range(2**self.trail_bits())
    )

  def target_sum_fail_probability_log2(self, target: int, tries: int) -> float:
    """
    Returns log2(Pr[sum(WOTS indices) != target]**tries).
    Computes the probability of WOTS+C grinding failure after `tries` grinding loops.
    Logic taken from https://gist.github.com/conduition/c19f00d9420eee009c9f33d9cd991bd6
    """
    # The number of invalid combinations (i.e. # of possible combos minus # of valid combos)
    n_total = 2 ** SHRINCS_SECURITY_BITS
    n_valid = self.count_target_sum_messages(target)
    n_invalid = n_total - n_valid

    # The failure probability for a single random combination (invalid_combinations / total_combinations).
    r = n_invalid / n_total

    # The probability of making `tries` consecutive rolls of n dice which do not sum to p is r ** tries.
    # We avoid the need for extremely high precision floats by computing with logarithms.
    #
    #   log2(r ** tries) = log2(r) * tries
    return log2(r) * tries

  def trailing_index_max(self) -> int:
    """
    Maximum of the last WOTS+C index digit. May be less than `w-1` for
    `log_w` parameters which do not divide `SHRINCS_SECURITY_BITS`.
    """
    pad_bits = self.log_w - self.trail_bits()
    return 2**self.log_w - 2**pad_bits

  def constant_sum(self) -> int:
    """The WOTS+C checksum target offset (WOTS_C_CONSTANT_SUM)."""
    return ceildiv((self.chain_count() - 1) * (2**self.log_w - 1) + self.trailing_index_max(), 2)

  def chains_size(self) -> int:
    return self.chain_count() * 16

  def combine_cost(self) -> int:
    """SHA256 compressions to combine WOTS+C chain tips into the merkle root."""
    return sha256_compressions(22 + self.chains_size())

  def wots_keygen_cost(self) -> int:
    """SHA256 compressions to build one WOTS+C key (every chain to the top, plus combine_cost)."""
    return self.chain_count() * 2**self.log_w + self.combine_cost()

  def grind_fail_probability_log2(self, tries: int) -> float:
    """The probability that WOTS+C grinding fails after a certain number of grinding attempts."""
    return self.target_sum_fail_probability_log2(self.constant_sum(), tries)

  def expected_grinding_attempts(self) -> float:
    """Expected number of WOTS+C grinding attempts per accepted message."""
    return 1 / (1 - 2**self.grind_fail_probability_log2(1))

  def signature_size(self, depth: int) -> int:
    """
    Byte size of a stateful signature over a WOTS+C tree of `depth`.
    Setting `depth = 1` yields `SHRINCS_SF_SIGNATURE_SIZE_MIN`.
    """
    return 1 + 16 + ceildiv(min(depth, 64), 8) + (2 + self.chains_size() + 16 * depth)

  def verify_compressions(self, depth: int) -> int:
    """
    SHA256 compressions to verify a stateful signature at `depth`:
    H_msg_sf + H_grind + recomputing WOTS+C chain tips + combining tips + `depth` merkle nodes.
    """
    wots_verify = self.chain_count() * (2**self.log_w - 1) - self.constant_sum()
    return 4 + 1 + wots_verify + self.combine_cost() + depth

  def verify_compressions_min(self) -> int:
    """Minimum SHA256 compressions to verify a stateful signature occurs at the highest leaf."""
    return self.verify_compressions(1)

  def verify_compressions_max(self) -> int:
    """Maximum SHA256 compressions to verify a stateful signature occurs at the deepest leaf."""
    return self.verify_compressions(255)

  def verify_compressions_per_byte(self, depth: int) -> float:
    """Verification SHA256 compressions per byte of a depth-`depth` stateful signature."""
    return round(self.verify_compressions(depth) / self.signature_size(depth), 3)

  def uxmss_sign_compressions(self, depth: int) -> int:
    """
    Average SHA256 compressions to sign with UXMSS (unbalanced stateful tree) at `depth`,
    assuming a 32-byte message.
    """
    # 2 bytes context string, 16 byte complementary root, 32 byte actual message.
    ctx_msg_size = 2 + 16 + 32

    return round(
      + sha256_compressions(16 + 16 + 16 + 9 + ctx_msg_size)  # H_msg_sf inner
      + sha256_compressions(16 + 16 + 32 + 9)      # H_msg_sf outer
      + sha256_compressions(16 + 9 + ctx_msg_size) # PRF_msg_sf HMAC inner
      + sha256_compressions(32)                    # PRF_msg_sf HMAC outer
      + self.expected_grinding_attempts()          # grinding
      + self.constant_sum()                        # WOTS+C checksum chains
      + self.chain_count()                         # WOTS+C message chains
      + depth * self.wots_keygen_cost()            # regenerating other leaves
      + depth * (depth - 1) / (2 * (depth + 1))    # merkle nodes (averaged over all leaves)
    )

  def bxmss_sign_compressions(self, depth: int) -> int:
    """
    Average SHA256 compressions to sign with BXMSS (balanced stateful tree) at `depth`,
    assuming a 32-byte message.
    """
    # 2 bytes context string, 16 byte complementary root, 32 byte actual message.
    ctx_msg_size = 2 + 16 + 32

    return round(
      + sha256_compressions(16 + 16 + 16 + 9 + ctx_msg_size)  # H_msg_sf inner
      + sha256_compressions(16 + 16 + 32 + 9)      # H_msg_sf outer
      + sha256_compressions(16 + 9 + ctx_msg_size) # PRF_msg_sf HMAC inner
      + sha256_compressions(32)                    # PRF_msg_sf HMAC outer
      + self.expected_grinding_attempts()          # grinding
      + self.constant_sum()                        # WOTS+C checksum chains
      + self.chain_count()                         # WOTS+C message chains
      + (2**depth - 1) * self.wots_keygen_cost()   # regenerating other leaves
      + 2**depth - 1 - depth                       # merkle nodes
    )

  def uxmss_keygen_compressions(self, depth: int) -> int:
    """SHA256 compressions to generate a stateful key with UXMSS at `depth`."""
    return (depth + 1) * self.wots_keygen_cost() + depth

  def bxmss_keygen_compressions(self, depth: int) -> int:
    """SHA256 compressions to generate a stateful key with BXMSS at `depth`."""
    return 2**depth * self.wots_keygen_cost() + (2**depth - 1)

  def wots_checksum_chains_hypothetical(self) -> int:
    """
    Number of chains a naive WOTS-TW-style checksum would need for this WOTS+C
    message (STATEFUL_WOTS_CHECKSUM_CHAINS_HYPOTHETICAL), used to estimate the
    size a WOTS+C checksum costs over a WOTS-TW checksum.
    """
    checksum_max = self.chain_count() * (2**self.log_w - 1)
    return ceildiv(checksum_max.bit_length(), self.log_w)
