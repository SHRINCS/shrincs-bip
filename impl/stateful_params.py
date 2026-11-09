from math import log2
from dataclasses import dataclass

from .shrincs import ceildiv
from .common import num_messages_sum, sha256_compressions

# Returns log2(Pr[sum(n random s-sided dice) != p]**tries).
# Used to compute the probability of WOTS+C grinding failure.
# Logic taken from https://gist.github.com/conduition/c19f00d9420eee009c9f33d9cd991bd6
def target_sum_fail_probability_log2(n: int, s: int, p: int, tries: int) -> float:
  # The total number of possible combinations rolling n dice with s sides each is:
  d = s**n

  # This finds the number of possible rolls of n dice with s sides whose faces sum to p.
  #
  # Uses the formula from https://mathworld.wolfram.com/Dice.html
  #   https://mathworld.wolfram.com/images/equations/Dice/NumberedEquation7.svg
  c = num_messages_sum(s, n, p)

  # The number of invalid combinations (i.e. # of possible combos minus # of valid combos)
  q = d - c

  # The failure probability for a single random combination (invalid_combinations / total_combinations).
  r = q / d

  # The probability of making `tries` consecutive rolls of n dice which do not sum to p is r ** tries.
  # We avoid the need for extremely high precision floats by computing with logarithms.
  #
  #   log2(r ** tries) = log2(r) * tries
  return log2(r) * tries


@dataclass
class StatefulParameterSet:
  log_w: int  # WOTS_C_CHAIN_BITS

  def __str__(self):
    return f"w={2**self.log_w} len={self.chain_count()}"

  def chain_count(self) -> int:
    """Number of WOTS+C chains (WOTS_C_CHAIN_COUNT)."""
    return ceildiv(128, self.log_w)

  def constant_sum(self) -> int:
    """The WOTS+C checksum target offset (WOTS_C_CONSTANT_SUM)."""
    return ceildiv(self.chain_count() * (2**self.log_w - 1), 2)

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
    return target_sum_fail_probability_log2(
      self.chain_count(),
      2**self.log_w,
      self.constant_sum(),
      tries
    )

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
    return round(
      1 + sha256_compressions(2 + 16 + 16 + 32) +   # PRF_msg_sf + H_msg_sf
      4 +
      self.expected_grinding_attempts() +           # grinding
      self.constant_sum() +                         # WOTS+C checksum chains
      self.chain_count() +                          # WOTS+C message chains
      depth * self.wots_keygen_cost() +             # regenerating other leaves
      depth * (depth - 1) / (2 * (depth + 1))       # merkle nodes (averaged over all leaves)
    )

  def bxmss_sign_compressions(self, depth: int) -> int:
    """
    SHA256 compressions to sign with BXMSS (balanced stateful tree) at `depth`,
    assuming a 32-byte message.
    """
    return round(
      1 + sha256_compressions(2 + 16 + 16 + 32) +   # PRF_msg_sf + H_msg_sf
      4 +
      self.expected_grinding_attempts() +           # grinding
      self.constant_sum() +                         # WOTS+C checksum chains
      self.chain_count() +                          # WOTS+C message chains
      (2**depth - 1) * self.wots_keygen_cost() +    # regenerating other leaves
      2**depth - 1 - depth                          # merkle nodes
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
