# This file stores derived values used for templating comparisons
# and other non-essential metadata into the specification document.

from .shrincs import *
from math import comb, floor, log2

# Returns log2(Pr[sum(n random s-sided dice DON'T sum to p)]**tries).
# Used to compute the probability of WOTS+C grinding failure.
# Logic taken from https://gist.github.com/conduition/c19f00d9420eee009c9f33d9cd991bd6
def target_sum_fail_probability(n: int, s: int, p: int, tries: int):
  # The total number of possible combinations rolling n dice with s sides each is:
  d = s**n

  # This finds the number of possible rolls of n dice with s sides whose faces sum to p.
  #
  # Uses the formula from https://mathworld.wolfram.com/Dice.html
  #   https://mathworld.wolfram.com/images/equations/Dice/NumberedEquation7.svg
  c = sum(((-1)**k * comb(n, k) * comb(p - s*k - 1, n - 1) for k in range((p-n)//s + 1)))

  # The number of invalid combinations (i.e. # of possible combos minus # of valid combos)
  q = d - c

  # The failure probability for a single random combination (invalid_combinations / total_combinations).
  r = q / d

  # The probability of making `tries` consecutive rolls of n dice which do not sum to p is r ** tries.
  # We avoid the need for extremely high precision floats by computing with logarithms.
  #
  #   log2(r ** tries) = log2(r) * tries
  return log2(r) * tries

WOTS_C_GRIND_FAIL_PROBABILITY_LOG = floor(
  -target_sum_fail_probability(
    WOTS_C_CHAIN_COUNT,                         # Number of WOTS+C chains
    2**WOTS_C_CHAIN_BITS,                       # WOTS+C chain length
    WOTS_C_CONSTANT_SUM + WOTS_C_CHAIN_COUNT,   # Target WOTS+C sum is modified because of non-zero dice rolls.
    2**16
  )
)
