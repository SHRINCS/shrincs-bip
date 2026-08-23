# This file stores derived values used for templating comparisons
# and other non-essential metadata into the specification document.

from .shrincs import *
from math import comb, floor, log2

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
  -target_sum_fail_probability_log2(
    WOTS_C_CHAIN_COUNT,                         # Number of WOTS+C chains
    2**WOTS_C_CHAIN_BITS,                       # WOTS+C chain length
    WOTS_C_CONSTANT_SUM + WOTS_C_CHAIN_COUNT,   # Target WOTS+C sum is modified because of non-zero dice rolls.
    2**16
  )
)

def sha256_compressions(size: int) -> int:
  """Compute the number of SHA256 compressions needed to hash a given size preimage."""
  return size // 64 + (1 if (size % 64) < 56 else 2)

# Signature/key size ratios.
SHRINCS_MIN_KEY_PLUS_SIG_SIZE = SHRINCS_SF_SIGNATURE_SIZE_MIN + 48
SLH_DSA_128S_SIZE_RATIO = round((7856+32) / SHRINCS_MIN_KEY_PLUS_SIG_SIZE, 2)
ML_DSA_SIZE_RATIO = round((2420+1312) / SHRINCS_MIN_KEY_PLUS_SIG_SIZE, 2)

# Comparison against SLH-DSA-SHA2-128s.
SLH_DSA_128S_SIGNATURE_SIZE = 7856
SHRINCS_SL_SIGNATURE_SIZE_REDUCTION_PERCENT = round(
  100 * (SLH_DSA_128S_SIGNATURE_SIZE - SHRINCS_SL_SIGNATURE_SIZE) /
  SLH_DSA_128S_SIGNATURE_SIZE
)

# Maximum percentage of the stateless signature budget that could appear in
# 200 years of blocks, assuming every block byte is a stateless signature made
# under the same public key.
SHRINCS_SL_SIGNATURE_BUDGET_USED_200_YEARS_PERCENT = round(
  100 * 200 * 365 * 144 * (4_000_000 // SHRINCS_SL_SIGNATURE_SIZE) / 2**40,
  2
)

# Comparing stateful/stateless signature sizes.
STATEFUL_SIG_SIZE_RATIO = round(SHRINCS_SL_SIGNATURE_SIZE / SHRINCS_SF_SIGNATURE_SIZE_MIN, 2)


# Minimum SHA256 compressions needed to verify a stateful SHRINCS signature.
#
# H_msg_sf call +
# H_grind call +
# Recomputing WOTS chain tips +
# Combining WOTS chain tips +
# One H() call (merkle node)
STATEFUL_VERIFY_COMPRESSIONS_MIN = 4 + \
                                   1 + \
                                   (WOTS_C_CHAIN_COUNT * (2**WOTS_C_CHAIN_BITS - 1) - WOTS_C_CONSTANT_SUM) + \
                                   sha256_compressions(22 + WOTS_C_CHAIN_COUNT * 16) + \
                                   1

# Maximum SHA256 compressions needed to verify a stateful SHRINCS signature.
STATEFUL_VERIFY_COMPRESSIONS_MAX = STATEFUL_VERIFY_COMPRESSIONS_MIN + 254 # 254 additional H() calls

# SHA256 compressions per byte for the stateful verifier (worst case).
STATEFUL_VERIFY_COMPRESSIONS_PER_BYTE_MAX = round(STATEFUL_VERIFY_COMPRESSIONS_MIN / SHRINCS_SF_SIGNATURE_SIZE_MIN, 3)

# SHA256 compressions needed to verify a FORS signature.
FORS_VERIFY_COMPRESSIONS = SPHX_FORS_COUNT + \
                           SPHX_FORS_COUNT * SPHX_FORS_HEIGHT + \
                           sha256_compressions(22 + SPHX_FORS_COUNT * 16) # Combining FORS roots

# Minimum SHA256 compressions needed to verify an XMSS signature.
#
# WOTS verify cost + H() invocations (merkle nodes)
XMSS_VERIFY_COMPRESSIONS_MIN = sum((2**WOTS_TW_CHAIN_BITS - i - 1 for i in wots_tw_message_to_indexes(replicate(0xFF, 16)))) + \
                               sha256_compressions(22 + WOTS_TW_CHAIN_COUNT * 16) + \
                               SPHX_XMSS_HEIGHT

# Maximum SHA256 compressions needed to verify an XMSS signature.
#
# WOTS verify cost + H() invocations (merkle nodes)
# H() invocations (merkle nodes)
XMSS_VERIFY_COMPRESSIONS_MAX = sum((2**WOTS_TW_CHAIN_BITS - i - 1 for i in wots_tw_message_to_indexes(zeros(16)))) + \
                               sha256_compressions(22 + WOTS_TW_CHAIN_COUNT * 16) + \
                               SPHX_XMSS_HEIGHT

XMSS_VERIFY_COMPRESSIONS_AVG = (XMSS_VERIFY_COMPRESSIONS_MIN + XMSS_VERIFY_COMPRESSIONS_MAX) // 2

# Minimum SHA256 compressions needed to verify a stateless SHRINCS signature.
#
# H_msg_sl call +
# FORS +
# hypertree verify
STATELESS_VERIFY_COMPRESSIONS_MIN = 4 + \
                                    FORS_VERIFY_COMPRESSIONS + \
                                    SPHX_LAYER_COUNT * XMSS_VERIFY_COMPRESSIONS_MIN

# Maximum SHA256 compressions needed to verify a stateless SHRINCS signature.
#
# H_msg_sl call +
# FORS +
# hypertree verify
STATELESS_VERIFY_COMPRESSIONS_MAX = 4 + \
                                    FORS_VERIFY_COMPRESSIONS + \
                                    SPHX_LAYER_COUNT * XMSS_VERIFY_COMPRESSIONS_MAX

# SHA256 compressions per byte for the stateless verifier (worst case).
STATELESS_VERIFY_COMPRESSIONS_PER_BYTE_MAX = round(STATELESS_VERIFY_COMPRESSIONS_MAX / SHRINCS_SL_SIGNATURE_SIZE, 3)

# Comparison of worst-case stateful vs stateless signing performance.
STATEFUL_VERIFY_SPEED_RATIO = round(STATELESS_VERIFY_COMPRESSIONS_MAX / STATEFUL_VERIFY_COMPRESSIONS_MAX, 2)

# WOTS chains +
# Combining WOTS chain tips
WOTS_TW_KEYGEN_COMPRESSIONS = WOTS_TW_CHAIN_COUNT * 2**WOTS_TW_CHAIN_BITS + \
                              sha256_compressions(22 + WOTS_TW_CHAIN_COUNT * 16)

WOTS_TW_SIGN_COMPRESSIONS_MIN = sum((i + 1 for i in wots_tw_message_to_indexes(zeros(16))))
WOTS_TW_SIGN_COMPRESSIONS_MAX = sum((i + 1 for i in wots_tw_message_to_indexes(replicate(0xFF, 16))))
WOTS_TW_SIGN_COMPRESSIONS_AVG = (WOTS_TW_SIGN_COMPRESSIONS_MIN + WOTS_TW_SIGN_COMPRESSIONS_MAX) // 2

# Generating other WOTS leaves +
# WOTS-TW signing +
# H() invocations (merkle nodes)
XMSS_SIGN_COMPRESSIONS_AVG = (2**SPHX_XMSS_HEIGHT - 1) * WOTS_TW_KEYGEN_COMPRESSIONS + \
                             WOTS_TW_SIGN_COMPRESSIONS_AVG + \
                             2**SPHX_XMSS_HEIGHT - 1

# One PRF call + one F call per leaf (total 2**(SPHX_FORS_HEIGHT+1)),
# plus 2**SPHX_FORS_HEIGHT - 1 calls to H (merkle nodes).
FORS_TREE_GEN_COMPRESSIONS = 3 * 2**SPHX_FORS_HEIGHT - 1

# SHA256 compressions needed to sign with the SHRINCS stateless component.
#
# PRF_msg_sl call +
# H_msg_sl call +
# FORS trees +
# Combining FORS roots +
# Hypertree signing (d - 1 XMSS layers) +
# Signing with top XMSS layer
STATELESS_SIGN_COMPRESSIONS_AVG = 2 + \
                                  4 + \
                                  SPHX_FORS_COUNT * FORS_TREE_GEN_COMPRESSIONS + \
                                  sha256_compressions(22 + SPHX_FORS_COUNT * 16) + \
                                  (SPHX_LAYER_COUNT - 1) * (XMSS_SIGN_COMPRESSIONS_AVG + XMSS_VERIFY_COMPRESSIONS_AVG) + \
                                  XMSS_SIGN_COMPRESSIONS_AVG

# 1 - SHRINCS work / SLH-DSA work
# TODO: compute the SLH-DSA costs using the same logic we use for SHRINCS
SHRINCS_SL_SIGN_COMPRESSIONS_REDUCTION_PERCENT = round(100 * (1 - STATELESS_SIGN_COMPRESSIONS_AVG / 2218245))
SHRINCS_SL_VERIFY_COMPRESSIONS_REDUCTION_PERCENT = round(100 * (1 - STATELESS_VERIFY_COMPRESSIONS_MAX / 3893))


EXPECTED_WOTS_C_GRINDING_ATTEMPTS = round(1 / (1 - 2**target_sum_fail_probability_log2(WOTS_C_CHAIN_COUNT, 2**WOTS_C_CHAIN_BITS, WOTS_C_CONSTANT_SUM + WOTS_C_CHAIN_COUNT, 1)))

# WOTS chains +
# Combining WOTS chain tips
WOTS_C_KEYGEN_COMPRESSIONS = (WOTS_C_CHAIN_COUNT * 2**WOTS_C_CHAIN_BITS + \
                             sha256_compressions(22 + 16 * WOTS_C_CHAIN_COUNT))

# Average number of SHA256 compressions needed for UXMSS signing.
#
# PRF_msg_sf call +
# H_msg_sf call +
# Expected number of grinding attempts +
# PRF invocations +
# WOTS chain computation +
# Regenerating other leaves
# H() invocations (merkle nodes) (averaged over all leaves)
def uxmss_sign_compressions(depth: int) -> int:
  return 2 + \
          4 + \
          EXPECTED_WOTS_C_GRINDING_ATTEMPTS + \
          WOTS_C_CONSTANT_SUM + \
          WOTS_C_CHAIN_COUNT + \
          depth * WOTS_C_KEYGEN_COMPRESSIONS + \
          round(depth * (depth - 1) / (2 * (depth + 1)))

UXMSS_31_SIGN_COMPRESSIONS_AVG  = uxmss_sign_compressions(31)
UXMSS_255_SIGN_COMPRESSIONS_AVG = uxmss_sign_compressions(255)

# Average number of SHA256 compressions needed for BXMSS signing.
#
# PRF_msg_sf call +
# H_msg_sf call +
# Expected number of grinding attempts +
# PRF invocations +
# WOTS chain computation +
# Regenerating other leaves +
# H() invocations (merkle nodes)
def bxmss_sign_compressions(depth: int) -> int:
  return 2 + \
          4 + \
          EXPECTED_WOTS_C_GRINDING_ATTEMPTS + \
          WOTS_C_CONSTANT_SUM + \
          WOTS_C_CHAIN_COUNT + \
          (2**depth - 1) * WOTS_C_KEYGEN_COMPRESSIONS + \
          2**depth - 1 - depth

BXMSS_5_SIGN_COMPRESSIONS_AVG  = bxmss_sign_compressions(5)
BXMSS_8_SIGN_COMPRESSIONS_AVG  = bxmss_sign_compressions(8)
BXMSS_10_SIGN_COMPRESSIONS_AVG = bxmss_sign_compressions(10)
BXMSS_12_SIGN_COMPRESSIONS_AVG = bxmss_sign_compressions(12)
BXMSS_16_SIGN_COMPRESSIONS_AVG = bxmss_sign_compressions(16)
BXMSS_20_SIGN_COMPRESSIONS_AVG = bxmss_sign_compressions(20)

# Generating leaves +
# H() invocations (merkle nodes)
STATELESS_KEYGEN_COMPRESSIONS = 2**SPHX_XMSS_HEIGHT * WOTS_TW_KEYGEN_COMPRESSIONS + \
                                2**SPHX_XMSS_HEIGHT - 1

# SHA256 compressions needed to generate a SHRINCS key with UXMSS at various depths.
#
# Generating leaves + H() invocations (merkle nodes)
def uxmss_keygen_compressions(depth: int) -> int:
  return (depth + 1) * WOTS_C_KEYGEN_COMPRESSIONS + depth


UXMSS_31_KEYGEN_COMPRESSIONS  = STATELESS_KEYGEN_COMPRESSIONS + uxmss_keygen_compressions(31)
UXMSS_255_KEYGEN_COMPRESSIONS = STATELESS_KEYGEN_COMPRESSIONS + uxmss_keygen_compressions(255)

UXMSS_255_KEYGEN_COMPRESSIONS_STATEFUL_ONLY = uxmss_keygen_compressions(255)

# SHA256 compressions needed to generate a SHRINCS key with BXMSS at various depths.
#
# Generating leaves + H() invocations (merkle nodes)
def bxmss_keygen_compressions(depth: int) -> int:
  return 2**depth * WOTS_C_KEYGEN_COMPRESSIONS + (2**depth - 1)

BXMSS_5_KEYGEN_COMPRESSIONS  = STATELESS_KEYGEN_COMPRESSIONS + bxmss_keygen_compressions(5)
BXMSS_8_KEYGEN_COMPRESSIONS  = STATELESS_KEYGEN_COMPRESSIONS + bxmss_keygen_compressions(8)
BXMSS_10_KEYGEN_COMPRESSIONS = STATELESS_KEYGEN_COMPRESSIONS + bxmss_keygen_compressions(10)
BXMSS_12_KEYGEN_COMPRESSIONS = STATELESS_KEYGEN_COMPRESSIONS + bxmss_keygen_compressions(12)
BXMSS_16_KEYGEN_COMPRESSIONS = STATELESS_KEYGEN_COMPRESSIONS + bxmss_keygen_compressions(16)
BXMSS_20_KEYGEN_COMPRESSIONS = STATELESS_KEYGEN_COMPRESSIONS + bxmss_keygen_compressions(20)

STATEFUL_WOTS_CHECKSUM_MAX = WOTS_C_CHAIN_COUNT * (2**WOTS_C_CHAIN_BITS - 1)
STATEFUL_WOTS_CHECKSUM_CHAINS_HYPOTHETICAL = ceildiv(STATEFUL_WOTS_CHECKSUM_MAX.bit_length(), WOTS_C_CHAIN_BITS)
STATEFUL_WOTS_TW_SIZE_INCREASE_PERCENT = round(100 * 16 * STATEFUL_WOTS_CHECKSUM_CHAINS_HYPOTHETICAL / SHRINCS_SF_SIGNATURE_SIZE_MIN)
