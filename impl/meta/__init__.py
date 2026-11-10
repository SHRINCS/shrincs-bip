# This file stores derived values used for templating comparisons
# and other non-essential metadata into the specification document.

from ..shrincs import *
from .stateless_params import StatelessParameterSet
from .stateful_params import StatefulParameterSet
from math import floor

# The stateless (SPHINCS+) parameter set, used to populate the stateless
# performance metrics templated into the specification.
STATELESS = StatelessParameterSet(
  h     = SPHX_XMSS_HEIGHT * SPHX_LAYER_COUNT,
  d     = SPHX_LAYER_COUNT,
  a     = SPHX_FORS_HEIGHT,
  k     = SPHX_FORS_COUNT,
  log_w = WOTS_TW_CHAIN_BITS,
  qs    = 2**40, # signature budget
  tsec  = 128,   # target security level
)

# The stateful (WOTS+C + FXMSS) parameter set, used to populate the stateful
# performance metrics templated into the specification.
STATEFUL = StatefulParameterSet(WOTS_C_CHAIN_BITS)

SLH_DSA_SHA2_128s = StatelessParameterSet(h=63, d=7, a=12, k=14, log_w=4, qs=2**64, tsec=128)

# For reference. Subtract 1 for the indicator byte.
SLH_DSA_128S_SIGNATURE_SIZE = SLH_DSA_SHA2_128s.signature_size() - 1

# Signature/key size ratios.
SHRINCS_MIN_KEY_PLUS_SIG_SIZE = SHRINCS_SF_SIGNATURE_SIZE_MIN + 48
SLH_DSA_128S_SIZE_RATIO = round((SLH_DSA_128S_SIGNATURE_SIZE+32) / SHRINCS_MIN_KEY_PLUS_SIG_SIZE, 2)
ML_DSA_SIZE_RATIO = round((2420+1312) / SHRINCS_MIN_KEY_PLUS_SIG_SIZE, 2)

# Comparison against SLH-DSA-SHA2-128s.
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

# Minimum SHA256 compressions needed to verify a stateless SHRINCS signature.
STATELESS_VERIFY_COMPRESSIONS_MIN = STATELESS.verify_compressions_min()

# Maximum SHA256 compressions needed to verify a stateless SHRINCS signature.
STATELESS_VERIFY_COMPRESSIONS_MAX = STATELESS.verify_compressions_max()

# SHA256 compressions per byte for the stateless verifier (worst case).
STATELESS_VERIFY_COMPRESSIONS_PER_BYTE_MAX = STATELESS.verify_compressions_per_byte()

# Comparing stateful/stateless signature sizes.
STATEFUL_SIG_SIZE_RATIO = round(SHRINCS_SL_SIGNATURE_SIZE / SHRINCS_SF_SIGNATURE_SIZE_MIN, 2)

# Minimum / maximum SHA256 compressions needed to verify a stateful SHRINCS
# signature (H_msg_sf + H_grind + recomputing WOTS+C chain tips + combining tips
# + merkle nodes).
STATEFUL_VERIFY_COMPRESSIONS_MIN = STATEFUL.verify_compressions_min()
STATEFUL_VERIFY_COMPRESSIONS_MAX = STATEFUL.verify_compressions_max()

# The worst-case stateful verifier compressions per byte.
# depth = 1 yields the smallest signature with highest verify cost density.
STATEFUL_VERIFY_COMPRESSIONS_PER_BYTE_MAX = STATEFUL.verify_compressions_per_byte(1)

# Comparison of worst-case stateful vs stateless signing performance.
STATEFUL_VERIFY_SPEED_RATIO = round(STATELESS_VERIFY_COMPRESSIONS_MAX / STATEFUL_VERIFY_COMPRESSIONS_MAX, 2)

# SHA256 compressions needed to sign with the SHRINCS stateless component.
STATELESS_SIGN_COMPRESSIONS_AVG = STATELESS.sign_compressions_avg()

# 1 - SHRINCS work / SLH-DSA work
SHRINCS_SL_SIGN_COMPRESSIONS_REDUCTION_PERCENT = \
  round(100 * (1 - STATELESS_SIGN_COMPRESSIONS_AVG / SLH_DSA_SHA2_128s.sign_compressions_avg()))
SHRINCS_SL_VERIFY_COMPRESSIONS_REDUCTION_PERCENT = \
  round(100 * (1 - STATELESS_VERIFY_COMPRESSIONS_MAX / SLH_DSA_SHA2_128s.verify_compressions_max()))

# WOTS+C grinding failure probability over 2**16 attempts.
WOTS_C_GRIND_FAIL_PROBABILITY_LOG = floor(-STATEFUL.grind_fail_probability_log2(2**16))

# Average SHA256 compressions to sign with the SHRINCS stateful component, at
# various UXMSS (unbalanced) / BXMSS (balanced) tree depths.
UXMSS_31_SIGN_COMPRESSIONS_AVG  = STATEFUL.uxmss_sign_compressions(31)
UXMSS_255_SIGN_COMPRESSIONS_AVG = STATEFUL.uxmss_sign_compressions(255)

BXMSS_5_SIGN_COMPRESSIONS_AVG  = STATEFUL.bxmss_sign_compressions(5)
BXMSS_8_SIGN_COMPRESSIONS_AVG  = STATEFUL.bxmss_sign_compressions(8)
BXMSS_10_SIGN_COMPRESSIONS_AVG = STATEFUL.bxmss_sign_compressions(10)
BXMSS_12_SIGN_COMPRESSIONS_AVG = STATEFUL.bxmss_sign_compressions(12)
BXMSS_16_SIGN_COMPRESSIONS_AVG = STATEFUL.bxmss_sign_compressions(16)
BXMSS_20_SIGN_COMPRESSIONS_AVG = STATEFUL.bxmss_sign_compressions(20)

# Stateful/stateless key-generation cost of the stateless root XMSS tree.
STATELESS_KEYGEN_COMPRESSIONS = STATELESS.keygen_compressions()

# SHA256 compressions needed to generate a SHRINCS key with UXMSS/BXMSS at
# various depths. The stateless keygen cost is added on top to describe the total
# SHRINCS keygen cost.
UXMSS_31_KEYGEN_COMPRESSIONS  = STATELESS_KEYGEN_COMPRESSIONS + STATEFUL.uxmss_keygen_compressions(31)
UXMSS_255_KEYGEN_COMPRESSIONS = STATELESS_KEYGEN_COMPRESSIONS + STATEFUL.uxmss_keygen_compressions(255)

UXMSS_255_KEYGEN_COMPRESSIONS_STATEFUL_ONLY = STATEFUL.uxmss_keygen_compressions(255)

BXMSS_5_KEYGEN_COMPRESSIONS  = STATELESS_KEYGEN_COMPRESSIONS + STATEFUL.bxmss_keygen_compressions(5)
BXMSS_8_KEYGEN_COMPRESSIONS  = STATELESS_KEYGEN_COMPRESSIONS + STATEFUL.bxmss_keygen_compressions(8)
BXMSS_10_KEYGEN_COMPRESSIONS = STATELESS_KEYGEN_COMPRESSIONS + STATEFUL.bxmss_keygen_compressions(10)
BXMSS_12_KEYGEN_COMPRESSIONS = STATELESS_KEYGEN_COMPRESSIONS + STATEFUL.bxmss_keygen_compressions(12)
BXMSS_16_KEYGEN_COMPRESSIONS = STATELESS_KEYGEN_COMPRESSIONS + STATEFUL.bxmss_keygen_compressions(16)
BXMSS_20_KEYGEN_COMPRESSIONS = STATELESS_KEYGEN_COMPRESSIONS + STATEFUL.bxmss_keygen_compressions(20)

# Percentage by which a naive WOTS-TW-style checksum would inflate the stateful
# signature, using the WOTS+C checksum chain count from the stateful ParameterSet.
STATEFUL_WOTS_TW_SIZE_INCREASE_PERCENT = round(
  100 * (16 * STATEFUL.wots_checksum_chains_hypothetical() - 2) / SHRINCS_SF_SIGNATURE_SIZE_MIN
)
