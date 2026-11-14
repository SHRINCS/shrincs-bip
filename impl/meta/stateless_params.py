from decimal import Decimal, getcontext
from math import log10, comb
from collections.abc import Hashable
from dataclasses import dataclass

from ..shrincs import ceildiv, base_2b
from .common import num_messages_sum, sha256_compressions


def wots_tw_chain_counts(log_w: int) -> tuple[int, int, int]:
  """Returns (count1, count2, checksum_max) for a WOTS-TW message of 128 bits."""
  count1 = ceildiv(128, log_w)
  checksum_max = count1 * (2**log_w - 1)
  count2 = ceildiv(checksum_max.bit_length(), log_w)
  return count1, count2, checksum_max

def wots_tw_message_to_indexes(message: bytes, log_w: int) -> list[int]:
  """Converts a 16-byte message into a checksummed array of WOTS-TW chain indexes."""
  count1, count2, checksum_max = wots_tw_chain_counts(log_w)
  msg_indexes = base_2b(message, log_w, count1)
  checksum = checksum_max - sum(msg_indexes)
  checksum_indexes = [0] * count2
  for i in range(count2):
    checksum_indexes[count2 - 1 - i] = (checksum // 2**(log_w * i)) % 2**log_w
  return msg_indexes + checksum_indexes

def encode_checksum(checksum: int, w: int, count2: int) -> list[int]:
  """Encodes a checksum into `count2` WOTS-TW chain indexes, each in [0, w)."""
  checksum_indexes = [0] * count2
  for i in range(count2):
    checksum_indexes[count2 - 1 - i] = checksum % w
    checksum //= w
  return checksum_indexes

def wots_tw_checksum_index_avg(w: int, l1: int, l2: int) -> float:
  """
  Average WOTS-TW checksum chain index over a uniform distribution of messages.

  `w` is the WOTS chain length (2**log_w), which is also the base used to
  re-encode the checksum.
  """
  msg_sum_counts = [num_messages_sum(w, l1, i) for i in range(1 + l1 * (w - 1))]

  # ensure we have accounted for every possible message.
  assert sum(msg_sum_counts) == w**l1

  # Sum and average all the indexes for each possible encoded checksum,
  # weighted by the probability of that checksum occurring.
  checksum_index_acc = 0
  for msg_sum, weight in enumerate(msg_sum_counts):
    checksum = l1 * (w - 1) - msg_sum
    checksum_index_acc += sum(encode_checksum(checksum, w, l2)) * weight
  return checksum_index_acc / (w**l1) / l2

getcontext().prec = int(log10(2**768)) + 1

# Pr[attacker H_msg call is covered by `sigs` FORS signatures among `leaves` keys]
def compute_sigma(leaves, a, k, sigs, tsec):
  q = Decimal(1) / Decimal(2)**a
  one = Decimal(1)
  sigma = Decimal(0)
  for j in range(k + 1):
    t = (one - q)**j
    pgf = (one - (one - t) / Decimal(leaves))**sigs
    sigma += comb(k, j) * ((-1)**j) * pgf
  return sigma


@dataclass
class StatelessParameterSet:
  h: int     # SPHX_XMSS_HEIGHT * SPHX_LAYER_COUNT
  d: int     # SPHX_LAYER_COUNT
  a: int     # SPHX_FORS_HEIGHT
  k: int     # SPHX_FORS_COUNT
  log_w: int # WOTS_TW_CHAIN_BITS
  qs: int    # Signature budget
  tsec: int  # Security level

  def sigma(self):
    return compute_sigma(2**self.h, self.a, self.k, self.qs, self.tsec)

  def __str__(self):
    return (f"h={self.h} d={self.d} a={self.a} k={self.k} w={2**self.log_w}")

  def _metrics(self):
    """
    Computes and caches every stateless performance metric for this parameter set.
    """
    cache = self.__dict__.get("_metrics_cache")
    if cache is not None:
      return cache

    log_w = self.log_w
    w = 2**log_w # WOTS chain length
    count1, count2, _ = wots_tw_chain_counts(log_w)
    count = count1 + count2
    chains_size = count * 16
    xmss_height = self.h // self.d

    # Average WOTS-TW chain indexes over a uniform distribution of messages.
    avg_msg_idx = (w - 1) / 2
    avg_check_idx = wots_tw_checksum_index_avg(w, count1, count2)

    # Combining WOTS-TW chain tips into a T_sl root.
    combine = sha256_compressions(22 + chains_size)

    # WOTS-TW keygen: every chain iterated to the top, plus combining.
    wots_keygen = count * w + combine

    # WOTS-TW signing, averaged over messages.
    wots_sign_avg = count + count1 * avg_msg_idx + count2 * avg_check_idx

    # XMSS signing/verification, averaged over messages.
    xmss_sign_avg = ((2**xmss_height - 1) * wots_keygen
                     + wots_sign_avg
                     + 2**xmss_height - 1 - xmss_height)
    xmss_verify_avg = (count1 * (w - 1 - avg_msg_idx)
                       + count2 * (w - 1 - avg_check_idx)
                       + combine + xmss_height)

    # XMSS verification in the best (all-0xFF message) and worst (all-0x00) cases.
    xmss_verify_min = (sum((w - i - 1 for i in wots_tw_message_to_indexes(bytes([0xFF]) * 16, log_w)))
                       + combine + xmss_height)
    xmss_verify_max = (sum((w - i - 1 for i in wots_tw_message_to_indexes(bytes(16), log_w)))
                       + combine + xmss_height)

    # FORS cost: one F per leaf used, one H per sibling, plus combining roots.
    fors_verify = self.k + self.k * self.a + sha256_compressions(22 + self.k * 16)
    # Generating one FORS tree: 2**(a+1) - 1 F/H calls over its leaves and nodes.
    fors_tree_gen = 3 * 2**self.a - 1

    # Signature sizes.
    xmss_sig_size = chains_size + 16 * xmss_height
    hypertree_sig_size = self.d * xmss_sig_size
    fors_sig_size = 16 * self.k * (self.a + 1)
    sphx_sig_size = 16 + fors_sig_size + hypertree_sig_size
    sl_sig_size = 1 + sphx_sig_size # indicator byte

    sign_avg = round(
      1
      + sha256_compressions(2 + 16 + 16 + 32)    # H_msg_sl
      + 4                                        # PRF_msg_sl
      + self.k * fors_tree_gen                   # FORS trees
      + sha256_compressions(22 + self.k * 16)    # combining FORS roots
      + (self.d - 1) * (xmss_sign_avg + xmss_verify_avg)  # intermediate layers
      + xmss_sign_avg                            # top layer
    )

    # Generating the stateless root tree of 2**xmss_height XMSS leaves.
    keygen = 2**xmss_height * wots_keygen + 2**xmss_height - 1

    verify_min = 4 + fors_verify + self.d * xmss_verify_min
    verify_max = 4 + fors_verify + self.d * xmss_verify_max
    verify_avg = 4 + fors_verify + self.d * xmss_verify_avg

    self.__dict__["_metrics_cache"] = cache = {
      "sign_avg": sign_avg,
      "verify_min": verify_min,
      "verify_max": verify_max,
      "verify_avg": verify_avg,
      "keygen": keygen,
      "sig_size": sl_sig_size,
      "verify_per_byte_max": round(verify_max / sl_sig_size, 3),
    }
    return cache

  def sign_compressions_avg(self):
    """The average number of SHA256 compressions needed for signing."""
    return self._metrics()["sign_avg"]

  def verify_compressions_min(self):
    """The minimum number of SHA256 compressions needed for signature verification."""
    return self._metrics()["verify_min"]

  def verify_compressions_max(self):
    """The maximum number of SHA256 compressions needed for signature verification."""
    return self._metrics()["verify_max"]

  def verify_compressions_avg(self):
    """The average number of SHA256 compressions needed for signature verification."""
    return self._metrics()["verify_avg"]

  def keygen_compressions(self):
    """The number of SHA256 compressions needed for keygen."""
    return self._metrics()["keygen"]

  def signature_size(self):
    """The size of the signature in bytes."""
    return self._metrics()["sig_size"]

  def verify_compressions_per_byte(self):
    """
    The number of SHA256 compressions per byte of the signature size
    needed to verify the signature in the worst case.
    (i.e. max verify compressions / sig size)
    """
    return self._metrics()["verify_per_byte_max"]
