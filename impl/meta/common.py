from math import comb

# Shared helpers used by both the stateless and stateful parameter models.

def num_messages_sum(w: int, l1: int, p: int) -> int:
  """
  Find the coefficient of x^p in the expanded polynomial (1 + x + x^2 + ... + x^(w-1))^l1.
  This is the number of possible WOTS messages whose indexes sum to `p`.
    https://mathworld.wolfram.com/Dice.html
    https://mathworld.wolfram.com/images/equations/Dice/NumberedEquation7.svg
  """
  return sum(((-1)**k * comb(l1, k) * comb(p + l1 - w*k - 1, l1 - 1) for k in range(p//w + 1)))


def sha256_compressions(size: int) -> int:
  """Compute the number of SHA256 compressions needed to hash a given size preimage."""
  return size // 64 + (1 if (size % 64) < 56 else 2)
