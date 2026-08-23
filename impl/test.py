from random import randbytes
from shrincs import shrincs_sign, shrincs_keygen, shrincs_verify
from shrincs import FXMSS_SHAPE_UNBALANCED, FXMSS_SHAPE_BALANCED, FXMSS_HEIGHT

if __name__ == "__main__":
  msg = b"foobar!"
  structures = [
    bytes([FXMSS_SHAPE_BALANCED, 4]),
    bytes([FXMSS_SHAPE_UNBALANCED, 16])
  ]
  for (i, sf_structure) in enumerate(structures):
    sk, pk = shrincs_keygen(randbytes(48), sf_structure)

    for j in range(16):
      sig = shrincs_sign(msg, b"", sk, j, None)
      assert shrincs_verify(msg, sig, b"", pk)
    print(f'verified all stateful signatures for structure {sf_structure.hex()}')

    if i == len(structures) - 1:
      sig = shrincs_sign(msg, b"", sk, None, None)
      assert shrincs_verify(msg, sig, b"", pk)
      print(f'verified stateless signature')

  # Trees deep enough to climb past 64 levels, which nothing else covers. Depth
  # 255 also gives the longest FXMSS signature, and counter 0 the shortest.
  for deep_depth, counters in ((70, (62, 63, 64, 65)), (FXMSS_HEIGHT, (0, 253, 254, 255))):
    deep_structure = bytes([FXMSS_SHAPE_UNBALANCED, deep_depth])
    sk, pk = shrincs_keygen(randbytes(48), deep_structure)
    for j in counters:
      sig = shrincs_sign(msg, b"", sk, j, None)
      assert shrincs_verify(msg, sig, b"", pk)
    print(f'verified deep stateful signatures for structure {deep_structure.hex()}')
