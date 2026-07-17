from random import randbytes
from shrincs import shrincs_sign, shrincs_keygen, shrincs_verify
from shrincs import FXMSS_SHAPE_UNBALANCED, FXMSS_SHAPE_BALANCED, FXMSS_HEIGHT

if __name__ == "__main__":
  structures = [
    bytes([FXMSS_SHAPE_BALANCED, 4]),
    bytes([FXMSS_SHAPE_UNBALANCED, 16])
  ]
  for (i, sf_structure) in enumerate(structures):
    sk, pk = shrincs_keygen(randbytes(48), sf_structure)

    msg = b"foobar!"
    for j in range(16):
      sig = shrincs_sign(msg, sk, j, None)
      assert shrincs_verify(msg, sig, pk)
    print(f'verified all stateful signatures for structure {sf_structure.hex()}')

    if i == len(structures) - 1:
      sig = shrincs_sign(msg, sk, -1, None)
      assert shrincs_verify(msg, sig, pk)
      print(f'verified stateless signature')
