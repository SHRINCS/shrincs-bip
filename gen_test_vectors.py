#!/usr/bin/env python3

from typing import Optional
from impl import shrincs
from binascii import hexlify, unhexlify
import csv
import os
from os import path

def write_file_fingerprint(fpath: str):
  """
  Write the SHA256 hash of a file to `fpath + '.fp'`.
  Warning: reads the entire file into memory.
  """
  with open(fpath, 'rb') as fh:
    fingerprint = shrincs.sha256(fh.read())
  with open(fpath + '.fp', 'wb') as fh:
    fh.write(hexlify(fingerprint) + b'\n')


class KeygenVectorInput:
  """The inputs to deterministically generate a keygen test vector."""
  def __init__(self, seed: bytes, balanced: bool, depth: int):
    self.seed = seed
    self.balanced = balanced
    self.depth = depth

KEYGEN_TEST_VEC_INPUTS = [
  KeygenVectorInput(seed=b"bxmss-5", balanced=True, depth=5),
  KeygenVectorInput(seed=b"bxmss-8", balanced=True, depth=8),
  KeygenVectorInput(seed=b"uxmss-5", balanced=False, depth=5),
  KeygenVectorInput(seed=b"uxmss-6", balanced=False, depth=6),
  KeygenVectorInput(seed=b"uxmss-8", balanced=False, depth=8),
  KeygenVectorInput(seed=b"uxmss-255", balanced=False, depth=255),
]

def generate_keygen_vectors():
  vec_path = path.join('test_vectors', 'keygen.csv')
  with open(vec_path, 'w') as fh:
    w = csv.writer(fh)
    w.writerow(['seed', 'structure', 'seckey', 'pubkey'])
    for inp in KEYGEN_TEST_VEC_INPUTS:
      structure = bytes([shrincs.FXMSS_SHAPE_BALANCED, inp.depth]) if inp.balanced else \
                  bytes([shrincs.FXMSS_SHAPE_UNBALANCED, inp.depth])
      derived = shrincs.sha256(inp.seed + b"1") + shrincs.sha256(inp.seed + b"2")
      seckey, pubkey = shrincs.shrincs_keygen(derived[:48], structure)
      row = [derived[:48], structure, seckey, pubkey]
      w.writerow([hexlify(x).decode() for x in row])
  write_file_fingerprint(vec_path)

class SignVectorInput:
  """The inputs to deterministically generate a valid signature test vector."""
  def __init__(
    self,
    message: bytes,
    ctx: bytes,
    seckey: bytes,
    state_ctr: Optional[int],
    opt_rand: Optional[bytes],
  ):
    self.message = message
    self.ctx = ctx
    self.seckey = seckey
    self.state_ctr = state_ctr
    self.opt_rand = opt_rand

SIGNATURES_VALID_TEST_VEC_INPUTS = [
  # UXMSS depth 6, first leaf
  SignVectorInput(
    message=b"hello",
    ctx=b"",
    seckey=unhexlify(
      b"9808b8a20a3985fe718939c9346d8965" +
      b"d46620508f040f53774de8070795a061" +
      b"759a6b5e090187b5ec68cd47e03b7339" +
      b"b001fdf281e15e0cdf8f43c54ebc8a96" +
      b"0006" +
      b"08aaad9493ab2c607c3c3addfa746b6b"
    ),
    state_ctr=0,
    opt_rand=None
  ),

  # UXMSS depth 6, third leaf
  SignVectorInput(
    message=b"hello",
    ctx=b"",
    seckey=unhexlify(
      b"9808b8a20a3985fe718939c9346d8965" +
      b"d46620508f040f53774de8070795a061" +
      b"759a6b5e090187b5ec68cd47e03b7339" +
      b"b001fdf281e15e0cdf8f43c54ebc8a96" +
      b"0006" +
      b"08aaad9493ab2c607c3c3addfa746b6b"
    ),
    state_ctr=2,
    opt_rand=None
  ),

  # BXMSS depth 5, 23rd leaf
  SignVectorInput(
    message=b"hello",
    ctx=b"",
    seckey=unhexlify(
      b"659f1db58b8e2d879fc3915ba778c93b" +
      b"62262cbc144bf4707d0705780ba2e2e8" +
      b"fd88bc133af444b91aa77bcd01bd27dd" +
      b"a8750154f486a3e00a563d51d96729ad" +
      b"0105" +
      b"d5dab9e1d2e67006791e40f0a8e5f1a9"
    ),
    state_ctr=22,
    opt_rand=None
  ),

  # Stateless
  SignVectorInput(
    message=b"hello",
    ctx=b"",
    seckey=unhexlify(
      b"9808b8a20a3985fe718939c9346d8965" +
      b"d46620508f040f53774de8070795a061" +
      b"759a6b5e090187b5ec68cd47e03b7339" +
      b"b001fdf281e15e0cdf8f43c54ebc8a96" +
      b"0006" +
      b"08aaad9493ab2c607c3c3addfa746b6b"
    ),
    state_ctr=None,
    opt_rand=None
  ),
]

def generate_signatures_valid_test_vectors():
  vec_path = path.join('test_vectors', 'signatures_valid.csv')
  with open(vec_path, 'w') as fh:
    w = csv.writer(fh)
    w.writerow(['seckey', 'pubkey', 'message', 'ctx', 'opt_rand', 'state_ctr', 'signature'])
    for inp in SIGNATURES_VALID_TEST_VEC_INPUTS:
      signature = shrincs.shrincs_sign(
        inp.message,
        inp.ctx,
        inp.seckey,
        inp.state_ctr,
        inp.opt_rand
      )
      pubkey = shrincs.shrincs_extract_pubkey(inp.seckey)

      assert shrincs.shrincs_verify(inp.message, signature, inp.ctx, pubkey)

      w.writerow([
        hexlify(inp.seckey).decode(),
        hexlify(pubkey).decode(),
        hexlify(inp.message).decode(),
        hexlify(inp.ctx).decode(),
        '' if inp.opt_rand is None else hexlify(inp.opt_rand).decode(),
        '' if inp.state_ctr is None else inp.state_ctr,
        hexlify(signature).decode(),
      ])
  write_file_fingerprint(vec_path)

def generate_test_vectors():
  try:
    os.mkdir('test_vectors')
  except:
    pass
  generate_keygen_vectors()
  generate_signatures_valid_test_vectors()

if __name__ == "__main__":
  generate_test_vectors()
