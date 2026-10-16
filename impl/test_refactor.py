"""Regression checks against the pinned Python specification from SHRINCS main."""

import ast
import hashlib
import importlib.abc
import importlib.util
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import shrincs


BASELINE_COMMIT = "a5891ec5b360a732c097e1d6af1ae59515a2560a"
REPOSITORY = Path(__file__).resolve().parent.parent
SEED = bytes(range(48))
MESSAGE = b"SHRINCS refactor regression"
DIGEST = bytes(range(32))


class BaselineLoader(importlib.abc.SourceLoader):
  def get_filename(self, fullname):
    return str(REPOSITORY / "impl" / "shrincs-baseline.py")

  def get_data(self, path):
    return subprocess.check_output(
      ["git", "show", BASELINE_COMMIT + ":impl/shrincs.py"], cwd=REPOSITORY
    )


def load_baseline():
  specification = importlib.util.spec_from_loader("shrincs_baseline", BaselineLoader())
  module = importlib.util.module_from_spec(specification)
  sys.modules[specification.name] = module
  specification.loader.exec_module(module)
  return module


def traced_call(module, function_name, *arguments):
  trace = hashlib.sha256()
  call_count = 0
  original_sha256 = module.sha256

  def traced_sha256(message):
    nonlocal call_count
    trace.update(len(message).to_bytes(8, "big"))
    trace.update(message)
    call_count += 1
    return original_sha256(message)

  with patch.object(module, "sha256", traced_sha256):
    result = getattr(module, function_name)(*arguments)
  return result, call_count, trace.digest()


def compare(baseline, function_name, *arguments):
  expected = traced_call(baseline, function_name, *arguments)
  actual = traced_call(shrincs, function_name, *arguments)
  assert actual == expected, function_name
  return actual[0]


def expect_assertion(function, *arguments):
  try:
    function(*arguments)
  except AssertionError:
    return
  raise AssertionError("missing input assertion in " + function.__name__)


def check_assertion_placement():
  specification = ast.parse((REPOSITORY / "impl" / "shrincs.py").read_text())
  for function in ast.walk(specification):
    if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
      continue
    body = function.body
    first_statement = 1 if ast.get_docstring(function) is not None else 0
    while first_statement < len(body) and isinstance(body[first_statement], ast.Assert):
      first_statement += 1
    for statement in body[first_statement:]:
      assert not any(isinstance(node, ast.Assert) for node in ast.walk(statement)), (
        function.name + " has an assertion after computation"
      )


def check_chains_and_checksum(baseline):
  for function_name, tail in (
    ("wots_tw_chain_iter", (SEED[32:], 0, 0, 0, 0)),
    ("wots_c_chain_iter", (SEED[32:], 254, 1, 0)),
  ):
    for start, stop in ((0, 0), (0, 15), (1, 15), (7, 8), (15, 15)):
      expected = traced_call(baseline, function_name, SEED[:16], start, stop - start, *tail)
      actual = traced_call(shrincs, function_name, SEED[:16], start, stop, *tail)
      assert actual == expected, (function_name, start, stop)
      assert actual[1] == stop - start
    for start, stop in ((1, 0), (0, 16), (16, 16)):
      expect_assertion(getattr(shrincs, function_name), SEED[:16], start, stop, *tail)

  for message in (bytes(16), bytes([255]) * 16, bytes(range(16)), bytes([0xF0]) * 16):
    indexes = compare(baseline, "wots_tw_message_to_indexes", message)
    assert indexes == compare(baseline, "wots_tw_message_to_indexes_alt", message)
    checksum = sum(15 - digit for digit in indexes[:shrincs.WOTS_TW_MESSAGE_CHAIN_COUNT])
    for i in range(shrincs.WOTS_TW_CHECKSUM_CHAIN_COUNT):
      destination = shrincs.WOTS_TW_CHAIN_COUNT - 1 - i
      assert indexes[destination] == (checksum // 2**(i * shrincs.WOTS_TW_CHAIN_BITS)) % 16


def check_stateful_signatures(baseline):
  last_keys = None
  for shape, depth, counters in (
    (shrincs.FXMSS_SHAPE_BALANCED, 2, (0, 3)),
    (shrincs.FXMSS_SHAPE_UNBALANCED, 3, (0, 1, 3)),
  ):
    structure = bytes([shape, depth])
    secret_key, public_key = compare(baseline, "shrincs_keygen", SEED, structure)
    last_keys = secret_key, public_key
    for counter in counters:
      for context in (b"", b"context", bytes(range(255))):
        signature = compare(baseline, "shrincs_sign", MESSAGE, context, secret_key, counter, None)
        assert signature is not None
        leaf_depth = 255 - signature[0]
        index_size = shrincs.ceildiv(min(leaf_depth, 64), 8)
        assert len(signature) == 17 + index_size + 2 + shrincs.WOTS_C_CHAINS_SIZE + 16 * leaf_depth
        assert compare(baseline, "shrincs_verify", MESSAGE, signature, context, public_key)
        assert not compare(baseline, "shrincs_verify", MESSAGE, signature, context + b"x" if len(context) < 255 else b"wrong", public_key)
        for malformed in (signature[:-1], signature + b"\0", signature[:17], b"", bytes([signature[0]]) + bytes(16)):
          assert not compare(baseline, "shrincs_verify", MESSAGE, malformed, context, public_key)
        invalid_index = 2**leaf_depth
        if invalid_index < 2**(8 * index_size):
          malformed = signature[:17] + invalid_index.to_bytes(index_size, "big") + signature[17 + index_size:]
          assert not compare(baseline, "shrincs_verify", MESSAGE, malformed, context, public_key)
  return last_keys


def check_stateless_signature(baseline, keys):
  secret_key, public_key = keys
  context = b"stateless context"
  signature = compare(baseline, "shrincs_sign", MESSAGE, context, secret_key, None, bytes(range(16)))
  assert signature[0] == 255
  assert len(signature) == shrincs.SHRINCS_SL_SIGNATURE_SIZE
  assert compare(baseline, "shrincs_verify", MESSAGE, signature, context, public_key)
  assert not compare(baseline, "shrincs_verify", MESSAGE, signature, b"wrong", public_key)
  for malformed in (signature[:-1], signature + b"\0", bytes([255]), bytes([255]) + bytes(100000)):
    assert not compare(baseline, "shrincs_verify", MESSAGE, malformed, context, public_key)


def check_candidate_lengths(baseline, keys):
  _, public_key = keys
  for indicator in range(255):
    depth = 255 - indicator
    index_size = shrincs.ceildiv(min(depth, 64), 8)
    expected_length = 17 + index_size + 2 + shrincs.WOTS_C_CHAINS_SIZE + 16 * depth
    for length in (expected_length - 1, expected_length + 1):
      candidate = bytes([indicator]) + bytes(length - 1)
      expected = traced_call(baseline, "shrincs_verify", MESSAGE, candidate, b"", public_key)
      actual = traced_call(shrincs, "shrincs_verify", MESSAGE, candidate, b"", public_key)
      assert actual == expected
      assert actual[0] is False
      assert actual[1] == 0
  assert not compare(baseline, "shrincs_verify", MESSAGE, bytes(100000), b"", public_key)


def check_hypertree_boundaries(baseline):
  # Mock XMSS computations to test traversal at the full tree-index boundary.
  for tree_index in (0, 2**shrincs.HYPERTREE_TREE_INDEX_BITS - 1):
    results = []
    for module in (baseline, shrincs):
      events = []

      def sign(message, sk_seed, leaf_index, pk_seed, layer, address):
        assert 0 <= leaf_index < 2**shrincs.XMSS_HEIGHT
        assert 0 <= address < 2**(shrincs.XMSS_HEIGHT * (shrincs.HYPERTREE_LAYER_COUNT - 1 - layer))
        events.append(("sign", layer, address, leaf_index, message))
        return bytes([layer + 1]) * shrincs.XMSS_SIGNATURE_SIZE

      def recover(leaf_index, signature, message, pk_seed, layer, address):
        assert len(signature) == shrincs.XMSS_SIGNATURE_SIZE
        events.append(("recover", layer, address, leaf_index, message))
        return bytes([layer + 1]) * 16

      with patch.object(module, "xmss_sign", sign), patch.object(module, "xmss_pubkey_from_sig", recover):
        signature = module.hypertree_sign(SEED[:16], SEED[:16], SEED[32:], tree_index, 511)
        signing_events = events.copy()
        events.clear()
        valid = module.hypertree_verify(SEED[:16], signature, SEED[32:], tree_index, 511, bytes([5]) * 16)
        results.append((signature, signing_events, events.copy(), valid))
    assert results[0] == results[1]
    assert results[1][3]
    assert [event[0] for event in results[1][1]] == ["sign", "recover"] * 4 + ["sign"]
    assert [event[0] for event in results[1][2]] == ["recover"] * 5


def check_forest_positions(baseline):
  digest = bytes([255]) * shrincs.FORS_DIGEST_SIZE
  signature = compare(baseline, "fors_sign", digest, SEED[:16], SEED[32:], 0, 0, 0)
  compare(baseline, "fors_pubkey_from_sig", signature, digest, SEED[32:], 0, 0, 0)
  positions = shrincs.base_2b(digest, shrincs.FORS_HEIGHT, shrincs.FORS_TREE_COUNT)
  for tree_index, position in enumerate(positions):
    leaf_index = tree_index * 2**shrincs.FORS_HEIGHT + position
    tree_offset = tree_index * 16 * (shrincs.FORS_HEIGHT + 1)
    assert signature[tree_offset:tree_offset + 16] == shrincs.fors_sk_gen(SEED[:16], SEED[32:], 0, 0, 0, leaf_index)
    for path_index in range(shrincs.FORS_HEIGHT):
      sibling_index = (leaf_index // 2**path_index) ^ 1
      assert sibling_index < shrincs.FORS_TREE_COUNT * 2**(shrincs.FORS_HEIGHT - path_index)
      assert sibling_index == tree_index * 2**(shrincs.FORS_HEIGHT - path_index) + ((position // 2**path_index) ^ 1)
      sibling_offset = tree_offset + 16 * (path_index + 1)
      assert len(signature[sibling_offset:sibling_offset + 16]) == 16


def check_large_depth_contracts():
  # These checks mock expensive leaf computations and retain the real tree arithmetic.
  leaf_calls = []

  def leaf_public_key(sk_seed, pk_seed, height, index, balanced, depth):
    leaf_calls.append((height, index, balanced, depth))
    return bytes(16)

  with patch.object(shrincs, "wots_c_pubkey_gen", leaf_public_key):
    shrincs.fxmss_node(SEED[:16], 2**63 - 1, 192, SEED[32:], True, 64)
    assert leaf_calls == [(191, 2**64 - 2, True, 64), (191, 2**64 - 1, True, 64)]
    shrincs.fxmss_node(SEED[:16], 0, 0, SEED[32:], False, 255)
    assert leaf_calls[-1] == (0, 0, False, 255)

  sibling_calls = []

  def sibling_node(sk_seed, index, height, pk_seed, balanced, depth):
    assert 0 <= height <= 255
    assert 255 - height <= depth <= 255
    assert 0 <= index < 2**min(64, 255 - height)
    assert not balanced or depth <= 64
    assert balanced or index in (0, 1)
    sibling_calls.append((height, index))
    return bytes(16)

  with patch.object(shrincs, "wots_c_sign", return_value=bytes(2 + shrincs.WOTS_C_CHAINS_SIZE)):
    with patch.object(shrincs, "fxmss_node", sibling_node):
      signature = shrincs.fxmss_sign(DIGEST, SEED[:16], 2**64 - 1, 191, SEED[32:], True, 64)
      assert len(signature) == 2 + shrincs.WOTS_C_CHAINS_SIZE + 16 * 64
      assert sibling_calls == [(191 + i, ((2**64 - 1) // 2**i) ^ 1) for i in range(64)]
      sibling_calls.clear()
      shrincs.fxmss_sign(DIGEST, SEED[:16], 0, 0, SEED[32:], False, 255)
      assert sibling_calls == [(i, 1) for i in range(255)]

  for depth, expected in ((0, None), (1, (0, 254)), (64, (2**64 - 1, 191))):
    counter = 0 if depth < 64 else 2**64 - 1
    assert shrincs.shrincs_sf_leaf_select(bytes([1, depth]), counter) == expected
  assert shrincs.shrincs_sf_leaf_select(bytes([0, 255]), 255) == (0, 0)

  expect_assertion(shrincs.shrincs_keygen, SEED, bytes([1, 65]))
  secret_key = SEED + bytes(16) + bytes([1, 65]) + bytes(16)
  expect_assertion(shrincs.shrincs_sign, MESSAGE, b"", secret_key, 0, None)


def check_leaf_boundaries(baseline):
  compare(baseline, "xmss_node", SEED[:16], 511, 0, SEED[32:], 255, 2**64 - 1)
  compare(baseline, "fors_node", SEED[:16], shrincs.FORS_TREE_COUNT * 2**shrincs.FORS_HEIGHT - 1, 0, SEED[32:], 255, 2**64 - 1, 511)
  for index, height, balanced, depth in (
    (0, 255, True, 0),
    (0, 0, False, 255),
    (1, 0, False, 255),
    (2**64 - 1, 191, True, 64),
  ):
    compare(baseline, "fxmss_node", SEED[:16], index, height, SEED[32:], balanced, depth)

  with patch.object(shrincs, "xmss_node", return_value=bytes(16)), patch.object(shrincs, "fxmss_node", return_value=bytes(16)):
    secret_key, public_key = shrincs.shrincs_keygen(SEED, bytes([1, 64]))
    assert len(secret_key) == 82
    assert len(public_key) == 48

  # Keep randomizer and digest hashing real while mocking the enormous authentication path.
  results = []
  for module in (baseline, shrincs):
    with patch.object(module, "fxmss_sign", return_value=bytes(2 + shrincs.WOTS_C_CHAINS_SIZE + 16 * 64)) as sign:
      result = traced_call(module, "shrincs_sign", MESSAGE, b"boundary", secret_key, 2**64 - 1, None)
      assert sign.call_args.args[2:4] == (2**64 - 1, 191)
      assert sign.call_args.args[5:7] == (True, 64)
      assert result[0][17:25] == bytes([255]) * 8
      results.append(result)
  assert results[0] == results[1]


def check_internal_contracts():
  for index, height, balanced, depth in ((0, 254, False, 0), (2, 254, False, 1), (2**63, 192, True, 63), (0, 255, True, 65)):
    expect_assertion(shrincs.fxmss_node, SEED[:16], index, height, SEED[32:], balanced, depth)
  for index, height, balanced, depth in ((0, 255, False, 0), (0, 254, False, 3), (2, 254, False, 3), (0, 254, True, 2), (2**63, 192, True, 63)):
    expect_assertion(shrincs.fxmss_sign, DIGEST, SEED[:16], index, height, SEED[32:], balanced, depth)
  expect_assertion(shrincs.fxmss_pubkey_from_sig, 0, 254, bytes(2 + shrincs.WOTS_C_CHAINS_SIZE + 16 * 2), DIGEST, SEED[32:])
  expect_assertion(shrincs.xmss_node, SEED[:16], 1, shrincs.XMSS_HEIGHT, SEED[32:], 0, 0)
  expect_assertion(shrincs.xmss_node, SEED[:16], 0, shrincs.XMSS_HEIGHT + 1, SEED[32:], 0, 0)
  expect_assertion(shrincs.fors_node, SEED[:16], shrincs.FORS_TREE_COUNT, shrincs.FORS_HEIGHT, SEED[32:], 0, 0, 0)
  expect_assertion(shrincs.fors_sk_gen, SEED[:16], SEED[32:], 0, 0, 0, shrincs.FORS_TREE_COUNT * 2**shrincs.FORS_HEIGHT)
  expect_assertion(shrincs.hypertree_sign, SEED[:16], SEED[:16], SEED[32:], 2**shrincs.HYPERTREE_TREE_INDEX_BITS, 0)
  expect_assertion(shrincs.base_2b, b"", 0, 0)
  expect_assertion(shrincs.base_2b, b"", 1, -1)
  expect_assertion(shrincs.base_2b, b"", 1, 1)


if __name__ == "__main__":
  baseline = load_baseline()
  for check in (check_assertion_placement, check_large_depth_contracts, check_internal_contracts):
    check()
    print(check.__name__ + " passed", flush=True)
  check_chains_and_checksum(baseline)
  print("chain endpoints and checksum comparisons passed", flush=True)
  check_leaf_boundaries(baseline)
  print("leaf and public caller boundary comparisons passed", flush=True)
  check_hypertree_boundaries(baseline)
  print("hypertree boundary traversal comparisons passed", flush=True)
  keys = check_stateful_signatures(baseline)
  print("stateful output and hash order comparisons passed", flush=True)
  check_candidate_lengths(baseline, keys)
  print("candidate signature lengths rejected before hashing", flush=True)
  check_forest_positions(baseline)
  print("FORS output and hash order comparisons passed", flush=True)
  check_stateless_signature(baseline, keys)
  print("stateless output and hash order comparisons passed", flush=True)
