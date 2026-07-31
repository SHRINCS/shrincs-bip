#!/usr/bin/env python3

"""
Runtime enforcement of the value types declared by the reference
implementation.

`enforce(shrincs)` replaces every function in the module with a wrapper which
checks each argument, and the return value, against the `typing.Annotated`
type in the function's signature, and wraps every dataclass in the module so
its fields are checked as they are constructed. Sizes declared with `Bytes[n]`,
`Array[T, n]` and `UIntN` are therefore not merely documentation: every call
made by the test suite, and every value it builds, is checked against them.
"""

import dataclasses
import inspect
import types
from typing import Annotated, Union, get_args, get_origin, get_type_hints

from shrincs import LEN, UINT, INT


class AnnotationError(Exception):
  pass

def describe(hint) -> str:
  return getattr(hint, "__name__", str(hint))

def check(value, hint, where: str):
  """
  Checks `value` against the annotation `hint`, raising `AnnotationError` if it
  does not conform. `where` names the argument being checked, for the error.
  """
  origin = get_origin(hint)

  if origin is Annotated:
    base, *constraints = get_args(hint)
    check(value, base, where)
    for constraint in constraints:
      check_constraint(value, constraint, where)

  elif origin in (Union, types.UnionType):
    for member in get_args(hint):
      try:
        return check(value, member, where)
      except AnnotationError:
        continue
    raise AnnotationError("%s: %r matches none of %s" % (where, value, describe(hint)))

  elif origin is tuple:
    members = get_args(hint)
    if not isinstance(value, tuple) or len(value) != len(members):
      raise AnnotationError("%s: expected a %d-tuple, got %r" % (where, len(members), value))
    for i, (element, member) in enumerate(zip(value, members)):
      check(element, member, "%s[%d]" % (where, i))

  elif origin is list:
    element_type, = get_args(hint)
    if not isinstance(value, list):
      raise AnnotationError("%s: expected a list, got %s" % (where, type(value).__name__))
    for i, element in enumerate(value):
      check(element, element_type, "%s[%d]" % (where, i))

  elif hint is type(None):
    if value is not None:
      raise AnnotationError("%s: expected null, got %r" % (where, value))

  elif isinstance(hint, type):
    #  `bytes` also accepts a `bytearray`; the two are interchangeable as hash
    #  function inputs.
    accepted = (bytes, bytearray) if hint is bytes else hint
    if not isinstance(value, accepted):
      raise AnnotationError("%s: expected %s, got %s" % (where, describe(hint), type(value).__name__))

def matches(value, constraint) -> bool:
  """
  Returns true iff `value` satisfies `constraint`. `check` has already verified
  the base type, so a LEN sees a sized value and a UINT or INT sees an int.
  """
  if isinstance(constraint, LEN):
    if constraint.size is not None:
      return len(value) == constraint.size
    elif constraint.max is None:
      return constraint.min <= len(value)
    else:
      return constraint.min <= len(value) <= constraint.max

  elif isinstance(constraint, UINT):
    return 0 <= value < 2**constraint.bits

  elif isinstance(constraint, INT):
    bound = 2**(constraint.bits - 1)
    return -bound <= value < bound

  return True

def check_constraint(value, constraint, where: str):
  """
  Checks `value` against a single constraint, raising `AnnotationError` if it
  does not satisfy it. `matches` holds the rule; only the diagnostic is here.
  """
  if matches(value, constraint):
    return

  if isinstance(constraint, LEN):
    if constraint.size is not None:
      expected = "size %d" % constraint.size
    elif constraint.max is None:
      expected = "size at least %d" % constraint.min
    elif constraint.min == 0:
      expected = "size at most %d" % constraint.max
    else:
      expected = "size between %d and %d" % (constraint.min, constraint.max)
    raise AnnotationError("%s: expected %s, got %d" % (where, expected, len(value)))

  elif isinstance(constraint, UINT):
    raise AnnotationError("%s: expected a UInt%d, got %r" % (where, constraint.bits, value))

  elif isinstance(constraint, INT):
    raise AnnotationError("%s: expected an Int%d, got %r" % (where, constraint.bits, value))

def checked(fn):
  """
  Wraps `fn` so that its arguments and return value are checked against the
  annotations in its signature.
  """
  hints = get_type_hints(fn, include_extras=True)
  signature = inspect.signature(fn)

  def wrapper(*args, **kwargs):
    bound = signature.bind(*args, **kwargs)
    for name, value in bound.arguments.items():
      if name not in hints:
        continue
      #  A variadic parameter annotates each element it collects, not the
      #  tuple or dict collecting them.
      kind = signature.parameters[name].kind
      if kind is inspect.Parameter.VAR_POSITIONAL:
        for i, element in enumerate(value):
          check(element, hints[name], "%s(%s[%d])" % (fn.__name__, name, i))
      elif kind is inspect.Parameter.VAR_KEYWORD:
        for key, element in value.items():
          check(element, hints[name], "%s(%s[%s])" % (fn.__name__, name, key))
      else:
        check(value, hints[name], "%s(%s)" % (fn.__name__, name))
    result = fn(*args, **kwargs)
    if "return" in hints:
      check(result, hints["return"], "%s() return value" % fn.__name__)
    return result

  wrapper.__name__ = fn.__name__
  wrapper.__doc__ = fn.__doc__
  return wrapper

def check_fields(cls):
  """
  Wraps a dataclass so that every field is checked against its annotation as an
  instance is constructed. Without this the annotations on an address type
  would be documentation only, since `checked` sees function arguments and a
  dataclass builds its values through a generated `__init__`.
  """
  hints = get_type_hints(cls, include_extras=True)
  construct = cls.__init__

  def __init__(self, *args, **kwargs):
    construct(self, *args, **kwargs)
    for name in (field.name for field in dataclasses.fields(cls)):
      if name in hints:
        check(getattr(self, name), hints[name], "%s(%s)" % (cls.__name__, name))

  cls.__init__ = __init__
  return cls

def enforce(module):
  """
  Replaces every function defined by `module` with a checked wrapper, and wraps
  every dataclass it defines so their fields are checked on construction. Calls
  made between the module's own functions are checked too, since they resolve
  through the module's globals.
  """
  for name, value in list(vars(module).items()):
    if inspect.isfunction(value) and value.__module__ == module.__name__:
      setattr(module, name, checked(value))
    elif (inspect.isclass(value) and dataclasses.is_dataclass(value)
          and value.__module__ == module.__name__):
      check_fields(value)
