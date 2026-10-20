"""Check value annotations as their underlying types, leaving bounds as metadata."""

from collections.abc import Callable

from mypy.plugin import AnalyzeTypeContext, Plugin
from mypy.types import Type


# Length expressions are runtime metadata, not static type arguments.
def analyze_bytes(context: AnalyzeTypeContext) -> Type:
  if len(context.type.args) != 1:
    context.api.fail("Bytes requires one length or length range", context.context)

  return context.api.named_type("builtins.bytes", [])


# Resolve the element type through mypy, leaving the count as metadata.
def analyze_array(context: AnalyzeTypeContext) -> Type:
  if len(context.type.args) != 2:
    context.api.fail("Array requires an element type and a length", context.context)
    return context.api.named_type("builtins.object", [])

  element_type = context.api.analyze_type(context.type.args[0])

  return context.api.named_type("builtins.list", [element_type])


class ValueTypesPlugin(Plugin):
  # Scripts use shrincs directly, while specification tooling uses impl.shrincs.
  def get_type_analyze_hook(self, fullname: str) -> Callable[[AnalyzeTypeContext], Type] | None:
    if fullname in ("shrincs.Bytes", "impl.shrincs.Bytes"):
      return analyze_bytes

    if fullname in ("shrincs.Array", "impl.shrincs.Array"):
      return analyze_array

    return None


def plugin(version: str) -> type[Plugin]:
  return ValueTypesPlugin
