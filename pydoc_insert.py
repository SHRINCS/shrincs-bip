#!/usr/bin/env python3

import re
import ast
import inspect
from argparse import ArgumentParser
import shutil
import sys

"""
This script parses the shrincs.py implementation, to substitute
docstrings and exact python code for reference functions and constants
into SHRINCS.md. We parse markdown comments as doc/const insert directives.

It also checks that the `- Inputs:` / `- Output:` list documenting each
function agrees with the value types annotating its signature.
"""

from impl import shrincs

with open('impl/shrincs.py') as fh:
  shrincs_source = fh.read()

shrincs_code_lines = [line.rstrip() for line in shrincs_source.split('\n')]
shrincs_ast = ast.parse(shrincs_source)

#  Top-level function and class definitions, by name.
definitions = {}
for node in shrincs_ast.body:
  if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
    definitions[node.name] = node


#  Consistency check between the annotated signatures and the documentation.

def expression(node: ast.expr) -> str:
  """
  Renders a size expression the way the specification prose writes it: literal
  integers as-is, and expressions over the scheme's constants quoted, so the
  documentation names the constant rather than its value.
  """
  if isinstance(node, ast.Constant):
    return str(node.value)
  return "`%s`" % ast.unparse(node).replace(' ** ', '**')

def size_phrases(annotation: ast.expr, exact_only: bool = False) -> list[list[str]]:
  """
  The sizes which documentation of a value of this type must state, each given
  as the list of spellings the documentation may use. An annotation which
  constrains no size (a bare `bytes`, `int` or `bool`) requires nothing. Under
  `exact_only`, a bounded size requires nothing either: the exact size of a
  variable-length output is a function of its inputs, which only prose can
  state.
  """
  if isinstance(annotation, ast.Subscript):
    name = ast.unparse(annotation.value)
    if name == "Optional":
      return size_phrases(annotation.slice, exact_only)
    if name == "Bytes":
      if isinstance(annotation.slice, ast.Slice):
        if exact_only:
          return []
        bounds = [annotation.slice.lower, annotation.slice.upper]
        return [["%s bytes" % expression(bound)] for bound in bounds if bound is not None]
      size = expression(annotation.slice)
      return [["%s-byte" % size, "length %s" % size]]

  if isinstance(annotation, ast.Name):
    if annotation.id == "ADRS_T":
      return [["22-byte"]]

  return []

def undocumented_sizes(annotation: ast.expr, text: str, exact_only: bool = False) -> bool:
  """
  Whether `text` fails to state some size which `annotation` constrains.
  """
  return any(not any(spelling in text for spelling in spellings)
             for spellings in size_phrases(annotation, exact_only))

def documented_values(docstring: str) -> tuple[list[tuple[str, str]], list[str]]:
  """
  Parses the `- Inputs:` and `- Output(s):` lists of a docstring into a list of
  `(name, text)` inputs and a list of output texts.
  """
  inputs, outputs, section = [], [], None
  for line in docstring.split('\n'):
    if re.match(r'^- Inputs?:$', line):
      section = inputs
    elif re.match(r'^- Outputs?:$', line):
      section = outputs
    elif section is not None and line.startswith('  - '):
      section.append(line[4:])
    elif section is not None and line.startswith('    '):
      section[-1] += ' ' + line.strip()
    elif line and not line.startswith(' '):
      section = None

  named = []
  for text in inputs:
    match = re.match(r'^`(\w+)`: (.*)$', text)
    named.append((match.group(1), match.group(2)) if match else (None, text))
  return named, outputs

def check_documentation(fn: ast.FunctionDef, docstring: str) -> list[str]:
  """
  Reports any disagreement between a function's annotated signature and the
  inputs and outputs documented by its docstring.
  """
  problems = []
  inputs, outputs = documented_values(docstring)
  if not inputs and not outputs:
    return problems

  arguments = fn.args.args
  if [name for name, _ in inputs] != [argument.arg for argument in arguments]:
    problems.append("documents inputs %s but takes (%s)" % (
      [name for name, _ in inputs], ", ".join(argument.arg for argument in arguments)))
    return problems

  for argument, (name, text) in zip(arguments, inputs):
    if undocumented_sizes(argument.annotation, text):
      problems.append("`%s` is annotated %s but is documented as \"%s\"" % (
        name, ast.unparse(argument.annotation), text))

  returns = fn.returns
  returned = returns.slice if isinstance(returns, ast.Subscript) \
    and ast.unparse(returns.value) == "Optional" else returns
  expected = returned.slice.elts if isinstance(returned, ast.Subscript) \
    and ast.unparse(returned.value) == "tuple" else [returned]

  #  A tuple may be documented either as one output per element, or as a single
  #  output describing the whole tuple.
  if len(outputs) == 1 and len(expected) > 1:
    if any(undocumented_sizes(annotation, outputs[0], exact_only=True) for annotation in expected):
      problems.append("returns %s but documents \"%s\"" % (ast.unparse(returns), outputs[0]))

  elif len(expected) != len(outputs):
    problems.append("returns %s but documents %d outputs" % (ast.unparse(returns), len(outputs)))
  else:
    for annotation, text in zip(expected, outputs):
      if undocumented_sizes(annotation, text, exact_only=True):
        problems.append("returns %s but documents \"%s\"" % (ast.unparse(annotation), text))

  return problems

class SpecDefinition:
  """
  Data structure to document a SHRINCS specification function or class.
  """
  def __init__(self, name: str):
    node = definitions[name]

    docstring = ast.get_docstring(node)
    if docstring is not None:
      docstring = inspect.cleandoc(docstring)
      if isinstance(node, ast.FunctionDef):
        for problem in check_documentation(node, docstring):
          print("%s: %s" % (name, problem), file=sys.stderr)
          problems.append(name)
    self.docstring = docstring

    #  The definition's source code, with the docstring elided.
    body_start = node.body[0]
    signature = shrincs_code_lines[node.lineno - 1 : body_start.lineno - 1]
    if isinstance(body_start, ast.Expr) and isinstance(body_start.value, ast.Constant):
      body = shrincs_code_lines[body_start.end_lineno : node.end_lineno]
    else:
      body = shrincs_code_lines[body_start.lineno - 1 : node.end_lineno]
    self.codestring = '\n'.join(signature + body)


problems = []

regex_doc_start = r"^<!-- DOC START (\w+) -->$"
regex_doc_end = r"^<!-- DOC END (\w+) -->$"
regex_const = r"<!-- CONST START (\w+) -->\w*<!-- CONST END (\w+) -->"

if __name__ == "__main__":
  parser = ArgumentParser(description="SHRINCS.md templating script.")
  parser.add_argument("-n", "--dry-run", action="store_true",
                     help="Produce the templated specification file in SHRINCS.new.md but do not overwrite SHRINCS.md.")
  args = parser.parse_args()

  with open('SHRINCS.md') as fh:
    markdown_lines = [line for line in fh]

  # with sys.stdout as out:
  with open('SHRINCS.new.md', 'w') as out:
    i = 0
    while i < len(markdown_lines):
      doc_start_match = re.match(regex_doc_start, markdown_lines[i])
      const_start_match = re.search(regex_const, markdown_lines[i])
      if doc_start_match:
        definition_name = doc_start_match.group(1)
        out.write(markdown_lines[i])

        spec_definition = SpecDefinition(definition_name)
        if spec_definition.docstring is not None:
          out.write(spec_definition.docstring + '\n\n')
        out.write("```py" + '\n')
        out.write(spec_definition.codestring + '\n')
        out.write("```" + '\n')

        while True:
          if re.match(r"^<!-- DOC END %s -->$" % definition_name, markdown_lines[i]):
            out.write(markdown_lines[i])
            break
          i += 1
          if i >= len(markdown_lines):
            raise RuntimeError("failed to find closing <!-- DOC END %s --> comment" % definition_name)

      elif const_start_match:
        replacements = []
        line = markdown_lines[i]
        for match in re.finditer(regex_const, markdown_lines[i]):
          matched_string = match.group(0)
          const_identifier = match.group(1)
          if match.group(2) != const_identifier:
            raise RuntimeError(f'failed to find CONST END for {const_identifier}', file=sys.stderr)
          const_value = shrincs.__getattribute__(const_identifier)
          substitution = f"<!-- CONST START {const_identifier} -->{const_value}<!-- CONST END {const_identifier} -->"
          line = line.replace(matched_string, substitution)
        out.write(line)

      else:
        out.write(markdown_lines[i])

      i += 1

  if problems:
    print("\n%d function(s) document types which disagree with their signature." % len(set(problems)),
          file=sys.stderr)
    sys.exit(1)

  if not args.dry_run:
    shutil.move('SHRINCS.new.md', 'SHRINCS.md')
