#!/usr/bin/env python3

import re
import ast
import inspect
from argparse import ArgumentParser
import shutil

"""
This script parses the shrincs.py implementation, to substitute
docstrings and exact python code for reference functions and constants
into SHRINCS.md. We parse markdown comments as doc/const insert directives.
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

class SpecDefinition:
  """
  Data structure to document a SHRINCS specification function or class.
  """
  def __init__(self, name: str):
    node = definitions[name]

    docstring = ast.get_docstring(node)
    if docstring is not None:
      docstring = inspect.cleandoc(docstring)
    self.docstring = docstring

    #  The definition's source code, with the docstring elided.
    body_start = node.body[0]
    signature = shrincs_code_lines[node.lineno - 1 : body_start.lineno - 1]
    if isinstance(body_start, ast.Expr) and isinstance(body_start.value, ast.Constant):
      body = shrincs_code_lines[body_start.end_lineno : node.end_lineno]
    else:
      body = shrincs_code_lines[body_start.lineno - 1 : node.end_lineno]
    self.codestring = '\n'.join(signature + body)


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

  if not args.dry_run:
    shutil.move('SHRINCS.new.md', 'SHRINCS.md')
