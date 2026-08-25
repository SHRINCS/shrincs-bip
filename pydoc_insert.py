#!/usr/bin/env python3

import re
import inspect
from argparse import ArgumentParser
import shutil

"""
This script parses the reference implementation, to substitute docstrings
and exact python code for reference functions and constants into the
templated markdown documents. We parse markdown comments as doc/const
insert directives.
"""

from impl import shrincs, meta

DOCUMENTS = [
  {'markdown': 'SHRINCS.md', 'module': shrincs, 'source': 'impl/shrincs.py'},
]

class SpecFunction:
  """
  Data structure to document a specification function.
  """
  def __init__(self, module, code_lines, function_name: str):
    fn = module.__getattribute__(function_name)
    positions = list(fn.__code__.co_positions())
    def_line = positions[0][0] - 1
    code_start_line = positions[1][0] - 1
    code_end_line = positions[-1][0]
    if fn.__doc__ is not None:
      self.docstring = inspect.cleandoc(fn.__doc__)
    else:
      self.docstring = None
    self.codestring = '\n'.join([code_lines[def_line], *code_lines[code_start_line : code_end_line]])


regex_doc_start = r"^<!-- DOC START (\w+) -->$"
regex_doc_end = r"^<!-- DOC END (\w+) -->$"
regex_const = r"<!-- CONST START (\w+) -->\S*<!-- CONST END (\w+) -->"

def template_document(markdown_path: str, module, source_path: str) -> str:
  with open(source_path) as fh:
    code_lines = [line.rstrip() for line in fh]

  with open(markdown_path) as fh:
    markdown_lines = [line for line in fh]

  out_path = markdown_path.replace('.md', '.new.md')
  with open(out_path, 'w') as out:
    i = 0
    while i < len(markdown_lines):
      doc_start_match = re.match(regex_doc_start, markdown_lines[i])
      const_start_match = re.search(regex_const, markdown_lines[i])
      if doc_start_match:
        function_name = doc_start_match.group(1)
        out.write(markdown_lines[i])

        spec_fn = SpecFunction(module, code_lines, function_name)
        if spec_fn.docstring is not None:
          out.write(spec_fn.docstring + '\n\n')
        out.write("```py" + '\n')
        out.write(spec_fn.codestring + '\n')
        out.write("```" + '\n')

        while True:
          if re.match(r"^<!-- DOC END %s -->$" % function_name, markdown_lines[i]):
            out.write(markdown_lines[i])
            break
          i += 1
          if i >= len(markdown_lines):
            raise RuntimeError("failed to find closing <!-- DOC END %s --> comment" % function_name)

      elif const_start_match:
        line = markdown_lines[i]
        for match in re.finditer(regex_const, markdown_lines[i]):
          matched_string = match.group(0)
          const_identifier = match.group(1)
          if match.group(2) != const_identifier:
            raise RuntimeError(f'failed to find CONST END for {const_identifier}')
          const_value = meta.__getattribute__(const_identifier)
          substitution = f"<!-- CONST START {const_identifier} -->{const_value}<!-- CONST END {const_identifier} -->"
          line = line.replace(matched_string, substitution)
        out.write(line)

      else:
        out.write(markdown_lines[i])

      i += 1

  return out_path

if __name__ == "__main__":
  parser = ArgumentParser(description="Templating script for the specification documents.")
  parser.add_argument("-n", "--dry-run", action="store_true",
                     help="Produce the templated documents as *.new.md files but do not overwrite the originals.")
  args = parser.parse_args()

  for document in DOCUMENTS:
    out_path = template_document(document['markdown'], document['module'], document['source'])
    if not args.dry_run:
      shutil.move(out_path, document['markdown'])
