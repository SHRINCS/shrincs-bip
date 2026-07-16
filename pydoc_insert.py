#!/usr/bin/env python3

import re
import inspect
from argparse import ArgumentParser
import shutil

"""
This script parses the shrincs.py reference implementation, to substitute
docstrings and exact python code for reference functions and constants
into SHRINCS.md. We parse markdown comments as doc/const insert directives.
"""

from impl import shrincs

with open('impl/shrincs.py') as fh:
  shrincs_code_lines = [line.rstrip() for line in fh]

class SpecFunction:
  """
  Data structure to document a SHRINCS specification function.
  """
  def __init__(self, function_name: str):
    fn = shrincs.__getattribute__(function_name)
    positions = list(fn.__code__.co_positions())
    def_line = positions[0][0] - 1
    code_start_line = positions[1][0] - 1
    code_end_line = positions[-1][0]
    if fn.__doc__ is not None:
      self.docstring = inspect.cleandoc(fn.__doc__)
    else:
      self.docstring = None
    self.codestring = '\n'.join([shrincs_code_lines[def_line], *shrincs_code_lines[code_start_line : code_end_line]])


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
        function_name = doc_start_match.group(1)
        out.write(markdown_lines[i])

        spec_fn = SpecFunction(function_name)
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
