#!/usr/bin/env python3

import re
import ast
import inspect
from argparse import ArgumentParser
import shutil

"""
This script parses the reference implementation, to substitute docstrings
and exact python code for reference functions and constants into the
templated markdown documents. We parse markdown comments as doc/const
insert directives.
"""

from impl import shrincs, meta, caches

DOCUMENTS = [
  {'markdown': 'SHRINCS.md', 'source': 'impl/shrincs.py'},
  {'markdown': 'docs/CACHE_MANAGEMENT.md', 'source': 'impl/caches.py'},
]

class SourceFile:
  """
  The top-level function definitions of one python source file, by name.
  """
  def __init__(self, path: str):
    with open(path) as fh:
      source = fh.read()

    self.source_lines = source.splitlines(keepends = True)
    self.code_lines = [line.rstrip() for line in source.split('\n')]

    self.definitions = {}
    for node in ast.parse(source).body:
      if isinstance(node, ast.FunctionDef):
        self.definitions[node.name] = node

  #  The first source line of a definition. A decorator is not part of the
  #  node's own extent, and the `@` may sit on a line above the expression it
  #  applies to.
  def start_line(self, node: ast.stmt) -> int:
    decorators = getattr(node, 'decorator_list', [])
    if not decorators:
      return node.lineno - 1
    line = min(decorator.lineno for decorator in decorators) - 1
    while not self.code_lines[line].lstrip().startswith('@'):
      line -= 1
    return line


class SpecFunction:
  """
  Data structure to document a specification function.
  """
  def __init__(self, source: SourceFile, name: str):
    node = source.definitions[name]

    self.docstring = ast.get_docstring(node)

    #  The signature, then the body with any docstring elided.
    body_start = node.body[0]
    starts_at = source.start_line(node)
    body_from = body_start.end_lineno if self.docstring is not None else body_start.lineno - 1

    #  `inspect.getblock` finds where the definition really ends, including
    #  any trailing comment, which is not a node and so has no `end_lineno`.
    #  It also keeps a comment which introduces whatever follows, so stop at
    #  the blank line which separates one from the body it would follow.
    block_end = starts_at + len(inspect.getblock(source.source_lines[starts_at:]))
    ends_at = node.end_lineno
    while ends_at < block_end and source.code_lines[ends_at].strip():
      ends_at += 1

    signature = source.code_lines[starts_at : body_start.lineno - 1]
    self.codestring = '\n'.join(signature + source.code_lines[body_from : ends_at])


regex_doc_start = r"^<!-- DOC START (\w+) -->\W*$"
regex_doc_end = r"^<!-- DOC END (\w+) -->\W*$"
regex_const = r"<!-- CONST START (\w+) -->\S*<!-- CONST END (\w+) -->"

def template_document(markdown_path: str, source: SourceFile) -> str:
  with open(markdown_path) as fh:
    markdown_lines = [line for line in fh]

  out_path = markdown_path.replace('.md', '.new.md')
  with open(out_path, 'w') as out:
    i = 0
    while i < len(markdown_lines):
      doc_start_match = re.match(regex_doc_start, markdown_lines[i])
      const_start_match = re.search(regex_const, markdown_lines[i])
      if doc_start_match:
        definition_name = doc_start_match.group(1)
        out.write(markdown_lines[i])

        spec_function = SpecFunction(source, definition_name)
        if spec_function.docstring is not None:
          out.write(spec_function.docstring + '\n\n')
        out.write("```py" + '\n')
        out.write(spec_function.codestring + '\n')
        out.write("```" + '\n')

        while True:
          if re.match(r"^<!-- DOC END %s -->$" % definition_name, markdown_lines[i]):
            out.write(markdown_lines[i])
            break
          i += 1
          if i >= len(markdown_lines):
            raise RuntimeError("failed to find closing <!-- DOC END %s --> comment" % definition_name)

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
    out_path = template_document(document['markdown'], SourceFile(document['source']))
    if not args.dry_run:
      shutil.move(out_path, document['markdown'])
