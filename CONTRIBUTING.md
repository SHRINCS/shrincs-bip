## Contributor Guide

Thank you for your interest in contributing to SHRINCS!

We have a few simple rules to keep things organized and running smoothly:

- Reviews of PRs, or general suggestions and feedback in GH issues are very welcome. Please be courteous and keep feedback constructive.
- Talk first, then implement. Please don't jump ahead to implement something without chatting with us first. Cryptographic reference code like SHRINCS is highly sensitive; Changes are not to be taken lightly.
  - If you want to make a big change like adding a feature, changing the spec, or making a large refactor, try to find an appropriate issue and post your plan there. If your desired change isn't already captured by an issue, please open a new issue.
  - In conversation we can come to consensus on the best design.
  - Small bugfixes or typo corrections are welcome any time and can be submitted without prior check-in.
- Specification changes should be checked for typos and grammatical errors.
- Code changes should be checked for type consistency with `mypy`, and validated against the tests in [`impl`](./impl).
- Ensure `pydoc_insert.py` is run before any commit. This script synchronizes the code in [`impl`](./impl) with the spec in `SHRINCS.md`. See [the README](./README.md#templating) for more info.

## Use of AI

- AI-assisted code review to find bugs is encouraged, but findings must be validated, summarized, and submitted by a human.
- AI-assisted code changes and PRs are acceptable, but the human committing the change is fully responsible for the quality and consequences of the code they submit, and for answering questions from reviewers.
  - Consistently low-quality contributors will be blocked.
- Representing AI-generated text as your own words when communicating over Github is prohibited. If other users wanted to talk to an AI, they would talk to an AI. People prefer talking to other humans.
  - Translation services are the sole exception, and the writing that is translated must be human-authored.
  - Writing "my AI says XYZ" and pasting a large blob of AI-generated text is acceptable, provided the AI has something important to say which you cannot personally comprehend, and would like to discuss as an artifact. This should not be a common practice.
- When you share something an AI produced, whether a finding or quoted text, consider linking to the conversation if your tool supports it, as Claude and ChatGPT do. It lets reviewers see what the AI was asked and what context it had.
