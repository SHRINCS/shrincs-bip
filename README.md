# SHRINCS

This repository is the staging ground for work on the SHRINCS specification document and accompanying BIPs.

> [!WARNING]
>
> All code and cryptography specified in this repository is highly experimental, and subject to change.
>
> Formal security proofs and optimized implementations are forthcoming as future work.


## Templating

The SHRINCS specification in [`SHRINCS.md`](./SHRINCS.md) includes Python reference code and documentation defined inline at [`impl/shrincs.py`](./impl/shrincs.py). We use simple templating to pull Python code and docstrings from `shrincs.py`.

If you wish to make changes to the specification of SHRINCS functions inside of a `<!-- DOC START xyz -->` ... `<!-- DOC END xyz -->` templating envelope, please make the changes directly in `shrincs.py` first, and then run the [`pydoc_insert.py` script](./pydoc_insert.py).

>[!WARNING]
> Running the templating script will overwrite `SHRINCS.md`. Make sure you have saved and committed other important changes first!

```sh
./pydoc_insert.py
```

A simple git pre-commit validation hook is available in [`hooks/pre-commit`](./hooks/pre-commit), to remind you to run the templating script if needed before committing.

```
cp hooks/pre-commit .git/hooks
```
