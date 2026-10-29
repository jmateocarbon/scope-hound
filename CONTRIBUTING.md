# Contributing

ScopeHound is a community-maintained Python project. Small, focused PRs are preferred. Keep the default Python CLI working; Docker is optional.

1. Open an issue to describe behavioral or architectural changes.
2. Add unit tests for any new provider fingerprints or input-validation behavior.
3. Test with domains you own or are explicitly authorized to assess.
4. Never commit API tokens, `.env` files, customer hostnames, screenshots, or actual scan reports.
5. Document limitations and false-positive considerations for detection changes.

Before submitting: `python -m compileall -q asm.py takeover.py` and `python -m unittest discover -s tests -v` (install dependencies first).
