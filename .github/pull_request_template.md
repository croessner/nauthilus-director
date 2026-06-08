## Summary

Describe what changed and why.

## Mandatory Guardrails

Mark all items to proceed. PRs missing these checks are considered incomplete.

- [ ] I added a reproducer test first for bugfixes, or documented why no reproducer test was possible.
- [ ] I verified DRY compliance and removed or consolidated duplicate logic.
- [ ] I verified OOP-oriented structure with small responsibilities, clear boundaries and composition where appropriate.
- [ ] I ensured all new or changed technical comments and docs are in English.
- [ ] I ran `make guardrails` locally.
- [ ] For release-sensitive publication to `main` or `v*` tags, I ran `make release-guardrails` or used hooks installed by `make install-hooks`.
