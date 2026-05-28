# nauthilus-director

`nauthilus-director` is the production implementation of the Nauthilus mail
protocol director. It authenticates users through Nauthilus, owns backend
selection itself, maintains active session affinity through Redis and proxies
mail protocols to the selected backend services.

The project is under active development. Public behavior, configuration paths
and operational tooling are still being shaped through the implementation
specifications under `docs/specs/implementation/`. The archived `poc/`
directory is historical reference material only; current production code lives
in the root project layout.

Implemented and planned areas include IMAP proxying, LMTP delivery routing,
Redis-backed affinity and runtime control, OpenAPI-based REST management,
`nauthilus-directorctl`, observability, and a demo Docker stack under
`contrib/demo-stack/`.

For development rules and contribution workflow, read `AGENTS.md` first. The
main architecture overview is in `docs/ARCHITECTURE_ROADMAP.md`.
