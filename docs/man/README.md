# Manpages

Manual page sources for `nauthilus-director`, `nauthilus-directorctl` and the
`nauthilus-director.yaml` config file live here.

Command manpages should keep `nauthilus-director(1)` and
`nauthilus-directorctl(1)` aligned with stable subcommands, flags, output formats
and exit codes.

The config-format manpage should use `nauthilus-director.yaml(5)` as the
canonical name, while noting that `.yml` files are accepted. It should stay
aligned with stable config paths, include and patch behavior, placeholder
expansion, environment overrides and redaction/protected-output semantics.

Generated config reference material should live under `docs/reference/` and be
guarded by `make check-docs`. The config-format manpage may explain and link to
those generated references instead of duplicating every default value by hand.

`make install` installs the production binaries and manpages below `PREFIX`
(`/usr/local` by default) and honors `DESTDIR` for staged package builds.
`make uninstall` removes the same binary and manual-page paths without pruning
parent directories.

Initial manpages now document the implemented server binary, generated-client
operator CLI and YAML configuration format. Future production hardening may
expand this area with broader operational and failure-mode documentation.
