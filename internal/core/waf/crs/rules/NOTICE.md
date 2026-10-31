# OWASP Core Rule Set

This directory vendors the OWASP Core Rule Set (CRS) v4.30.0, downloaded
2026-10-31 from `https://github.com/coreruleset/coreruleset`.

- Upstream: https://coreruleset.org
- License: Apache License 2.0 (see `LICENSE`)
- Vendored files: `rules/*.conf`, `rules/*.data`, and `../crs-setup.conf`

The rules are embedded into the binary and compiled by Coraza. Do not edit
them in place; update the vendored release instead so the upstream license and
version stay traceable.
