# The version the flake reports when it is not fetched at a tag.
#
# `nix build github:soroauth/soroauth-go#` (a branch checkout, no tag) has no
# tag for the flake to read, so the binary it builds reports this value. The
# release workflow rewrites this file on `main` after every release, so a
# branch install reports the newest released version rather than a stale one.
#
# Never edit it by hand: it is generated from the release tag. A `nix build`
# at a tag ignores this value entirely (see flake.nix).
"0.1.0"
