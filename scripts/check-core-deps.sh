#!/usr/bin/env bash
#
# check-core-deps.sh: keep the root module light.
#
# The root module is Chronicle's core. It must build and test without Forge,
# Grove, any database driver or Redis, so a library can embed Chronicle without
# pulling those in. The stores, the handler and the Forge extension live in
# nested modules, and each of those must require the root at the version this
# repo releases together, so no consumer can end up with the same package in
# two modules.
#
# Run it from the repo root. It prints every problem it finds, then exits 1 if
# there was any.

set -euo pipefail

RELEASE=v1.11.0
ROOT_MODULE=github.com/xraph/chronicle
FORBIDDEN='^(github\.com/xraph/(forge|grove|vessel)|github\.com/jackc/pgx|go\.mongodb\.org/|github\.com/redis/go-redis|modernc\.org/sqlite)'

failed=0

report() {
  echo "check-core-deps: $*" >&2
  failed=1
}

# 1 and 2: what the root's packages pull in, without and with their tests.
for mode in build test; do
  flags=(-deps)
  [ "$mode" = test ] && flags+=(-test)
  errs=$(mktemp)
  if ! pkgs=$(go list "${flags[@]}" ./... 2>"$errs"); then
    report "go list ${flags[*]} failed in the root module:"
    cat "$errs" >&2
    rm -f "$errs"
    continue
  fi
  rm -f "$errs"
  while IFS= read -r pkg; do
    report "root module ($mode) depends on $pkg"
  done < <(printf '%s\n' "$pkgs" | grep -E "$FORBIDDEN" | sed -E 's/ \[.*\]$//' | sort -u)
done

# 3: every nested module that requires the root pins the release and replaces
# it with the checkout.
while IFS= read -r -d '' gomod; do
  [ "$gomod" = ./go.mod ] && continue
  json=$(go mod edit -json "$gomod")
  required=$(printf '%s' "$json" | jq -r --arg m "$ROOT_MODULE" \
    '[.Require[]? | select(.Path == $m) | .Version] | first // empty')
  [ -n "$required" ] || continue
  if [ "$required" != "$RELEASE" ]; then
    report "$gomod requires $ROOT_MODULE $required, want $RELEASE"
  fi
  replaced=$(printf '%s' "$json" | jq -r --arg m "$ROOT_MODULE" \
    '[.Replace[]? | select(.Old.Path == $m and (.Old.Version // "") == "") | .New.Path] | first // empty')
  case $replaced in
    .|..|./*|../*) ;;
    *) report "$gomod does not replace $ROOT_MODULE with a local path" ;;
  esac
done < <(find . \( -name node_modules -o -name .git -o -name testdata -o -name _examples \) -prune \
  -o -name go.mod -type f -print0)

if [ "$failed" -ne 0 ]; then
  exit 1
fi
echo "check-core-deps: root module is light and every nested module requires $ROOT_MODULE $RELEASE"
