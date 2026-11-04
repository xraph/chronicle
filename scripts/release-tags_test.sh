#!/usr/bin/env bash
#
# Tests for release-tags.sh, run against a throwaway repo and a local bare
# remote. Run it from the repo root: bash scripts/release-tags_test.sh

set -euo pipefail

SCRIPT="$(cd "$(dirname "$0")" && pwd)/release-tags.sh"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

failures=0
fail() {
  echo "FAIL: $*" >&2
  failures=$((failures + 1))
}

# fixture makes a repo with a print-tagged target and a bare remote it pushes
# to, and prints the clone's path.
fixture() {
  local name=$1
  local remote="$WORK/$name.git" clone="$WORK/$name"
  git init -q --bare "$remote"
  git init -q "$clone"
  (
    cd "$clone"
    git config user.name test
    git config user.email test@example.com
    printf 'print-tagged:\n\t@echo store/postgres store/redis extension\n' > Makefile
    git add Makefile
    git commit -q -m init
    git remote add origin "$remote"
    git push -q origin HEAD:main
  )
  echo "$clone"
}

remote_tags() {
  git --git-dir="$1" tag --list | sort | tr '\n' ' '
}

want='extension/v1.11.0 store/postgres/v1.11.0 store/redis/v1.11.0 v1.11.0 '

# A dispatched release: nothing is tagged yet, so every tag goes out together.
repo=$(fixture dispatch)
(cd "$repo" && bash "$SCRIPT" v1.11.0 >/dev/null)
got=$(remote_tags "$WORK/dispatch.git")
[ "$got" = "$want" ] || fail "dispatch: remote has '$got', want '$want'"

# Running it again changes nothing and doesn't fail.
(cd "$repo" && bash "$SCRIPT" v1.11.0 >/dev/null) || fail "rerun: exited non-zero"
got=$(remote_tags "$WORK/dispatch.git")
[ "$got" = "$want" ] || fail "rerun: remote has '$got', want '$want'"

# A pushed root tag: the root is already on the remote, the nested tags follow.
repo=$(fixture pushed)
(cd "$repo" && git tag v1.11.0 && git push -q origin v1.11.0)
(cd "$repo" && bash "$SCRIPT" v1.11.0 >/dev/null)
got=$(remote_tags "$WORK/pushed.git")
[ "$got" = "$want" ] || fail "pushed root: remote has '$got', want '$want'"

# All or nothing: when the remote refuses one tag, none of them land.
repo=$(fixture refused)
# An update hook decides per ref, so without --atomic the other tags would
# still land. (A pre-receive hook refuses the whole push either way.)
cat > "$WORK/refused.git/hooks/update" <<'HOOK'
#!/usr/bin/env bash
case $1 in refs/tags/store/redis/*) echo "refusing $1" >&2; exit 1 ;; esac
HOOK
chmod +x "$WORK/refused.git/hooks/update"
if (cd "$repo" && bash "$SCRIPT" v1.11.0 >/dev/null 2>&1); then
  fail "refused: exited zero although the remote refused a tag"
fi
got=$(remote_tags "$WORK/refused.git")
[ -z "$got" ] || fail "refused: remote has '$got', want no tags"

# An empty module list is an error, not a release of the root alone.
repo=$(fixture empty)
(cd "$repo" && printf 'print-tagged:\n\t@echo\n' > Makefile && git commit -q -am empty)
if (cd "$repo" && bash "$SCRIPT" v1.11.0 >/dev/null 2>&1); then
  fail "empty: exited zero with no nested modules to tag"
fi
got=$(remote_tags "$WORK/empty.git")
[ -z "$got" ] || fail "empty: remote has '$got', want no tags"

if [ "$failures" -ne 0 ]; then
  echo "$failures failure(s)" >&2
  exit 1
fi
echo "release-tags: all tests passed"
