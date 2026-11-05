#!/usr/bin/env bash
# cascade.sh <upstream-repo> <version>
#
# Releases every repo in the org that depends on <upstream-repo>@<version>,
# in dependency order. For each one it moves the go.mod files onto the new
# versions, builds, vets and tests, commits to the default branch, then runs
# that repo's own release workflow and waits for it before moving on, so a
# repo is only bumped once everything it depends on has been released.
#
# Which modules change is worked out from the go.mod files, not a list:
#   - every module of the upstream repo that got a <version> tag has changed;
#   - a module in another repo has changed if it requires a changed module.
# Requirements between modules of the same repo are ignored, because a repo
# releases all its modules together at one version.
#
# Environment:
#   CASCADE_OWNER    GitHub org (default xraph)
#   CASCADE_CONFIG   JSON config (default .github/cascade.json)
#   CASCADE_WORKDIR  scratch directory (default: a new temp dir)
#   CASCADE_BUMP     patch | minor (default patch)
#   CASCADE_TESTS    true | false: run go test before pushing (default true)
#   DRY_RUN          true: bump and verify the first wave, push nothing
#   GH_TOKEN         token with contents and actions write on every repo
#
# Config keys (all optional):
#   exclude_repos    repos never touched
#   exclude_paths    regexes; go.mod files whose directory matches are ignored
#   bump_only        repos that get the bump commit but are never released
#   release_workflow {"repo": "file.yml"} when it isn't release.yml
#   release_inputs   {"repo": {"input": "value"}} extra release workflow inputs
#
# A repo is released only when its release workflow can be dispatched with a
# `tag` input. Anything else (apps that deploy, repos with no release) gets
# the bump commit and nothing more.
#
# Needs bash 3.2+, git, go, gh, jq, tsort and a sort that knows -V.
# golangci-lint is optional: with it on PATH, repos whose release lints are
# linted before they're pushed.
set -euo pipefail

UPSTREAM=${1:?usage: cascade.sh <upstream-repo> <version>}
VERSION=${2:?usage: cascade.sh <upstream-repo> <version>}
OWNER=${CASCADE_OWNER:-xraph}
CONFIG=${CASCADE_CONFIG:-.github/cascade.json}
WORK=${CASCADE_WORKDIR:-$(mktemp -d)}
BUMP=${CASCADE_BUMP:-patch}
TESTS=${CASCADE_TESTS:-true}
DRY_RUN=${DRY_RUN:-false}
GIT_NAME=${CASCADE_GIT_NAME:-github-actions[bot]}
GIT_EMAIL=${CASCADE_GIT_EMAIL:-41898282+github-actions[bot]@users.noreply.github.com}

case $BUMP in patch|minor) ;; *) echo "CASCADE_BUMP must be patch or minor" >&2; exit 2;; esac
mkdir -p "$WORK/scan" "$WORK/full"
WORK=$(cd "$WORK" && pwd)
if [ -f "$CONFIG" ]; then
  CONFIG=$(cd "$(dirname "$CONFIG")" && pwd)/$(basename "$CONFIG")
else
  echo '{}' > "$WORK/empty.json"; CONFIG="$WORK/empty.json"
fi
cd "$WORK"

# git and go both reach GitHub through gh's credentials, so private repos and
# private modules work with GH_TOKEN alone. Go skips the proxy and checksum
# database for the org, so a tag pushed a minute ago resolves at once.
export GIT_CONFIG_COUNT=2
export GIT_CONFIG_KEY_0=credential.https://github.com.helper GIT_CONFIG_VALUE_0=
export GIT_CONFIG_KEY_1=credential.https://github.com.helper GIT_CONFIG_VALUE_1='!gh auth git-credential'
export GOPRIVATE="github.com/$OWNER/*${GOPRIVATE:+,$GOPRIVATE}"
export GOFLAGS=-mod=mod
# A repo's go.work is for working on it locally, and -mod=mod is refused in
# workspace mode. Each module is checked on its own, the way a consumer
# builds it.
export GOWORK=off
export GIT_TERMINAL_PROMPT=0
export LC_ALL=C

log()  { printf '%s\n' "$*" >&2; }
die()  { log "::error::$*"; exit 1; }
cfg()  { jq -r "$1" "$CONFIG"; }
summary() { [ -n "${GITHUB_STEP_SUMMARY:-}" ] && printf '%s\n' "$*" >> "$GITHUB_STEP_SUMMARY" || true; }
url()  { printf 'https://github.com/%s/%s.git' "$OWNER" "$1"; }
release_wf() { jq -r --arg r "$1" '.release_workflow[$r] // "release.yml"' "$CONFIG"; }

in_list() { # in_list <word> <newline-separated list>
  printf '%s\n' "$2" | grep -qxF -- "$1"
}

EXCLUDE_REPOS=$(cfg '.exclude_repos // [] | .[]')
BUMP_ONLY=$(cfg '.bump_only // [] | .[]')
EXCLUDE_PATHS=$(cfg '.exclude_paths // [] | join("|")')

# ---------------------------------------------------------------------------
# 1. Scan: a sparse clone of every repo, holding only go.mod files and the
#    release workflow, into index.tsv (repo dir module) and requires.tsv
#    (module required-module version).
# ---------------------------------------------------------------------------
log "==> Scanning $OWNER repos"
: > index.tsv; : > requires.tsv; : > releasable.txt; : > blocked.tsv
REPOS=$(gh repo list "$OWNER" --no-archived --source --limit 1000 --json name,isEmpty --jq '.[] | select(.isEmpty | not) | .name' | sort)

for repo in $REPOS; do
  in_list "$repo" "$EXCLUDE_REPOS" && continue
  dest="scan/$repo"
  ref_args=""
  [ "$repo" = "$UPSTREAM" ] && ref_args="--branch $VERSION"
  # A repo that can't be read must stop the run: skipping it would quietly
  # leave a dependent behind.
  ok=false
  for _ in 1 2 3; do
    rm -rf "$dest"
    # shellcheck disable=SC2086
    if git clone -q --depth 1 --filter=blob:none --no-checkout $ref_args "$(url "$repo")" "$dest" \
      && git -C "$dest" sparse-checkout set --no-cone 'go.mod' '/.github/workflows/' \
      && git -C "$dest" checkout -q; then
      ok=true; break
    fi
    sleep 5
  done
  [ "$ok" = true ] || die "could not read $repo after three tries"

  rel="$dest/.github/workflows/$(release_wf "$repo")"
  if [ -f "$rel" ] && grep -q 'workflow_dispatch:' "$rel" && grep -Eq '^[[:space:]]+tag:[[:space:]]*$' "$rel"; then
    echo "$repo" >> releasable.txt
  fi

  (cd "$dest" && find . -name go.mod -not -path '*/node_modules/*') | sed 's|^\./||; s|/\{0,1\}go.mod$||' | while read -r dir; do
    [ -z "$dir" ] && dir=.
    if [ -n "$EXCLUDE_PATHS" ] && [ "$dir" != . ] && printf '%s' "$dir" | grep -Eq "$EXCLUDE_PATHS"; then continue; fi
    json=$(cd "$dest/$dir" && go mod edit -json 2>/dev/null) || continue
    mod=$(printf '%s' "$json" | jq -r '.Module.Path')
    printf '%s\t%s\t%s\n' "$repo" "$dir" "$mod" >> index.tsv
    printf '%s' "$json" | jq -r --arg m "$mod" '.Require[]? | [$m, .Path, .Version] | @tsv' >> requires.tsv
    # A replace that points outside the repo only resolves on someone's
    # machine. Such a module can't be bumped here, so it sits the cascade out.
    depth=0; [ "$dir" != . ] && depth=$(printf '%s' "$dir" | awk -F/ '{print NF}')
    printf '%s' "$json" | jq -r '.Replace[]? | select(.New.Version == null) | .New.Path' | while read -r target; do
      ups=$(printf '%s' "$target" | awk -F/ '{n=0; for(i=1;i<=NF;i++) if($i=="..") n++; else if($i!=".") break; print n}')
      if [ "$ups" -gt "$depth" ]; then printf '%s\t%s\n' "$mod" "$target" >> blocked.tsv; fi
    done
  done
done

grep -q "^$UPSTREAM	" index.tsv || die "$UPSTREAM@$VERSION has no go.mod (or is excluded)"

# ---------------------------------------------------------------------------
# 2. Plan: which modules changed, which repos they live in, in what order.
# ---------------------------------------------------------------------------
repo_of() { awk -F'\t' -v m="$1" '$3==m{print $1; exit}' "$WORK/index.tsv"; }

# The upstream's modules that this release tagged.
UP_TAGS=$(git ls-remote --tags --refs "$(url "$UPSTREAM")" | awk '{sub("refs/tags/","",$2); print $2}')
: > changed.txt; : > released.tsv; : > failed_repos.txt
awk -F'\t' -v r="$UPSTREAM" '$1==r{print $2"\t"$3}' index.tsv | while IFS=$'\t' read -r dir mod; do
  tag=$VERSION; [ "$dir" != . ] && tag="$dir/$VERSION"
  if in_list "$tag" "$UP_TAGS"; then
    echo "$mod" >> changed.txt
    printf '%s\t%s\treal\n' "$mod" "$VERSION" >> released.tsv
  fi
done
[ -s changed.txt ] || die "no module of $UPSTREAM is tagged $VERSION"

# Fixed point: a module changes when it requires a changed module that lives
# in a different repo.
while :; do
  before=$(wc -l < changed.txt)
  awk -F'\t' '
    FILENAME=="index.tsv"   { repo[$3]=$1; next }
    FILENAME=="blocked.tsv" { bl[$1]=1; next }
    FILENAME=="changed.txt" { ch[$1]=1; next }
    ($2 in ch) && ($1 in repo) && repo[$1]!=repo[$2] && !($1 in ch) && !($1 in bl) { print $1; ch[$1]=1 }
  ' index.tsv blocked.tsv changed.txt requires.tsv >> changed.txt
  sort -u -o changed.txt changed.txt
  [ "$(wc -l < changed.txt)" -eq "$before" ] && break
done

# Repo edges for changed modules: "S R" means S releases before R.
awk -F'\t' '
  FILENAME=="index.tsv"   { repo[$3]=$1; next }
  FILENAME=="changed.txt" { ch[$1]=1; next }
  ($1 in ch) && ($2 in ch) && repo[$1]!=repo[$2] { print repo[$2], repo[$1] }
' index.tsv changed.txt requires.tsv | sort -u > edges.txt
for m in $(cat changed.txt); do r=$(repo_of "$m"); echo "$r $r"; done | sort -u >> edges.txt

if ! ORDER=$(tsort edges.txt 2> tsort.err) || [ -s tsort.err ]; then
  cat tsort.err >&2
  die "the changed repos depend on each other in a cycle; release them by hand"
fi
ORDER=$(printf '%s\n' "$ORDER" | grep -vxF "$UPSTREAM" || true)

[ -n "$ORDER" ] || { log "Nothing depends on $UPSTREAM@$VERSION."; summary "Nothing depends on \`$UPSTREAM@$VERSION\`."; exit 0; }

releasable() { in_list "$1" "$(cat "$WORK/releasable.txt")" && ! in_list "$1" "$BUMP_ONLY"; }

# A repo that is never released can't be a dependency of another changed repo.
while read -r from to; do
  [ "$from" = "$to" ] || [ "$from" = "$UPSTREAM" ] && continue
  releasable "$from" || die "$to needs a release of $from, but $from has no release workflow that takes a tag input (or is bump_only)"
done < edges.txt

log ""
log "==> Cascade from $UPSTREAM $VERSION ($BUMP bumps)"
summary "## Cascade from \`$UPSTREAM\` $VERSION"
summary ""
summary "| repo | modules | result |"
summary "|---|---|---|"
for r in $ORDER; do
  mods=$(awk -F'\t' -v r="$r" 'FILENAME=="changed.txt"{c[$1]=1;next} $1==r && ($3 in c){printf "%s ", $2}' changed.txt index.tsv)
  mode=release; releasable "$r" || mode="bump only"
  log "    $r [$mode]: $mods"
done
# Modules that would have changed but carry a replace pointing outside their repo.
awk -F'\t' '
  FILENAME=="index.tsv"   { repo[$3]=$1; next }
  FILENAME=="changed.txt" { ch[$1]=1; next }
  FILENAME=="blocked.tsv" { bl[$1]=$2; next }
  ($1 in bl) && ($2 in ch) && repo[$1]!=repo[$2] { print repo[$1] "\t" $1 "\t" bl[$1] }
' index.tsv changed.txt blocked.tsv requires.tsv | sort -u > skipped.tsv
while IFS=$'\t' read -r r m target; do
  log "::warning::skipping $m: its go.mod replaces a module with $target, outside the repo"
  summary "| $r | ${m#github.com/$OWNER/$r} | skipped: replace points at \`$target\` |"
done < skipped.tsv
log ""

# ---------------------------------------------------------------------------
# 3. Release, one repo at a time.
# ---------------------------------------------------------------------------
released_version() { awk -F'\t' -v m="$1" '$1==m{print $2"\t"$3; exit}' "$WORK/released.tsv"; }

latest_tag() { # newest plain vX.Y.Z tag of a repo
  git ls-remote --tags --refs "$(url "$1")" 'refs/tags/v*' | awk '{sub("refs/tags/","",$2); print $2}' \
    | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -1
}

next_version() { # next_version <vX.Y.Z> <patch|minor>
  local v=${1#v} major minor patch
  IFS=. read -r major minor patch <<EOF
$v
EOF
  case $2 in
    minor) echo "v$major.$((minor + 1)).0" ;;
    *)     echo "v$major.$minor.$((patch + 1))" ;;
  esac
}

# Moves every requirement on a released module up to its released version.
# Never moves one down: if the repo already needs something newer, it keeps it.
pin_released() {
  go mod edit -json | jq -r '.Require[]? | "\(.Path) \(.Version)"' | while read -r p v; do
    rv=$(released_version "$p"); [ -z "$rv" ] && continue
    want=${rv%%	*}
    [ "$v" = "$want" ] && continue
    top=$(printf '%s\n%s\n' "$v" "$want" | sort -V | tail -1)
    if [ "$top" = "$want" ]; then
      go mod edit -require="$p@$want"
    fi
  done
}

wait_for_release() { # wait_for_release <repo> <sha> <since>
  local repo=$1 sha=$2 since=$3 id=""
  for _ in $(seq 1 30); do
    id=$(gh run list -R "$OWNER/$repo" --workflow "$(release_wf "$repo")" --event workflow_dispatch --limit 10 \
      --json databaseId,headSha,createdAt \
      --jq "[.[] | select(.headSha==\"$sha\" and .createdAt >= \"$since\")][0].databaseId // empty")
    [ -n "$id" ] && break
    sleep 10
  done
  [ -n "$id" ] || die "$repo: release run did not start"
  log "    watching https://github.com/$OWNER/$repo/actions/runs/$id"
  gh run watch "$id" -R "$OWNER/$repo" --exit-status --interval 30 > /dev/null \
    || die "$repo: release run failed: https://github.com/$OWNER/$repo/actions/runs/$id"
  echo "$id"
}

tag_commit() { # commit a tag points at, peeled
  git ls-remote --tags "$(url "$1")" "refs/tags/$2" "refs/tags/$2^{}" | awk '{c=$1} END{print c}'
}
record() { # record <mods> <version> <real|planned>
  printf '%s\n' "$1" | while IFS=$'\t' read -r dir mod; do printf '%s\t%s\t%s\n' "$mod" "$2" "$3" >> "$WORK/released.tsv"; done
}
reqs() { go mod edit -json | jq -r '.Require[]? | "\(.Path) \(.Version)"' | sort; }

for repo in $ORDER; do
  log "==> $repo"
  : > "$WORK/moved.txt"
  mods=$(awk -F'\t' -v r="$repo" 'FILENAME=="changed.txt"{c[$1]=1;next} $1==r && ($3 in c){print $2"\t"$3}' changed.txt index.tsv)
  dirs=$(printf '%s\n' "$mods" | cut -f1 | paste -sd' ' -)
  row() { summary "| $repo | $dirs | $1 |"; }
  prev=""; nv=""
  if releasable "$repo"; then
    prev=$(latest_tag "$repo")
    [ -n "$prev" ] || die "$repo has no vX.Y.Z tag yet; cut its first release by hand or list it in bump_only"
    nv=$(next_version "$prev" "$BUMP")
  fi

  # In a dry run, later waves need versions that don't exist yet.
  pending=$(printf '%s\n' "$mods" | while IFS=$'\t' read -r dir mod; do
    awk -F'\t' -v m="$mod" '$1==m{print $2}' requires.tsv | while read -r q; do
      rv=$(released_version "$q"); if [ "${rv##*	}" = planned ]; then echo "$q ${rv%%	*}"; fi
    done
  done | sort -u)
  if [ -n "$pending" ]; then
    log "    after its upstreams release, would move to:"
    printf '%s\n' "$pending" | sed 's/^/      /' >&2
    if [ -n "$nv" ]; then
      log "    and release $nv"; record "$mods" "$nv" planned; row "dry run: would bump and release $nv"
    else
      row "dry run: would bump"
    fi
    continue
  fi

  dest="full/$repo"
  git clone -q --depth 1 "$(url "$repo")" "$dest"
  git -C "$dest" config user.name "$GIT_NAME"
  git -C "$dest" config user.email "$GIT_EMAIL"

  printf '%s\n' "$mods" | while IFS=$'\t' read -r dir mod; do
    log "    bump $mod"
    (
      cd "$dest/$dir"
      reqs > "$WORK/before.txt"
      pin_released && go mod tidy && pin_released && go mod tidy
      reqs > "$WORK/after.txt"
      join -a2 -e none -o '0,1.2,2.2' "$WORK/before.txt" "$WORK/after.txt" | while read -r p old new; do
        [ "$old" != "$new" ] && [ -n "$(released_version "$p")" ] && echo "$p $old $new" >> "$WORK/moved.txt"
        true
      done
    ) || die "$repo/$dir: go mod tidy failed"
  done

  # A release tags every module in the repo, and release workflows check that
  # each one is tidy. Tidy the ones the bump didn't touch as well, so a stale
  # go.sum fails here, before anything is pushed, and not halfway through a
  # release that has already tagged the root.
  : > "$WORK/tidied.txt"
  if [ -n "$nv" ]; then
    awk -F'\t' -v r="$repo" '$1==r{print $2}' index.tsv | while read -r dir; do
      printf '%s\n' "$mods" | cut -f1 | grep -qxF "$dir" && continue
      (cd "$dest/$dir" && go mod tidy) >&2 || die "$repo/$dir: go mod tidy failed"
      if [ -n "$(git -C "$dest" status --porcelain -- "$dir/go.mod" "$dir/go.sum")" ]; then
        echo "$dir" >> "$WORK/tidied.txt"
      fi
    done
  fi

  bumped=false
  [ -n "$(git -C "$dest" status --porcelain)" ] && bumped=true
  head=$(git -C "$dest" rev-parse HEAD)

  if [ "$bumped" = false ]; then
    if [ -z "$nv" ]; then
      log "    already on the new versions"; row "already up to date"; continue
    fi
    if [ "$(tag_commit "$repo" "$prev")" = "$head" ]; then
      log "    already released as $prev"; record "$mods" "$prev" real; row "already released as $prev"; continue
    fi
    log "    already on the new versions, but $prev doesn't include them; releasing"
  fi

  # When the repo's release lints, lint here too, so a lint failure stops
  # the cascade before anything is pushed rather than after the release has
  # tagged the root.
  lint=false
  if [ -n "$nv" ] && command -v golangci-lint >/dev/null \
    && grep -q golangci "$dest/.github/workflows/$(release_wf "$repo")" 2>/dev/null; then
    lint=true
  fi
  # Each step exits on its own failure. set -e doesn't reach inside a
  # subshell that sits on the left of ||, so without the explicit exits the
  # last step's status would hide an earlier failure.
  : > "$WORK/verify_failed.txt"
  { printf '%s\n' "$mods" | cut -f1; cat "$WORK/tidied.txt"; } | sort -u | while read -r dir; do
    log "    verify $dir"
    (
      cd "$dest/$dir" || exit 1
      go build ./... || exit 1
      go vet ./... || exit 1
      if [ "$TESTS" = true ]; then go test -count=1 ./... || exit 1; fi
      if [ "$lint" = true ]; then golangci-lint run ./... || exit 1; fi
    ) >&2 || echo "$dir" >> "$WORK/verify_failed.txt"
  done
  if [ -s "$WORK/verify_failed.txt" ]; then
    where=$(paste -sd' ' "$WORK/verify_failed.txt")
    # Nothing depends on a repo that is never released (the plan checks
    # that), so the cascade can leave it behind and carry on. A repo others
    # wait on has to stop the run.
    if [ -n "$nv" ]; then
      die "$repo ($where): build, vet, tests or lint failed on the new versions"
    fi
    log "::error::$repo ($where): build, vet, tests or lint failed on the new versions; not pushed"
    row "verify failed in $where, not pushed"
    echo "$repo" >> "$WORK/failed_repos.txt"
    continue
  fi

  if [ "$bumped" = true ]; then
    # The subject names each upstream repo once: "move to chronicle v1.11.0 and dispatch v1.9.4".
    names=$(sort -u "$WORK/moved.txt" | while read -r p _ new; do
      r=$(repo_of "$p"); root=$(awk -F'\t' -v r="$r" '$1==r && $2=="."{print $3}' index.tsv)
      printf '%s %s\n' "${root:-$p}" "$new"
    done | sed "s|^github.com/$OWNER/||" | sort -u)
    if [ -n "$names" ]; then
      n=$(printf '%s\n' "$names" | wc -l | tr -d ' ')
      subject="build(deps): move to $(printf '%s\n' "$names" | awk -v n="$n" 'NR>1{printf (NR==n?" and ":", ")} {printf "%s",$0}')"
    elif [ -s "$WORK/tidied.txt" ]; then
      subject="build(deps): tidy the nested modules"
    else
      subject="build(deps): tidy after the $UPSTREAM $VERSION release"
    fi
    [ ${#subject} -gt 72 ] && subject="build(deps): move to the $UPSTREAM $VERSION releases"
    {
      echo "$subject"
      if [ -s "$WORK/moved.txt" ]; then
        echo; echo "Cascade from $UPSTREAM $VERSION."; echo
        sort -u "$WORK/moved.txt" | awk '{ if ($2=="none") printf "- add %s %s\n", $1, $3; else printf "- %s %s to %s\n", $1, $2, $3 }'
      fi
      if [ -s "$WORK/tidied.txt" ]; then
        echo; echo "Also tidies $(paste -sd' ' "$WORK/tidied.txt" | sed 's/ /, /g'), so the release's tidy check passes."
      fi
    } > "$WORK/msg.txt"
    git -C "$dest" add -A
    git -C "$dest" commit -q -F "$WORK/msg.txt"
    log "    $subject"
  fi

  if [ "$DRY_RUN" = true ]; then
    [ "$bumped" = true ] && git -C "$dest" show --stat --format= HEAD | sed 's/^/      /' >&2
    if [ -n "$nv" ]; then
      log "    would release $nv"; record "$mods" "$nv" planned; row "dry run: would release $nv"
    else
      row "dry run: would push the bump"
    fi
    continue
  fi

  if [ "$bumped" = true ]; then
    git -C "$dest" push -q origin HEAD || die "$repo: push rejected (default branch moved or protected); rerun the cascade"
  fi
  sha=$(git -C "$dest" rev-parse HEAD)

  if [ -z "$nv" ]; then
    log "    pushed $sha, not released (bump only)"; row "bumped, not released"; continue
  fi

  since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  log "    release $nv"
  # shellcheck disable=SC2046
  gh workflow run "$(release_wf "$repo")" -R "$OWNER/$repo" --ref "$(git -C "$dest" rev-parse --abbrev-ref HEAD)" -f tag="$nv" \
    $(jq -r --arg r "$repo" '.release_inputs[$r] // {} | to_entries[] | "-f \(.key)=\(.value)"' "$CONFIG")
  run=$(wait_for_release "$repo" "$sha" "$since")

  tags=$(git ls-remote --tags --refs "$(url "$repo")" | awk '{sub("refs/tags/","",$2); print $2}')
  printf '%s\n' "$mods" | while IFS=$'\t' read -r dir mod; do
    tag=$nv; [ "$dir" != . ] && tag="$dir/$nv"
    in_list "$tag" "$tags" || die "$repo: release finished but tag $tag is missing"
  done
  record "$mods" "$nv" real
  row "[$nv](https://github.com/$OWNER/$repo/actions/runs/$run)"
done

if [ -s "$WORK/failed_repos.txt" ]; then
  die "finished, but these repos were left behind: $(paste -sd' ' "$WORK/failed_repos.txt")"
fi
log "==> Done"
