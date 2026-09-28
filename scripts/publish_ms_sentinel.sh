#!/usr/bin/env bash
set -euo pipefail

BUILD_ROOT="${1:?usage: publish_ms_sentinel.sh <build-root> <target-repo> [source-sha]}"
TARGET_REPO="${2:?usage: publish_ms_sentinel.sh <build-root> <target-repo> [source-sha]}"
SOURCE_SHA="${3:-unknown}"

log() {
  local level="$1" stage="$2" message="$3"
  shift 3
  printf 'DAC | %s | stage=%s' "$level" "$stage"
  local item
  for item in "$@"; do
    printf ' | %s' "$item"
  done
  printf ' | %s\n' "$message"
}

fail() {
  log ERROR publish "$1" "source_sha=$SOURCE_SHA"
  if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
    printf '::error title=Detection-as-Code publish::%s\n' "$1"
  fi
  exit 1
}

[[ -d "$BUILD_ROOT/Clients" ]] || fail "missing generated Clients directory: $BUILD_ROOT/Clients"
[[ -f "$BUILD_ROOT/_build/build-manifest.json" ]] || fail "missing generated build manifest"
[[ -d "$TARGET_REPO/.git" ]] || fail "target repository is not a Git checkout: $TARGET_REPO"

BUILD_ROOT="$(cd "$BUILD_ROOT" && pwd)"
TARGET_REPO="$(cd "$TARGET_REPO" && pwd)"
SRC_ROOT="$BUILD_ROOT/Clients"

log INFO publish "starting Microsoft Sentinel publication" "source_sha=$SOURCE_SHA" "target=$TARGET_REPO"

git -C "$TARGET_REPO" config user.name 'detection-as-code-bot'
git -C "$TARGET_REPO" config user.email 'detection-as-code-bot@users.noreply.github.com'
git -C "$TARGET_REPO" fetch origin --prune

# Generated catalog on main. This branch is the audit/catalog view; workspaces use deploy/<client> branches.
git -C "$TARGET_REPO" switch main
mkdir -p "$TARGET_REPO/Clients" "$TARGET_REPO/_build"
rsync -a --delete "$SRC_ROOT/" "$TARGET_REPO/Clients/"
cp "$BUILD_ROOT/_build/build-manifest.json" "$TARGET_REPO/_build/build-manifest.json"
git -C "$TARGET_REPO" add Clients _build/build-manifest.json
if ! git -C "$TARGET_REPO" diff --cached --quiet; then
  git -C "$TARGET_REPO" commit -m "chore: publish generated Microsoft Sentinel catalog ($SOURCE_SHA)"
  git -C "$TARGET_REPO" push origin HEAD:main
  log INFO publish "catalog published" "branch=main" "source_sha=$SOURCE_SHA"
else
  log INFO publish "catalog unchanged" "branch=main" "source_sha=$SOURCE_SHA"
fi

git -C "$TARGET_REPO" fetch origin --prune

for src in "$SRC_ROOT"/*; do
  [[ -d "$src" ]] || continue
  client="$(basename "$src")"
  branch="deploy/$client"
  log INFO publish "publishing client" "client=$client" "branch=$branch" "source_sha=$SOURCE_SHA"

  if git -C "$TARGET_REPO" show-ref --verify --quiet "refs/remotes/origin/$branch"; then
    git -C "$TARGET_REPO" switch --force-create "$branch" "origin/$branch"
  else
    git -C "$TARGET_REPO" switch --orphan "$branch"
    git -C "$TARGET_REPO" rm -rf . >/dev/null 2>&1 || true
  fi

  # Replace only deployment content. Existing branch-owned files outside Solutions/
  # (including Microsoft Sentinel's generated workflow) are preserved.
  rm -rf "$TARGET_REPO/Solutions"
  cp -a "$src/Solutions" "$TARGET_REPO/Solutions"
  git -C "$TARGET_REPO" add -A Solutions

  # Microsoft Sentinel repository connections deploy creates/updates, but removing
  # a file from Git does not remove the already deployed Sentinel content. Surface
  # deletions loudly so rule retirement is deliberate rather than silently assumed.
  deleted_files="$(git -C "$TARGET_REPO" diff --cached --name-only --diff-filter=D -- Solutions || true)"
  if [[ -n "$deleted_files" ]]; then
    while IFS= read -r deleted; do
      [[ -n "$deleted" ]] || continue
      log WARNING publish "generated rule removed from repository; live Sentinel rule must be retired separately" "client=$client" "branch=$branch" "path=$deleted"
      if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
        printf '::warning title=Sentinel rule retirement required::%s was removed from %s; deleting repository content does not delete the deployed Sentinel rule.\n' "$deleted" "$branch"
      fi
    done <<< "$deleted_files"
  fi

  if ! git -C "$TARGET_REPO" diff --cached --quiet; then
    git -C "$TARGET_REPO" commit -m "chore: publish Sentinel content for $client ($SOURCE_SHA)"
    git -C "$TARGET_REPO" push origin "HEAD:$branch"
    log INFO publish "client branch published" "client=$client" "branch=$branch" "source_sha=$SOURCE_SHA"
  else
    log INFO publish "client branch unchanged" "client=$client" "branch=$branch" "source_sha=$SOURCE_SHA"
  fi
done

while read -r ref; do
  [[ -n "$ref" ]] || continue
  client="${ref#origin/deploy/}"
  if [[ ! -d "$SRC_ROOT/$client" ]]; then
    log WARNING publish "stale deployment branch requires deliberate retirement" "branch=$ref" "client=$client"
    if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
      printf '::warning title=Stale Sentinel deployment branch::%s is not present in clients.yml; disconnect/retire it deliberately before deletion.\n' "$ref"
    fi
  fi
done < <(git -C "$TARGET_REPO" for-each-ref --format='%(refname:short)' 'refs/remotes/origin/deploy/*')

git -C "$TARGET_REPO" switch main
log INFO publish "Microsoft Sentinel publication completed" "source_sha=$SOURCE_SHA"
