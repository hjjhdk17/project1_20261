#!/usr/bin/env bash
# Collect rules/windows/process_creation from SigmaHQ at the current default-branch tip.
# The tip is resolved to a commit SHA and checked out in detached HEAD.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

REPO_URL="https://github.com/SigmaHQ/sigma.git"
SOURCE_PATH="rules/windows/process_creation"
COMMIT=""
CLONE_DIR="$ROOT/cache/sigmahq"
DEST="$ROOT/input/sigma_rules/windows/process_creation"
METADATA="$ROOT/input/sigma_rules/collection_metadata.json"

usage() {
  echo "Usage: $0 [--commit SHA] [--clone-dir PATH] [--dest PATH] [--metadata PATH]" >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --commit)
      COMMIT="${2:-}"
      shift 2
      ;;
    --clone-dir)
      CLONE_DIR="${2:-}"
      shift 2
      ;;
    --dest)
      DEST="${2:-}"
      shift 2
      ;;
    --metadata)
      METADATA="${2:-}"
      shift 2
      ;;
    *)
      usage
      ;;
  esac
done

if ! command -v git >/dev/null 2>&1; then
  echo "git is not available." >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is not available." >&2
  exit 1
fi

export GIT_TERMINAL_PROMPT=0

symref_line=$(git ls-remote --symref "$REPO_URL" HEAD | awk '$1 == "ref:" { print $2; exit }')
if [[ "$symref_line" != refs/heads/* ]]; then
  echo "Could not determine the upstream default branch. ls-remote returned: ${symref_line:-<empty>}" >&2
  exit 1
fi
DEFAULT_BRANCH="${symref_line#refs/heads/}"

if [[ -z "$COMMIT" ]]; then
  COMMIT=$(git ls-remote "$REPO_URL" "$symref_line" | awk 'NR == 1 { print $1 }')
fi
if [[ ! "$COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
  echo "Refusing to continue without a 40-character commit SHA. Got: ${COMMIT:-<empty>}" >&2
  exit 1
fi

echo "Default branch: $DEFAULT_BRANCH"
echo "Pinned commit:  $COMMIT"

if [[ ! -d "$CLONE_DIR/.git" ]]; then
  if [[ -e "$CLONE_DIR" ]]; then
    echo "Clone path exists but is not a git repository: $CLONE_DIR" >&2
    exit 1
  fi
  mkdir -p "$(dirname "$CLONE_DIR")"
  git clone --filter=blob:none --no-checkout "$REPO_URL" "$CLONE_DIR"
  git -C "$CLONE_DIR" sparse-checkout init --cone
  git -C "$CLONE_DIR" sparse-checkout set "$SOURCE_PATH"
  git -C "$CLONE_DIR" checkout "$COMMIT"
else
  origin=$(git -C "$CLONE_DIR" remote get-url origin)
  case "$origin" in
    *github.com[:/]SigmaHQ/sigma.git|*github.com[:/]SigmaHQ/sigma)
      ;;
    *)
      echo "Existing clone does not point at SigmaHQ/sigma: $origin" >&2
      exit 1
      ;;
  esac
  current=$(git -C "$CLONE_DIR" rev-parse HEAD)
  if [[ "$current" != "$COMMIT" ]]; then
    git -C "$CLONE_DIR" sparse-checkout init --cone
    git -C "$CLONE_DIR" sparse-checkout set "$SOURCE_PATH"
    git -C "$CLONE_DIR" fetch --filter=blob:none origin "$COMMIT"
    git -C "$CLONE_DIR" checkout "$COMMIT"
  fi
fi

actual=$(git -C "$CLONE_DIR" rev-parse HEAD)
if [[ "$actual" != "$COMMIT" ]]; then
  echo "Checkout did not land on $COMMIT (HEAD is $actual)." >&2
  exit 1
fi
if [[ -n "$(git -C "$CLONE_DIR" status --porcelain)" ]]; then
  echo "Clone worktree is dirty. Refusing to archive it." >&2
  exit 1
fi

WORK=$(mktemp -d)
cleanup() {
  rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$WORK/tree"
git -C "$CLONE_DIR" archive --format=tar "$COMMIT:$SOURCE_PATH" | tar -x -C "$WORK/tree"
git -C "$CLONE_DIR" ls-tree -r --name-only "$COMMIT" -- "$SOURCE_PATH" > "$WORK/files.txt"
git -C "$CLONE_DIR" log -1 --format='%s%n%cI' > "$WORK/commit.txt"

collected_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
git_version=$(git --version)

python3 "$SCRIPT_DIR/stage_sigma_snapshot.py" \
  --source "$WORK/tree" \
  --dest "$DEST" \
  --upstream-list "$WORK/files.txt" \
  --metadata "$METADATA" \
  --project-root "$ROOT" \
  --source-repo "https://github.com/SigmaHQ/sigma" \
  --source-path "$SOURCE_PATH" \
  --source-commit "$COMMIT" \
  --default-branch "$DEFAULT_BRANCH" \
  --commit-file "$WORK/commit.txt" \
  --clone-dir "$CLONE_DIR" \
  --git-version "$git_version" \
  --collected-at-utc "$collected_at"

echo "Collection metadata: $METADATA"
