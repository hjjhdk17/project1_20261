#!/usr/bin/env bash
set -euo pipefail

DEST="${1:-$HOME/project1-datasets/sigmahq}"
BRANCH_OR_COMMIT="${2:-master}"

if [[ -e "$DEST/.git" ]]; then
  echo "Repository already exists: $DEST"
  echo "Updating refs and checking out: $BRANCH_OR_COMMIT"
  git -C "$DEST" fetch origin
  git -C "$DEST" sparse-checkout init --cone
  git -C "$DEST" sparse-checkout set rules/windows/process_creation
  git -C "$DEST" checkout "$BRANCH_OR_COMMIT"
else
  mkdir -p "$(dirname "$DEST")"
  git clone --filter=blob:none --no-checkout https://github.com/SigmaHQ/sigma.git "$DEST"
  git -C "$DEST" sparse-checkout init --cone
  git -C "$DEST" sparse-checkout set rules/windows/process_creation
  git -C "$DEST" checkout "$BRANCH_OR_COMMIT"
fi

echo
echo "Repository: $DEST"
echo "Commit: $(git -C "$DEST" rev-parse HEAD)"
echo "Tracked YAML files in target directory:"
git -C "$DEST" ls-files 'rules/windows/process_creation/*.yml' 'rules/windows/process_creation/*.yaml' | sort | tee "$DEST/process_creation_files.txt"
echo
echo "Count: $(wc -l < "$DEST/process_creation_files.txt")"
echo "NOTE: master is mutable. Record the commit SHA and use that SHA for reproducible runs."
