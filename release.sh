#!/bin/bash
set -Eeuo pipefail
cd "$(dirname "$0")"

tag=$1

# build to ensure all is fine
goreleaser build --clean

# generate new changelog
chglog add --version $tag
chglog format --template-file .chglog.template > CHANGELOG.md
git add changelog.yml CHANGELOG.md
git commit -m "docs: update changelog"

# release new version
goreleaser release --clean --skip-publish --skip-validate
