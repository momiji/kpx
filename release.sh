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
git commit -m "docs: update changelog for $tag"

# create tag and push
git tag $tag
git push
git push --tags

# release new version
export GITHUB_TOKEN=$( gh auth token )
goreleaser release --clean
