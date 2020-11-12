#!/bin/bash

set -euo pipefail

VERSION=${1#"v"}
if [ -z "$VERSION" ]; then
    echo "Must specify version!"
    exit 1
fi

MODS=($(
    curl -sS https://raw.githubusercontent.com/kubernetes/kubernetes/v${VERSION}/go.mod |
    sed -n 's|.*k8s.io/\(.*\) => ./staging/src/k8s.io/.*|k8s.io/\1|p'
))

for MOD in "${MODS[@]}"; do
    go mod edit "-replace=${MOD}=${MOD}@v0${VERSION:1}"
done

go get "k8s.io/kubernetes@v${VERSION}"

go mod tidy
