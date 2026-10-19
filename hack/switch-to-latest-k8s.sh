#!/bin/bash

set -xeuo pipefail

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
KUBE_ROOT=${SCRIPTDIR}/../../../k8s.io/kubernetes/

# shellcheck disable=SC2164
pushd "${KUBE_ROOT}" >/dev/null
git reset --hard HEAD && git clean -xdff
git fetch --all
git checkout master
# shellcheck disable=SC2164
popd >/dev/null

git reset --hard HEAD && git clean -xdff

export GOPROXY=direct
export GOSUMDB=off

# Replace every k8s.io staging module with the local kubernetes checkout.
# Looping over the staging directory keeps the list in sync when kubernetes
# adds a module (k8s.io/streaming and k8s.io/ktesting both broke a fixed list).
for gomod in "${KUBE_ROOT}"/staging/src/k8s.io/*/go.mod; do
  module=$(basename "$(dirname "${gomod}")")
  go mod edit -replace "k8s.io/${module}=../../k8s.io/kubernetes/staging/src/k8s.io/${module}"
done

go mod tidy
go mod vendor
rm -rf vendor/

VERSION=$(git describe --dirty --tags --match='v*')
sed -i "s|cloud-controller-manager:.*$|cloud-controller-manager:$VERSION|" examples/existing-cluster/base/aws-cloud-controller-manager-daemonset.yaml

git status