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

go mod edit -replace k8s.io/api=../../k8s.io/kubernetes/staging/src/k8s.io/api
go mod edit -replace k8s.io/apimachinery=../../k8s.io/kubernetes/staging/src/k8s.io/apimachinery
go mod edit -replace k8s.io/client-go=../../k8s.io/kubernetes/staging/src/k8s.io/client-go
go mod edit -replace k8s.io/cloud-provider=../../k8s.io/kubernetes/staging/src/k8s.io/cloud-provider
go mod edit -replace k8s.io/code-generator=../../k8s.io/kubernetes/staging/src/k8s.io/code-generator
go mod edit -replace k8s.io/component-base=../../k8s.io/kubernetes/staging/src/k8s.io/component-base
go mod edit -replace k8s.io/controller-manager=../../k8s.io/kubernetes/staging/src/k8s.io/controller-manager
go mod edit -replace k8s.io/csi-translation-lib=../../k8s.io/kubernetes/staging/src/k8s.io/csi-translation-lib
go mod edit -replace k8s.io/apiserver=../../k8s.io/kubernetes/staging/src/k8s.io/apiserver
go mod edit -replace k8s.io/component-helpers=../../k8s.io/kubernetes/staging/src/k8s.io/component-helpers
go mod edit -replace k8s.io/kms=../../k8s.io/kubernetes/staging/src/k8s.io/kms


go mod tidy
go mod vendor
rm -rf vendor/

VERSION=$(git describe --dirty --tags --match='v*')
sed -i "s|cloud-controller-manager:.*$|cloud-controller-manager:$VERSION|" examples/existing-cluster/base/aws-cloud-controller-manager-daemonset.yaml

git status