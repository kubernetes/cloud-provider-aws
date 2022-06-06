#!/usr/bin/env bash

# Copyright 2020 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit
set -o nounset
set -o pipefail

GINKGO_VERSION="${GINKGO_VERSION:-v1.14.0}"
KOPS_ROOT="${KOPS_ROOT:-}"
export GO111MODULE=on

if [[ -n ${INSTALL_PATH} ]]; then
    export GOBIN="${INSTALL_PATH}"
fi

cd "$(mktemp -d)" > /dev/null

echo " + Installing kubetest2"
go install "sigs.k8s.io/kubetest2@latest"

echo " + Installing ginkgo"
go install "github.com/onsi/ginkgo/ginkgo@${GINKGO_VERSION}"

if [[ -z "${KOPS_ROOT}" ]]; then
    git clone https://github.com/kubernetes/kops.git
    KOPS_ROOT="$(pwd)/kops"
fi

cd "${KOPS_ROOT}" > /dev/null

make test-e2e-install
