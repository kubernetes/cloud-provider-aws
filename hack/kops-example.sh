#!/usr/bin/env bash

# Copyright 2014 The Kubernetes Authors.
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

function cleanup() {
    popd
}
trap cleanup EXIT

# The cluster name is hardcoded in the kops kustomization yaml
CLUSTER_NAME=aws-external-cloud-provider-example.k8s.local
REPO_ROOT="$(cd "$( dirname "${BASH_SOURCE[0]}" )"/.. &> /dev/null && pwd)"
OUTPUT="${OUTPUT:-${REPO_ROOT}}/kops-example"
pushd ${REPO_ROOT}
OS_ARCH=$(go env GOOS)-$(go env GOARCH)

function validate() {
    if [[ -z "${KOPS_STATE_STORE:-}" ]]; then
        echo "KOPS_STATE_STORE is empty or unset.  You can use an S3 bucket that you own, for example:"
        echo "export KOPS_STATE_STORE=s3://<your-state-store-bucket>"
        exit 1
    else
        echo "Using KOPS_STATE_STORE=${KOPS_STATE_STORE}"
    fi
}

function install_kustomize() {
    if [[ -z "$(command -v kustomize)" ]]; then
        local temp_kustomize="/tmp/kustomize"
        if [[ ! -f "${temp_kustomize}" ]]; then
            echo "Downloading kustomize to ${temp_kustomize}"
            curl -s "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh"  | bash
            mv kustomize "${temp_kustomize}"
        else
            echo "Using kustomize found at ${temp_kustomize}"
        fi
        KUSTOMIZE="${temp_kustomize}"
    else
        KUSTOMIZE="$(which kustomize)"
        echo "Using ${KUSTOMIZE}"
    fi
}

function install_kops() {
    if [[ -z "$(command -v kops)" ]]; then
        local temp_kops="/tmp/kops"
        if [[ ! -f "${temp_kops}" ]]; then
            echo "Downloading kops to ${temp_kops}"
            local latest_kops_version=$(curl -s https://api.github.com/repos/kubernetes/kops/releases/latest | grep tag_name | cut -d '"' -f 4)
            curl -Lo kops https://github.com/kubernetes/kops/releases/download/${latest_kops_version}/kops-${OS_ARCH}
            chmod +x ./kops
            mv ./kops "${temp_kops}"
        else
            echo "Using kops found at ${temp_kops}"
        fi
        KOPS=${temp_kops}
    else
        KOPS="$(which kops)"
        echo "Using ${KOPS}"
    fi
}

install_kustomize
install_kops
validate

echo "Generating cluster configuration at ${OUTPUT}/cluster.yaml"
mkdir -p ${OUTPUT}
cluster_yaml="${OUTPUT}/cluster.yaml"

${KUSTOMIZE} build ${REPO_ROOT}/examples/kops-new-cluster/overlays/cloud-controller-manager > ${cluster_yaml}
${KOPS} create -f ${cluster_yaml}
${KOPS} update cluster ${CLUSTER_NAME} --yes --admin

echo "In order to clean up the cluster, run the following:"
echo "  ${KOPS} delete cluster ${CLUSTER_NAME} --yes"
