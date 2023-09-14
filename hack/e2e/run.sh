#!/bin/bash

# Copyright 2019 The Kubernetes Authors.
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
set -o pipefail
set -o nounset

function test_run_id() {
    date '+%Y%m%d%H%M%S'
}

test_run_id="$(test_run_id)"
repo_root="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )/../.." &> /dev/null && pwd )"
output="${repo_root}/_output"
test_output_root="${output}/test"
test_run="${test_output_root}/${test_run_id}"

# Set in Makefile
BUILD_VERSION="${BUILD_VERSION:-}"
BUILD_IMAGE="${BUILD_IMAGE:-}"

if [[ -z "${BUILD_VERSION}" || -z "${BUILD_IMAGE}" ]]; then
    echo "$0: Execute with 'make test-e2e'"
    exit 1
fi

# Configurable
KUBECONFIG="${KUBECONFIG:-${HOME}/.kube/config}"
SSH_PUBLIC_KEY_PATH="${SSH_PUBLIC_KEY_PATH:-}"

# If UP==yes, provision a cluster as part of testing
# Otherwise, rely on KUBECONFIG to determine test cluster.
UP="${UP:-yes}"
# if DOWN==yes, delete cluster after test
DOWN="${DOWN:-yes}"

KUBERNETES_VERSION="${KUBERNETES_VERSION:-$(curl -L -s https://dl.k8s.io/release/stable.txt)}"
CLUSTER_NAME="${CLUSTER_NAME:-test-cluster-${test_run_id}.k8s}"
KOPS_STATE_STORE="${KOPS_STATE_STORE:-}"
REGION="${AWS_REGION:-us-west-2}"
ZONES="${AWS_AVAILABILITY_ZONES:-us-west-2a,us-west-2b,us-west-2c}"
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
IMAGE_NAME=${IMAGE_NAME:-${AWS_ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/provider-aws/cloud-controller-manager}
IMAGE_TAG=${IMAGE_TAG:-${BUILD_VERSION}-${test_run_id}}

# Test args
GINKGO_FOCUS=${GINKGO_FOCUS:-"\[cloud-provider-aws-e2e\]"}
GINKGO_SKIP=${GINKGO_SKIP:-"\[Disruptive\]"}
GINKGO_NODES=${GINKGO_NODES:-4}

EXPANDED_TEST_EXTRA_FLAGS="${EXPANDED_TEST_EXTRA_FLAGS:-}"

mkdir -p "${test_run}"

if [[ -z "${KOPS_STATE_STORE}" ]]; then
    echo "KOPS_STATE_STORE must be set"
    exit 1
fi

if [[ ! -f "${repo_root}/e2e.test" ]]; then
    echo "Missing e2e.test binary"
    exit 1
fi

yes_or_no="^(yes|no)$"

if [[ ! "${UP}" =~ $yes_or_no ]]; then
    echo "Invalid UP: ${UP} (valid: [yes|no])"
    exit 1
fi

if [[ ! "${DOWN}" =~ $yes_or_no ]]; then
    echo "Invalid DOWN: ${DOWN} (valid: [yes|no])"
    exit 1
fi

if [[ -z "${INSTALL_PATH}" ]]; then
    echo "INSTALL_PATH must be set"
    exit 1
fi

export PATH="${INSTALL_PATH}:${PATH}"

echo "Starting test run ---"
echo " + Region:              ${REGION} (${ZONES})"
echo " + Cluster name:        ${CLUSTER_NAME}"
echo " + Kubernetes version:  ${KUBERNETES_VERSION}"
echo " + Focus:               ${GINKGO_FOCUS}"
echo " + Skip:                ${GINKGO_SKIP}"
echo " + kOps state store:    ${KOPS_STATE_STORE}"
echo " + SSH public key path: ${SSH_PUBLIC_KEY_PATH}"
echo " + Test run ID:         ${test_run_id}"
echo " + Kubetest run dir:    ${test_run}"
echo " + Image:               ${IMAGE_NAME}:${IMAGE_TAG}"
echo " + Create cluster:      ${UP}"
echo " + Delete cluster:      ${DOWN}"

export KOPS_STATE_STORE
# kubetest2 sets RunDir as filepath.Join(artifacts.BaseDir(), o.RunID())
export ARTIFACTS="${ARTIFACTS:-$test_output_root}"
export KUBETEST2_RUN_DIR="${test_run}"

echo "Installing e2e.test to ${test_run}"
cp "${repo_root}/e2e.test" "${test_run}"

echo "Building and pushing test driver image to ${IMAGE_NAME}:${IMAGE_TAG}"
aws ecr get-login-password --region "${REGION}" | docker login --username AWS --password-stdin "${AWS_ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"
docker tag "${BUILD_IMAGE}" "${IMAGE_NAME}:${IMAGE_TAG}"
docker push "${IMAGE_NAME}:${IMAGE_TAG}"

if [[ "${UP}" = "yes" ]]; then
    kubetest2 kops \
      -v 2 \
      --up \
      --run-id="${test_run_id}" \
      --cloud-provider=aws \
      --cluster-name="${CLUSTER_NAME}" \
      --create-args="--dns=none --zones=${ZONES} --node-size=m5.large --master-size=m5.large --override=cluster.spec.cloudControllerManager.cloudProvider=aws --override=cluster.spec.cloudControllerManager.image=${IMAGE_NAME}:${IMAGE_TAG}" \
      --admin-access="0.0.0.0/0" \
      --kubernetes-version="${KUBERNETES_VERSION}" \
      --kops-version-marker=https://storage.googleapis.com/kops-ci/bin/latest-ci-updown-green.txt \

      # Use the kops tester once we have a way of consuming an arbitrary e2e.test binary.
      #--test=kops \
      #-- \
      #--use-built-binaries=true \
      #--focus-regex="${GINKGO_FOCUS}" \
      #--parallel 25
fi

set -x
pushd ./tests/e2e
ginkgo . -v -p --nodes="${GINKGO_NODES}" --focus="${GINKGO_FOCUS}" --skip="${GINKGO_SKIP}" --report-dir="${ARTIFACTS}"
popd

if [[ "${DOWN}" = "yes" ]]; then
    # This should be changed to ${test_run}/kops once https://github.com/kubernetes/kops/pull/13217 is merged.
    ${test_run}/${test_run_id}/kops delete cluster --name "${CLUSTER_NAME}" --yes
fi
