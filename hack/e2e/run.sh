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
    echo "$(date '+%Y%m%d%H%M%S')"
}

test_run_id="$(test_run_id)"
repo_root="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )/../.." &> /dev/null && pwd )"
output="${repo_root}/_output"
test_output_root="${output}/test"
test_run="${test_output_root}/${test_run_id}"

# Set in Makefile
MAKE_VERSION="${MAKE_VERSION:-}"
MAKE_IMAGE="${MAKE_IMAGE:-}"

if [[ -z "${MAKE_VERSION}" || -z "${MAKE_IMAGE}" ]]; then
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

KUBERNETES_VERSION="${KUBERNETES_VERSION:-v1.23.2}"
GINKGO_VERSION="v1.14.0"
CLUSTER_NAME="test-cluster-${test_run_id}.k8s.local"
KOPS_STATE_STORE="${KOPS_STATE_STORE:-}"
REGION="${AWS_REGION:-us-west-2}"
ZONES="${AWS_AVAILABILITY_ZONES:-us-west-2a,us-west-2b,us-west-2c}"
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
IMAGE_NAME=${IMAGE_NAME:-${AWS_ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/amazon/cloud-controller-manager}
# $VERSION is set in Makefile
IMAGE_TAG=${IMAGE_TAG:-${MAKE_VERSION}-${test_run_id}}

# Test args
GINKGO_FOCUS=${GINKGO_FOCUS:-"\[cloud-provider-aws-e2e\]"}
GINKGO_SKIP=${GINKGO_SKIP:-"\[Disruptive\]"}
GINKGO_NODES=${GINKGO_NODES:-4}

EXPANDED_TEST_EXTRA_FLAGS="${EXPANDED_TEST_EXTRA_FLAGS:-}"

if [[ -z "${KOPS_STATE_STORE}" ]]; then
    echo "KOPS_STATE_STORE must be set"
    exit 1
fi

if [[ ! -f "${repo_root}/e2e.test" ]]; then
    echo "Missing e2e.test binary"
    exit 1
fi

if [[ -z "${SSH_PUBLIC_KEY_PATH}" ]]; then
    ssh_key_path=${test_run}/sshkey
    ssh-keygen -b 2048 -t rsa -f ${ssh_key_path} -q -N ""
    SSH_PUBLIC_KEY_PATH=${ssh_key_path}.pub
fi

yes_or_no="^(yes|no)$"

if [[ "${UP}" =~ $yes_or_no ]]; then
    echo "Creating cluster: ${UP}"
else
    echo "Invalid UP: ${UP} (valid: [yes|no])"
    exit 1
fi

if [[ "${DOWN}" =~ $yes_or_no ]]; then
    echo "Deleting cluster: ${DOWN}"
else
    echo "Invalid DOWN: ${DOWN} (valid: [yes|no])"
    exit 1
fi

echo "Starting test run ---"
echo " + Region:              ${REGION} (${ZONES})"
echo " + Cluster name:        ${CLUSTER_NAME}"
echo " + Kubernetes version:  ${KUBERNETES_VERSION}"
echo " + Focus:               ${GINKGO_FOCUS}"
echo " + Skip:                ${GINKGO_SKIP}"
echo " + Kops state store:    ${KOPS_STATE_STORE}"
echo " + SSH public key path: ${SSH_PUBLIC_KEY_PATH}"
echo " + Test run ID:         ${test_run_id}"
echo " + Kubetest run dir:    ${test_run}"
echo " + Image:               ${IMAGE_NAME}:${IMAGE_TAG}"
echo " + Up:                  ${UP}"
echo " + Down:                ${DOWN}"

mkdir -p "${test_run}"

export KOPS_STATE_STORE
# kubetest2 sets RunDir as filepath.Join(artifacts.BaseDir(), o.RunID())
export ARTIFACTS="${test_output_root}"
export KUBETEST2_RUN_DIR="${test_run}"
export PATH="${PATH}"

echo "Installing e2e.test to ${test_run}"
cp "${repo_root}/e2e.test" "${test_run}"

echo "Installing ginkgo to ${test_run}"
GINKGO_BIN="${test_run}/ginkgo"
if [[ ! -f ${GINKGO_BIN} ]]; then
  GOBIN=${test_run} go install "github.com/onsi/ginkgo/ginkgo@${GINKGO_VERSION}"
fi

echo "Building and pushing test driver image to ${IMAGE_NAME}:${IMAGE_TAG}"
aws ecr get-login-password --region "${REGION}" | docker login --username AWS --password-stdin "${AWS_ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"
docker tag "${MAKE_IMAGE}" "${IMAGE_NAME}:${IMAGE_TAG}"
docker push "${IMAGE_NAME}:${IMAGE_TAG}"

if [[ "${UP}" = "yes" ]]; then
    kubetest2 kops \
      -v 2 \
      --up \
      --run-id="${test_run_id}" \
      --cloud-provider=aws \
      --cluster-name="${CLUSTER_NAME}" \
      --create-args="--zones=${ZONES} --node-size=m5.large --master-size=m5.large --override=cluster.spec.kubeAPIServer.cloudProvider=external --override=cluster.spec.kubeControllerManager.cloudProvider=external --override=cluster.spec.kubelet.cloudProvider=external --override=cluster.spec.cloudControllerManager.cloudProvider=aws --override=cluster.spec.cloudControllerManager.image=${IMAGE_NAME}:${IMAGE_TAG} --override=spec.cloudConfig.awsEBSCSIDriver.enabled=true" \
      --admin-access="0.0.0.0/0" \
      --kubernetes-version="${KUBERNETES_VERSION}" \
      --ssh-public-key="${SSH_PUBLIC_KEY_PATH}" \
      --kops-version-marker=https://storage.googleapis.com/kops-ci/bin/latest-ci-updown-green.txt \

      # Use the kops tester once we have a way of consuming an arbitrary e2e.test binary.
      #--test=kops \
      #-- \
      #--use-built-binaries=true \
      #--focus-regex="${GINKGO_FOCUS}" \
      #--parallel 25
fi

pushd ./tests/e2e
${GINKGO_BIN} . -p -nodes="${GINKGO_NODES}" -v --focus="${GINKGO_FOCUS}" --skip="${GINKGO_SKIP}" "" -- -kubeconfig="${KUBECONFIG}" -report-dir="${test_run}" -gce-zone="${ZONES%,*}" "${EXPANDED_TEST_EXTRA_FLAGS}"
popd

if [[ "${DOWN}" = "yes" ]]; then
    kops delete cluster --name "${CLUSTER_NAME}" --yes
fi
