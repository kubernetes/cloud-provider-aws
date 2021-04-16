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

set -euo pipefail

BASE_DIR=$(dirname "$(realpath "${BASH_SOURCE[0]}")")

TEST_ID=${TEST_ID:-$RANDOM}
CLUSTER_NAME=test-cluster-${TEST_ID}.k8s.local

TEST_DIR=${BASE_DIR}/cloud-provider-test-artifacts
BIN_DIR=${TEST_DIR}/bin
SSH_KEY_PATH=${TEST_DIR}/id_rsa

REGION=${AWS_REGION:-us-west-2}
ZONES=${AWS_AVAILABILITY_ZONES:-us-west-2a,us-west-2b,us-west-2c}

AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

TEST_PATH=${TEST_PATH:-"./tests/e2e/..."}
KUBECONFIG=${KUBECONFIG:-"${HOME}/.kube/config"}
ARTIFACTS=${ARTIFACTS:-"${TEST_DIR}/artifacts"}
GINKGO_FOCUS=${GINKGO_FOCUS:-"\[cloud-provider-aws-e2e\]"}
GINKGO_SKIP=${GINKGO_SKIP:-"\[Disruptive\]"}
GINKGO_NODES=${GINKGO_NODES:-4}
TEST_EXTRA_FLAGS=${TEST_EXTRA_FLAGS:-}

CLEAN=${CLEAN:-"true"}

echo "Testing in region ${REGION} and zones ${ZONES}"
mkdir -p "${BIN_DIR}"
export PATH=${PATH}:${BIN_DIR}

echo "Installing ginkgo to ${BIN_DIR}"
GINKGO_BIN=${BIN_DIR}/ginkgo
if [[ ! -e ${GINKGO_BIN} ]]; then
  pushd /tmp
  GOPATH=${TEST_DIR} GOBIN=${BIN_DIR} GO111MODULE=on go get github.com/onsi/ginkgo/ginkgo@v1.12.0
  popd
fi

echo "Testing focus ${GINKGO_FOCUS}"
eval "EXPANDED_TEST_EXTRA_FLAGS=$TEST_EXTRA_FLAGS"
set -x
set +e
${GINKGO_BIN} -p -nodes="${GINKGO_NODES}" -v --focus="${GINKGO_FOCUS}" --skip="${GINKGO_SKIP}" "${TEST_PATH}" -- -kubeconfig="${KUBECONFIG}" -report-dir="${ARTIFACTS}" -gce-zone="${ZONES%,*}" "${EXPANDED_TEST_EXTRA_FLAGS}"
TEST_PASSED=$?
set -e
set +x
echo "TEST_PASSED: ${TEST_PASSED}"

if [[ $TEST_PASSED -ne 0 ]]; then
  echo "FAIL!"
  exit 1
else
  echo "SUCCESS!"
fi
