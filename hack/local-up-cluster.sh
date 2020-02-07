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


CLOUD_PROVIDER_ROOT=$(dirname "${BASH_SOURCE[0]}")/..

export KUBE_ROOT="$GOPATH/src/k8s.io/kubernetes"
export NODE_ROLE_ARN=${NODE_ROLE_ARN:-""}
export CLOUD_PROVIDER=aws
export EXTERNAL_CLOUD_PROVIDER=true
export CLOUD_CONFIG=$(pwd)/cloudconfig
export EXTERNAL_CLOUD_PROVIDER_BINARY="$GOPATH/src/k8s.io/cloud-provider-aws/aws-cloud-controller-manager"
export NODE_ZONE=${AWS_NODE_ZONE:-"us-west-2a"}

# Stop right away if the build fails
set -e

make -C "${CLOUD_PROVIDER_ROOT}"

write_cloudconfig() {
    rm -f $CLOUD_CONFIG
    cat <<EOF >> $CLOUD_CONFIG
[Global]
Zone=$NODE_ZONE
RoleARN="$NODE_ROLE_ARN"
EOF
}

write_cloudconfig

$KUBE_ROOT/hack/local-up-cluster.sh "$@"
