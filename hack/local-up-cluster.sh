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

info() {
    color='\033[0;35m'; end='\033[0m'
    printf "${color}$@${end}\n"
}

write_cloudconfig() {
    rm -f $CLOUD_CONFIG
    cat <<EOF >> $CLOUD_CONFIG
[Global]
Zone=$NODE_ZONE
RoleARN="$NODE_ROLE_ARN"
EOF
}

CLOUD_PROVIDER_ROOT=${CLOUD_PROVIDER_ROOT:-"$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." &> /dev/null && pwd )"}
KUBE_ROOT=${KUBE_ROOT:-"$GOPATH/src/k8s.io/kubernetes"}
KUBE_VERSION=${KUBE_VERSION:-v1.22.1}

# Configuration for k8s.io/kubernetes/hack/local-up-cluster.sh
NODE_ROLE_ARN=${NODE_ROLE_ARN:-""}
CLOUD_PROVIDER=aws
EXTERNAL_CLOUD_PROVIDER=true
CLOUD_CONFIG=${CLOUD_CONFIG:-${CLOUD_PROVIDER_ROOT}/cloudconfig}
EXTERNAL_CLOUD_PROVIDER_BINARY=${EXTERNAL_CLOUD_PROVIDER_BINARY:-"$GOPATH/src/k8s.io/cloud-provider-aws/aws-cloud-controller-manager"}
NODE_ZONE=${AWS_NODE_ZONE:-"us-west-2a"}
NET_PLUGIN="${NET_PLUGIN:-kubenet}"
CLOUD_CTLRMGR_FLAGS=${CLOUD_CTLRMGR_FLAGS:-"--controllers=*"}

info "\n + + Testing on a local cluster + +\n"
info "Printing configuration:"
info "CLOUD_PROVIDER_ROOT=$CLOUD_PROVIDER_ROOT"
info "KUBE_ROOT=$KUBE_ROOT"
info "KUBE_VERSION=$KUBE_VERSION"
info "NODE_ROLE_ARN=$NODE_ROLE_ARN"
info "CLOUD_PROVIDER=$CLOUD_PROVIDER"
info "EXTERNAL_CLOUD_PROVIDER=$EXTERNAL_CLOUD_PROVIDER"
info "CLOUD_CONFIG=$CLOUD_CONFIG"
info "EXTERNAL_CLOUD_PROVIDER_BINARY=$EXTERNAL_CLOUD_PROVIDER_BINARY"
info "NODE_ZONE=$NODE_ZONE"
info "NET_PLUGIN=$NET_PLUGIN"
info "CLOUD_CTLRMGR_FLAGS=$CLOUD_CTLRMGR_FLAGS\n"

read -p "Do you wish to continue? (y/N)?" answer
case ${answer:0:1} in
    y|Y )
    ;;
    * )
        echo "Quitting.."
        exit 0
    ;;
esac

export NODE_ROLE_ARN
export CLOUD_PROVIDER
export EXTERNAL_CLOUD_PROVIDER
export CLOUD_CONFIG
export EXTERNAL_CLOUD_PROVIDER_BINARY
export NODE_ZONE
export NET_PLUGIN
export CLOUD_CTLRMGR_FLAGS
(
    cd ${KUBE_ROOT}
    git checkout ${KUBE_VERSION}
    make clean
)
make -C "${CLOUD_PROVIDER_ROOT}"
write_cloudconfig
$KUBE_ROOT/hack/local-up-cluster.sh "$@"
