#!/bin/bash

set -o errexit
set -o pipefail
set -o nounset

UPSTREAM_SHA="${UPSTREAM_SHA:-}"
REWRITE_PATH="${REWRITE_PATH:-pkg/providers/v1}"
LEGACY_PROVIDER_PATH="${LEGACY_PROVIDER_PATH:-staging/src/k8s.io/legacy-cloud-providers/aws}"
KUBERNETES_DIR="${KUBERNETES_DIR:-$HOME/go/src/k8s.io/kubernetes}"
CLOUD_PROVIDER_AWS_DIR="${CLOUD_PROVIDER_AWS_DIR:-$HOME/go/src/k8s.io/cloud-provider-aws}"

function echo_color() {
    printf  "\e[1;31m${@}\e[0m\n"
}

if [[ ! -n ${UPSTREAM_SHA} ]]; then
    echo "UPSTREAM_SHA must be set with the commit SHA that should be cherry-picked from k8s.io/kubernetes."
    exit 1
fi

pushd "${CLOUD_PROVIDER_AWS_DIR}" > /dev/null
echo "Entering ${CLOUD_PROVIDER_AWS_DIR}"

if [[ -n "$(git status --porcelain)" ]]; then
    echo "`pwd` is dirty - stash or commit changes and checkout a clean copy of upstream master."
    exit 1
fi

echo "Creating patch from kubernetes/kubernetes@${UPSTREAM_SHA}..."
pushd "${KUBERNETES_DIR}" > /dev/null
echo "Entering ${KUBERNETES_DIR}"

target_commit=$(git log -n 1 "${UPSTREAM_SHA}")
printf "\nFound target commit:\n-----------------------------------------------\n${target_commit}\n-----------------------------------------------\n\n"

commit_author=$(git log -1 --pretty=format:'%an <%ae>' ${UPSTREAM_SHA})
commit_body=$(git log -1 --pretty=format:'%B' ${UPSTREAM_SHA})

patch_file=$(mktemp)
git diff "${UPSTREAM_SHA}^" "${UPSTREAM_SHA}" -- ${LEGACY_PROVIDER_PATH} > ${patch_file}
echo "Saving diff to ${patch_file}"
popd > /dev/null

echo "Modifying paths in patch..."
sed -i "s|staging/src/k8s.io/legacy-cloud-providers/aws|pkg/providers/v1|g" "${patch_file}"

printf "Applying patch file...\n\n"
cat ${patch_file} | git apply -

status=$(git status)
printf "Status of ${CLOUD_PROVIDER_AWS_DIR}:\n-----------------------------------------------\n${status}\n-----------------------------------------------\n\n"

echo_color "\nTo finish the cherry-pick:\n"
echo_color "git add -A"
echo_color "git commit --author ${commit_author} --message=\"$commit_body\"\n"

popd > /dev/null
