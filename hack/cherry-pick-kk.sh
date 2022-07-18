#!/bin/bash

set -o errexit
set -o pipefail
set -o nounset

# This script will attempt to cherry pick a commit from the legacy in-tree provider, and
# rewrite the paths to make it compatible with this repository.

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
git diff -U10 "${UPSTREAM_SHA}^" "${UPSTREAM_SHA}" -- ${LEGACY_PROVIDER_PATH} > ${patch_file}
echo "Saving diff to ${patch_file}"
popd > /dev/null

printf "Applying patch file...\n\n"
cat ${patch_file} | git apply --3way --ignore-whitespace --directory="${REWRITE_PATH}" -p6 - || true

status=$(git status)
printf "Status of ${CLOUD_PROVIDER_AWS_DIR}:\n-----------------------------------------------\n${status}\n-----------------------------------------------\n\n"

echo_color "\nThis should have resulted in a 3-way merge of the patch.  This means if there were conflicts, you can (and must) fix them by editing the conflicting files."
echo_color "To cancel the merge, try:"
echo "git reset --merge"

echo_color "\nTo finish applying the patch (after fixing any conflicts):"
echo "git add -A"
echo "git commit --author \"${commit_author}\" --message=\"$commit_body\""


popd > /dev/null
