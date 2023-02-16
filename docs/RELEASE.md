# AWS Cloud Provider Release Process

## Quick Steps to Create a New Release

Notes:
- Each step is covered in greater detail below.
- Your GitHub account must have the required permissions and you must have generated a GitHub token.

In the case that we are backporting a fix to the 1.22 compatible controller:

1. Create the release branch (named release-1.22) if it doesn't exist from the last 1.22 compatible commit (or check it out if it already exists).
2. Cherry-pick the necessary commits onto the release branch.
3. Follow the instructions below to create the release commit.
4. Create a pull request to merge your fork of the release branch into the upstream release branch (i.e. <user>/cloud-provider-aws/release-1.22 -> kubernetes/cloud-provider-aws/release-1.22).
4. Once the image builds in staging, create a PR to promote it to prod.
5. Follow the instructions below to update the deployment files.
6. Cherry pick the release commit to master.

If you just need to create a release for the latest Kubernetes version that the project currently supports, you can skip creating the release branch.  Instead, your steps would be:

1. Edit the `version.txt` file and update the release version.
2. Create the release commit.
3. Create a PR to merge the release commit, and get it reviewed and merged.  This will trigger a github action which will automatically create the release tag.
4. Once the image builds in staging, create a PR to promote it to prod.
5. Create the commit to update helm charts and example config with the new prod image tag.
6. Create the release.

## Choosing the Release Version

We use versioning scheme that looks like semantic versioning but is technically not semantic versioning.  It is designed to be explicit about
which versions of the cloud-provider-repository are compatible with which versions of Kubernetes.

The first two numbers are reserved for the Kubernetes major and minor versions that the release is intended to be compatible with.  For example,
a release called 1.22.x is designed to be compatible with Kubernetes version 1.22.  The patch version is reserved for this project.  Backwards
incompatible changes should only be introduced during Kubernetes minor version changes, except in rare circumstances like when there are security
implications.

For further information, refer to the versioning policy KEP [here](https://github.com/kubernetes/enhancements/tree/master/keps/sig-cloud-provider/1771-versioning-policy-for-external-cloud-providers).

## Creating a Release Branch
You also might need to create a release branch, if it doesn't already exist, if this release requires backporting
changes to an older major or minor version. Note that if it doesn't exist, you'll need someone with write privileges to create it for you.

### Generate the CHANGELOG
We need to generate the CHANGELOG.md for the new release by running `./hack/changelog.py`. Pass the range from the previous release tag to the commit you
are releasing.

```
python3 hack/changelog.py --token $GITHUB_TOKEN --changelog-file docs/CHANGELOG.md --section-title  v1.20.0-alpha.1 --range v1.19.0-alpha.1..
```

For the first value in the commit range, use the previous commit *that is reachable* from the release tag, and for the second value,
use the commit you are releasing.  If this is HEAD, then it can be omitted.  Use two dots as the delimiter "..".

This will prepend the changes to the CHANGELOG.md file.

### Update the README
Search for any references to the previous version on the README, and update them if necessary.  If there's not an entry in the version table yet for the target
Kubernetes version, add one.

## Create the Release Commit
At this point you should have all changes required for the release commit. Verify the changes via `git diff` and create a new PR
with the release commit against the release branch.  Get it reviewed and merged.

## Tag the release

Once the PR is merged, pull the release branch locally and tag the release commit with the release tag. You'll need push privileges for this step.

```
git checkout release-1.22
git pull upstream release-1.22
git tag v1.22.0
git push upstream v1.22.0
```

## Verify the release on GitHub

The new tag should trigger a new Github release. Verify that it has run by going to [Releases](https://github.com/kubernetes/cloud-provider-aws/releases). Then, click on the new version and verify all assets have been created:

- Source code (zip)
- Source code (tar.gz)

### Staging Image

After the release commit is merged and tagged, then a cloud-build image build will trigger.  Once this build
completes, the image will be deployed to [gcr.io/k8s-staging-provider-aws/cloud-controller-manager](https://console.cloud.google.com/gcr/images/k8s-staging-provider-aws/global/cloud-controller-manager?project=k8s-staging-provider-aws).  Verify the build completes and the image is deployed.

### Promoting the Image to Prod

In order to publish the image to prod, create a PR to add its tag and SHA to [images.yaml](https://github.com/kubernetes/k8s.io/blob/main/registry.k8s.io/images/k8s-staging-provider-aws/images.yaml).  Once that merges and completes, you should be able to find the published image [us.gcr.io/provider-aws/cloud-controller-manager](https://console.cloud.google.com/gcr/images/k8s-artifacts-prod/us/provider-aws/cloud-controller-manager).

See [registry.k8s.io](https://github.com/kubernetes/k8s.io/tree/main/registry.k8s.io) for the latest information about managing and publishing images to GCR using k8s infrastructure.

### Update the deployment files

In a new PR to the release branch (or master for releases to the most up to date version), update the following files:

1. Update the app version to the new image tag and increment the chart version:
   - `charts/aws-cloud-controller-manager/Chart.yaml`
   - `charts/aws-cloud-controller-manager/values.yaml`
1. Update the image tag: ` manifests/aws-cloud-controller-manager-daemonset.yaml`

Once this PR is merged, verify the helm chart workflow completes successfully (you should see a new helm release).

## Cherry Pick The Release Commit

Once the images are promoted, send a PR to cherry-pick the release commit to the main branch.  This is to update the Kubernetes version compatibility table and the CHANGELOG.
