# AWS Cloud Provider Release Process

NOTE: Your GitHub account must have the required permissions and you must have generated a GitHub token.

## Choosing the release version

Using semantic versioning, pick a release number that makes sense by bumping the major, minor or patch release version.  If its a major or minor release (backwards incompatible changes, and new features, respectively) then you will want to start this process with an alpha release first.  Here are some examples:

Bumping a minor version after releasing a new feature:
```
v1.4.5 -> v1.5.0-alpha.0
```

After testing and allowing some time for feedback on the alpha, releasing v1.5.0:
```
v1.4.5 -> v1.5.0
```

New patch release:
```
v1.5.3 -> v1.5.4
```

New major version release with two alpha releases:
```
v1.6.2 -> v2.0.0-alpha.0
       -> v2.0.0-alpha.1
       -> v2.0.0
```

## Choosing the release branch
You also might need to create a release branch, if it doesn't already exist, if this release requires backporting changes to an older major or minor version.  For example, in the case that we are backporting a fix to the v0.5 release branch, and we have a v0.6 release branch (which we don't at the time of writing), then we would do the following:

1. Create the release branch (named release-0.5) if it doesn't exist from the last v0.5.x tagged release (or check it out if it already exists).
2. Cherry-pick the necessary commits onto the release branch.
3. Follow the instructions below to create the release commit.
4. Create a pull request to merge your fork of the release branch into the upstream release branch (i.e. <user>/cloud-provider-aws/release-0.5 -> kubernetes/cloud-provider-aws/release-0.5).

## Create the release commit

### Generate the CHANGELOG
We need to generate the CHANGELOG for the new release by running `./hack/changelog.py`. You need to pass previous release tag to generate the changelog.

```
python3 hack/changelog.py --token $GITHUB_TOKEN --changelog-file docs/CHANGELOG.md --section-title  v1.20.0-alpha.1 --range v1.19.0-alpha.1..
```
This will prepend the changes to the CHANGELOG.md file.

### Update the README
Search for any references to the previous version on the README, and update them if necessary. You'll need to update the compatibility table the least.

### Update the deployment files
1. Update Helm values
   - `charts/aws-cloud-controller-manager/Chart.yaml`
   - `charts/aws-cloud-controller-manager/values.yaml`
1. Update ` manifests/aws-cloud-controller-manager-daemonset.yaml`

### Send a release PR
At this point you should have all changes required for the release commit. Verify the changes via `git diff` and send a new PR with the release commit against the release branch. Note that if it doesn't exist, you'll need someone with write privileges to create it for you.

## Tag the release

Once the PR is merged, pull the release branch locally and tag the release commit with the release tag. You'll need push privileges for this step.

```
git checkout release-0.7
git pull upstream release-0.7
git tag v0.7.0
git push upstream v0.7.0
```

## Verify the release on GitHub

The new tag should trigger a new Github release. Verify that it has run by going to [Releases](https://github.com/kubernetes/cloud-provider-aws/releases). Then, click on the new version and verify all assets have been created:

- Source code (zip)
- Source code (tar.gz)

## Merge the release commit to the main branch

Once the images are promoted, send a PR to merge the release commit to the main branch.
