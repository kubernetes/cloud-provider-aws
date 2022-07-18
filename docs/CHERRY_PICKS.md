# AWS Cloud Provider Cherry Pick Process

## Cherry picking a commit

If you merge a pull request to the main branch, there is a chance you will want to cherry pick that change to other branches so that the change is present in all supported versions.  When should you cherry pick a commit?

Reasons NOT to cherry pick a commit to supported release branches:
- In most cases, when the commit is a new feature.
- The commit is documentation.

Reasons to cherry pick a commit to previous versions:
- It is a bug fix.
- A feature may only be cherry-picked if it is backwards compatible.

## How to Cherry Pick

First, ensure you have a git remote called `upstream` that points at `github.com/kubernetes/cloud-provider-aws`, and also a git remote called `origin` which points at your fork.

Set environment variables referring to your github user (where the fork is location):
```
export GITHUB_USER=<youruser>
export GITHUB_TOKEN=<yourtoken> # optional, avoids prompt for password
```

Run the cherry pick script:
```
./hack/cherry_pick_pull.sh upstream/release-1.23 98765
```

Rerun for all branches you intend to cherry pick to.
