# AWS cloud-controller-manager Helm Chart

Installs the [aws cloud-controller-manager](https://github.com/kubernetes/cloud-provider-aws).

## Get Repo Info

```console
helm repo add aws-cloud-controller-manager https://kubernetes.github.io/cloud-provider-aws
helm repo update
```

_See [helm repo](https://helm.sh/docs/helm/helm_repo/) for command documentation._

## Install Chart

```console
# Helm 3
$ helm upgrade --install aws-cloud-controller-manager aws-cloud-controller-manager/aws-cloud-controller-manager

```

_See [configuration](#configuration) below._

_See [helm install](https://helm.sh/docs/helm/helm_install/) for command documentation._

## Uninstall Chart

```console
# Helm 3
$ helm uninstall [RELEASE_NAME]

```

This removes all the Kubernetes components associated with the chart and deletes the release.

_See [helm uninstall](https://helm.sh/docs/helm/helm_uninstall/) for command documentation._

## Upgrading Chart

```console
# Helm 3 or 2
$ helm upgrade [RELEASE_NAME] cloud-provider-aws/charts/aws-cloud-controller-manager  [flags]
```

_See [helm upgrade](https://helm.sh/docs/helm/helm_upgrade/) for command documentation._

Starting with chart version 0.0.12, controller service-account credentials are
managed by a Role in `kube-system`. Remove any `serviceaccounts/token` creation
rule from custom `clusterRoleRules` before upgrading. The chart rejects these
rules, including wildcard rules that grant the same permission.

When upgrading from an earlier version with `--reuse-values`, Helm also reuses
the old default rules. Instead, use `--reset-values` and supply your desired
overrides explicitly, after removing the obsolete token rule:

```console
helm upgrade [RELEASE_NAME] aws-cloud-controller-manager/aws-cloud-controller-manager \
  --reset-values -f my-values.yaml
```

Review the rendered changes with `helm template` before applying them, especially
when migrating custom values.

## Configuration

The chart supports `--use-service-account-credentials=true` through `args`.
The controller credential Role permits service-account lookup and token creation
for `node-controller`, `service-controller`, `route-controller`,
`aws-cloud-provider`, and `tagging-controller` in `kube-system`, matching the
controller manager's credential builder. The Role is included regardless of the
flag so existing `args` overrides continue to work.

The `namespace` value controls the controller manager's workload and service
account location. Its credential Role and RoleBinding remain in `kube-system`,
where the credential builder manages the individual controller accounts. The
binding uses `serviceAccountName` and `namespace` to select the controller
manager's service account.
