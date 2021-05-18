# Getting Started

Before you start, make sure you go through the [prerequisites](prerequisites.md).

In order to launch a cluster running the aws-cloud-controller-manager, you can run the appropriate container image release from this repository on an existing cluster, or you can use a deployment tool that has support for deploying it, like kops.

## Running on an Existing Cluster

Follow these steps when upgrading an existing cluster by launching the aws-cloud-controller-manager as a pod:

1. Temporarily stop the kube-controller-managers from running.
1. Add the `--cloud-provider=external` to the kube-controller-manager config.
1. Add the `--cloud-provider=external` to the kube-apiserver config.
1. Add the `--cloud-provider=external` to each the kubelet's config.
1. Add the tag kubernetes.io/cluster/your_cluster_id=owned (if resources are owned and managed by the cluster) or kubernetes.io/cluster/your_cluster_id=shared (if resources are shared between clusters, and should not be destroyed if the cluster is destroyed) to your instances.
1. Apply the kustomize configuration:
   `kubectl apply -k 'github.com/kubernetes/cloud-provider-aws/manifests/base/?ref=master'`

### Flags

| flag | component | description |
|------|-----------|-------------|
| `--cloud-provider=external` | kube-apiserver | Disables the cloud provider in the API Server. |
| `--cloud-provider=external` | kube-controller-manager | Disables the cloud provider in the Kube Controller Manager. |
| `--cloud-provider=external` | kubelet | Disables the cloud provider in the Kubelet. |
| <code>--cloud-provider=[aws&#124;aws/v2]</code> | aws-cloud-controller-manager | Optional.  Selects the legacy cloud-provider or the v2 cloud-provider in the aws-cloud-controller-manager. WARNING: the v2 cloud-provider is in a pre-alpha state. |
| `--external-cloud-volume-plugin=aws` | kube-controller-manager | Tells the Kube Controller Manager to run the volume loops that have cloud provider code in them.  This is required for volumes to work if you are not using CSI with migration enabled. |

## Using Kops

In order to create a cluster using kops, the following flags should be set in your cluster.yaml in order to pass the correct flags to the control plane components.

```
apiVersion: kops.k8s.io/v1alpha2
kind: Cluster
metadata:
  name: cloud-controller-example
spec:
  cloudControllerManager:
    cloudProvider: aws
  kubeControllerManager:
    externalCloudVolumePlugin: aws
  cloudProvider: aws
  kubeAPIServer:
    cloudProvider: external
  kubelet:
    cloudProvider: aws
```

Note: the above config omits all config not related to the aws-cloud-controller-manager Check `examples/kops` for a full kops configuration. (TODO)
