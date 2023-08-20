# Getting Started with the External Cloud Controller Manager

Before you start, make sure you go through the [prerequisites](prerequisites.md).

In order to launch a cluster running the aws-cloud-controller-manager, you can
run the appropriate container image release from this repository on an existing
cluster, or you can use a deployment tool that has support for deploying it,
like kops.

## Upgrading an Existing Cluster

### When Downtime is Acceptable

In order to upgrade an existing cluster from using the built-in cloud provider
code in the kube controller manager, to using the external cloud controller
manager, you can shut down the kube controller manager, and modify the flags of
the control plane components, and then restart the kube controller manager along
with the cloud controller manager.  The steps are as follows:

1. Temporarily stop the kube controller managers from running.  This might be
   done by temporarily moving manifests out of kubelet's `staticPodPath` (or
   `--pod-manifest-path`), or scaling down the kube controller manager
   deployment, or using `systemctl stop` if they are managed by systemd.
1. Add the `--cloud-provider=external` to the kube-controller-manager config.
1. Add the `--cloud-provider=external` to the kube apiserver config.
1. Add the `--cloud-provider=external` to each the kubelet's config.
1. Add the tag kubernetes.io/cluster/your_cluster_id=owned (if resources are
   owned and managed by the cluster) or
   kubernetes.io/cluster/your_cluster_id=shared (if resources are shared
   between clusters, and should not be destroyed if the cluster is destroyed)
   to your instances.
1. Apply the kustomize configuration: `kubectl apply -k
   'github.com/kubernetes/cloud-provider-aws/examples/existing-cluster/base/?ref=master'` or
   run the cloud cloud controller manager in some alternative way.

### Using Leader Migration

In the case where the control plane cannot tolerate downtime, configuration must be deployed to the cluster in order to facilitate a smooth migration from the controllers in the kube controller manager to their counterparts in the cloud controller manager.  That is, no controller should be running as a leader simultaneously in both controller managers.  In order to determine which controller should be the leader at any given time, they must, at least temporarily, each respect the same leader election lock.  This lock is referred to as the migration lock, and can be removed once the migration is complete and rolling back is no longer on the table.

Follow the detailed steps in [the documentation](https://kubernetes.io/docs/tasks/administer-cluster/controller-manager-leader-migration/) to initiate leader migration.

### Flags

| Component | Flag | Description |
|------|-----------|-------------|
| kube-apiserver | `--cloud-provider=external` | Disables the cloud provider in the API Server. This will disable the cloud provider code in the kube apiserver, which is limited to the persistent volume labelling controller.  |
| kube-controller-manager | `--cloud-provider=external` | Disables the cloud provider in the Kube Controller Manager. This disables cloud related control loops, including the route controller, the service controller, and the node lifecycle controller. |
| kube-controller-manager | --leader-elect=true | Enable leader election  |
| kube-controller-manager | `--external-cloud-volume-plugin=aws` | Tells the Kube Controller Manager to run the volume loops that have cloud provider code in them.  This is required for volumes to work if you are not using CSI with migration enabled. |
| kubelet | `--cloud-provider=external` | Disables the cloud provider in the Kubelet. This disables the built-in kubelet image credential provider, so in order for the kubelet to fetch from ECR repositories, it will need the external ECR kubelet image credential provider binary.  This also disables the EBS attacher interface implementation, which is generally safe as long as the EBS CSI driver is installed and CSI migration is enabled.|
| aws-cloud-controller-manager | <code>--cloud-provider=[aws&#124;aws/v2]</code> | Optional.  Selects the legacy cloud-provider or the v2 cloud-provider in the aws-cloud-controller-manager. WARNING: the v2 cloud-provider is in a pre-alpha state. |

## Using Kops

In order to create a cluster using kops, you can try the kops example cluster. Run the following command:

`make kops-example`

This will create a sample kops cluster with the example configuration, found in [examples/kops-new-cluster](../examples/kops-new-cluster)  The cloud cloud controller manager specific configuration is separate, purely for readability purposes, and can be found in [overlays/cloud-controller-manager](../examples/kops-new-cluster/overlays/cloud-controller-manager).
