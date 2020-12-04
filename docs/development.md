# Development

A local single node cluster can be brought up on AWS by running the local up script while on an AWS EC2 instance.
Before running this, ensure that the instance you are running on has the `KubernetesCluster` tag. The tag can be any value.

```
./hack/local-up-cluster.sh
```

By default this script will use the cloud provider binary from this repository. You will need to have the k8s main repo cloned before running this script.
