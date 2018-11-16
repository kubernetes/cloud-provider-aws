# Amazon Cloud Controller Manager
**NOTE:** This cloud controller manager functionality is currently in ALPHA testing stage. There maybe be potentially backwards compatibility breaking changes moving forward and there may also be bugs. Please test and report bugs but do NOT use this in a production environment.

The AWS cloud controller manager provides the interface between a Kubernetes cluster and AWS service APIs. This project allows a Kubernetes cluster to provision, monitor and remove resources necessary for operation of the cluster.

For general cloud controller manager setup instructions see the [Kubernetes Cloud Controller Manager docs](https://kubernetes.io/docs/tasks/administer-cluster/running-cloud-controller/).

For more details about cloud controller managers see:

* [KEP 0002: Remove Cloud Provider Code From Kubernetes Core](https://github.com/kubernetes/community/blob/master/keps/sig-cloud-provider/0002-cloud-controller-manager.md)
* [Running Cloud Controller Manager](https://kubernetes.io/docs/tasks/administer-cluster/running-cloud-controller/#running-cloud-controller-manager)
* [Developing Cloud Controller Manager](https://kubernetes.io/docs/tasks/administer-cluster/developing-cloud-controller-manager/)

## Requirements
* Kubernetes 1.13+
* `kube-apiserver` and `kube-controller-manager` MUST NOT specify the `--cloud-provider` flag. This ensures that it does not run any cloud specific loops that would be run by cloud controller manager. In the future, this flag will be deprecated and removed.
* `kubelet` must run with `--cloud-provider=external`. This is to ensure that the kubelet is aware that it must be initialized by the cloud controller manager before it is scheduled any work.
* `kube-apiserver` SHOULD NOT run the `PersistentVolumeLabel` admission controller since the cloud controller manager takes over labeling persistent volumes.

## IAM Policy
For the aws-cloud-controller-manager to be able to communicate to AWS APIs, you will need to create a few IAM policies for your EC2 instances. The master policy is a bit open and can be scaled back depending on the use case. Adjust these based on your needs.

1. [Master Policy](https://github.com/kubernetes/cloud-provider-aws/blob/master/deploy/master_iam_policy.json)
2. [Node Policy](https://github.com/kubernetes/cloud-provider-aws/blob/master/deploy/node_iam_policy.json)

## Proper Node Names
The cloud provider currently uses the instance private DNS name as the node name, but this is subject to change in the future.

## Development
This code builds with Golang 1.11+. The `make` command will build and test the project. This project uses [go dep](https://golang.github.io/dep/) for dependency management but will use native Go modules in the near future.

## License
Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

## NOTE
This is not an officially supported Amazon product.
