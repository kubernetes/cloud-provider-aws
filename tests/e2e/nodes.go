/*
Copyright 2024 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package e2e

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
)

var _ = Describe("[cloud-provider-aws-e2e] nodes", func() {
	f := framework.NewDefaultFramework("cloud-provider-aws")

	It("should set zone-id topology label", func(ctx context.Context) {
		framework.ExpectNoError(e2enode.WaitForAllNodesSchedulable(f.ClientSet, 10*time.Minute))

		nodeList, err := e2enode.GetReadySchedulableNodes(f.ClientSet)

		framework.ExpectNoError(err)

		if len(nodeList.Items) < 2 {
			framework.Failf("Conformance requires at least two nodes")
		}

		for _, node := range nodeList.Items {
			gomega.Expect(node.Labels).To(gomega.HaveKey("topology.k8s.aws/zone-id"))
		}
	})

	It("should correctly label nodes with instance type p3dn.24xlarge", func(ctx context.Context) {
		framework.ExpectNoError(e2enode.WaitForAllNodesSchedulable(f.ClientSet, 10*time.Minute))
		nodeList, err := e2enode.GetReadySchedulableNodes(f.ClientSet)
		framework.ExpectNoError(err)

		if len(nodeList.Items) < 2 {
			framework.Failf("Conformance requires at least two nodes")
		}

		supportedInstanceType := "p3dn.24xlarge"
		topologyNetworkLabel1 := "topology.k8s.aws/network-node-layer-1"
		topologyNetworkLabel2 := "topology.k8s.aws/network-node-layer-2"
		topologyNetworkLabel3 := "topology.k8s.aws/network-node-layer-3"

		for _, node := range nodeList.Items {
			instanceType, hasInstanceType := node.Labels["node.kubernetes.io/instance-type"]
			if !hasInstanceType {
				framework.Failf("Node %s does not have instance-type label", node.Name)
			}

			if instanceType == supportedInstanceType {
				gomega.Expect(node.Labels).To(gomega.HaveKey(topologyNetworkLabel1),
					"Node with instance type %s should have label %s", supportedInstanceType, topologyNetworkLabel1)
				gomega.Expect(node.Labels).To(gomega.HaveKey(topologyNetworkLabel2),
					"Node with instance type %s should have label %s", supportedInstanceType, topologyNetworkLabel2)
				gomega.Expect(node.Labels).To(gomega.HaveKey(topologyNetworkLabel3),
					"Node with instance type %s should have label %s", supportedInstanceType, topologyNetworkLabel3)
			} else {
				gomega.Expect(node.Labels).NotTo(gomega.HaveKey(topologyNetworkLabel1),
					"Node with instance type %s should not have label %s", instanceType, topologyNetworkLabel1)
				gomega.Expect(node.Labels).NotTo(gomega.HaveKey(topologyNetworkLabel2),
					"Node with instance type %s should not have label %s", instanceType, topologyNetworkLabel2)
				gomega.Expect(node.Labels).NotTo(gomega.HaveKey(topologyNetworkLabel3),
					"Node with instance type %s should not have label %s", instanceType, topologyNetworkLabel3)
			}
		}
	})
})
