/*
Copyright 2016 The Kubernetes Authors.
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

package tagging

import (
	"context"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/record"
	awsv1 "k8s.io/cloud-provider-aws/pkg/providers/v1"
	"k8s.io/klog/v2"
	"testing"
	"time"
)

const TestClusterID = "clusterid.test"

func Test_NodesJoiningAndLeaving(t *testing.T) {
	testcases := []struct {
		name                string
		currNode            *v1.Node
		taggingController   TaggingController
		noOfToBeTaggedNodes int
		totalNodes          int
	}{
		{
			name: "node0 joins the cluster.",
			currNode: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "node0",
					CreationTimestamp: metav1.Date(2012, 1, 1, 0, 0, 0, 0, time.UTC),
				},
				Spec: v1.NodeSpec{
					ProviderID: "i-00000",
				},
			},
			taggingController: TaggingController{
				currNodes:  make(map[string]bool),
				totalNodes: make(map[string]*v1.Node),
			},
			noOfToBeTaggedNodes: 1,
			totalNodes:          1,
		},
		{
			name: "node1 joins the cluster, node0 left.",
			currNode: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "node1",
					CreationTimestamp: metav1.Date(2012, 1, 1, 0, 0, 0, 0, time.UTC),
				},
				Spec: v1.NodeSpec{
					ProviderID: "i-00001",
				},
			},
			taggingController: TaggingController{
				currNodes: map[string]bool{
					"node0": true,
				},
				totalNodes: map[string]*v1.Node{
					"node0": {
						ObjectMeta: metav1.ObjectMeta{
							Name:              "node0",
							CreationTimestamp: metav1.Date(2012, 1, 1, 0, 0, 0, 0, time.UTC),
						},
						Spec: v1.NodeSpec{
							ProviderID: "i-00000",
						},
					},
				},
			},
			noOfToBeTaggedNodes: 1,
			totalNodes:          2,
		},
		{
			name: "node2 joins the cluster, node0 and node1 left.",
			currNode: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "node2",
					CreationTimestamp: metav1.Date(2012, 1, 1, 0, 0, 0, 0, time.UTC),
				},
				Spec: v1.NodeSpec{
					ProviderID: "i-00002",
				},
			},
			taggingController: TaggingController{
				currNodes: map[string]bool{
					"node0": true,
					"node1": true,
				},
				totalNodes: map[string]*v1.Node{
					"node0": {
						ObjectMeta: metav1.ObjectMeta{
							Name:              "node0",
							CreationTimestamp: metav1.Date(2012, 1, 1, 0, 0, 0, 0, time.UTC),
						},
						Spec: v1.NodeSpec{
							ProviderID: "i-00000",
						},
					},
					"node1": {
						ObjectMeta: metav1.ObjectMeta{
							Name:              "node1",
							CreationTimestamp: metav1.Date(2012, 1, 1, 0, 0, 0, 0, time.UTC),
						},
						Spec: v1.NodeSpec{
							ProviderID: "i-00001",
						},
					},
				},
			},
			noOfToBeTaggedNodes: 1,
			totalNodes:          3,
		},
		{
			name: "no new node joins the cluster.",
			currNode: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "node2",
					CreationTimestamp: metav1.Date(2012, 1, 1, 0, 0, 0, 0, time.UTC),
				},
				Spec: v1.NodeSpec{
					ProviderID: "i-00002",
				},
			},
			taggingController: TaggingController{
				currNodes: map[string]bool{
					"node0": true,
					"node1": true,
					"node2": true,
				},
				totalNodes: map[string]*v1.Node{
					"node0": {
						ObjectMeta: metav1.ObjectMeta{
							Name:              "node0",
							CreationTimestamp: metav1.Date(2012, 1, 1, 0, 0, 0, 0, time.UTC),
						},
						Spec: v1.NodeSpec{
							ProviderID: "i-00000",
						},
					},
					"node1": {
						ObjectMeta: metav1.ObjectMeta{
							Name:              "node1",
							CreationTimestamp: metav1.Date(2012, 1, 1, 0, 0, 0, 0, time.UTC),
						},
						Spec: v1.NodeSpec{
							ProviderID: "i-00001",
						},
					},
					"node2": {
						ObjectMeta: metav1.ObjectMeta{
							Name:              "node2",
							CreationTimestamp: metav1.Date(2012, 1, 1, 0, 0, 0, 0, time.UTC),
						},
						Spec: v1.NodeSpec{
							ProviderID: "i-00002",
						},
					},
				},
			},
			noOfToBeTaggedNodes: 1,
			totalNodes:          3,
		},
		{
			name: "node 3 joins the cluster but failed to be tagged.",
			currNode: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "node3",
					CreationTimestamp: metav1.Date(2012, 1, 1, 0, 0, 0, 0, time.UTC),
				},
				Spec: v1.NodeSpec{
					ProviderID: "i-error",
				},
			},
			taggingController: TaggingController{
				currNodes: map[string]bool{
					"node0": true,
					"node1": true,
					"node2": true,
				},
				totalNodes: map[string]*v1.Node{
					"node0": {
						ObjectMeta: metav1.ObjectMeta{
							Name:              "node0",
							CreationTimestamp: metav1.Date(2012, 1, 1, 0, 0, 0, 0, time.UTC),
						},
						Spec: v1.NodeSpec{
							ProviderID: "i-00000",
						},
					},
					"node1": {
						ObjectMeta: metav1.ObjectMeta{
							Name:              "node1",
							CreationTimestamp: metav1.Date(2012, 1, 1, 0, 0, 0, 0, time.UTC),
						},
						Spec: v1.NodeSpec{
							ProviderID: "i-00001",
						},
					},
					"node2": {
						ObjectMeta: metav1.ObjectMeta{
							Name:              "node2",
							CreationTimestamp: metav1.Date(2012, 1, 1, 0, 0, 0, 0, time.UTC),
						},
						Spec: v1.NodeSpec{
							ProviderID: "i-00002",
						},
					},
				},
			},
			noOfToBeTaggedNodes: 0,
			totalNodes:          4,
		},
		{
			name: "node 1 joins the cluster, node 0 left but failed to be untagged.",
			currNode: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "node1",
					CreationTimestamp: metav1.Date(2012, 1, 1, 0, 0, 0, 0, time.UTC),
				},
				Spec: v1.NodeSpec{
					ProviderID: "i-0001",
				},
			},
			taggingController: TaggingController{
				currNodes: map[string]bool{
					"node0": true,
				},
				totalNodes: map[string]*v1.Node{
					"node0": {
						ObjectMeta: metav1.ObjectMeta{
							Name:              "node0",
							CreationTimestamp: metav1.Date(2012, 1, 1, 0, 0, 0, 0, time.UTC),
						},
						Spec: v1.NodeSpec{
							ProviderID: "i-error",
						},
					},
				},
			},
			noOfToBeTaggedNodes: 2,
			totalNodes:          2,
		},
	}

	awsServices := awsv1.NewFakeAWSServices(TestClusterID)
	fakeAws, _ := awsv1.NewAWSCloud(awsv1.CloudConfig{}, awsServices)

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			clientset := fake.NewSimpleClientset(testcase.currNode)
			informer := informers.NewSharedInformerFactory(clientset, time.Second)
			nodeInformer := informer.Core().V1().Nodes()

			if err := syncNodeStore(nodeInformer, clientset); err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			eventBroadcaster := record.NewBroadcaster()
			testcase.taggingController.nodeLister = nodeInformer.Lister()
			testcase.taggingController.kubeClient = clientset
			testcase.taggingController.cloud = fakeAws
			testcase.taggingController.nodeMonitorPeriod = 1 * time.Second

			w := eventBroadcaster.StartLogging(klog.Infof)
			defer w.Stop()

			testcase.taggingController.MonitorNodes(ctx)

			if len(testcase.taggingController.currNodes) != testcase.noOfToBeTaggedNodes || len(testcase.taggingController.totalNodes) != testcase.totalNodes {
				t.Errorf("currNodes must contain %d element(s), and totalNodes must contain %d element(s).", testcase.noOfToBeTaggedNodes, testcase.totalNodes)
			}
		})
	}
}

func syncNodeStore(nodeinformer coreinformers.NodeInformer, f *fake.Clientset) error {
	nodes, err := f.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}
	newElems := make([]interface{}, 0, len(nodes.Items))
	for i := range nodes.Items {
		newElems = append(newElems, &nodes.Items[i])
	}
	return nodeinformer.Informer().GetStore().Replace(newElems, "newRV")
}
