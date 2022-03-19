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
	fakecloud "k8s.io/cloud-provider/fake"
	"k8s.io/klog/v2"
	"testing"
	"time"
)

func Test_NodesJoining(t *testing.T) {
	testcases := []struct {
		name              string
		fakeCloud         *fakecloud.Cloud
		currNode          *v1.Node
		taggingController TaggingController
		noOfNodes         int
	}{
		{
			name: "node0 joins the cluster.",
			currNode: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "node0",
					CreationTimestamp: metav1.Date(2012, 1, 1, 0, 0, 0, 0, time.UTC),
				},
			},
			fakeCloud: &fakecloud.Cloud{
				ExistsByProviderID: false,
			},
			taggingController: TaggingController{
				taggedNodes: make(map[string]bool),
				nodeMap:     make(map[string]*v1.Node),
			},
			noOfNodes: 1,
		},
		{
			name: "node1 joins the cluster, node0 left.",
			currNode: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "node1",
					CreationTimestamp: metav1.Date(2012, 1, 1, 0, 0, 0, 0, time.UTC),
				},
			},
			fakeCloud: &fakecloud.Cloud{
				ExistsByProviderID: false,
			},
			taggingController: TaggingController{
				taggedNodes: map[string]bool{
					"node0": true,
				},
				nodeMap: map[string]*v1.Node{
					"node0": {
						ObjectMeta: metav1.ObjectMeta{
							Name:              "node0",
							CreationTimestamp: metav1.Date(2012, 1, 1, 0, 0, 0, 0, time.UTC),
						},
					},
				},
			},
			noOfNodes: 1,
		},
		{
			name: "node2 joins the cluster, node0 and node1 left.",
			currNode: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "node2",
					CreationTimestamp: metav1.Date(2012, 1, 1, 0, 0, 0, 0, time.UTC),
				},
			},
			fakeCloud: &fakecloud.Cloud{
				ExistsByProviderID: false,
			},
			taggingController: TaggingController{
				taggedNodes: map[string]bool{
					"node0": true,
					"node1": true,
				},
				nodeMap: map[string]*v1.Node{
					"node0": {
						ObjectMeta: metav1.ObjectMeta{
							Name:              "node0",
							CreationTimestamp: metav1.Date(2012, 1, 1, 0, 0, 0, 0, time.UTC),
						},
					},
					"node1": {
						ObjectMeta: metav1.ObjectMeta{
							Name:              "node1",
							CreationTimestamp: metav1.Date(2012, 1, 1, 0, 0, 0, 0, time.UTC),
						},
					},
				},
			},
			noOfNodes: 1,
		},
	}

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
			testcase.taggingController.cloud = testcase.fakeCloud
			testcase.taggingController.nodeMonitorPeriod = 1 * time.Second

			w := eventBroadcaster.StartLogging(klog.Infof)
			defer w.Stop()

			nodeCountBeforeTagging := len(testcase.taggingController.nodeMap)
			testcase.taggingController.MonitorNodes(ctx)

			klog.Infof("testcase.taggingController.taggedNodes %s", testcase.taggingController.taggedNodes)
			klog.Errorf("testcase.taggingController.nodeMap %s", testcase.taggingController.nodeMap)

			if len(testcase.taggingController.taggedNodes) != testcase.noOfNodes || len(testcase.taggingController.nodeMap) != nodeCountBeforeTagging+testcase.noOfNodes {
				t.Errorf("taggedNodes must contain %d element(s), and nodeMap must contain %d element(s).", testcase.noOfNodes, nodeCountBeforeTagging+testcase.noOfNodes)
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
