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
	"k8s.io/client-go/util/workqueue"
	awsv1 "k8s.io/cloud-provider-aws/pkg/providers/v1"
	"k8s.io/klog/v2"
	"testing"
	"time"
)

const TestClusterID = "clusterid.test"

func Test_NodesJoiningAndLeaving(t *testing.T) {
	testcases := []struct {
		name         string
		currNode     *v1.Node
		noOfItemLeft int
		toBeTagged   bool
	}{
		{
			name: "node0 joins the cluster, but fail to tag.",
			currNode: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "node0",
					CreationTimestamp: metav1.Date(2012, 1, 1, 0, 0, 0, 0, time.UTC),
				},
				Spec: v1.NodeSpec{
					ProviderID: "i-error",
				},
			},
			noOfItemLeft: 1,
			toBeTagged:   true,
		},
		{
			name: "node0 joins the cluster.",
			currNode: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "node0",
					CreationTimestamp: metav1.Date(2012, 1, 1, 0, 0, 0, 0, time.UTC),
				},
				Spec: v1.NodeSpec{
					ProviderID: "i-0001",
				},
			},
			noOfItemLeft: 0,
			toBeTagged:   true,
		},
		{
			name: "node0 leaves the cluster, failed to tag.",
			currNode: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "node0",
					CreationTimestamp: metav1.Date(2012, 1, 1, 0, 0, 0, 0, time.UTC),
				},
				Spec: v1.NodeSpec{
					ProviderID: "i-error",
				},
			},
			noOfItemLeft: 1,
			toBeTagged:   false,
		},
		{
			name: "node0 leaves the cluster.",
			currNode: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "node0",
					CreationTimestamp: metav1.Date(2012, 1, 1, 0, 0, 0, 0, time.UTC),
				},
				Spec: v1.NodeSpec{
					ProviderID: "i-0001",
				},
			},
			noOfItemLeft: 0,
			toBeTagged:   false,
		},
	}

	awsServices := awsv1.NewFakeAWSServices(TestClusterID)
	fakeAws, _ := awsv1.NewAWSCloud(awsv1.CloudConfig{}, awsServices)

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			clientset := fake.NewSimpleClientset(testcase.currNode)
			informer := informers.NewSharedInformerFactory(clientset, time.Second)
			nodeInformer := informer.Core().V1().Nodes()

			if err := syncNodeStore(nodeInformer, clientset); err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			eventBroadcaster := record.NewBroadcaster()
			tc := &TaggingController{
				nodeInformer:      nodeInformer,
				kubeClient:        clientset,
				cloud:             fakeAws,
				nodeMonitorPeriod: 1 * time.Second,
				tags:              map[string]string{"key": "value"},
				resources:         []string{"instance"},
				workqueue:         workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "Tagging"),
			}

			w := eventBroadcaster.StartLogging(klog.Infof)
			defer w.Stop()

			tc.enqueueNode(testcase.currNode, testcase.toBeTagged)
			tc.Process()

			if tc.workqueue.Len() != testcase.noOfItemLeft {
				t.Fatalf("workqueue not processed properly, expected %d left, got %d.", testcase.noOfItemLeft, tc.workqueue.Len())
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
