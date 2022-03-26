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
	"bytes"
	"context"
	"flag"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/util/workqueue"
	awsv1 "k8s.io/cloud-provider-aws/pkg/providers/v1"
	"k8s.io/klog"
	"os"
	"strings"
	"testing"
	"time"
)

const TestClusterID = "clusterid.test"

func Test_NodesJoiningAndLeaving(t *testing.T) {
	klog.InitFlags(nil)
	flag.CommandLine.Parse([]string{"--logtostderr=false"})
	testcases := []struct {
		name             string
		currNode         *v1.Node
		toBeTagged       bool
		expectedMessages []string
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
			toBeTagged:       true,
			expectedMessages: []string{"Error occurred while processing ToBeTagged:node0"},
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
			toBeTagged:       true,
			expectedMessages: []string{"Successfully tagged i-0001"},
		},
		{
			name: "node0 leaves the cluster, failed to untag.",
			currNode: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "node0",
					CreationTimestamp: metav1.Date(2012, 1, 1, 0, 0, 0, 0, time.UTC),
				},
				Spec: v1.NodeSpec{
					ProviderID: "i-error",
				},
			},
			toBeTagged:       false,
			expectedMessages: []string{"Error in untagging EC2 instance for node node0"},
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
			toBeTagged:       false,
			expectedMessages: []string{"Successfully untagged i-0001"},
		},
	}

	awsServices := awsv1.NewFakeAWSServices(TestClusterID)
	fakeAws, _ := awsv1.NewAWSCloud(awsv1.CloudConfig{}, awsServices)

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			var logBuf bytes.Buffer
			klog.SetOutput(&logBuf)
			defer func() {
				klog.SetOutput(os.Stderr)
			}()

			clientset := fake.NewSimpleClientset(testcase.currNode)
			informer := informers.NewSharedInformerFactory(clientset, time.Second)
			nodeInformer := informer.Core().V1().Nodes()

			if err := syncNodeStore(nodeInformer, clientset); err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			//eventBroadcaster := record.NewBroadcaster()
			tc := &TaggingController{
				nodeInformer:      nodeInformer,
				kubeClient:        clientset,
				cloud:             fakeAws,
				nodeMonitorPeriod: 1 * time.Second,
				tags:              map[string]string{"key": "value"},
				resources:         []string{"instance"},
				workqueue:         workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "Tagging"),
			}

			tc.enqueueNode(testcase.currNode, testcase.toBeTagged)
			tc.Process()

			for _, msg := range testcase.expectedMessages {
				if !strings.Contains(logBuf.String(), msg) {
					t.Errorf("\nMsg %q not found in log: \n%v\n", msg, logBuf.String())
				}
				if strings.Contains(logBuf.String(), "error tagging ") || strings.Contains(logBuf.String(), "error untagging ") {
					if !strings.Contains(logBuf.String(), ", requeuing") {
						t.Errorf("\nFailed to tag or untag but logs do not contain 'requeueing': \n%v\n", logBuf.String())
					}
				}
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
