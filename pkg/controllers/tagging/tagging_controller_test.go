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
	"os"
	"strings"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/util/workqueue"
	awsv1 "k8s.io/cloud-provider-aws/pkg/providers/v1"
	"k8s.io/klog/v2"
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
		rateLimited      bool
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
			expectedMessages: []string{"Error occurred while processing"},
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
			expectedMessages: []string{"Successfully tagged i-0001", "to the workqueue (without any rate-limit)"},
		},
		{
			name: "node0 joins the cluster (rate-limited).",
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
			expectedMessages: []string{"Successfully tagged i-0001", "to the workqueue (rate-limited)"},
			rateLimited:      true,
		},
		{
			name: "node0 joins the cluster and was tagged earlier with different tags.",
			currNode: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "node0",
					CreationTimestamp: metav1.Date(2012, 1, 1, 0, 0, 0, 0, time.UTC),
					Labels: map[string]string{
						taggingControllerLabelKey: "9767c4972ba72e87ab553bad2afde741", // MD5 for key1=value1
					},
				},
				Spec: v1.NodeSpec{
					ProviderID: "i-0001",
				},
			},
			toBeTagged:       true,
			expectedMessages: []string{"Successfully tagged i-0001"},
		},
		{
			name: "node0 joins the cluster but isn't tagged because it was already tagged earlier.",
			currNode: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "node0",
					CreationTimestamp: metav1.Date(2012, 1, 1, 0, 0, 0, 0, time.UTC),
					Labels: map[string]string{
						taggingControllerLabelKey: "c812faa65d1d5e5aefa6b069b3da39df", // MD5 for key1=value1,key2=value2
					},
				},
				Spec: v1.NodeSpec{
					ProviderID: "i-0001",
				},
			},
			toBeTagged:       true,
			expectedMessages: []string{"Skip tagging node node0 since it was already tagged earlier."},
		},
		{
			name: "fargate node joins the cluster.",
			currNode: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "fargatenode0",
					CreationTimestamp: metav1.Date(2012, 1, 1, 0, 0, 0, 0, time.UTC),
				},
				Spec: v1.NodeSpec{
					ProviderID: "aws:///us-west-2a/2ea696a557-9e55466d21eb4f83a99a9aa396bbd134/fargate-ip-10-0-55-27.us-west-2.compute.internal",
				},
			},
			toBeTagged:       true,
			expectedMessages: []string{"Skip processing the node fargate-ip-10-0-55-27.us-west-2.compute.internal since it is a Fargate node"},
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
			expectedMessages: []string{"Error in untagging EC2 instance i-error for node node0"},
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
		{
			name: "node0 is recently created and the instance is not found the first 3 CreateTags attempts",
			currNode: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "node0",
					CreationTimestamp: metav1.Now(),
				},
				Spec: v1.NodeSpec{
					ProviderID: "i-not-found-count-3-0001",
				},
			},
			toBeTagged:       true,
			expectedMessages: []string{"Successfully tagged i-not-found-count-3-0001", "node is within eventual consistency grace period"},
		},
		{
			name: "node0 is not recently created and the instance is not found",
			currNode: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "node0",
					CreationTimestamp: metav1.Date(2012, 1, 1, 0, 0, 0, 0, time.UTC),
				},
				Spec: v1.NodeSpec{
					ProviderID: "i-not-found",
				},
			},
			toBeTagged:       true,
			expectedMessages: []string{"Skip tagging since EC2 instance i-not-found for node node0 does not exist"},
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
			tc := &Controller{
				nodeInformer:      nodeInformer,
				kubeClient:        clientset,
				cloud:             fakeAws,
				nodeMonitorPeriod: 1 * time.Second,
				tags:              map[string]string{"key2": "value2", "key1": "value1"},
				resources:         []string{"instance"},
				workqueue:         workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "Tagging"),
				rateLimitEnabled:  testcase.rateLimited,
			}

			if testcase.toBeTagged {
				tc.enqueueNode(testcase.currNode, tc.tagNodesResources)
			} else {
				tc.enqueueNode(testcase.currNode, tc.untagNodeResources)
			}

			if tc.rateLimitEnabled {
				// If rate limit is enabled, sleep for 10 ms to wait for the item to be added to the queue since the base delay is 5 ms.
				time.Sleep(10 * time.Millisecond)
			}

			for tc.workqueue.Len() > 0 {
				tc.process()

				// sleep briefly because of exponential backoff when requeueing failed workitem
				// resulting in workqueue to be empty if checked immediately
				time.Sleep(1500 * time.Millisecond)
			}

			for _, msg := range testcase.expectedMessages {
				if !strings.Contains(logBuf.String(), msg) {
					t.Errorf("\nMsg %q not found in log: \n%v\n", msg, logBuf.String())
				}
				if strings.Contains(logBuf.String(), "Unable to tag") || strings.Contains(logBuf.String(), "Unable to untag") {
					if !strings.Contains(logBuf.String(), ", requeuing count ") {
						t.Errorf("\nFailed to tag or untag but logs did not requeue: \n%v\n", logBuf.String())
					}

					if !strings.Contains(logBuf.String(), "requeuing count exceeded") {
						t.Errorf("\nExceeded requeue count but did not stop: \n%v\n", logBuf.String())
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
