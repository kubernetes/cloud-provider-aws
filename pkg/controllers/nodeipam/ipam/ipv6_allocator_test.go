/*
Copyright 2023 The Kubernetes Authors.

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

package ipam

import (
	"bytes"
	"flag"
	"os"
	"strings"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/cloud-provider-aws/pkg/controllers/nodeipam/testutil"
	awsv1 "k8s.io/cloud-provider-aws/pkg/providers/v1"
	"k8s.io/klog/v2"
)

func TestIPv6CIDRAllocator(t *testing.T) {
	klog.InitFlags(nil)
	flag.CommandLine.Parse([]string{"--logtostderr=false"})
	// all tests operate on a single node
	testCases := []testCase{
		{
			rateLimitEnabled: true,
			description:      "success, correct node allocation",
			fakeNodeHandler: &testutil.FakeNodeHandler{
				Existing: []*v1.Node{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name: "node0",
						},
						Spec: v1.NodeSpec{
							ProviderID: "aws:///eu-west-1a/i-123456789",
						},
					},
				},
				Clientset: fake.NewSimpleClientset(),
			},
			allocatedCIDRs: nil,
			expectedAllocatedCIDR: map[int]string{
				0: "2001:0db8:85a3:0000:0000:8a2e:0000:0000/80",
			},
			ctrlCreateFail: false,
		},
	}
	// test function
	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {

			var logBuf bytes.Buffer
			klog.SetOutput(&logBuf)
			defer func() {
				klog.SetOutput(os.Stderr)
			}()

			fakeNodeInformer := getFakeNodeInformer(tc.fakeNodeHandler)
			rateLimiter := workqueue.DefaultControllerRateLimiter()
			rateLimitEnabled := false
			nodeMonitorPeriod := 1 * time.Second

			// Initialize the IPv6 range allocator.
			ra6, err := NewIPv6RangeAllocator(tc.fakeNodeHandler, fakeNodeInformer, nil, rateLimiter, rateLimitEnabled, nodeMonitorPeriod)
			if err == nil && tc.ctrlCreateFail {
				t.Fatalf("failed to create IPv6 range allocator")
			}
			rangeAllocatorIPv6, ok := ra6.(*IPv6RangeAllocator)
			if !ok {
				t.Logf("%v: found non-default implementation of IPv6RangeAllocator, skipping white-box test...", tc.description)
				return
			}

			rangeAllocatorIPv6.nodesSynced = alwaysReady
			awsServices := awsv1.NewFakeAWSServices("clusterid.test")
			rangeAllocatorIPv6.cloud, _ = awsv1.NewAWSCloud(awsv1.CloudConfig{}, awsServices)
			go rangeAllocatorIPv6.Run(wait.NeverStop)

			rangeAllocatorIPv6.enqueueNode(tc.fakeNodeHandler.Existing[0], rangeAllocatorIPv6.prefixNodeResource)

			if tc.rateLimitEnabled {
				// If rate limit is enabled, sleep for 10 ms to wait for the item to be added to the queue since the base delay is 5 ms.
				time.Sleep(10 * time.Millisecond)
			}

			for rangeAllocatorIPv6.workqueue.Len() > 0 {
				rangeAllocatorIPv6.process()

				// sleep briefly because of exponential backoff when requeueing failed workitem
				// resulting in workqueue to be empty if checked immediately
				time.Sleep(1500 * time.Millisecond)
			}

			for _, node := range tc.fakeNodeHandler.Existing {
				if !strings.Contains(logBuf.String(), tc.expectedAllocatedCIDR[0]) {
					t.Errorf("\nDid not successfully prefix node %s.\n%v\n", node.Name, logBuf.String())
				}
			}

		})
	}
}
