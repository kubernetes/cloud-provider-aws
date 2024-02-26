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

package e2e

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	. "github.com/onsi/ginkgo/v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/kubernetes/test/e2e/framework"
	admissionapi "k8s.io/pod-security-admission/api"
)

var _ = Describe("[cloud-provider-aws-e2e]", Label("ipv6 prefix"), func() {
	f := framework.NewDefaultFramework("cloud-provider-aws")
	f.NamespacePodSecurityEnforceLevel = admissionapi.LevelPrivileged

	var (
		cs clientset.Interface
	)

	BeforeEach(func() {
		cs = f.ClientSet
	})

	AfterEach(func() {
		// After each test
	})

	It("should check if the nodes have the correct ipv6 prefix from the NIC assigned", func() {

		sess, err := session.NewSession(&aws.Config{
			Region: aws.String("eu-north-1")},
		)
		framework.ExpectNoError(err)

		svc := ec2.New(sess)

		// get the nodes
		nodes, err := cs.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{})
		framework.ExpectNoError(err)

		for _, node := range nodes.Items {
			input := &ec2.DescribeInstancesInput{
				InstanceIds: []*string{
					&node.Name,
				},
			}
			result, err := svc.DescribeInstances(input)
			framework.ExpectNoError(err)
			for _, reservation := range result.Reservations {
				for _, instance := range reservation.Instances {
					for _, networkInterface := range instance.NetworkInterfaces {
						for _, ipv6Prefix := range networkInterface.Ipv6Prefixes {
							if node.Spec.PodCIDR != *ipv6Prefix.Ipv6Prefix {
								fmt.Errorf("Name: %s, PodCIDR: %s does not match IPv6Prefix: %s\n", node.Name, node.Spec.PodCIDR, *ipv6Prefix.Ipv6Prefix)
								framework.ExpectNoError(err)
							}
						}
					}
				}
			}
		}
	})
})
