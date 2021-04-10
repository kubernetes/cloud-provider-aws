/*
Copyright 2018 The Kubernetes Authors.
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
	. "github.com/onsi/ginkgo"
	v1 "k8s.io/api/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/cloud-provider-aws/tests/e2e/testsuites"
	"k8s.io/kubernetes/test/e2e/framework"
)

var _ = Describe("[cloud-provider-aws-e2e] loadbalancer", func() {
	f := framework.NewDefaultFramework("cloud-provider-aws")

	var (
		cs clientset.Interface
		ns *v1.Namespace
	)

	BeforeEach(func() {
		cs = f.ClientSet
		ns = f.Namespace
	})

	AfterEach(func() {
		// After each test
	})

	It("should create an elastic load balancer", func() {
		service := testsuites.ServiceDetails{}
		test := testsuites.LoadBalancerExampleTest{
			Service: service,
		}
		test.Run(cs, ns)
	})
})
