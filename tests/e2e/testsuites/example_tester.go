package testsuites

import (
	v1 "k8s.io/api/core/v1"
	clientset "k8s.io/client-go/kubernetes"

	. "github.com/onsi/ginkgo"
)

type LoadBalancerExampleTest struct {
	Service ServiceDetails
}

func (t *LoadBalancerExampleTest) Run(client clientset.Interface, namespace *v1.Namespace) {
	testsvc := NewTestService(client, namespace)
	By("deploying the service")
	testsvc.Create()
	defer testsvc.Cleanup()
	By("checking that the service creates the loadbalancer successfully")
	testsvc.WaitForSuccess()
}
