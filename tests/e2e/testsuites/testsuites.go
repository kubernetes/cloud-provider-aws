package testsuites

import (
	"context"
	"fmt"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/kubernetes/test/e2e/framework"
)

var generateName = "aws-e2e-"

type TestService struct {
	client    clientset.Interface
	service   *v1.Service
	namespace *v1.Namespace
}

func NewTestService(c clientset.Interface, ns *v1.Namespace) *TestService {
	selector := make(map[string]string)
	selector["app"] = "test"
	return &TestService{
		client:    c,
		namespace: ns,
		service: &v1.Service{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: fmt.Sprintf("%ssvc-", generateName),
				Namespace:    ns.Name,
			},
			Spec: v1.ServiceSpec{
				Ports: []v1.ServicePort{
					v1.ServicePort{
						Port: 80,
					},
				},
				Selector: selector,
			},
		},
	}
}

func (t *TestService) Create() {
	var err error

	t.service, err = t.client.CoreV1().Services(t.namespace.Name).Create(context.Background(), t.service, metav1.CreateOptions{})
	framework.ExpectNoError(err)
}

func (t *TestService) Cleanup() {
	var err error

	err = t.client.CoreV1().Services(t.namespace.Name).Delete(context.Background(), t.service.Name, metav1.DeleteOptions{})
	framework.ExpectNoError(err)
}

func (t *TestService) WaitForSuccess() {
	// todo
	var err error
	time.Sleep(10 * time.Second)
	framework.ExpectNoError(err)
}
