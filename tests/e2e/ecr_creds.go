/*
Copyright 2025 The Kubernetes Authors.

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

	gingko "github.com/onsi/ginkgo/v2"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	e2epod "k8s.io/kubernetes/test/e2e/framework/pod"
)

var _ = gingko.Describe("[cloud-provider-aws-e2e] ecr", func() {
	f := framework.NewDefaultFramework("cloud-provider-aws")

	gingko.It("should start pod using public ecr image", func(ctx context.Context) {
		gingko.By("creating a pod")
		podclient := e2epod.NewPodClient(f)
		podclient.CreateSync(&v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: "ecr-test-pod",
			},
			Spec: v1.PodSpec{
				Containers: []v1.Container{
					{
						SecurityContext: &v1.SecurityContext{
							AllowPrivilegeEscalation: &[]bool{false}[0],
							Capabilities: &v1.Capabilities{
								Drop: []v1.Capability{"ALL"},
							},
							RunAsNonRoot: &[]bool{true}[0],
							RunAsUser:    &[]int64{1000}[0],
							RunAsGroup:   &[]int64{1000}[0],
							SeccompProfile: &v1.SeccompProfile{
								Type: v1.SeccompProfileTypeRuntimeDefault,
							},
						},
						Name:  "test",
						Image: "602401143452.dkr.ecr.us-east-1.amazonaws.com/eks/pause:3.5",
					},
				},
			},
		})
	})
})
