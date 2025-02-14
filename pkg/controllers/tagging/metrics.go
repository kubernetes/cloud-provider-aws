/*
Copyright 2020 The Kubernetes Authors.
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
	"sync"

	"k8s.io/component-base/metrics"
	"k8s.io/component-base/metrics/legacyregistry"
)

var register sync.Once

var (
	workItemError = metrics.NewCounterVec(
		&metrics.CounterOpts{
			Name:           "cloudprovider_aws_tagging_controller_work_item_errors_total",
			Help:           "any error in dequeueing the work queue and processing workItem",
			StabilityLevel: metrics.ALPHA,
		},
		[]string{"error_type", "instance_id"})
)

// registerMetrics registers tagging-controller metrics.
func registerMetrics() {
	register.Do(func() {
		legacyregistry.MustRegister(workItemError)
	})
}

func recordWorkItemErrorMetrics(errorType string, instanceID string) {
	workItemError.With(metrics.Labels{"error_type": errorType, "instance_id": instanceID}).Inc()
}
