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
	"k8s.io/component-base/metrics"
	"k8s.io/component-base/metrics/legacyregistry"
	"sync"
)

var register sync.Once

var (
	workItemDuration = metrics.NewHistogramVec(
		&metrics.HistogramOpts{
			Name:           "cloudprovider_aws_tagging_controller_work_item_duration_seconds",
			Help:           "workitem latency of workitem being in the queue and time it takes to process",
			StabilityLevel: metrics.ALPHA,
			Buckets:        metrics.ExponentialBuckets(0.5, 1.5, 20),
		},
		[]string{"latency_type"})

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
		legacyregistry.MustRegister(workItemDuration)
		legacyregistry.MustRegister(workItemError)
	})
}

func recordWorkItemLatencyMetrics(latencyType string, timeTaken float64) {
	workItemDuration.With(metrics.Labels{"latency_type": latencyType}).Observe(timeTaken)
}

func recordWorkItemErrorMetrics(errorType string, instanceID string) {
	workItemError.With(metrics.Labels{"error_type": errorType, "instance_id": instanceID}).Inc()
}
