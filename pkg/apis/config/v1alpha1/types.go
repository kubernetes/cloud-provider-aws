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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AWSCloudConfig represents configuration information that will be passed into the AWS v2 cloud provider.
type AWSCloudConfig struct {
	metav1.TypeMeta `json:",inline"`

	// config stores configuration information read by the AWS v2 cloud provider
	Config AWSConfig `json:"config"`
}

// AWSConfig contains configuration information read by the AWS v2 cloud provider
type AWSConfig struct {
	// clusterName is the name of the cluster and should be unique in any given AWS account.
	// This name will be used when naming AWS resources such as load balancers. It is also
	// expected as tag values for every AWS resource that represents this cluster. The expected
	// tagging format is:
	//
	//     kubernetes.io/cluster=<clusterName>
	//
	// Resources without this tag will not be seen by the AWS cloud provider. Changing the cluster name is not supported.
	ClusterName string `json:"clusterName"`
}
