/*
Copyright 2024 The Kubernetes Authors.

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

package aws

const (
	// LabelZoneID is a topology label that can be applied to any resource
	// but will be initially applied to nodes.
	LabelZoneID = "topology.k8s.aws/zone-id"
	// LabelNetworkNode is a topology label that can be applied to any resource
	// but will be initially applied to nodes.
	LabelNetworkNode = "topology.k8s.aws/network-node-layer-"
)
