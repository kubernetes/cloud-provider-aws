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

// Package v1 is the legacy cloud provider imported from the main kubernetes repo.
// This is the same implementation used the in-tree Kubernetes components (kubelet,
// kube-controller-manager, etc) but works out-of-tree as well.
package v1

import (
	// install the legacy provider by importing it
	"k8s.io/legacy-cloud-providers/aws"
)

const (
	// ProviderName is the name of the v1 AWS cloud provider
	ProviderName = aws.ProviderName
)
