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

package ipam

import (
	"context"
	"encoding/json"
	"fmt"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

// NodePatch holds the fields to patch
type NodePatch struct {
	Spec     *NodePatchSpec     `json:"spec,omitempty"`
	Metadata *NodePatchMetadata `json:"metadata,omitempty"`
}

// NodePatchSpec holds the spec for the node patch operation
type NodePatchSpec struct {
	PodCIDR  string   `json:"podCIDR,omitempty"`
	PodCIDRs []string `json:"podCIDRs,omitempty"`
}

// NodePatchMetadata holds the metadata for the node patch operation
type NodePatchMetadata struct {
	Labels map[string]*string `json:"labels,omitempty"`
}

// PatchNodePodCIDRs patches the node podCIDR to the specified value.
func PatchNodePodCIDRs(kubeClient clientset.Interface, node *v1.Node, cidr []string) error {
	klog.Infof("assigning cidr %q to node %q", cidr, node.ObjectMeta.Name)
	nodePatchSpec := &NodePatchSpec{
		PodCIDR:  cidr[0],
		PodCIDRs: cidr,
	}
	nodePatch := &NodePatch{
		Spec: nodePatchSpec,
	}
	nodePatchJSON, err := json.Marshal(nodePatch)
	if err != nil {
		return fmt.Errorf("error building node patch: %v", err)
	}

	klog.V(2).Infof("sending patch for node %q: %q", node.Name, string(nodePatchJSON))

	_, err = kubeClient.CoreV1().Nodes().Patch(context.TODO(), node.Name, types.StrategicMergePatchType, nodePatchJSON, metav1.PatchOptions{})
	if err != nil {
		return fmt.Errorf("error applying patch to node: %v", err)
	}

	return nil
}
