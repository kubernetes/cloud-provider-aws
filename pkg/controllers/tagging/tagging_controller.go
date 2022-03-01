/*
Copyright 2016 The Kubernetes Authors.
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
	"container/list"
	"context"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
	"time"

	v1 "k8s.io/api/core/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	coreinformers "k8s.io/client-go/informers/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	v1lister "k8s.io/client-go/listers/core/v1"
	cloudprovider "k8s.io/cloud-provider"
)

// TaggingController is the controller implementation for tagging cluster resources.
// It periodically check for Node events (creating/deleting) to apply appropriate
// tags to resources.
type TaggingController struct {
	kubeClient clientset.Interface
	nodeLister v1lister.NodeLister

	cloud cloudprovider.Interface

	// Value controlling TaggingController monitoring period, i.e. how often does TaggingController
	// check node list. This value should be lower than nodeMonitorGracePeriod
	// set in controller-manager
	nodeMonitorPeriod time.Duration

	// A map presenting the node and whether it currently exists
	taggedNodes map[string]bool
}

// NewTaggingController creates a NewTaggingController object
func NewTaggingController(
	nodeInformer coreinformers.NodeInformer,
	kubeClient clientset.Interface,
	cloud cloudprovider.Interface,
	nodeMonitorPeriod time.Duration) (*TaggingController, error) {

	tc := &TaggingController{
		kubeClient:        kubeClient,
		nodeLister:        nodeInformer.Lister(),
		cloud:             cloud,
		nodeMonitorPeriod: nodeMonitorPeriod,
		taggedNodes:       make(map[string]bool),
	}

	return tc, nil
}

// Run will start the controller to tag resources attached to a cluster
// and untag resources detached from a cluster.
func (tc *TaggingController) Run(ctx context.Context) {
	defer utilruntime.HandleCrash()

	wait.UntilWithContext(ctx, tc.monitorNodes, tc.nodeMonitorPeriod)
}

func (tc *TaggingController) monitorNodes(ctx context.Context) {
	nodes, err := tc.nodeLister.List(labels.Everything())
	if err != nil {
		klog.Errorf("error listing nodes from cache: %s", err)
		return
	}

	// Set all elements to be false
	// to sync taggedNodes with nodes
	for k := range tc.taggedNodes {
		tc.taggedNodes[k] = false
	}

	nodeList := list.New()
	for _, node := range nodes {
		if _, ok := tc.taggedNodes[node.GetName()]; !ok {
			nodeList.PushBack(node)
		}

		tc.taggedNodes[node.GetName()] = true
	}

	//tc.tagNodesResources(nodeList)

	tc.syncDeletedNodesToTaggedNodes()
}

// tagNodesResources tag node resources from a list of node
func (tc *TaggingController) tagNodesResources(nodes []*v1.Node) {
	tc.tagEc2Instances(nodes)
}

// syncDeletedNodes delete (k, v) from taggedNodes
// if it doesn't exist
func (tc *TaggingController) syncDeletedNodesToTaggedNodes() {
	for k, v := range tc.taggedNodes {
		if v == false {
			delete(tc.taggedNodes, k)
		}
	}
}

func (tc *TaggingController) tagEc2Instances(nodes []*v1.Node) {
	
}
