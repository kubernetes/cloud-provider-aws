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
	"context"
	"fmt"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	v1lister "k8s.io/client-go/listers/core/v1"
	cloudprovider "k8s.io/cloud-provider"
	"k8s.io/cloud-provider-aws/pkg/controllers/options"
	awsv1 "k8s.io/cloud-provider-aws/pkg/providers/v1"
	"k8s.io/klog/v2"
	"time"
)

// TaggingController is the controller implementation for tagging cluster resources.
// It periodically check for Node events (creating/deleting) to apply appropriate
// tags to resources.
type TaggingController struct {
	controllerOptions options.TaggingControllerOptions
	kubeClient        clientset.Interface
	nodeLister        v1lister.NodeLister
	cloud             *awsv1.Cloud

	// Value controlling TaggingController monitoring period, i.e. how often does TaggingController
	// check node list. This value should be lower than nodeMonitorGracePeriod
	// set in controller-manager
	nodeMonitorPeriod time.Duration

	// A map presenting the node and whether it currently exists
	currNodes map[string]bool

	// A map representing nodes that were ever part of the cluster
	totalNodes map[string]*v1.Node

	// Representing the user input for tags
	tags map[string]string

	// Representing the resources to tag
	resources []string
}

// NewTaggingController creates a NewTaggingController object
func NewTaggingController(
	nodeInformer coreinformers.NodeInformer,
	kubeClient clientset.Interface,
	cloud cloudprovider.Interface,
	nodeMonitorPeriod time.Duration,
	tags map[string]string) (*TaggingController, error) {

	awsCloud, ok := cloud.(*awsv1.Cloud)
	if !ok {
		err := fmt.Errorf("tagging controller does not support %v provider", cloud.ProviderName())
		return nil, err
	}

	tc := &TaggingController{
		kubeClient:        kubeClient,
		nodeLister:        nodeInformer.Lister(),
		cloud:             awsCloud,
		nodeMonitorPeriod: nodeMonitorPeriod,
		currNodes:         make(map[string]bool),
		totalNodes:        make(map[string]*v1.Node),
		tags:              tags,
	}
	return tc, nil
}

// Run will start the controller to tag resources attached to the cluster
// and untag resources detached from the cluster.
func (tc *TaggingController) Run(ctx context.Context) {
	defer utilruntime.HandleCrash()

	wait.UntilWithContext(ctx, tc.MonitorNodes, tc.nodeMonitorPeriod)
}

func (tc *TaggingController) MonitorNodes(ctx context.Context) {
	nodes, err := tc.nodeLister.List(labels.Everything())
	if err != nil {
		klog.Fatalf("error listing nodes: %s", err)
	}

	for k := range tc.currNodes {
		tc.currNodes[k] = false
	}

	var nodesToTag []*v1.Node
	for _, node := range nodes {
		if _, ok := tc.currNodes[node.GetName()]; !ok {
			nodesToTag = append(nodesToTag, node)
		}

		tc.totalNodes[node.GetName()] = node
		tc.currNodes[node.GetName()] = true
	}
	tc.tagNodesResources(nodesToTag)

	var nodesToUntag []*v1.Node
	for nodeName, existed := range tc.currNodes {
		if existed == false {
			nodesToUntag = append(nodesToUntag, tc.totalNodes[nodeName])
		}
	}
	tc.untagNodeResources(nodesToUntag)
}

// tagNodesResources tag node resources from a list of nodes
// If we want to tag more resources, modify this function appropriately
func (tc *TaggingController) tagNodesResources(nodes []*v1.Node) {
	for _, node := range nodes {
		nodeTagged := false
		nodeTagged = tc.tagEc2Instances(node)

		if !nodeTagged {
			// Node tagged unsuccessfully, remove from currNodes
			// so that we can try later if it still exists
			delete(tc.currNodes, node.GetName())
		}
	}
}

// tagEc2Instances applies the provided tags to each EC2 instance in
// the cluster. Return a boolean value representing if a node is tagged or not
func (tc *TaggingController) tagEc2Instances(node *v1.Node) bool {
	instanceId, err := awsv1.KubernetesInstanceID(node.Spec.ProviderID).MapToAWSInstanceID()

	if err != nil {
		klog.Errorf("Error in getting instanceID for node %s, error: %v", node.GetName(), err)
		return false
	} else {
		err := tc.cloud.TagResource(string(instanceId), tc.tags)

		if err != nil {
			klog.Errorf("Error in tagging EC2 instance for node %s, error: %v", node.GetName(), err)
			return false
		}
	}

	return true
}

// untagNodeResources untag node resources from a list of nodes
// If we want to untag more resources, modify this function appropriately
func (tc *TaggingController) untagNodeResources(nodes []*v1.Node) {
	for _, node := range nodes {
		nodeUntagged := false
		nodeUntagged = tc.untagEc2Instance(node)

		if nodeUntagged {
			delete(tc.currNodes, node.GetName())
		}
	}
}

// untagEc2Instances deletes the provided tags to each EC2 instances in
// the cluster. Return if a node is tagged or not
func (tc *TaggingController) untagEc2Instance(node *v1.Node) bool {
	instanceId, err := awsv1.KubernetesInstanceID(node.Spec.ProviderID).MapToAWSInstanceID()

	if err != nil {
		klog.Errorf("Error in getting instanceID for node %s, error: %v", node.GetName(), err)
		return false
	} else {
		err := tc.cloud.UntagResource(string(instanceId), tc.tags)

		if err != nil {
			klog.Errorf("Error in untagging EC2 instance for node %s, error: %v", node.GetName(), err)
			return false
		}
	}

	return true
}
