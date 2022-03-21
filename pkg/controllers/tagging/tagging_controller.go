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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
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
	taggedNodes map[string]bool

	// A map representing nodes that were part of the cluster at any point in time
	nodeMap map[string]*v1.Node

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
		taggedNodes:       make(map[string]bool),
		nodeMap:           make(map[string]*v1.Node),
		tags:              tags,
	}
	return tc, nil
}

// Run will start the controller to tag resources attached to a cluster
// and untag resources detached from a cluster.
func (tc *TaggingController) Run(ctx context.Context) {
	defer utilruntime.HandleCrash()

	wait.UntilWithContext(ctx, tc.MonitorNodes, tc.nodeMonitorPeriod)
}

func (tc *TaggingController) MonitorNodes(ctx context.Context) {
	klog.Info("Listing nodes as part of tagging controller.")
	nodes, err := tc.nodeLister.List(labels.Everything())
	if err != nil {
		klog.Errorf("error listing nodes: %s", err)
		return
	}
	klog.Infof("Got these nodes as part of tagging controller %s and will tag them with %s", nodes, tc.tags)

	for k := range tc.taggedNodes {
		tc.taggedNodes[k] = false
	}

	var nodesToTag []*v1.Node
	for _, node := range nodes {
		if _, ok := tc.taggedNodes[node.GetName()]; !ok {
			nodesToTag = append(nodesToTag, node)
		}

		tc.nodeMap[node.GetName()] = node
		tc.taggedNodes[node.GetName()] = true
	}
	tc.tagNodesResources(nodesToTag)

	var nodesToUntag []*v1.Node
	for nodeName, existed := range tc.taggedNodes {
		if existed == false {
			nodesToUntag = append(nodesToUntag, tc.nodeMap[nodeName])
		}
	}
	tc.untagNodeResources(nodesToUntag)

	tc.syncDeletedNodesToTaggedNodes()
}

// tagNodesResources tag node resources from a list of node
// If we want to tag more resources, modify this function appropriately
func (tc *TaggingController) tagNodesResources(nodes []*v1.Node) {
	tc.tagEc2Instances(nodes)
}

// untagNodeResources untag node resources from a list of node
// If we want to untag more resources, modify this function appropriately
func (tc *TaggingController) untagNodeResources(nodes []*v1.Node) {
	for _, node := range nodes {
		klog.Infof("Untagging resources for node %s with %s.", node.GetName(), tc.tags)
	}
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

// tagEc2Instances applies the provided tags to each EC2 instances in
// the cluster.
func (tc *TaggingController) tagEc2Instances(nodes []*v1.Node) {
	var instanceIds []*string
	for _, node := range nodes {
		instanceId, err := awsv1.KubernetesInstanceID(node.Spec.ProviderID).MapToAWSInstanceID()
		if err != nil {
			klog.Infof("Error in getting instanceID for node %s, error: %v", node.GetName(), err)
		} else {
			instanceIds = append(instanceIds, aws.String(string(instanceId)))
		}
	}

	tc.cloud.TagResources(instanceIds, tc.tags)
}

// Sample function demonstrating that we'll get the tag list from user
func (tc *TaggingController) getTagsFromInputs() []*ec2.Tag {
	var awsTags []*ec2.Tag
	for k, v := range tc.tags {
		newTag := &ec2.Tag{
			Key:   aws.String(k),
			Value: aws.String(v),
		}
		awsTags = append(awsTags, newTag)
	}

	return awsTags
}
