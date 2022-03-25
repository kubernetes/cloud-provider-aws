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
	"fmt"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	v1lister "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	cloudprovider "k8s.io/cloud-provider"
	"k8s.io/cloud-provider-aws/pkg/controllers/options"
	opt "k8s.io/cloud-provider-aws/pkg/controllers/options"
	awsv1 "k8s.io/cloud-provider-aws/pkg/providers/v1"
	"k8s.io/klog/v2"
	"time"
)

// TaggingController is the controller implementation for tagging cluster resources.
// It periodically check for Node events (creating/deleting) to apply appropriate
// tags to resources.
type TaggingController struct {
	nodeInformer      coreinformers.NodeInformer
	controllerOptions options.TaggingControllerOptions
	kubeClient        clientset.Interface
	nodeLister        v1lister.NodeLister
	cloud             *awsv1.Cloud
	workqueue         workqueue.RateLimitingInterface

	// Value controlling TaggingController monitoring period, i.e. how often does TaggingController
	// check node list. This value should be lower than nodeMonitorGracePeriod
	// set in controller-manager
	nodeMonitorPeriod time.Duration

	// A map presenting the node and whether it currently exists
	currentNodes map[string]bool

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
	tags map[string]string,
	resources []string) (*TaggingController, error) {

	awsCloud, ok := cloud.(*awsv1.Cloud)
	if !ok {
		err := fmt.Errorf("tagging controller does not support %v provider", cloud.ProviderName())
		return nil, err
	}

	tc := &TaggingController{
		nodeInformer:      nodeInformer,
		kubeClient:        kubeClient,
		nodeLister:        nodeInformer.Lister(),
		cloud:             awsCloud,
		nodeMonitorPeriod: nodeMonitorPeriod,
		currentNodes:      make(map[string]bool),
		totalNodes:        make(map[string]*v1.Node),
		tags:              tags,
		resources:         resources,
		workqueue:         workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "Tagging"),
	}

	// Use shared informer to listen to add/update of nodes. Note that any nodes
	// that exist before node controller starts will show up in the update method
	tc.nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    tc.enqueueNode,
		UpdateFunc: func(oldObj, newObj interface{}) { tc.enqueueNode(newObj) },
		DeleteFunc: tc.untagNodeResources,
	})

	return tc, nil
}

// Run will start the controller to tag resources attached to the cluster
// and untag resources detached from the cluster.
func (tc *TaggingController) Run(stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	defer tc.workqueue.ShutDown()

	klog.Infof("Starting the tagging controller")
	go wait.Until(tc.MonitorNodes, tc.nodeMonitorPeriod, stopCh)

	<-stopCh
}

// MonitorNodes is a long-running function that continuously
// read and process a message on the work queue
func (tc *TaggingController) MonitorNodes() {
	obj, shutdown := tc.workqueue.Get()
	if shutdown {
		return
	}

	err := func(obj interface{}) error {
		defer tc.workqueue.Done(obj)

		var key string
		var ok bool
		if key, ok = obj.(string); !ok {
			tc.workqueue.Forget(obj)
			utilruntime.HandleError(fmt.Errorf("expected string in workqueue but got %#v", obj))
			return nil
		}

		_, nodeName, err := cache.SplitMetaNamespaceKey(key)

		if err != nil {
			utilruntime.HandleError(fmt.Errorf("invalid resource key: %s", key))
			return nil
		}

		// Run the syncHandler, passing it the key of the
		// Node resource to be synced.
		if err := tc.tagNodesResources(nodeName); err != nil {
			// Put the item back on the workqueue to handle any transient errors.
			tc.workqueue.AddRateLimited(key)
			return fmt.Errorf("error tagging '%s': %s, requeuing", key, err.Error())
		}

		tc.workqueue.Forget(obj)
		return nil
	}(obj)

	if err != nil {
		utilruntime.HandleError(err)
	}
}

// tagNodesResources tag node resources from a list of nodes
// If we want to tag more resources, modify this function appropriately
func (tc *TaggingController) tagNodesResources(nodeName string) error {
	node, err := tc.nodeInformer.Lister().Get(nodeName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}

		return err
	}

	for _, resource := range tc.resources {
		switch resource {
		case opt.Instance:
			err = tc.tagEc2Instances(node)
		}
	}

	return err
}

// tagEc2Instances applies the provided tags to each EC2 instance in
// the cluster. Return a boolean value representing if a node is tagged or not
func (tc *TaggingController) tagEc2Instances(node *v1.Node) error {
	instanceId, err := awsv1.KubernetesInstanceID(node.Spec.ProviderID).MapToAWSInstanceID()

	if err != nil {
		klog.Errorf("Error in getting instanceID for node %s, error: %v", node.GetName(), err)
		return err
	} else {
		err := tc.cloud.TagResource(string(instanceId), tc.tags)

		if err != nil {
			klog.Errorf("Error in tagging EC2 instance for node %s, error: %v", node.GetName(), err)
			return err
		}
	}

	return nil
}

// untagNodeResources untag node resources from a list of nodes
// If we want to untag more resources, modify this function appropriately
func (tc *TaggingController) untagNodeResources(obj interface{}) {
	// Unlike tagging/enqueue obj, when untag resource,
	// we can get off node object is to force conversion from obj to Node.
	// This is not desirable but NodeLister at this point should not contain
	// the deleted node
	var node *v1.Node
	var ok bool
	if node, ok = obj.(*v1.Node); !ok {
		utilruntime.HandleError(fmt.Errorf("unable to get Node object from %v", obj))
	}

	for _, resource := range tc.resources {
		if resource == opt.Instance {
			tc.untagEc2Instance(node)
		}
	}
}

// untagEc2Instances deletes the provided tags to each EC2 instances in
// the cluster. Return if a node is tagged or not
func (tc *TaggingController) untagEc2Instance(node *v1.Node) {
	instanceId, err := awsv1.KubernetesInstanceID(node.Spec.ProviderID).MapToAWSInstanceID()

	if err != nil {
		klog.Fatalf("Error in getting instanceID for node %s, error: %v", node.GetName(), err)
	} else {
		err := tc.cloud.UntagResource(string(instanceId), tc.tags)

		if err != nil {
			klog.Fatalf("Error in untagging EC2 instance for node %s, error: %v", node.GetName(), err)
		}
	}
}

func (tc *TaggingController) enqueueNode(obj interface{}) {
	var key string
	var err error
	if key, err = cache.MetaNamespaceKeyFunc(obj); err != nil {
		utilruntime.HandleError(err)
		return
	}
	tc.workqueue.Add(key)
}
