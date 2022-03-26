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
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	cloudprovider "k8s.io/cloud-provider"
	opt "k8s.io/cloud-provider-aws/pkg/controllers/options"
	awsv1 "k8s.io/cloud-provider-aws/pkg/providers/v1"
	"k8s.io/klog"
	"strings"
	"time"
)

const (
	// This is a prefix used to recognized if a node
	// in the workqueue is to be tagged or not
	tagKeyPrefix string = "ToBeTagged:"
)

// TaggingController is the controller implementation for tagging cluster resources.
// It periodically check for Node events (creating/deleting) to apply appropriate
// tags to resources.
type TaggingController struct {
	nodeInformer coreinformers.NodeInformer
	kubeClient   clientset.Interface
	cloud        *awsv1.Cloud
	workqueue    workqueue.RateLimitingInterface

	// Value controlling TaggingController monitoring period, i.e. how often does TaggingController
	// check node list. This value should be lower than nodeMonitorGracePeriod
	// set in controller-manager
	nodeMonitorPeriod time.Duration

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
		cloud:             awsCloud,
		nodeMonitorPeriod: nodeMonitorPeriod,
		tags:              tags,
		resources:         resources,
		workqueue:         workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "Tagging"),
	}

	// Use shared informer to listen to add/update/delete of nodes. Note that any nodes
	// that exist before tagging controller starts will show up in the update method
	tc.nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { tc.enqueueNode(obj, true) },
		UpdateFunc: func(oldObj, newObj interface{}) { tc.enqueueNode(newObj, true) },
		DeleteFunc: func(obj interface{}) { tc.enqueueNode(obj, false) },
	})

	return tc, nil
}

// Run will start the controller to tag resources attached to the cluster
// and untag resources detached from the cluster.
func (tc *TaggingController) Run(stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	defer tc.workqueue.ShutDown()

	klog.Infof("Starting the tagging controller")
	go wait.Until(tc.work, tc.nodeMonitorPeriod, stopCh)

	<-stopCh
}

// work is a long-running function that continuously
// call process() for each message on the workqueue
func (tc *TaggingController) work() {
	for tc.Process() {
	}
}

// Process reads each message in the queue and performs either
// tag or untag function on the Node object
func (tc *TaggingController) Process() bool {
	obj, shutdown := tc.workqueue.Get()
	if shutdown {
		return false
	}

	klog.Infof("Starting to process %v", obj)

	err := func(obj interface{}) error {
		defer tc.workqueue.Done(obj)

		var key string
		var ok bool
		if key, ok = obj.(string); !ok {
			tc.workqueue.Forget(obj)
			utilruntime.HandleError(fmt.Errorf("expected string in workqueue but got %#v", obj))
			return nil
		}

		var toBeTagged bool
		toBeTagged, key = tc.getActionAndKey(key)

		_, nodeName, err := cache.SplitMetaNamespaceKey(key)

		if err != nil {
			utilruntime.HandleError(fmt.Errorf("invalid resource key: %s", key))
			return nil
		}

		node, err := tc.nodeInformer.Lister().Get(nodeName)
		if err != nil {
			if apierrors.IsNotFound(err) {
				klog.Errorf("Unable to find a node with name %s", nodeName)
				return nil
			}

			return err
		}

		if toBeTagged {
			key = tagKeyPrefix + key
			if err := tc.tagNodesResources(node); err != nil {
				// Put the item back on the workqueue to handle any transient errors.
				tc.workqueue.AddRateLimited(key)
				return fmt.Errorf("error tagging '%s': %s, requeuing", key, err.Error())
			}
		} else {
			if err := tc.untagNodeResources(node); err != nil {
				tc.workqueue.AddRateLimited(key)
				return fmt.Errorf("error untagging '%s': %s, requeuing", key, err.Error())
			}
		}

		tc.workqueue.Forget(obj)
		klog.Infof("Finished processing %v", obj)
		return nil
	}(obj)

	if err != nil {
		klog.Errorf("Error occurred while processing %v", obj)
		utilruntime.HandleError(err)
	}

	return true
}

// tagNodesResources tag node resources from a list of nodes
// If we want to tag more resources, modify this function appropriately
func (tc *TaggingController) tagNodesResources(node *v1.Node) error {
	for _, resource := range tc.resources {
		switch resource {
		case opt.Instance:
			err := tc.tagEc2Instance(node)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// tagEc2Instances applies the provided tags to each EC2 instance in
// the cluster.
func (tc *TaggingController) tagEc2Instance(node *v1.Node) error {
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

	klog.Infof("Successfully tagged %s with %v", instanceId, tc.tags)

	return nil
}

// untagNodeResources untag node resources from a list of nodes
// If we want to untag more resources, modify this function appropriately
func (tc *TaggingController) untagNodeResources(node *v1.Node) error {
	for _, resource := range tc.resources {
		switch resource {
		case opt.Instance:
			err := tc.untagEc2Instance(node)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// untagEc2Instances deletes the provided tags to each EC2 instances in
// the cluster.
func (tc *TaggingController) untagEc2Instance(node *v1.Node) error {
	instanceId, err := awsv1.KubernetesInstanceID(node.Spec.ProviderID).MapToAWSInstanceID()

	if err != nil {
		klog.Errorf("Error in getting instanceID for node %s, error: %v", node.GetName(), err)
		return err
	} else {
		err := tc.cloud.UntagResource(string(instanceId), tc.tags)

		if err != nil {
			klog.Errorf("Error in untagging EC2 instance for node %s, error: %v", node.GetName(), err)
			return err
		}
	}

	klog.Infof("Successfully untagged %s with %v", instanceId, tc.tags)

	return nil
}

// enqueueNode takes in the object to enqueue to the workqueue and whether
// the object is to be tagged
func (tc *TaggingController) enqueueNode(obj interface{}, toBeTagged bool) {
	var key string
	var err error
	if key, err = cache.MetaNamespaceKeyFunc(obj); err != nil {
		utilruntime.HandleError(err)
		return
	}

	if toBeTagged {
		key = tagKeyPrefix + key
	}

	tc.workqueue.Add(key)

	klog.Infof("Added %s to the workqueue", key)
}

// getActionAndKey from the provided key, check if the object is to be tagged
// and extract that action together with the key
func (tc *TaggingController) getActionAndKey(key string) (bool, string) {
	toBeTagged := false
	if strings.HasPrefix(key, tagKeyPrefix) {
		toBeTagged = true
		key = strings.TrimPrefix(key, tagKeyPrefix)
	}

	return toBeTagged, key
}
