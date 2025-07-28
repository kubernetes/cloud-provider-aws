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
	"crypto/md5"
	"fmt"
	"sort"
	"strings"
	"time"

	"golang.org/x/time/rate"
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
	nodehelpers "k8s.io/cloud-provider/node/helpers"
	_ "k8s.io/component-base/metrics/prometheus/workqueue" // enable prometheus provider for workqueue metrics
	"k8s.io/klog/v2"

	"k8s.io/cloud-provider-aws/pkg/providers/v1/variant"
)

func init() {
	registerMetrics()
}

// taggingControllerNode contains the node details required for tag/untag of node resources.
type taggingControllerNode struct {
	providerID string
	name       string
}

// workItem contains the node name, provider id and an action for that node.
type workItem struct {
	name       string
	providerID string
	action     string
}

func (w workItem) String() string {
	return fmt.Sprintf("[Node: %s, Action: %s]", w.name, w.action)
}

const (
	taggingControllerLabelKey = "k8s.io/cloud-provider-aws"

	maxRequeuingCount = 9

	// The label for depicting total number of errors a work item encounter and succeed
	totalErrorsWorkItemErrorMetric = "total_errors"

	// The label for depicting total number of errors a work item encounter and fail
	errorsAfterRetriesExhaustedWorkItemErrorMetric = "errors_after_retries_exhausted"

	// The period of time after Node creation to retry tagging due to eventual consistency of the CreateTags API.
	newNodeEventualConsistencyGracePeriod = time.Minute * 5

	addTag = "ADD"

	deleteTag = "DELETE"
)

// Controller is the controller implementation for tagging cluster resources.
// It periodically checks for Node events (creating/deleting) to apply/delete appropriate
// tags to resources.
type Controller struct {
	nodeInformer coreinformers.NodeInformer
	kubeClient   clientset.Interface
	cloud        *awsv1.Cloud
	workqueue    workqueue.RateLimitingInterface
	nodesSynced  cache.InformerSynced

	// Value controlling Controller monitoring period, i.e. how often does Controller
	// check node list. This value should be lower than nodeMonitorGracePeriod
	// set in controller-manager
	nodeMonitorPeriod time.Duration

	// Representing the user input for tags
	tags map[string]string

	// Representing the resources to tag
	resources []string

	rateLimitEnabled bool
	workerCount      int
	batchingEnabled  bool
}

// NewTaggingController creates a NewTaggingController object
func NewTaggingController(
	nodeInformer coreinformers.NodeInformer,
	kubeClient clientset.Interface,
	cloud cloudprovider.Interface,
	nodeMonitorPeriod time.Duration,
	tags map[string]string,
	resources []string,
	rateLimit float64,
	burstLimit int,
	workerCount int,
	batchingEnabled bool) (*Controller, error) {
	awsCloud, ok := cloud.(*awsv1.Cloud)
	if !ok {
		err := fmt.Errorf("tagging controller does not support %v provider", cloud.ProviderName())
		return nil, err
	}

	var rateLimiter workqueue.TypedRateLimiter[any]
	var rateLimitEnabled bool
	if rateLimit > 0.0 && burstLimit > 0 {
		klog.Infof("Rate limit enabled on controller with rate %f and burst %d.", rateLimit, burstLimit)
		// This is the workqueue.DefaultControllerRateLimiter() but in case where throttling is enabled on the controller,
		// the rate and burst values are set to the provided values.
		rateLimiter = workqueue.NewTypedMaxOfRateLimiter(
			workqueue.NewTypedItemExponentialFailureRateLimiter[any](5*time.Millisecond, 1000*time.Second),
			&workqueue.TypedBucketRateLimiter[any]{Limiter: rate.NewLimiter(rate.Limit(rateLimit), burstLimit)},
		)
		rateLimitEnabled = true
	} else {
		klog.Infof("Rate limit disabled on controller.")
		rateLimiter = workqueue.DefaultTypedControllerRateLimiter[any]()
		rateLimitEnabled = false
	}

	tc := &Controller{
		nodeInformer: nodeInformer,
		kubeClient:   kubeClient,
		cloud:        awsCloud,
		tags:         tags,
		resources:    resources,
		workqueue: workqueue.NewTypedRateLimitingQueueWithConfig[any](rateLimiter, workqueue.TypedRateLimitingQueueConfig[any]{
			Name: TaggingControllerClientName,
		}),
		nodesSynced:       nodeInformer.Informer().HasSynced,
		nodeMonitorPeriod: nodeMonitorPeriod,
		rateLimitEnabled:  rateLimitEnabled,
		workerCount:       workerCount,
		batchingEnabled:   batchingEnabled,
	}

	// Use shared informer to listen to add/update/delete of nodes. Note that any nodes
	// that exist before tagging controller starts will show up in the update method
	tc.nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			node := obj.(*v1.Node)
			tc.enqueueNode(node, addTag)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			node := newObj.(*v1.Node)
			// Check if tagging is required by inspecting the labels. This check here prevents us from putting a tagged node into the
			// work queue. We check this again before tagging the node to make sure that between when a node was put in the work queue
			// and when it gets tagged, there might be another event which put the same item in the work queue
			// (since the node won't have the labels yet) and hence prevents us from making an unnecessary EC2 call.
			if !tc.isTaggingRequired(node) {
				klog.V(3).Infof("Skip putting node %s in work queue since it was already tagged earlier.", node.GetName())
				return
			}

			tc.enqueueNode(node, addTag)
		},
		DeleteFunc: func(obj interface{}) {
			node := obj.(*v1.Node)
			tc.enqueueNode(node, deleteTag)
		},
	})

	return tc, nil
}

// Run will start the controller to tag resources attached to the cluster
// and untag resources detached from the cluster.
func (tc *Controller) Run(ctx context.Context) {
	defer utilruntime.HandleCrash()
	defer tc.workqueue.ShutDown()

	// Wait for the caches to be synced before starting workers
	klog.Info("Waiting for informer caches to sync")
	if ok := cache.WaitForCacheSync(ctx.Done(), tc.nodesSynced); !ok {
		klog.Errorf("failed to wait for caches to sync")
		return
	}

	klog.Infof("Starting the tagging controller")
	for i := 0; i < tc.workerCount; i++ {
		go wait.UntilWithContext(ctx, func(ctx context.Context) { tc.work(ctx) }, tc.nodeMonitorPeriod)
	}

	<-ctx.Done()
}

// work is a long-running function that continuously
// call process() for each message on the workqueue
func (tc *Controller) work(ctx context.Context) {
	for tc.process(ctx) {
	}
}

// process reads each message in the queue and performs either
// tag or untag function on the Node object
func (tc *Controller) process(ctx context.Context) bool {
	obj, shutdown := tc.workqueue.Get()
	if shutdown {
		return false
	}

	klog.Infof("Starting to process %s", obj)

	err := func(obj interface{}) error {
		defer tc.workqueue.Done(obj)

		workItem, ok := obj.(workItem)
		if !ok {
			tc.workqueue.Forget(obj)
			err := fmt.Errorf("expected workItem in workqueue but got %s", obj)
			utilruntime.HandleError(err)
			return nil
		}

		instanceID, err := awsv1.KubernetesInstanceID(workItem.providerID).MapToAWSInstanceID()
		if err != nil {
			err = fmt.Errorf("error in getting instanceID for node %s, error: %v", workItem.name, err)
			utilruntime.HandleError(err)
			return nil
		}
		klog.Infof("Instance ID of work item %s is %s", workItem, instanceID)

		if variant.IsVariantNode(string(instanceID)) {
			klog.Infof("Skip processing the node %s since it is a %s node",
				instanceID, variant.NodeType(string(instanceID)))
			tc.workqueue.Forget(obj)
			return nil
		}
		if workItem.action == addTag {
			err = tc.tagNodesResources(ctx, &taggingControllerNode{
				name:       workItem.name,
				providerID: workItem.providerID,
			})
		} else {
			err = tc.untagNodeResources(ctx, &taggingControllerNode{
				name:       workItem.name,
				providerID: workItem.providerID,
			})
		}
		if err != nil {
			numRetries := tc.workqueue.NumRequeues(workItem)
			if numRetries < maxRequeuingCount {
				// Put the item back on the workqueue to handle any transient errors.
				tc.workqueue.AddRateLimited(workItem)

				recordWorkItemErrorMetrics(totalErrorsWorkItemErrorMetric, string(instanceID))
				return fmt.Errorf("error processing work item '%v': %s, requeuing count %d", workItem, err.Error(), numRetries)
			}

			klog.Errorf("error processing work item %s: %s, requeuing count exceeded", workItem, err.Error())
			recordWorkItemErrorMetrics(errorsAfterRetriesExhaustedWorkItemErrorMetric, string(instanceID))
		} else {
			klog.Infof("Finished processing %s", workItem)
		}

		tc.workqueue.Forget(obj)
		return nil
	}(obj)

	if err != nil {
		klog.Errorf("Error occurred while processing %s", obj)
		utilruntime.HandleError(err)
	}

	return true
}

// tagNodesResources tag node resources
// If we want to tag more resources, modify this function appropriately
func (tc *Controller) tagNodesResources(ctx context.Context, node *taggingControllerNode) error {
	for _, resource := range tc.resources {
		switch resource {
		case opt.Instance:
			v1node, err := tc.nodeInformer.Lister().Get(node.name)
			if err != nil {
				// If node not found, just ignore it as its okay to not add tags when the node object is deleted.
				if apierrors.IsNotFound(err) {
					return nil
				}
				return err
			}
			err = tc.tagEc2Instance(ctx, v1node)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// tagEc2Instances applies the provided tags to each EC2 instance in
// the cluster.
func (tc *Controller) tagEc2Instance(ctx context.Context, node *v1.Node) error {
	if !tc.isTaggingRequired(node) {
		klog.Infof("Skip tagging node %s since it was already tagged earlier.", node.GetName())
		return nil
	}
	var err error
	instanceID, _ := awsv1.KubernetesInstanceID(node.Spec.ProviderID).MapToAWSInstanceID()
	if tc.batchingEnabled {
		err = tc.cloud.TagResourceBatch(ctx, string(instanceID), tc.tags)
	} else {
		err = tc.cloud.TagResource(ctx, string(instanceID), tc.tags)
	}

	if err != nil {
		if awsv1.IsAWSErrorInstanceNotFound(err) {
			// This can happen for two reasons.
			// 1. The CreateTags API is eventually consistent. In rare cases, a newly-created instance may not be taggable for a short period.
			//    We will re-queue the event and retry.
			if isNodeWithinEventualConsistencyGracePeriod(node) {
				return fmt.Errorf("EC2 instance %s for node %s does not exist, but node is within eventual consistency grace period", instanceID, node.GetName())
			}
			// 2. The event in our workQueue is stale, and the instance no longer exists.
			//    Tagging will never succeed, and the event should not be re-queued.
			klog.Infof("Skip tagging since EC2 instance %s for node %s does not exist", instanceID, node.GetName())
			return nil
		}
		klog.Errorf("Error in tagging EC2 instance %s for node %s, error: %v", instanceID, node.GetName(), err)
		return err
	}

	labels := map[string]string{taggingControllerLabelKey: tc.getChecksumOfTags()}
	klog.Infof("Successfully tagged %s with %v. Labeling the nodes with tagging controller labels now.", instanceID, tc.tags)
	if !nodehelpers.AddOrUpdateLabelsOnNode(tc.kubeClient, labels, node) {
		klog.Errorf("Couldn't apply labels %s to node %s.", labels, node.GetName())
		return fmt.Errorf("couldn't apply labels %s to node %s", labels, node.GetName())
	}

	klog.Infof("Successfully labeled node %s with %v.", node.GetName(), labels)

	if tc.isInitialTag(node) {
		initialNodeTaggingDelay.Observe(time.Since(node.CreationTimestamp.Time).Seconds())
	}

	return nil
}

// untagNodeResources untag node resources
// If we want to untag more resources, modify this function appropriately
func (tc *Controller) untagNodeResources(ctx context.Context, node *taggingControllerNode) error {
	for _, resource := range tc.resources {
		switch resource {
		case opt.Instance:
			err := tc.untagEc2Instance(ctx, node)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// untagEc2Instances deletes the provided tags to each EC2 instances in
// the cluster.
func (tc *Controller) untagEc2Instance(ctx context.Context, node *taggingControllerNode) error {
	instanceID, _ := awsv1.KubernetesInstanceID(node.providerID).MapToAWSInstanceID()

	var err error
	if tc.batchingEnabled {
		err = tc.cloud.UntagResourceBatch(ctx, string(instanceID), tc.tags)
	} else {
		err = tc.cloud.UntagResource(ctx, string(instanceID), tc.tags)
	}

	if err != nil {
		klog.Errorf("Error in untagging EC2 instance %s for node %s, error: %v", instanceID, node.name, err)
		return err
	}

	klog.Infof("Successfully untagged %s with %v", instanceID, tc.tags)

	return nil
}

// enqueueNode takes in the object and an
// action for the object for a workitem and enqueue to the workqueue
func (tc *Controller) enqueueNode(node *v1.Node, action string) {
	// if the struct has fields which are all comparable then the workqueue add will handle make sure multiple adds of the same object
	// will only have one item in the workqueue.
	item := workItem{
		name:       node.GetName(),
		providerID: node.Spec.ProviderID,
		action:     action,
	}

	if tc.rateLimitEnabled {
		tc.workqueue.AddRateLimited(item)
		klog.Infof("Added %s to the workqueue (rate-limited)", item)
	} else {
		tc.workqueue.Add(item)
		klog.Infof("Added %s to the workqueue (without any rate-limit)", item)
	}
}

func (tc *Controller) isInitialTag(node *v1.Node) bool {
	_, ok := node.Labels[taggingControllerLabelKey]
	return !ok
}

func (tc *Controller) isTaggingRequired(node *v1.Node) bool {
	if node.Labels == nil {
		return true
	}

	if labelValue, ok := node.Labels[taggingControllerLabelKey]; !ok || labelValue != tc.getChecksumOfTags() {
		return true
	}

	return false
}

func (tc *Controller) getChecksumOfTags() string {
	tags := []string{}
	for key, value := range tc.tags {
		tags = append(tags, key+"="+value)
	}
	sort.Strings(tags)
	return fmt.Sprintf("%x", md5.Sum([]byte(strings.Join(tags, ","))))
}

func isNodeWithinEventualConsistencyGracePeriod(node *v1.Node) bool {
	return time.Since(node.CreationTimestamp.Time) < newNodeEventualConsistencyGracePeriod
}
