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

package nodeipam

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"golang.org/x/time/rate"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	cloudprovider "k8s.io/cloud-provider"
	awsv1 "k8s.io/cloud-provider-aws/pkg/providers/v1"
	"k8s.io/klog/v2"
)

// workItem contains the node and an action for that node
type workItem struct {
	node           *v1.Node
	action         func(node *v1.Node) error
	requeuingCount int
	enqueueTime    time.Time
}

type nodePatch struct {
	Spec     *nodePatchSpec     `json:"spec,omitempty"`
	Metadata *nodePatchMetadata `json:"metadata,omitempty"`
}

type nodePatchMetadata struct {
	Labels map[string]*string `json:"labels,omitempty"`
}

func (w workItem) String() string {
	return fmt.Sprintf("[Node: %s, RequeuingCount: %d, EnqueueTime: %s]", w.node.GetName(), w.requeuingCount, w.enqueueTime)
}

const (
	maxRequeuingCount = 9

	// The label for depicting total number of errors a work item encounter and succeed
	totalErrorsWorkItemErrorMetric = "total_errors"

	// The label for depicting total time when work item gets queued to processed
	workItemProcessingTimeWorkItemMetric = "work_item_processing_time"

	// The label for depicting total time when work item gets queued to dequeued
	workItemDequeuingTimeWorkItemMetric = "work_item_dequeuing_time"

	// The label for depicting total number of errors a work item encounter and fail
	errorsAfterRetriesExhaustedWorkItemErrorMetric = "errors_after_retries_exhausted"
)

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

	rateLimitEnabled bool
}

// NewNodeIpamController creates a NewNodeIpamController object
func NewNodeIpamController(
	nodeInformer coreinformers.NodeInformer,
	kubeClient clientset.Interface,
	cloud cloudprovider.Interface,
	nodeMonitorPeriod time.Duration,
	rateLimit float64,
	burstLimit int) (*Controller, error) {

	awsCloud, ok := cloud.(*awsv1.Cloud)
	if !ok {
		err := fmt.Errorf("nodeipam controller does not support %v provider", cloud.ProviderName())
		return nil, err
	}

	var rateLimiter workqueue.RateLimiter
	var rateLimitEnabled bool
	if rateLimit > 0.0 && burstLimit > 0 {
		klog.Infof("Rate limit enabled on controller with rate %f and burst %d.", rateLimit, burstLimit)
		// This is the workqueue.DefaultControllerRateLimiter() but in case where throttling is enabled on the controller,
		// the rate and burst values are set to the provided values.
		rateLimiter = workqueue.NewMaxOfRateLimiter(
			workqueue.NewItemExponentialFailureRateLimiter(5*time.Millisecond, 1000*time.Second),
			&workqueue.BucketRateLimiter{Limiter: rate.NewLimiter(rate.Limit(rateLimit), burstLimit)},
		)
		rateLimitEnabled = true
	} else {
		klog.Infof("Rate limit disabled on controller.")
		rateLimiter = workqueue.DefaultControllerRateLimiter()
		rateLimitEnabled = false
	}

	registerMetrics()
	nc := &Controller{
		nodeInformer:      nodeInformer,
		kubeClient:        kubeClient,
		cloud:             awsCloud,
		workqueue:         workqueue.NewNamedRateLimitingQueue(rateLimiter, "NodeIpam"),
		nodesSynced:       nodeInformer.Informer().HasSynced,
		nodeMonitorPeriod: nodeMonitorPeriod,
		rateLimitEnabled:  rateLimitEnabled,
	}

	// Use shared informer to listen to add/update/delete of nodes. Note that any nodes
	// that exist before nodeipam controller starts will show up in the update method
	nc.nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			node := obj.(*v1.Node)
			nc.enqueueNode(node, nc.prefixNodeResource)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			node := newObj.(*v1.Node)
			// Check if nodeipam is required by inspecting the labels. This check here prevents us from putting a tagged node into the
			// work queue. We check this again before nodeipam the node to make sure that between when a node was put in the work queue
			// and when it gets prefixed, there might be another event which put the same item in the work queue
			// (since the node won't have the labels yet) and hence prevents us from making an unnecessary EC2 call.
			if !nc.isPrefixNodeRequired(node) {
				klog.Infof("Skip putting node %s in work queue since it was already prefixed earlier.", node.GetName())
				return
			}

			nc.enqueueNode(node, nc.prefixNodeResource)
		},
	})

	return nc, nil
}

// Run will start the controller to add write the prefix from the network interface to the node
func (nc *Controller) Run(stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	defer nc.workqueue.ShutDown()

	// Wait for the caches to be synced before starting workers
	klog.Info("Waiting for informer caches to sync")
	if ok := cache.WaitForCacheSync(stopCh, nc.nodesSynced); !ok {
		klog.Errorf("failed to wait for caches to sync")
		return
	}

	klog.Infof("Starting the nodeipam controller")
	go wait.Until(nc.work, nc.nodeMonitorPeriod, stopCh)

	<-stopCh
}

// work is a long-running function that continuously
// call process() for each message on the workqueue
func (nc *Controller) work() {
	for nc.process() {
	}
}

// process reads each message in the queue and performs either
// add prefix to kubernetes node object
func (nc *Controller) process() bool {
	obj, shutdown := nc.workqueue.Get()
	if shutdown {
		return false
	}

	klog.Infof("Starting to process %s", obj)

	err := func(obj interface{}) error {
		defer nc.workqueue.Done(obj)

		workItem, ok := obj.(*workItem)
		if !ok {
			nc.workqueue.Forget(obj)
			err := fmt.Errorf("expected workItem in workqueue but got %s", obj)
			utilruntime.HandleError(err)
			return nil
		}

		timeTaken := time.Since(workItem.enqueueTime).Seconds()
		recordWorkItemLatencyMetrics(workItemDequeuingTimeWorkItemMetric, timeTaken)
		klog.Infof("Dequeuing latency %s", timeTaken)

		instanceID, err := awsv1.KubernetesInstanceID(workItem.node.Spec.ProviderID).MapToAWSInstanceID()
		if err != nil {
			err = fmt.Errorf("Error in getting instanceID for node %s, error: %v", workItem.node.GetName(), err)
			utilruntime.HandleError(err)
			return nil
		}
		klog.Infof("Instance ID of work item %s is %s", workItem, instanceID)

		if awsv1.IsFargateNode(string(instanceID)) {
			klog.Infof("Skip processing the node %s since it is a Fargate node", instanceID)
			nc.workqueue.Forget(obj)
			return nil
		}

		err = workItem.action(workItem.node)

		if err != nil {
			if workItem.requeuingCount < maxRequeuingCount {
				// Put the item back on the workqueue to handle any transient errors.
				workItem.requeuingCount++
				nc.workqueue.AddRateLimited(workItem)

				recordWorkItemErrorMetrics(totalErrorsWorkItemErrorMetric, string(instanceID))
				return fmt.Errorf("error processing work item '%v': %s, requeuing count %d", workItem, err.Error(), workItem.requeuingCount)
			}

			klog.Errorf("error processing work item %s: %s, requeuing count exceeded", workItem, err.Error())
			recordWorkItemErrorMetrics(errorsAfterRetriesExhaustedWorkItemErrorMetric, string(instanceID))
		} else {
			klog.Infof("Finished processing %s", workItem)
			timeTaken = time.Since(workItem.enqueueTime).Seconds()
			recordWorkItemLatencyMetrics(workItemProcessingTimeWorkItemMetric, timeTaken)
			klog.Infof("Processing latency %s", timeTaken)
		}

		nc.workqueue.Forget(obj)
		return nil
	}(obj)

	if err != nil {
		klog.Errorf("Error occurred while processing %s", obj)
		utilruntime.HandleError(err)
	}

	return true
}

func (nc *Controller) prefixNodeResource(node *v1.Node) error {
	if node.Spec.ProviderID == "" {
		klog.Infof("Node %q has empty provider ID", node.Name)
		return nil
	}

	// aws:///eu-central-1a/i-07577a7bcf3e576f2
	instanceID, _ := awsv1.KubernetesInstanceID(node.Spec.ProviderID).MapToAWSInstanceID()
	eni, err := nc.cloud.DescribeNetworkInterfaces(
		&ec2.DescribeNetworkInterfacesInput{
			Filters: []*ec2.Filter{
				{
					Name: ptrTo("attachment.instance-id"),
					Values: []*string{
						ptrTo(string(instanceID)),
					},
				},
			},
		})
	if err != nil {
		return err
	}

	if len(eni.Ipv6Prefixes) != 1 {
		return fmt.Errorf("unexpected amount of ipv6 prefixes on interface %q: %v", *eni.NetworkInterfaceId, len(eni.Ipv6Prefixes))
	}

	ipv6Address := aws.StringValue(eni.Ipv6Prefixes[0].Ipv6Prefix)
	if err := patchNodePodCIDRs(nc.kubeClient, node, ipv6Address); err != nil {
		return err
	}
	klog.Infof("Successfully prefixed node %s with %v.", node.GetName(), ipv6Address)
	return nil
}

type nodePatchSpec struct {
	PodCIDR  string   `json:"podCIDR,omitempty"`
	PodCIDRs []string `json:"podCIDRs,omitempty"`
}

// enqueueNode takes in the object and an
// action for the object for a workitem and enqueue to the workqueue
func (nc *Controller) enqueueNode(node *v1.Node, action func(node *v1.Node) error) {
	item := &workItem{
		node:           node,
		action:         action,
		requeuingCount: 0,
		enqueueTime:    time.Now(),
	}

	if nc.rateLimitEnabled {
		nc.workqueue.AddRateLimited(item)
		klog.Infof("Added %s to the workqueue (rate-limited)", item)
	} else {
		nc.workqueue.Add(item)
		klog.Infof("Added %s to the workqueue (without any rate-limit)", item)
	}
}

// patchNodePodCIDRs patches the node podCIDR to the specified value.
func patchNodePodCIDRs(kubeClient clientset.Interface, node *corev1.Node, cidr string) error {
	klog.Infof("assigning cidr %q to node %q", cidr, node.ObjectMeta.Name)
	nodePatchSpec := &nodePatchSpec{
		PodCIDR:  cidr,
		PodCIDRs: []string{cidr},
	}
	nodePatch := &nodePatch{
		Spec: nodePatchSpec,
	}
	nodePatchJson, err := json.Marshal(nodePatch)
	if err != nil {
		return fmt.Errorf("error building node patch: %v", err)
	}

	klog.V(2).Infof("sending patch for node %q: %q", node.Name, string(nodePatchJson))

	_, err = kubeClient.CoreV1().Nodes().Patch(context.TODO(), node.Name, types.StrategicMergePatchType, nodePatchJson, metav1.PatchOptions{})
	if err != nil {
		return fmt.Errorf("error applying patch to node: %v", err)
	}

	return nil
}

func (nc *Controller) isPrefixNodeRequired(node *v1.Node) bool {
	if node.Spec.PodCIDR == "" && node.Spec.PodCIDRs == nil {
		return true
	}
	return false
}

// ptrTo returns a pointer to a copy of any value.
func ptrTo[T any](v T) *T {
	return &v
}
