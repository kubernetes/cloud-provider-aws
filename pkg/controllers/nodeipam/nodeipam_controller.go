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
	"fmt"
	"net"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"

	"golang.org/x/time/rate"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	coreinformers "k8s.io/client-go/informers/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	v1core "k8s.io/client-go/kubernetes/typed/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	cloudprovider "k8s.io/cloud-provider"
	"k8s.io/cloud-provider-aws/pkg/controllers/nodeipam/config"
	"k8s.io/cloud-provider-aws/pkg/controllers/nodeipam/ipam"
	cidrset "k8s.io/cloud-provider-aws/pkg/controllers/nodeipam/ipam/cidrset"
	awsv1 "k8s.io/cloud-provider-aws/pkg/providers/v1"
	controllersmetrics "k8s.io/component-base/metrics/prometheus/controllers"
	"k8s.io/klog/v2"
)

const (
	// The amount of time the nodecontroller polls on the list nodes endpoint.
	apiserverStartupGracePeriod = 10 * time.Minute
)

// nodePollInterval is used in listing node
// This is a variable instead of a const to enable testing.
var nodePollInterval = 10 * time.Second

// Controller is the controller that manages node ipam state.
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

	// nodeLister is able to list/get nodes and is populated by the shared informer passed to controller
	nodeLister corelisters.NodeLister
	// cluster cidrs as passed in during controller creation
	clusterCIDRs []*net.IPNet
	// for each entry in clusterCIDRs we maintain a list of what is used and what is not
	cidrSets []*cidrset.CidrSet
	// Channel that is used to pass updating Nodes and their reserved CIDRs to the background
	// This increases a throughput of CIDR assignment by not blocking on long operations.
	nodeCIDRUpdateChannel chan ipam.NodeReservedCIDRs
	recorder              record.EventRecorder
	// Keep a set of nodes that are currently being processed to avoid races in CIDR allocation
	lock              sync.Mutex
	nodesInProcessing sets.String
	cidrAllocator     ipam.CIDRAllocator
	ipv6CIDRAllocator ipam.IPv6CIDRAllocator
}

// NewNodeIpamController creates a NewNodeIpamController object
func NewNodeIpamController(
	nodeInformer coreinformers.NodeInformer,
	kubeClient clientset.Interface,
	cloud cloudprovider.Interface,
	nodeMonitorPeriod time.Duration,
	nodeIpamConfig config.NodeIPAMControllerConfiguration,
) (*Controller, error) {
	var err error
	awsCloud, ok := cloud.(*awsv1.Cloud)
	if !ok {
		err = fmt.Errorf("nodeipam controller does not support %v provider", cloud.ProviderName())
		return nil, err
	}

	var rateLimiter workqueue.RateLimiter
	var rateLimitEnabled bool
	if nodeIpamConfig.RateLimit > 0.0 && nodeIpamConfig.BurstLimit > 0 {
		klog.Infof("Rate limit enabled on controller with rate %f and burst %d.", nodeIpamConfig.RateLimit, nodeIpamConfig.BurstLimit)
		// This is the workqueue.DefaultControllerRateLimiter() but in case where throttling is enabled on the controller,
		// the rate and burst values are set to the provided values.
		rateLimiter = workqueue.NewMaxOfRateLimiter(
			workqueue.NewItemExponentialFailureRateLimiter(5*time.Millisecond, 1000*time.Second),
			&workqueue.BucketRateLimiter{Limiter: rate.NewLimiter(rate.Limit(nodeIpamConfig.RateLimit), nodeIpamConfig.BurstLimit)},
		)
		rateLimitEnabled = true
	} else {
		klog.Infof("Rate limit disabled on controller.")
		rateLimiter = workqueue.DefaultControllerRateLimiter()
		rateLimitEnabled = false
	}

	nc := &Controller{
		nodeInformer:      nodeInformer,
		kubeClient:        kubeClient,
		cloud:             awsCloud,
		workqueue:         workqueue.NewNamedRateLimitingQueue(rateLimiter, "NodeIpam"),
		nodesSynced:       nodeInformer.Informer().HasSynced,
		nodeMonitorPeriod: nodeMonitorPeriod,
		rateLimitEnabled:  rateLimitEnabled,
	}

	// for IPv6 only
	if !nodeIpamConfig.DualStack {
		ipam.RegisterMetrics()
		nc.ipv6CIDRAllocator, err = ipam.NewIPv6RangeAllocator(kubeClient, nodeInformer, awsCloud, rateLimiter, rateLimitEnabled, nodeMonitorPeriod)
		if err != nil {
			return nil, err
		}
	} else {
		eventBroadcaster := record.NewBroadcaster()
		recorder := eventBroadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: "cidrAllocator"})
		eventBroadcaster.StartStructuredLogging(0)
		klog.V(0).Infof("Sending events to api server.")
		eventBroadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: kubeClient.CoreV1().Events("")})
		allocatorParams := ipam.CIDRAllocatorParams{
			ClusterCIDRs:      nodeIpamConfig.ClusterCIDRs,
			NodeCIDRMaskSizes: []int{int(nodeIpamConfig.NodeCIDRMaskSize)},
		}
		nc = &Controller{
			kubeClient:            kubeClient,
			clusterCIDRs:          allocatorParams.ClusterCIDRs,
			cloud:                 awsCloud,
			cidrSets:              []*cidrset.CidrSet{},
			nodeLister:            nodeInformer.Lister(),
			nodesSynced:           nodeInformer.Informer().HasSynced,
			nodeCIDRUpdateChannel: make(chan ipam.NodeReservedCIDRs, ipam.CidrUpdateQueueSize),
			recorder:              recorder,
			nodesInProcessing:     sets.NewString(),
		}
		nodeList, err := listNodes(kubeClient)
		if err != nil {
			return nil, err
		}
		nc.cidrAllocator, err = ipam.NewCIDRRangeAllocator(kubeClient, nodeInformer, awsCloud, allocatorParams, nodeList)
		if err != nil {
			return nil, err
		}

	}
	return nc, nil
}

// Run starts an asynchronous loop that monitors the status of cluster nodes.
func (nc *Controller) Run(stopCh <-chan struct{}, controllerManagerMetrics *controllersmetrics.ControllerManagerMetrics, dualStack bool) {
	defer utilruntime.HandleCrash()

	klog.Infof("Starting ipam controller")
	defer klog.Infof("Shutting down ipam controller")
	controllerManagerMetrics.ControllerStarted("nodeipam")
	defer controllerManagerMetrics.ControllerStopped("nodeipam")

	if !cache.WaitForNamedCacheSync("node", stopCh, nc.nodesSynced) {
		return
	}

	if !dualStack {
		go nc.ipv6CIDRAllocator.Run(stopCh)
	} else {
		go nc.cidrAllocator.Run(stopCh)
	}

	<-stopCh
}

func listNodes(kubeClient clientset.Interface) (*v1.NodeList, error) {
	var nodeList *v1.NodeList
	// We must poll because apiserver might not be up. This error causes
	// controller manager to restart.
	if pollErr := wait.Poll(nodePollInterval, apiserverStartupGracePeriod, func() (bool, error) {
		var err error
		nodeList, err = kubeClient.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{
			FieldSelector: fields.Everything().String(),
			LabelSelector: labels.Everything().String(),
		})
		if err != nil {
			klog.Errorf("Failed to list all nodes: %v", err)
			return false, nil
		}
		return true, nil
	}); pollErr != nil {
		return nil, fmt.Errorf("failed to list all nodes in %v, cannot proceed without updating CIDR map",
			apiserverStartupGracePeriod)
	}
	return nodeList, nil
}
