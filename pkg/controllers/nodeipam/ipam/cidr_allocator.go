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
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"k8s.io/klog/v2"

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	informers "k8s.io/client-go/informers/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	v1core "k8s.io/client-go/kubernetes/typed/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	cidrset "k8s.io/cloud-provider-aws/pkg/controllers/nodeipam/ipam/cidrset"
	awsv1 "k8s.io/cloud-provider-aws/pkg/providers/v1"
	nodeutil "k8s.io/cloud-provider-aws/pkg/util"
)

// cidrs are reserved, then node resource is patched with them
// this type holds the reservation info for a node

// NodeReservedCIDRs holds the allocated CIDRs
type NodeReservedCIDRs struct {
	allocatedCIDRs []*net.IPNet
	nodeName       string
}

// TODO: figure out the good setting for those constants.
const (
	// The amount of time the nodecontroller polls on the list nodes endpoint.
	apiserverStartupGracePeriod = 10 * time.Minute

	// The no. of NodeSpec updates NC can process concurrently.
	cidrUpdateWorkers = 30

	// The max no. of NodeSpec updates that can be enqueued.
	CidrUpdateQueueSize = 5000

	// cidrUpdateRetries is the no. of times a NodeSpec update will be retried before dropping it.
	cidrUpdateRetries = 3

	// updateRetryTimeout is the time to wait before requeing a failed node for retry
	updateRetryTimeout = 250 * time.Millisecond

	// maxUpdateRetryTimeout is the maximum amount of time between timeouts.
	maxUpdateRetryTimeout = 5 * time.Second

	// updateMaxRetries is the max retries for a failed node
	updateMaxRetries = 10
)

// nodePollInterval is used in listing node
// This is a variable instead of a const to enable testing.
var nodePollInterval = 10 * time.Second

// CIDRAllocator is an interface implemented by things that know how
// to allocate/occupy/recycle CIDR for nodes.
type CIDRAllocator interface {
	// AllocateOrOccupyCIDR looks at the given node, assigns it a valid
	// CIDR if it doesn't currently have one or mark the CIDR as used if
	// the node already have one.
	AllocateOrOccupyCIDR(node *v1.Node) error
	// ReleaseCIDR releases the CIDR of the removed node
	ReleaseCIDR(node *v1.Node) error
	// Run starts all the working logic of the allocator.
	Run(stopCh <-chan struct{})
}

// CIDRAllocatorParams is parameters that's required for creating new
// cidr range allocator.
type CIDRAllocatorParams struct {
	// ClusterCIDRs is list of cluster cidrs
	ClusterCIDRs []*net.IPNet
	// NodeCIDRMaskSizes is list of node cidr mask sizes
	NodeCIDRMaskSizes []int
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

type rangeAllocator struct {
	client clientset.Interface
	// cluster cidrs as passed in during controller creation
	clusterCIDRs []*net.IPNet
	// for each entry in clusterCIDRs we maintain a list of what is used and what is not
	cidrSets []*cidrset.CidrSet
	// nodeLister is able to list/get nodes and is populated by the shared informer passed to controller
	nodeLister corelisters.NodeLister
	// nodesSynced returns true if the node shared informer has been synced at least once.
	nodesSynced cache.InformerSynced
	// Channel that is used to pass updating Nodes and their reserved CIDRs to the background
	// This increases a throughput of CIDR assignment by not blocking on long operations.
	nodeCIDRUpdateChannel chan NodeReservedCIDRs
	recorder              record.EventRecorder
	// Keep a set of nodes that are currently being processed to avoid races in CIDR allocation
	lock              sync.Mutex
	nodesInProcessing sets.String
	cloud             *awsv1.Cloud
}

// NewCIDRRangeAllocator returns a CIDRAllocator to allocate CIDRs for node (one from each of clusterCIDRs)
// Caller must ensure subNetMaskSize is not less than cluster CIDR mask size.
// Caller must always pass in a list of existing nodes so the new allocator.
// can initialize its CIDR map. NodeList is only nil in testing.
func NewCIDRRangeAllocator(client clientset.Interface, nodeInformer informers.NodeInformer, awsCloud *awsv1.Cloud, allocatorParams CIDRAllocatorParams, nodeList *v1.NodeList) (CIDRAllocator, error) {
	if client == nil {
		klog.Fatalf("kubeClient is nil when starting NodeController")
	}

	eventBroadcaster := record.NewBroadcaster()
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: "cidrAllocator"})
	eventBroadcaster.StartStructuredLogging(0)
	klog.V(0).Infof("Sending events to api server.")
	eventBroadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: client.CoreV1().Events("")})

	// create a cidrSet for each CIDR we operate on.
	// cidrSet are mapped to clusterCIDR by index
	cidrSets := make([]*cidrset.CidrSet, len(allocatorParams.ClusterCIDRs))
	for idx, cidr := range allocatorParams.ClusterCIDRs {
		cidrSet, err := cidrset.NewCIDRSet(cidr, allocatorParams.NodeCIDRMaskSizes[idx])
		if err != nil {
			return nil, err
		}
		cidrSets[idx] = cidrSet
	}

	ra := &rangeAllocator{
		client:                client,
		clusterCIDRs:          allocatorParams.ClusterCIDRs,
		cloud:                 awsCloud,
		cidrSets:              cidrSets,
		nodeLister:            nodeInformer.Lister(),
		nodesSynced:           nodeInformer.Informer().HasSynced,
		nodeCIDRUpdateChannel: make(chan NodeReservedCIDRs, CidrUpdateQueueSize),
		recorder:              recorder,
		nodesInProcessing:     sets.NewString(),
	}

	if nodeList != nil {
		for _, node := range nodeList.Items {
			if len(node.Spec.PodCIDRs) == 0 {
				klog.V(4).Infof("Node %v has no CIDR, ignoring", node.Name)
				continue
			}
			klog.V(4).Infof("Node %v has CIDR %s, occupying it in CIDR map", node.Name, node.Spec.PodCIDR)
			if err := ra.occupyCIDRs(&node); err != nil {
				// This will happen if:
				// 1. We find garbage in the podCIDRs field. Retrying is useless.
				// 2. CIDR out of range: This means a node CIDR has changed.
				// This error will keep crashing controller-manager.
				return nil, err
			}
		}
	}

	nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: nodeutil.CreateAddNodeHandler(ra.AllocateOrOccupyCIDR),
		UpdateFunc: nodeutil.CreateUpdateNodeHandler(func(_, newNode *v1.Node) error {
			// If the PodCIDRs list is not empty we either:
			// - already processed a Node that already had CIDRs after NC restarted
			//   (cidr is marked as used),
			// - already processed a Node successfully and allocated CIDRs for it
			//   (cidr is marked as used),
			// - already processed a Node but we did saw a "timeout" response and
			//   request eventually got through in this case we haven't released
			//   the allocated CIDRs (cidr is still marked as used).
			// There's a possible error here:
			// - NC sees a new Node and assigns CIDRs X,Y.. to it,
			// - Update Node call fails with a timeout,
			// - Node is updated by some other component, NC sees an update and
			//   assigns CIDRs A,B.. to the Node,
			// - Both CIDR X,Y.. and CIDR A,B.. are marked as used in the local cache,
			//   even though Node sees only CIDR A,B..
			// The problem here is that in in-memory cache we see CIDR X,Y.. as marked,
			// which prevents it from being assigned to any new node. The cluster
			// state is correct.
			// Restart of NC fixes the issue.
			if len(newNode.Spec.PodCIDRs) == 0 {
				return ra.AllocateOrOccupyCIDR(newNode)
			}
			return nil
		}),
		DeleteFunc: nodeutil.CreateDeleteNodeHandler(ra.ReleaseCIDR),
	})

	return ra, nil
}

func (r *rangeAllocator) Run(stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()

	klog.Infof("Starting range CIDR allocator")
	defer klog.Infof("Shutting down range CIDR allocator")

	if !cache.WaitForNamedCacheSync("cidrallocator", stopCh, r.nodesSynced) {
		return
	}

	for i := 0; i < cidrUpdateWorkers; i++ {
		go r.worker(stopCh)
	}

	<-stopCh
}

func (r *rangeAllocator) worker(stopChan <-chan struct{}) {
	for {
		select {
		case workItem, ok := <-r.nodeCIDRUpdateChannel:
			if !ok {
				klog.Warning("Channel nodeCIDRUpdateChannel was unexpectedly closed")
				return
			}
			if err := r.updateCIDRsAllocation(workItem); err != nil {
				// Requeue the failed node for update again.
				r.nodeCIDRUpdateChannel <- workItem
			}
		case <-stopChan:
			return
		}
	}
}

func (r *rangeAllocator) insertNodeToProcessing(nodeName string) bool {
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.nodesInProcessing.Has(nodeName) {
		return false
	}
	r.nodesInProcessing.Insert(nodeName)
	return true
}

func (r *rangeAllocator) removeNodeFromProcessing(nodeName string) {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.nodesInProcessing.Delete(nodeName)
}

// marks node.PodCIDRs[...] as used in allocator's tracked cidrSet
func (r *rangeAllocator) occupyCIDRs(node *v1.Node) error {
	defer r.removeNodeFromProcessing(node.Name)
	if len(node.Spec.PodCIDRs) == 0 {
		return nil
	}
	for idx, cidr := range node.Spec.PodCIDRs {
		_, podCIDR, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("failed to parse node %s, CIDR %s", node.Name, node.Spec.PodCIDR)
		}
		// If node has a pre allocate cidr that does not exist in our cidrs.
		// This will happen if cluster went from dualstack(multi cidrs) to non-dualstack
		// then we have now way of locking it
		if idx >= len(r.cidrSets) {
			return fmt.Errorf("node:%s has an allocated cidr: %v at index:%v that does not exist in cluster cidrs configuration", node.Name, cidr, idx)
		}

		if err := r.cidrSets[idx].Occupy(podCIDR); err != nil {
			return fmt.Errorf("failed to mark cidr[%v] at idx [%v] as occupied for node: %v: %v", podCIDR, idx, node.Name, err)
		}
	}
	return nil
}

// WARNING: If you're adding any return calls or defer any more work from this
// function you have to make sure to update nodesInProcessing properly with the
// disposition of the node when the work is done.
func (r *rangeAllocator) AllocateOrOccupyCIDR(node *v1.Node) error {
	if node == nil {
		return nil
	}
	if !r.insertNodeToProcessing(node.Name) {
		klog.V(2).Infof("Node %v is already in a process of CIDR assignment.", node.Name)
		return nil
	}

	if len(node.Spec.PodCIDRs) > 0 {
		return r.occupyCIDRs(node)
	}
	// allocate and queue the assignment
	allocated := NodeReservedCIDRs{
		nodeName:       node.Name,
		allocatedCIDRs: make([]*net.IPNet, len(r.cidrSets)),
	}

	for idx := range r.cidrSets {
		podCIDR, err := r.cidrSets[idx].AllocateNext()
		if err != nil {
			r.removeNodeFromProcessing(node.Name)
			nodeutil.RecordNodeStatusChange(r.recorder, node, "CIDRNotAvailable")
			return fmt.Errorf("failed to allocate cidr from cluster cidr at idx:%v: %v", idx, err)
		}
		allocated.allocatedCIDRs[idx] = podCIDR
	}

	//queue the assignment
	klog.V(4).Infof("Putting node %s with CIDR %v into the work queue", node.Name, allocated.allocatedCIDRs)
	r.nodeCIDRUpdateChannel <- allocated
	return nil
}

// ReleaseCIDR marks node.podCIDRs[...] as unused in our tracked cidrSets
func (r *rangeAllocator) ReleaseCIDR(node *v1.Node) error {
	if node == nil || len(node.Spec.PodCIDRs) == 0 {
		return nil
	}

	for idx, cidr := range node.Spec.PodCIDRs {
		_, podCIDR, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("failed to parse CIDR %s on Node %v: %v", cidr, node.Name, err)
		}

		// If node has a pre allocate cidr that does not exist in our cidrs.
		// This will happen if cluster went from dualstack(multi cidrs) to non-dualstack
		// then we have now way of locking it
		if idx >= len(r.cidrSets) {
			return fmt.Errorf("node:%s has an allocated cidr: %v at index:%v that does not exist in cluster cidrs configuration", node.Name, cidr, idx)
		}

		klog.V(4).Infof("release CIDR %s for node:%v", cidr, node.Name)
		if err = r.cidrSets[idx].Release(podCIDR); err != nil {
			return fmt.Errorf("error when releasing CIDR %v: %v", cidr, err)
		}
	}
	return nil
}

// updateCIDRsAllocation assigns CIDR to Node and sends an update to the API server.
func (r *rangeAllocator) updateCIDRsAllocation(data NodeReservedCIDRs) error {
	var err error
	var node *v1.Node
	defer r.removeNodeFromProcessing(data.nodeName)
	cidrsString := cidrsAsString(data.allocatedCIDRs)
	node, err = r.nodeLister.Get(data.nodeName)
	if err != nil {
		klog.Errorf("Failed while getting node %v for updating Node.Spec.PodCIDRs: %v", data.nodeName, err)
		return err
	}

	// if cidr list matches the proposed.
	// then we possibly updated this node
	// and just failed to ack the success.
	if len(node.Spec.PodCIDRs) == len(data.allocatedCIDRs) {
		match := true
		for idx, cidr := range cidrsString {
			if node.Spec.PodCIDRs[idx] != cidr {
				match = false
				break
			}
		}
		if match {
			klog.V(4).Infof("Node %v already has allocated CIDR %v. It matches the proposed one.", node.Name, data.allocatedCIDRs)
			return nil
		}
	}

	// node has cidrs, release the reserved
	if len(node.Spec.PodCIDRs) != 0 {
		klog.Errorf("Node %v already has a CIDR allocated %v. Releasing the new one.", node.Name, node.Spec.PodCIDRs)
		for idx, cidr := range data.allocatedCIDRs {
			if releaseErr := r.cidrSets[idx].Release(cidr); releaseErr != nil {
				klog.Errorf("Error when releasing CIDR idx:%v value: %v err:%v", idx, cidr, releaseErr)
			}
		}
		return nil
	}

	//  fetch ipv6 cidr address
	if node.Spec.ProviderID == "" {
		klog.Infof("Node %q has empty provider ID", node.Name)
		return nil
	}

	// aws:///eu-central-1a/i-07577a7bcf3e576f2
	instanceID, _ := awsv1.KubernetesInstanceID(node.Spec.ProviderID).MapToAWSInstanceID()
	eni, err := r.cloud.DescribeNetworkInterfaces(
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
	cidrsString = append(cidrsString, ipv6Address)

	// If we reached here, it means that the node has no CIDR currently assigned. So we set it.
	for i := 0; i < cidrUpdateRetries; i++ {
		if err = PatchNodePodCIDRs(r.client, node, cidrsString); err == nil {
			klog.Infof("Set node %v PodCIDR to %v", node.Name, cidrsString)
			return nil
		}
	}
	// failed release back to the pool
	klog.Errorf("Failed to update node %v PodCIDR to %v after multiple attempts: %v", node.Name, cidrsString, err)
	nodeutil.RecordNodeStatusChange(r.recorder, node, "CIDRAssignmentFailed")
	// We accept the fact that we may leak CIDRs here. This is safer than releasing
	// them in case when we don't know if request went through.
	// NodeController restart will return all falsely allocated CIDRs to the pool.
	if !apierrors.IsServerTimeout(err) {
		klog.Errorf("CIDR assignment for node %v failed: %v. Releasing allocated CIDR", node.Name, err)
		for idx, cidr := range data.allocatedCIDRs {
			if releaseErr := r.cidrSets[idx].Release(cidr); releaseErr != nil {
				klog.Errorf("Error releasing allocated CIDR for node %v: %v", node.Name, releaseErr)
			}
		}
	}
	return err
}

// converts a slice of cidrs into <c-1>,<c-2>,<c-n>
func cidrsAsString(inCIDRs []*net.IPNet) []string {
	outCIDRs := make([]string, len(inCIDRs))
	for idx, inCIDR := range inCIDRs {
		outCIDRs[idx] = inCIDR.String()
	}
	return outCIDRs
}
