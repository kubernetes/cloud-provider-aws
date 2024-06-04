package variant

import (
	"fmt"
	"k8s.io/cloud-provider-aws/pkg/providers/v1/awsnode"
	"net/url"
	"sync"

	v1 "k8s.io/api/core/v1"
	cloudprovider "k8s.io/cloud-provider"

	"github.com/aws/aws-sdk-go/aws/credentials"

	"k8s.io/cloud-provider-aws/pkg/providers/v1/config"
	"k8s.io/cloud-provider-aws/pkg/providers/v1/iface"
)

var variantsLock sync.Mutex
var variants = make(map[string]Variant)

// Variant is a slightly different type of node
type Variant interface {
	Initialize(cloudConfig *config.CloudConfig, credentials *credentials.Credentials,
		provider config.SDKProvider, ec2API iface.EC2, region string) error
	IsSupportedNode(nodeID awsnode.NodeID) bool
	NodeAddresses(nodeID awsnode.NodeID, vpcID string) ([]v1.NodeAddress, error)
	GetZone(nodeID awsnode.NodeID, vpcID, region string) (cloudprovider.Zone, error)
	InstanceExists(nodeID awsnode.NodeID, vpcID string) (bool, error)
	InstanceShutdown(nodeID awsnode.NodeID, vpcID string) (bool, error)
	InstanceTypeByProviderID(nodeID awsnode.NodeID) (string, error)
	NodeID(providerID url.URL) awsnode.NodeID
}

// RegisterVariant is used to register code that needs to be called for a specific variant
func RegisterVariant(name string, variant Variant) {
	variantsLock.Lock()
	defer variantsLock.Unlock()
	if _, found := variants[name]; found {
		panic(fmt.Sprintf("%q was registered twice", name))
	}
	variants[name] = variant
}

// IsVariantNode helps evaluate if a specific variant handles a given instance
func IsVariantNode(nodeID awsnode.NodeID) bool {
	variantsLock.Lock()
	defer variantsLock.Unlock()
	for _, v := range variants {
		if v.IsSupportedNode(nodeID) {
			return true
		}
	}
	return false
}

// NodeType returns the type name example: "fargate"
func NodeType(nodeID awsnode.NodeID) string {
	variantsLock.Lock()
	defer variantsLock.Unlock()
	for key, v := range variants {
		if v.IsSupportedNode(nodeID) {
			return key
		}
	}
	return ""
}

// GetVariant returns the interface that can then be used to handle a specific instance
func GetVariant(nodeID awsnode.NodeID) Variant {
	variantsLock.Lock()
	defer variantsLock.Unlock()
	for _, v := range variants {
		if v.IsSupportedNode(nodeID) {
			return v
		}
	}
	return nil
}

// GetNodeID returns the node id of the variant if a variant supports this particular provider id
// A return value of an empty string denotes no variant supported the node with this providerId.
func GetNodeID(providerID url.URL) awsnode.NodeID {
	variantsLock.Lock()
	defer variantsLock.Unlock()
	for _, v := range variants {
		if varID := v.NodeID(providerID); varID != "" {
			return varID
		}
	}
	return ""
}

// GetVariants returns the names of all the variants registered
func GetVariants() []Variant {
	variantsLock.Lock()
	defer variantsLock.Unlock()
	var values []Variant

	// Iterate over the map and collect all values
	for _, v := range variants {
		values = append(values, v)
	}
	return values
}
