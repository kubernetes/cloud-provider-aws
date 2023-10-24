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

package options

import (
	"fmt"

	"github.com/spf13/pflag"
	"k8s.io/cloud-provider-aws/pkg/controllers/nodeipam/config"
)

const (

	// DefaultNodeMaskCIDR is default mask size for IPv4 node cidr
	DefaultNodeMaskCIDR = int32(24)
)

// NodeIpamControllerOptions contains the inputs that can
// be used in the nodeipam controller
type NodeIpamControllerOptions struct {
	RateLimit  float64
	BurstLimit int
	DualStack  bool
	// NodeCIDRMaskSize is the mask size for node cidr in single-stack cluster.
	// This can be used only with single stack clusters and is incompatible with dual stack clusters.
	NodeCIDRMaskSize int32
}

// AddFlags add the additional flags for the controller
func (o *NodeIpamControllerOptions) AddFlags(fs *pflag.FlagSet) {
	fs.Float64Var(&o.RateLimit, "nodeipam-controller-rate-limit", o.RateLimit,
		"Steady-state rate limit (per sec) at which the controller processes items in its queue. A value of zero (default) disables rate limiting.")
	fs.IntVar(&o.BurstLimit, "nodeipam-controller-burst-limit", o.BurstLimit,
		"Burst limit at which the controller processes items in its queue. A value of zero (default) disables rate limiting.")
	fs.BoolVar(&o.DualStack, "dualstack", o.DualStack, "IP mode in which the controller runs, can be either dualstack or IPv6. A value of false (default) enables IPv6 only mode.")
	fs.Int32Var(&o.NodeCIDRMaskSize, "node-cidr-mask-size", o.NodeCIDRMaskSize, "Mask size for node cidr in cluster. Default is 24 for IPv4")
}

// Validate checks for errors from user input
func (o *NodeIpamControllerOptions) Validate() error {

	if o.RateLimit < 0.0 {
		return fmt.Errorf("--nodeipam-controller-rate-limit should not be less than zero")
	}

	if o.BurstLimit < 0 {
		return fmt.Errorf("--nodeipam-controller-burst-limit should not be less than zero")
	}

	return nil
}

// ApplyTo fills up NodeIpamController config with options.
func (o *NodeIpamControllerOptions) ApplyTo(cfg *config.NodeIPAMControllerConfiguration) error {
	if o == nil {
		return nil
	}

	cfg.DualStack = o.DualStack
	if o.NodeCIDRMaskSize == 0 {
		cfg.NodeCIDRMaskSize = DefaultNodeMaskCIDR
	} else {
		cfg.NodeCIDRMaskSize = o.NodeCIDRMaskSize

	}
	return nil
}
