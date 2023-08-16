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
)

// NodeIpamControllerOptions contains the inputs that can
// be used in the nodeipam controller
type NodeIpamControllerOptions struct {
	RateLimit  float64
	BurstLimit int
}

// AddFlags add the additional flags for the controller
func (o *NodeIpamControllerOptions) AddFlags(fs *pflag.FlagSet) {
	fs.Float64Var(&o.RateLimit, "nodeipam-controller-rate-limit", o.RateLimit,
		"Steady-state rate limit (per sec) at which the controller processes items in its queue. A value of zero (default) disables rate limiting.")
	fs.IntVar(&o.BurstLimit, "nodeipam-controller-burst-limit", o.BurstLimit,
		"Burst limit at which the controller processes items in its queue. A value of zero (default) disables rate limiting.")
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
