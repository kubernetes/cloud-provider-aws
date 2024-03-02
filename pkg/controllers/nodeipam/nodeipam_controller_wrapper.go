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
	"strings"

	cloudprovider "k8s.io/cloud-provider"
	"k8s.io/cloud-provider/app"
	cloudcontrollerconfig "k8s.io/cloud-provider/app/config"
	genericcontrollermanager "k8s.io/controller-manager/app"
	"k8s.io/controller-manager/controller"
	"k8s.io/klog/v2"
	netutils "k8s.io/utils/net"

	"k8s.io/cloud-provider-aws/pkg/controllers/nodeipam/config"
	"k8s.io/cloud-provider-aws/pkg/controllers/options"
)

const (
	// NodeIpamControllerClientName is the name of the nodeipam controller
	NodeIpamControllerClientName = "nodeipam-controller"

	// NodeIpamControllerKey is the key used to register this controller
	NodeIpamControllerKey = "nodeipam"
)

// ControllerWrapper is the wrapper for the nodeipam controller
type ControllerWrapper struct {
	Options options.NodeIpamControllerOptions
	Config  config.NodeIPAMControllerConfiguration
}

// StartNodeIpamControllerWrapper is used to take cloud config as input and start the nodeipam controller
func (nc *ControllerWrapper) StartNodeIpamControllerWrapper(initContext app.ControllerInitContext, completedConfig *cloudcontrollerconfig.CompletedConfig, cloud cloudprovider.Interface) app.InitFunc {
	return func(ctx context.Context, controllerContext genericcontrollermanager.ControllerContext) (controller.Interface, bool, error) {
		return nc.startNodeIpamController(ctx, initContext, completedConfig, controllerContext, cloud)
	}
}

func (nc *ControllerWrapper) startNodeIpamController(ctx context.Context, initContext app.ControllerInitContext, completedConfig *cloudcontrollerconfig.CompletedConfig, controllerContext genericcontrollermanager.ControllerContext, cloud cloudprovider.Interface) (controller.Interface, bool, error) {
	err := nc.Options.Validate()
	if err != nil {
		klog.Fatalf("NodeIpam controller inputs are not properly set: %v", err)
	}

	nc.Config.ClusterCIDRs, _, err = processCIDRs(completedConfig.ComponentConfig.KubeCloudShared.ClusterCIDR)
	if err != nil {
		return nil, false, err
	}
	nc.Options.ApplyTo(&nc.Config)

	klog.Infof("Cluster CIDR: %s", nc.Config.ClusterCIDRs[0].String())
	klog.Infof("Running in dualstack mode: %t", nc.Config.DualStack)
	klog.Infof("Node CIDR mask size: %v", nc.Config.NodeCIDRMaskSize)

	// failure: more than cidrs is not allowed even with dual stack
	if len(nc.Config.ClusterCIDRs) > 1 {
		return nil, false, fmt.Errorf("len of clusters is:%v > more than 1 is not allowed for the nodeipam controller", len(nc.Config.ClusterCIDRs))
	}

	// Start the Controller
	nodeIpamController, err := NewNodeIpamController(
		completedConfig.SharedInformers.Core().V1().Nodes(),
		completedConfig.ClientBuilder.ClientOrDie(initContext.ClientName),
		cloud,
		completedConfig.ComponentConfig.KubeCloudShared.NodeMonitorPeriod.Duration,
		nc.Config)

	if err != nil {
		klog.Warningf("failed to start nodeipam controller: %s", err)
		return nil, false, nil
	}

	go nodeIpamController.Run(controllerContext.Stop, controllerContext.ControllerManagerMetrics, nc.Config.DualStack)

	return nil, true, nil
}

// processCIDRs is a helper function that works on a comma separated cidrs and returns
// a list of typed cidrs
// a flag if cidrs represents a dual stack
// error if failed to parse any of the cidrs
func processCIDRs(cidrsList string) ([]*net.IPNet, bool, error) {
	cidrsSplit := strings.Split(strings.TrimSpace(cidrsList), ",")

	cidrs, err := netutils.ParseCIDRs(cidrsSplit)
	if err != nil {
		return nil, false, err
	}

	// if cidrs has an error then the previous call will fail
	// safe to ignore error checking on next call
	dualstack, _ := netutils.IsDualStackCIDRs(cidrs)

	return cidrs, dualstack, nil
}
