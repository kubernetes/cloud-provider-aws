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

	cloudprovider "k8s.io/cloud-provider"
	"k8s.io/cloud-provider/app"
	cloudcontrollerconfig "k8s.io/cloud-provider/app/config"
	genericcontrollermanager "k8s.io/controller-manager/app"
	"k8s.io/controller-manager/controller"
	"k8s.io/klog/v2"

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
}

// StartNodeIpamControllerWrapper is used to take cloud config as input and start the nodeipam controller
func (nc *ControllerWrapper) StartNodeIpamControllerWrapper(initContext app.ControllerInitContext, completedConfig *cloudcontrollerconfig.CompletedConfig, cloud cloudprovider.Interface) app.InitFunc {
	return func(ctx context.Context, controllerContext genericcontrollermanager.ControllerContext) (controller.Interface, bool, error) {
		return nc.startNodeIpamController(ctx, initContext, completedConfig, cloud)
	}
}

func (nc *ControllerWrapper) startNodeIpamController(ctx context.Context, initContext app.ControllerInitContext, completedConfig *cloudcontrollerconfig.CompletedConfig, cloud cloudprovider.Interface) (controller.Interface, bool, error) {
	err := nc.Options.Validate()
	if err != nil {
		klog.Fatalf("NodeIpam controller inputs are not properly set: %v", err)
	}

	// Start the Controller
	nodeipamcontroller, err := NewNodeIpamController(
		completedConfig.SharedInformers.Core().V1().Nodes(),
		completedConfig.ClientBuilder.ClientOrDie(initContext.ClientName),
		cloud,
		completedConfig.ComponentConfig.KubeCloudShared.NodeMonitorPeriod.Duration,
		nc.Options.RateLimit,
		nc.Options.BurstLimit)

	if err != nil {
		klog.Warningf("failed to start nodeipam controller: %s", err)
		return nil, false, nil
	}

	go nodeipamcontroller.Run(ctx.Done())

	return nil, true, nil
}
