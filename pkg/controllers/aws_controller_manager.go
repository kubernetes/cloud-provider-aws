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

package controllers

import (
	"context"
	"errors"
	cloudprovider "k8s.io/cloud-provider"
	taggingcontroller "k8s.io/cloud-provider-aws/pkg/controllers/tagging"
	"k8s.io/cloud-provider/app"
	cloudcontrollerconfig "k8s.io/cloud-provider/app/config"
	genericcontrollermanager "k8s.io/controller-manager/app"
	"k8s.io/controller-manager/controller"
	"k8s.io/klog/v2"
)

const (
	TaggingControllerClientName = "tagging-controller"
	TaggingControllerKey        = "tagging"
)

// BuildControllerInitializers is used to add new controllers built in this package to
// the existing list of controllers from cloud-provider
func BuildControllerInitializers() map[string]app.ControllerInitFuncConstructor {
	controllerInitializers := app.DefaultInitFuncConstructors

	taggingControllerConstructor := app.ControllerInitFuncConstructor{
		InitContext: app.ControllerInitContext{
			ClientName: TaggingControllerClientName,
		},
		Constructor: startTaggingControllerWrapper,
	}

	controllerInitializers[TaggingControllerKey] = taggingControllerConstructor

	// TODO: remove the following line to enable the route controller
	delete(controllerInitializers, "route")

	return controllerInitializers
}

// StartTaggingControllerWrapper is used to take cloud config as input and start the tagging controller
func startTaggingControllerWrapper(initContext app.ControllerInitContext, completedConfig *cloudcontrollerconfig.CompletedConfig, cloud cloudprovider.Interface) app.InitFunc {
	return func(ctx context.Context, controllerContext genericcontrollermanager.ControllerContext) (controller.Interface, bool, error) {
		return startTaggingController(ctx, initContext, completedConfig, cloud)
	}
}

func startTaggingController(ctx context.Context, initContext app.ControllerInitContext, completedConfig *cloudcontrollerconfig.CompletedConfig, cloud cloudprovider.Interface) (controller.Interface, bool, error) {
	if ok, error := verifyTaggingControllerUserInput(completedConfig.ComponentConfig.KubeCloudShared.ClusterCIDR); ok {
		klog.Infof("Will not start the tagging controller due to invalid user input, --configure-cloud-routes: %v", error)
		return nil, false, nil
	}

	// Start the TaggingController
	taggingcontroller, err := taggingcontroller.NewTaggingController(
		completedConfig.SharedInformers.Core().V1().Nodes(),
		completedConfig.ClientBuilder.ClientOrDie(initContext.ClientName),
		cloud,
		completedConfig.ComponentConfig.KubeCloudShared.NodeMonitorPeriod.Duration,
		completedConfig.ComponentConfig.KubeCloudShared.ClusterCIDR)
	if err != nil {
		klog.Warningf("failed to start tagging controller: %s", err)
		return nil, false, nil
	}

	go taggingcontroller.Run(ctx)

	return nil, true, nil
}

func verifyTaggingControllerUserInput(input string) (bool, error) {
	if len(input) == 0 {
		return false, errors.New("Provide input for --configure-cloud-routes to use the tagging controller.")
	}

	return true, nil
}
