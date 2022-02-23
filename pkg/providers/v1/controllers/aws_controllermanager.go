package controllers

import (
	"context"
	"k8s.io/klog/v2"

	cloudprovider "k8s.io/cloud-provider"
	"k8s.io/cloud-provider/app"
	cloudcontrollerconfig "k8s.io/cloud-provider/app/config"
	"k8s.io/controller-manager/controller"
	genericcontrollermanager "k8s.io/controller-manager/app"
	taggingcontroller "k8s.io/cloud-provider-aws/pkg/providers/v1/controllers/tagging"
)

// BuildControllerInitializers is used to add new controllers built in this package to
// the existing list of controllers from cloud-provider
func BuildControllerInitializers() map[string]app.ControllerInitFuncConstructor {
	controllerInitializers := app.DefaultInitFuncConstructors

	taggingControllerInitFuncConstrustor :=  app.ControllerInitFuncConstructor{
		InitContext: app.ControllerInitContext{
			ClientName: "tagging-controller",
		},
		Constructor: startTaggingControllerWrapper,
	}

	controllerInitializers["tagging"] = taggingControllerInitFuncConstrustor

	return controllerInitializers
}

// StartTaggingControllerWrapper is used to take cloud config as input and start tagging controller
func startTaggingControllerWrapper(initContext app.ControllerInitContext, completedConfig *cloudcontrollerconfig.CompletedConfig, cloud cloudprovider.Interface) app.InitFunc {
	return func(ctx context.Context, controllerContext genericcontrollermanager.ControllerContext) (controller.Interface, bool, error) {
		return startTaggingController(ctx, initContext, completedConfig, cloud)
	}
}

func startTaggingController(ctx context.Context, initContext app.ControllerInitContext, completedConfig *cloudcontrollerconfig.CompletedConfig, cloud cloudprovider.Interface) (controller.Interface, bool, error) {
	// Start the TaggingController
	taggingcontroller, err := taggingcontroller.NewTaggingController()
	if err != nil {
		klog.Warningf("failed to start tagging controller: %s", err)
		return nil, false, nil
	}

	go taggingcontroller.Run(ctx.Done())

	return nil, true, nil
}