package tagging

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
	TaggingControllerClientName = "tagging-controller"
	TaggingControllerKey        = "tagging"
)

type TaggingControllerWrapper struct {
	Options options.TaggingControllerOptions
}

// StartTaggingControllerWrapper is used to take cloud config as input and start the tagging controller
func (tc *TaggingControllerWrapper) StartTaggingControllerWrapper(initContext app.ControllerInitContext, completedConfig *cloudcontrollerconfig.CompletedConfig, cloud cloudprovider.Interface) app.InitFunc {
	return func(ctx context.Context, controllerContext genericcontrollermanager.ControllerContext) (controller.Interface, bool, error) {
		return tc.startTaggingController(ctx, initContext, completedConfig, cloud)
	}
}

func (tc *TaggingControllerWrapper) startTaggingController(ctx context.Context, initContext app.ControllerInitContext, completedConfig *cloudcontrollerconfig.CompletedConfig, cloud cloudprovider.Interface) (controller.Interface, bool, error) {
	err := tc.Options.Validate()
	if err != nil {
		klog.Fatal("Tagging controller inputs are not properly set.")
	}

	// Start the TaggingController
	taggingcontroller, err := NewTaggingController(
		completedConfig.SharedInformers.Core().V1().Nodes(),
		completedConfig.ClientBuilder.ClientOrDie(initContext.ClientName),
		cloud,
		completedConfig.ComponentConfig.KubeCloudShared.NodeMonitorPeriod.Duration,
		tc.Options.Tags)

	if err != nil {
		klog.Warningf("failed to start tagging controller: %s", err)
		return nil, false, nil
	}

	go taggingcontroller.Run(ctx)

	return nil, true, nil
}