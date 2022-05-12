package tagging

import (
	"net/http"

	cloudprovider "k8s.io/cloud-provider"
	"k8s.io/cloud-provider/app"
	cloudcontrollerconfig "k8s.io/cloud-provider/app/config"
	genericcontrollermanager "k8s.io/controller-manager/app"
	"k8s.io/klog/v2"

	"k8s.io/cloud-provider-aws/pkg/controllers/options"
)

const (
	// TaggingControllerClientName is the name of the tagging controller
	TaggingControllerClientName = "tagging-controller"

	// TaggingControllerKey is the key used to register this controller
	TaggingControllerKey = "tagging"
)

// ControllerWrapper is the wrapper for the tagging controller
type ControllerWrapper struct {
	Options options.TaggingControllerOptions
}

// StartTaggingControllerWrapper is used to take cloud config as input and start the tagging controller
func (tc *ControllerWrapper) StartTaggingControllerWrapper(completedConfig *cloudcontrollerconfig.CompletedConfig, cloud cloudprovider.Interface) app.InitFunc {
	return func(ctx genericcontrollermanager.ControllerContext) (http.Handler, bool, error) {
		return tc.startTaggingController(ctx, completedConfig, cloud)
	}
}

func (tc *ControllerWrapper) startTaggingController(ctx genericcontrollermanager.ControllerContext, completedConfig *cloudcontrollerconfig.CompletedConfig, cloud cloudprovider.Interface) (http.Handler, bool, error) {
	err := tc.Options.Validate()
	if err != nil {
		klog.Fatalf("Tagging controller inputs are not properly set: %v", err)
	}

	// Start the Controller
	taggingcontroller, err := NewTaggingController(
		completedConfig.SharedInformers.Core().V1().Nodes(),
		completedConfig.ClientBuilder.ClientOrDie(TaggingControllerClientName),
		cloud,
		completedConfig.ComponentConfig.KubeCloudShared.NodeMonitorPeriod.Duration,
		tc.Options.Tags,
		tc.Options.Resources)

	if err != nil {
		klog.Warningf("failed to start tagging controller: %s", err)
		return nil, false, nil
	}

	go taggingcontroller.Run(ctx.Stop)

	return nil, true, nil
}
