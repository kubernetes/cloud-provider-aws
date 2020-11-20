/*
Copyright 2018 The Kubernetes Authors.

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

// aws-cloud-controller-manager is responsible for running controller loops
// that create, delete and monitor cloud resources on AWS. These cloud
// resources include EC2 instances and autoscaling groups, along with network
// load balancers (NLB) and application load balancers (ALBs) The cloud
// resources help provide a place for both control plane components -- e.g. EC2
// instances might house Kubernetes worker nodes -- as well as data plane
// components -- e.g. a Kubernetes Ingress object might be mapped to an EC2
// application load balancer.

package main

import (
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/cloud-provider/app"
	"k8s.io/cloud-provider/options"
	cliflag "k8s.io/component-base/cli/flag"
	"k8s.io/component-base/cli/globalflag"
	"k8s.io/component-base/logs"
	_ "k8s.io/component-base/metrics/prometheus/clientgo" // for client metric registration
	_ "k8s.io/component-base/metrics/prometheus/version"  // for version metric registration
	"k8s.io/component-base/term"
	"k8s.io/component-base/version/verflag"
	"k8s.io/klog/v2"
	netutils "k8s.io/utils/net"

	cloudprovider "k8s.io/cloud-provider"
	awsv1 "k8s.io/cloud-provider-aws/pkg/providers/v1"
	awsv2 "k8s.io/cloud-provider-aws/pkg/providers/v2"

	cloudcontrollerconfig "k8s.io/cloud-provider/app/config"
	cloudnodecontroller "k8s.io/cloud-provider/controllers/node"
	cloudnodelifecyclecontroller "k8s.io/cloud-provider/controllers/nodelifecycle"
	routecontroller "k8s.io/cloud-provider/controllers/route"
	servicecontroller "k8s.io/cloud-provider/controllers/service"
)

const (
	enableAlphaV2EnvVar = "ENABLE_ALPHA_V2"
)

var version string

func main() {
	rand.Seed(time.Now().UTC().UnixNano())

	logs.InitLogs()
	defer logs.FlushLogs()

	s, err := options.NewCloudControllerManagerOptions()
	if err != nil {
		klog.Fatalf("unable to initialize command options: %v", err)
	}

	var controllerInitializers map[string]app.InitFunc
	command := &cobra.Command{
		Use:  "aws-cloud-controller-manager",
		Long: `aws-cloud-controller-manager manages AWS cloud resources for a Kubernetes cluster.`,
		Run: func(cmd *cobra.Command, args []string) {

			// Use our version instead of the Kubernetes formatted version
			versionFlag := cmd.Flags().Lookup("version")
			if versionFlag.Value.String() == "true" {
				fmt.Printf("%s version: %s\n", cmd.Name(), version)
				os.Exit(0)
			}

			// Default to the v1 provider if not set
			cloudProviderFlag := cmd.Flags().Lookup("cloud-provider")
			if cloudProviderFlag.Value.String() == "" {
				cloudProviderFlag.Value.Set(awsv1.ProviderName)
			}

			cloudProvider := cloudProviderFlag.Value.String()
			if cloudProvider != awsv1.ProviderName && cloudProvider != awsv2.ProviderName {
				klog.Fatalf("unknown cloud provider %s, only 'aws' and 'aws/v2' are supported", cloudProvider)
			}

			if cloudProvider == awsv2.ProviderName {
				if v2Enabled := os.Getenv(enableAlphaV2EnvVar); v2Enabled != "true" {
					klog.Fatalf("aws/v2 cloud provider requires environment variable ENABLE_ALPHA_V2=true to be set")
				}
			}

			cliflag.PrintFlags(cmd.Flags())

			c, err := s.Config(KnownControllers(), app.ControllersDisabledByDefault.List())
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
				os.Exit(1)
			}

			// initialize cloud provider with the cloud provider name and config file provided
			cloud, err := cloudprovider.InitCloudProvider(cloudProvider, "")
			if err != nil {
				klog.Fatalf("Cloud provider could not be initialized: %v", err)
			}
			if cloud == nil {
				klog.Fatalf("Cloud provider is nil")
			}

			if !cloud.HasClusterID() {
				if c.ComponentConfig.KubeCloudShared.AllowUntaggedCloud {
					klog.Warning("detected a cluster without a ClusterID.  A ClusterID will be required in the future.  Please tag your cluster to avoid any future issues")
				} else {
					klog.Fatalf("no ClusterID found.  A ClusterID is required for the cloud provider to function properly.  This check can be bypassed by setting the allow-untagged-cloud option")
				}
			}

			// Initialize the cloud provider with a reference to the clientBuilder
			cloud.Initialize(c.ClientBuilder, make(chan struct{}))
			// Set the informer on the user cloud object
			if informerUserCloud, ok := cloud.(cloudprovider.InformerUser); ok {
				informerUserCloud.SetInformers(c.SharedInformers)
			}

			controllerInitializers = app.DefaultControllerInitializers(c.Complete(), cloud)

			if err := app.Run(c.Complete(), controllerInitializers, wait.NeverStop); err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
				os.Exit(1)
			}
		},
		Args: func(cmd *cobra.Command, args []string) error {
			for _, arg := range args {
				if len(arg) > 0 {
					return fmt.Errorf("%q does not take any arguments, got %q", cmd.CommandPath(), args)
				}
			}
			return nil
		},
	}

	fs := command.Flags()
	namedFlagSets := s.Flags(app.KnownControllers(controllerInitializers), app.ControllersDisabledByDefault.List())
	verflag.AddFlags(namedFlagSets.FlagSet("global"))
	globalflag.AddGlobalFlags(namedFlagSets.FlagSet("global"), command.Name())

	for _, f := range namedFlagSets.FlagSets {
		fs.AddFlagSet(f)
	}
	usageFmt := "Usage:\n  %s\n"
	cols, _, _ := term.TerminalSize(command.OutOrStdout())
	command.SetUsageFunc(func(cmd *cobra.Command) error {
		fmt.Fprintf(cmd.OutOrStderr(), usageFmt, cmd.UseLine())
		cliflag.PrintSections(cmd.OutOrStderr(), namedFlagSets, cols)
		return nil
	})
	command.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		fmt.Fprintf(cmd.OutOrStdout(), "%s\n\n"+usageFmt, cmd.Long, cmd.UseLine())
		cliflag.PrintSections(cmd.OutOrStdout(), namedFlagSets, cols)
	})

	if err := command.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// initFunc is used to launch a particular controller.  It may run additional "should I activate checks".
// Any error returned will cause the controller process to `Fatal`
// The bool indicates whether the controller was enabled.
type initFunc func(ctx *cloudcontrollerconfig.CompletedConfig, cloud cloudprovider.Interface, stop <-chan struct{}) (debuggingHandler http.Handler, enabled bool, err error)

// KnownControllers indicate the default controller we are known.
func KnownControllers() []string {
	ret := sets.StringKeySet(newControllerInitializers())
	return ret.List()
}

// newControllerInitializers is a private map of named controller groups (you can start more than one in an init func)
// paired to their initFunc.  This allows for structured downstream composition and subdivision.
func newControllerInitializers() map[string]initFunc {
	controllers := map[string]initFunc{}
	controllers["cloud-node"] = startCloudNodeController
	controllers["cloud-node-lifecycle"] = startCloudNodeLifecycleController
	controllers["service"] = startServiceController
	controllers["route"] = startRouteController
	return controllers
}

func startCloudNodeController(ctx *cloudcontrollerconfig.CompletedConfig, cloud cloudprovider.Interface, stopCh <-chan struct{}) (http.Handler, bool, error) {
	// Start the CloudNodeController
	nodeController, err := cloudnodecontroller.NewCloudNodeController(
		ctx.SharedInformers.Core().V1().Nodes(),
		// cloud node controller uses existing cluster role from node-controller
		ctx.ClientBuilder.ClientOrDie("node-controller"),
		cloud,
		ctx.ComponentConfig.NodeStatusUpdateFrequency.Duration,
	)
	if err != nil {
		klog.Warningf("failed to start cloud node controller: %s", err)
		return nil, false, nil
	}

	go nodeController.Run(stopCh)

	return nil, true, nil
}

func startCloudNodeLifecycleController(ctx *cloudcontrollerconfig.CompletedConfig, cloud cloudprovider.Interface, stopCh <-chan struct{}) (http.Handler, bool, error) {
	// Start the cloudNodeLifecycleController
	cloudNodeLifecycleController, err := cloudnodelifecyclecontroller.NewCloudNodeLifecycleController(
		ctx.SharedInformers.Core().V1().Nodes(),
		// cloud node lifecycle controller uses existing cluster role from node-controller
		ctx.ClientBuilder.ClientOrDie("node-controller"),
		cloud,
		ctx.ComponentConfig.KubeCloudShared.NodeMonitorPeriod.Duration,
	)
	if err != nil {
		klog.Warningf("failed to start cloud node lifecycle controller: %s", err)
		return nil, false, nil
	}

	go cloudNodeLifecycleController.Run(stopCh)

	return nil, true, nil
}

func startServiceController(ctx *cloudcontrollerconfig.CompletedConfig, cloud cloudprovider.Interface, stopCh <-chan struct{}) (http.Handler, bool, error) {
	// Start the service controller
	serviceController, err := servicecontroller.New(
		cloud,
		ctx.ClientBuilder.ClientOrDie("service-controller"),
		ctx.SharedInformers.Core().V1().Services(),
		ctx.SharedInformers.Core().V1().Nodes(),
		ctx.ComponentConfig.KubeCloudShared.ClusterName,
		utilfeature.DefaultFeatureGate,
	)
	if err != nil {
		// This error shouldn't fail. It lives like this as a legacy.
		klog.Errorf("Failed to start service controller: %v", err)
		return nil, false, nil
	}

	go serviceController.Run(stopCh, int(ctx.ComponentConfig.ServiceController.ConcurrentServiceSyncs))

	return nil, true, nil
}

func startRouteController(ctx *cloudcontrollerconfig.CompletedConfig, cloud cloudprovider.Interface, stopCh <-chan struct{}) (http.Handler, bool, error) {
	if !ctx.ComponentConfig.KubeCloudShared.AllocateNodeCIDRs || !ctx.ComponentConfig.KubeCloudShared.ConfigureCloudRoutes {
		klog.Infof("Will not configure cloud provider routes for allocate-node-cidrs: %v, configure-cloud-routes: %v.", ctx.ComponentConfig.KubeCloudShared.AllocateNodeCIDRs, ctx.ComponentConfig.KubeCloudShared.ConfigureCloudRoutes)
		return nil, false, nil
	}

	// If CIDRs should be allocated for pods and set on the CloudProvider, then start the route controller
	routes, ok := cloud.Routes()
	if !ok {
		klog.Warning("configure-cloud-routes is set, but cloud provider does not support routes. Will not configure cloud provider routes.")
		return nil, false, nil
	}

	// failure: bad cidrs in config
	clusterCIDRs, dualStack, err := processCIDRs(ctx.ComponentConfig.KubeCloudShared.ClusterCIDR)
	if err != nil {
		return nil, false, err
	}

	// failure: more than one cidr and dual stack is not enabled
	if len(clusterCIDRs) > 1 && !utilfeature.DefaultFeatureGate.Enabled(app.IPv6DualStack) {
		return nil, false, fmt.Errorf("len of ClusterCIDRs==%v and dualstack feature is not enabled", len(clusterCIDRs))
	}

	// failure: more than one cidr but they are not configured as dual stack
	if len(clusterCIDRs) > 1 && !dualStack {
		return nil, false, fmt.Errorf("len of ClusterCIDRs==%v and they are not configured as dual stack (at least one from each IPFamily", len(clusterCIDRs))
	}

	// failure: more than two cidrs is not allowed even with dual stack
	if len(clusterCIDRs) > 2 {
		return nil, false, fmt.Errorf("length of clusterCIDRs is:%v more than max allowed of 2", len(clusterCIDRs))
	}

	routeController := routecontroller.New(
		routes,
		ctx.ClientBuilder.ClientOrDie("route-controller"),
		ctx.SharedInformers.Core().V1().Nodes(),
		ctx.ComponentConfig.KubeCloudShared.ClusterName,
		clusterCIDRs,
	)
	go routeController.Run(stopCh, ctx.ComponentConfig.KubeCloudShared.RouteReconciliationPeriod.Duration)

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
