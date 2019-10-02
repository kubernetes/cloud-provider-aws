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
	"k8s.io/component-base/cli/globalflag"
	"k8s.io/component-base/logs"
	"k8s.io/klog"
	"k8s.io/kubernetes/cmd/cloud-controller-manager/app"
	"k8s.io/kubernetes/cmd/cloud-controller-manager/app/options"
	_ "k8s.io/kubernetes/pkg/client/metrics/prometheus" // for client metric registration
	_ "k8s.io/kubernetes/pkg/features"                  // add the kubernetes feature gates
	utilflag "k8s.io/kubernetes/pkg/util/flag"
	_ "k8s.io/kubernetes/pkg/version/prometheus" // for version metric registration
	"k8s.io/legacy-cloud-providers/aws"

	cloudprovider "k8s.io/cloud-provider"
	cloudcontrollerconfig "k8s.io/kubernetes/cmd/cloud-controller-manager/app/config"
	cloudcontrollers "k8s.io/kubernetes/pkg/controller/cloud"
	routecontroller "k8s.io/kubernetes/pkg/controller/route"
	servicecontroller "k8s.io/kubernetes/pkg/controller/service"
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

			// Hard code aws cloud provider
			cloudProviderFlag := cmd.Flags().Lookup("cloud-provider")
			cloudProviderFlag.Value.Set(aws.ProviderName)

			utilflag.PrintFlags(cmd.Flags())

			c, err := s.Config(KnownControllers(), ControllersDisabledByDefault.List())
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
				os.Exit(1)
			}

			if err := app.Run(c.Complete(), wait.NeverStop); err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
				os.Exit(1)
			}
		},
	}

	fs := command.Flags()
	namedFlagSets := s.Flags(KnownControllers(), ControllersDisabledByDefault.List())
	globalflag.AddGlobalFlags(namedFlagSets.FlagSet("global"), command.Name())

	for _, f := range namedFlagSets.FlagSets {
		fs.AddFlagSet(f)
	}

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

// ControllersDisabledByDefault is the controller disabled default when starting cloud-controller managers.
var ControllersDisabledByDefault = sets.NewString()

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
	nodeController := cloudcontrollers.NewCloudNodeController(
		ctx.SharedInformers.Core().V1().Nodes(),
		// cloud node controller uses existing cluster role from node-controller
		ctx.ClientBuilder.ClientOrDie("node-controller"),
		cloud,
		ctx.ComponentConfig.NodeStatusUpdateFrequency.Duration)

	go nodeController.Run(stopCh)

	return nil, true, nil
}

func startCloudNodeLifecycleController(ctx *cloudcontrollerconfig.CompletedConfig, cloud cloudprovider.Interface, stopCh <-chan struct{}) (http.Handler, bool, error) {
	// Start the cloudNodeLifecycleController
	cloudNodeLifecycleController, err := cloudcontrollers.NewCloudNodeLifecycleController(
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
	var clusterCIDR *net.IPNet
	var err error
	if len(strings.TrimSpace(ctx.ComponentConfig.KubeCloudShared.ClusterCIDR)) != 0 {
		_, clusterCIDR, err = net.ParseCIDR(ctx.ComponentConfig.KubeCloudShared.ClusterCIDR)
		if err != nil {
			klog.Warningf("Unsuccessful parsing of cluster CIDR %v: %v", ctx.ComponentConfig.KubeCloudShared.ClusterCIDR, err)
		}
	}

	routeController := routecontroller.New(
		routes,
		ctx.ClientBuilder.ClientOrDie("route-controller"),
		ctx.SharedInformers.Core().V1().Nodes(),
		ctx.ComponentConfig.KubeCloudShared.ClusterName,
		clusterCIDR,
	)
	go routeController.Run(stopCh, ctx.ComponentConfig.KubeCloudShared.RouteReconciliationPeriod.Duration)

	return nil, true, nil
}
