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
	"math/rand"
	"os"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/cloud-provider/app"
	"k8s.io/cloud-provider/options"
	cliflag "k8s.io/component-base/cli/flag"
	"k8s.io/component-base/logs"
	_ "k8s.io/component-base/metrics/prometheus/clientgo" // for client metric registration
	_ "k8s.io/component-base/metrics/prometheus/version"  // for version metric registration
	"k8s.io/klog/v2"

	cloudprovider "k8s.io/cloud-provider"
	awsv1 "k8s.io/cloud-provider-aws/pkg/providers/v1"
	awsv2 "k8s.io/cloud-provider-aws/pkg/providers/v2"

	cloudcontrollerconfig "k8s.io/cloud-provider/app/config"

	acm "k8s.io/cloud-provider-aws/cmd/aws-cloud-controller-manager/controllers"
)

const (
	enableAlphaV2EnvVar = "ENABLE_ALPHA_V2"
)

var version string

func main() {
	rand.Seed(time.Now().UTC().UnixNano())

	logs.InitLogs()
	defer logs.FlushLogs()

	opts, err := options.NewCloudControllerManagerOptions()
	if err != nil {
		klog.Fatalf("unable to initialize command options: %v", err)
	}

	klog.Info("Nguyen about to add tagging.")
	controllerInitializers := acm.BuildControllerInitializers()

	klog.Info("Nguyen tagging added.")
	fss := cliflag.NamedFlagSets{}
	command := app.NewCloudControllerManagerCommand(opts, cloudInitializer, controllerInitializers, fss, wait.NeverStop)

	if err := command.Execute(); err != nil {
		os.Exit(1)
	}
}

func cloudInitializer(config *cloudcontrollerconfig.CompletedConfig) cloudprovider.Interface {
	cloudConfig := config.ComponentConfig.KubeCloudShared.CloudProvider
	providerName := cloudConfig.Name

	// Default to the v1 provider if not set
	if providerName == "" {
		providerName = awsv1.ProviderName
	}

	if providerName != awsv1.ProviderName && providerName != awsv2.ProviderName {
		klog.Fatalf("unknown cloud provider %s, only 'aws' and 'aws/v2' are supported", providerName)
	}

	if providerName == awsv2.ProviderName {
		if v2Enabled := os.Getenv(enableAlphaV2EnvVar); v2Enabled != "true" {
			klog.Fatalf("aws/v2 cloud provider requires environment variable ENABLE_ALPHA_V2=true to be set")
		}
	}

	// initialize cloud provider with the cloud provider name and config file provided
	cloud, err := cloudprovider.InitCloudProvider(providerName, cloudConfig.CloudConfigFile)
	if err != nil {
		klog.Fatalf("Cloud provider could not be initialized: %v", err)
	}
	if cloud == nil {
		klog.Fatalf("Cloud provider is nil")
	}

	if !cloud.HasClusterID() {
		if config.ComponentConfig.KubeCloudShared.AllowUntaggedCloud {
			klog.Warning("detected a cluster without a ClusterID.  A ClusterID will be required in the future.  Please tag your cluster to avoid any future issues")
		} else {
			klog.Fatalf("no ClusterID found.  A ClusterID is required for the cloud provider to function properly.  This check can be bypassed by setting the allow-untagged-cloud option")
		}
	}

	return cloud
}
