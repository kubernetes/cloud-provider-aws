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
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/types"
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

	///////
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	enableAlphaV2EnvVar = "ENABLE_ALPHA_V2"
	validateWebhookPath = "/validate"
)

func main() {
	rand.Seed(time.Now().UTC().UnixNano())

	logs.InitLogs()
	defer logs.FlushLogs()

	opts, err := options.NewCloudControllerManagerOptions()
	if err != nil {
		klog.Fatalf("unable to initialize command options: %v", err)
	}

	controllerInitializers := app.DefaultInitFuncConstructors
	webhooks := make(map[string]app.WebhookConfig)
	webhooks["validating-webhook"] = app.WebhookConfig{
		Path:    validateWebhookPath,
		Webhook: validatePodReview,
	}

	fss := cliflag.NamedFlagSets{}
	command := app.NewCloudControllerManagerCommand(opts, cloudInitializer, controllerInitializers, webhooks, fss, wait.NeverStop)

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

func validatePodReview(request *admissionv1.AdmissionRequest) (*admissionv1.AdmissionResponse, error) {
	pod, err := pod(request)
	if err != nil {
		e := fmt.Sprintf("could not parse pod in admission review request: %v", err)
		return reviewResponse(request.UID, false, http.StatusBadRequest, e), err
	}

	val, err := validatePod(pod)
	if err != nil {
		e := fmt.Sprintf("could not validate pod: %v", err)
		return reviewResponse(request.UID, false, http.StatusBadRequest, e), err
	}

	if !val.Valid {
		return reviewResponse(request.UID, false, http.StatusForbidden, val.Reason), nil
	}

	return reviewResponse(request.UID, true, http.StatusAccepted, "valid pod"), nil
}

type validation struct {
	Valid  bool
	Reason string
}

// validatePod returns true if a pod is valid
func validatePod(pod *corev1.Pod) (validation, error) {
	var podName string
	if pod.Name != "" {
		podName = pod.Name
	} else {
		if pod.ObjectMeta.GenerateName != "" {
			podName = pod.ObjectMeta.GenerateName
		}
	}
	klog.Infof("delete me: %s", podName)

	// list of all validations to be applied to the pod
	validations := []podValidator{
		nameValidator{},
	}

	// apply all validations
	for _, v := range validations {
		var err error
		vp, err := v.Validate(pod)
		if err != nil {
			return validation{Valid: false, Reason: err.Error()}, err
		}
		if !vp.Valid {
			return validation{Valid: false, Reason: vp.Reason}, err
		}
	}

	return validation{Valid: true, Reason: "valid pod"}, nil
}

// podValidators is an interface used to group functions mutating pods
type podValidator interface {
	Validate(*corev1.Pod) (validation, error)
	Name() string
}

// nameValidator is a container for validating the name of pods
type nameValidator struct {
}

// nameValidator implements the podValidator interface
var _ podValidator = (*nameValidator)(nil)

// Name returns the name of nameValidator
func (n nameValidator) Name() string {
	return "name_validator"
}

// Validate inspects the name of a given pod and returns validation.
// The returned validation is only valid if the pod name does not contain some
// bad string.
func (n nameValidator) Validate(pod *corev1.Pod) (validation, error) {
	badString := "offensive"

	if strings.Contains(pod.Name, badString) {
		v := validation{
			Valid:  false,
			Reason: fmt.Sprintf("pod name contains %q", badString),
		}
		return v, nil
	}

	return validation{Valid: true, Reason: "valid name"}, nil
}

// pod extracts a pod from an admission request
func pod(request *admissionv1.AdmissionRequest) (*corev1.Pod, error) {
	if request.Kind.Kind != "Pod" {
		return nil, fmt.Errorf("only pods are supported here")
	}

	p := corev1.Pod{}
	if err := json.Unmarshal(request.Object.Raw, &p); err != nil {
		return nil, err
	}

	return &p, nil
}

func reviewResponse(uid types.UID, allowed bool, httpCode int32,
	reason string) *admissionv1.AdmissionResponse {
	return &admissionv1.AdmissionResponse{
		UID:     uid,
		Allowed: allowed,
		Result: &metav1.Status{
			Code:    httpCode,
			Message: reason,
		},
	}
}
