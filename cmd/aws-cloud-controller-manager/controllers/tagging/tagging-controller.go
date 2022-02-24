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

package tagging

import (
	"k8s.io/klog/v2"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
)

// eksResourceTagPrefix is the prefix for tag to group resources that are used by eks
// for a particular cluster, this tag is added to the existing tags.
// Example: "Key1=Val1,aws:eks:cluster-name:my-cluster=Val2"
const eksResourceTagPrefix = "aws:eks:cluster-name:"

// TaggingController is the controller implementation for tagging cluster resources
type TaggingController struct {
}

// NewTaggingController creates a NewTaggingController object
func NewTaggingController() (*TaggingController, error) {
	tc := &TaggingController{
	}

	return tc, nil
}

// Run will start the controller to tag resources attached to a cluster
// and untag resources detached from a cluster.
func (tc *TaggingController) Run(stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	klog.Infof("Running the TaggingController, eksResourceTagPrefix is %s.", eksResourceTagPrefix)

	<-stopCh
}