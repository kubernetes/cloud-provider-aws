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

package options

import (
	"fmt"
	"github.com/spf13/pflag"
)

type TaggingControllerOptions struct {
	Tags      map[string]string
	Resources []string
}

func (o *TaggingControllerOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringToStringVar(&o.Tags, "tags", o.Tags, "Tags to apply to AWS resources in the tagging controller.")
	fs.StringArrayVar(&o.Resources, "resources", o.Resources, "AWS resources name to add/remove tags in the tagging controller.")
}

func (o *TaggingControllerOptions) Validate() error {
	if len(o.Tags) == 0 {
		return fmt.Errorf("--tags must not be empty and must be a form of key=value")
	}

	if len(o.Resources) == 0 {
		return fmt.Errorf("--resources must not be empty")
	}

	for _, r := range o.Resources {
		found := false

		for _, resource := range SupportedResources {
			if r == resource {
				found = true
			}
		}

		if !found {
			return fmt.Errorf("%s is not a supported resource. Current supported resources %v", r, SupportedResources)
		}
	}

	return nil
}
