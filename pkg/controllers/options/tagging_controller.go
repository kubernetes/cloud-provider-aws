package options

import (
	"github.com/spf13/pflag"
	"k8s.io/klog/v2"
)

type TaggingControllerOptions struct {
	Tags map[string]string
}

func (o *TaggingControllerOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringToStringVar(&o.Tags, "tags", o.Tags, "Tags to apply to AWS resources in the tagging controller.")
}

func (o *TaggingControllerOptions) Validate() error {
	// TODO: Add validation logic here.
	klog.Info("Validating tags here")
	return nil
}
