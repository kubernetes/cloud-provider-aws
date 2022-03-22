package options

import (
	"fmt"
	"github.com/spf13/pflag"
)

type TaggingControllerOptions struct {
	Tags map[string]string
}

func (o *TaggingControllerOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringToStringVar(&o.Tags, "tags", o.Tags, "Tags to apply to AWS resources in the tagging controller.")
}

func (o *TaggingControllerOptions) Validate() error {
	if len(o.Tags) == 0 {
		return fmt.Errorf("--tags must not be empty")
	}

	return nil
}
