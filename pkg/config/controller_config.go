package config

import (
	"flag"
	"fmt"
	"github.com/spf13/pflag"
	"k8s.io/cloud-provider/config"
	"os"
)

const (
	flagResourceTags     = "resource-tags"
	flagTaggingResources = "tagging-resources"
)

var ControllerCFG = &ControllerConfig{}

// ControllerConfig stores the additional flags for global usage
type ControllerConfig struct {
	config.KubeCloudSharedConfiguration
	ResourceTags     string
	TaggingResources string

	//RuntimeConfig RuntimeConfig
	//CloudConfig   *CloudConfig
}

func (cfg *ControllerConfig) BindFlags(fs *pflag.FlagSet) {
	fs.StringVar(&cfg.ResourceTags, flagResourceTags, "", "List of tags for the cluster.")
	fs.StringVar(&cfg.TaggingResources, flagTaggingResources, "", "List of EC2 resources that need to be tagged.")
}

// Validate the controller configuration
func (cfg *ControllerConfig) Validate() error {
	if len(cfg.TaggingResources) > 0 && len(cfg.ResourceTags) == 0 {
		return fmt.Errorf("--resource-tags must be set when --tagging-resources is not empty.")
	}

	return nil
}

func (cfg *ControllerConfig) LoadControllerConfig() error {
	fs := pflag.NewFlagSet("", pflag.ExitOnError)
	fs.AddGoFlagSet(flag.CommandLine)
	cfg.BindFlags(fs)

	if err := fs.Parse(os.Args); err != nil {
		return err
	}

	if err := cfg.Validate(); err != nil {
		return err
	}

	return nil
}
