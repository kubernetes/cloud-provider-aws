package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"k8s.io/apiserver/pkg/server/healthz"
	"k8s.io/apiserver/pkg/util/logs"
	"k8s.io/kubernetes/cmd/cloud-controller-manager/app"
	"k8s.io/kubernetes/cmd/cloud-controller-manager/app/options"
	_ "k8s.io/kubernetes/pkg/client/metrics/prometheus" // for client metric registration
	_ "k8s.io/kubernetes/pkg/cloudprovider/providers/aws"
	_ "k8s.io/kubernetes/pkg/version/prometheus" // for version metric registration
	"k8s.io/kubernetes/pkg/version/verflag"
)

func init() {
	healthz.DefaultHealthz()
}

func main() {
	c := NewAWSCloudControllerManagerCommand()

	if err := c.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func NewAWSCloudControllerManagerCommand() *cobra.Command {
	s := options.NewCloudControllerManagerOptions()
	s.Generic.ComponentConfig.CloudProvider = "aws"

	cmd := &cobra.Command{
		Use: "aws-cloud-controller-manager",
		Long: `The Cloud controller manager is a daemon that embeds
the cloud specific control loops shipped with Kubernetes.`,
		Run: func(cmd *cobra.Command, args []string) {
			verflag.PrintAndExitIfRequested()

			c, err := s.Config()
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
				os.Exit(1)
			}

			if err := app.Run(c.Complete()); err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
				os.Exit(1)
			}
		},
	}
	s.AddFlags(cmd.Flags())
	logs.InitLogs()
	defer logs.FlushLogs()
	//flagutil.InitFlags()

	return cmd
}
