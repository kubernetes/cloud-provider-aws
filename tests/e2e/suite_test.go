package e2e

import (
	"flag"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"k8s.io/kubernetes/test/e2e/framework"
	frameworkconfig "k8s.io/kubernetes/test/e2e/framework/config"
)

const kubeconfigEnvVar = "KUBECONFIG"

func init() {
	rand.Seed(time.Now().UTC().UnixNano())
	testing.Init()

	// k8s.io/kubernetes/test/e2e/framework requires env KUBECONFIG to be set
	// it does not fall back to defaults
	if os.Getenv(kubeconfigEnvVar) == "" {
		kubeconfig := filepath.Join(os.Getenv("HOME"), ".kube", "config")
		_ = os.Setenv(kubeconfigEnvVar, kubeconfig)
	}
	framework.AfterReadingAllFlags(&framework.TestContext)

	frameworkconfig.CopyFlags(frameworkconfig.Flags, flag.CommandLine)
	framework.RegisterCommonFlags(flag.CommandLine)
	framework.RegisterClusterFlags(flag.CommandLine)
	flag.Parse()
}

func TestE2E(t *testing.T) {
	gomega.RegisterFailHandler(framework.Fail)
	if framework.TestContext.ReportDir != "" {
		if err := os.MkdirAll(framework.TestContext.ReportDir, 0755); err != nil {
			t.Fatalf("Failed creating report directory: %v", err)
		}
	}
	suiteConfig, reporterConfig := framework.CreateGinkgoConfig()
	ginkgo.RunSpecs(t, "AWS Cloud Provider End-to-End Tests", suiteConfig, reporterConfig)
}
