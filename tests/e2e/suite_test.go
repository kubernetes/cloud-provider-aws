package e2e

import (
	"flag"
	"math/rand"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	ginkgo "github.com/onsi/ginkgo/v2"
	"github.com/onsi/ginkgo/v2/reporters"
	"github.com/onsi/ginkgo/v2/types"
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
	repoDir := framework.TestContext.ReportDir
	if repoDir == "" {
		repoDir = os.Getenv("ARTIFACTS")
	}
	t.Logf("ReportDir: %s", repoDir)
	if repoDir != "" {
		if err := os.MkdirAll(repoDir, 0755); err != nil {
			t.Fatalf("Failed creating report directory: %v", err)
		}

		ginkgo.ReportAfterSuite("Kubernetes e2e JUnit report", func(report ginkgo.Report) {
			// With Ginkgo v1, we used to write one file per
			// parallel node. Now Ginkgo v2 automatically merges
			// all results into a report for us. The 01 suffix is
			// kept in case that users expect files to be called
			// "junit_<prefix><number>.xml".
			junitReport := path.Join(repoDir, "junit_"+framework.TestContext.ReportPrefix+"01.xml")

			// writeJUnitReport generates a JUnit file in the e2e
			// report directory that is shorter than the one
			// normally written by `ginkgo --junit-report`. This is
			// needed because the full report can become too large
			// for tools like Spyglass
			// (https://github.com/kubernetes/kubernetes/issues/111510).
			framework.ExpectNoError(WriteJUnitReport(report, junitReport))
		})
	}
	suiteConfig, reporterConfig := framework.CreateGinkgoConfig()
	ginkgo.RunSpecs(t, "AWS Cloud Provider End-to-End Tests", suiteConfig, reporterConfig)
}

// WriteJUnitReport generates a JUnit file that is shorter than the one
// normally written by `ginkgo --junit-report`. This is needed because the full
// report can become too large for tools like Spyglass
// (https://github.com/kubernetes/kubernetes/issues/111510).
func WriteJUnitReport(report ginkgo.Report, filename string) error {
	config := reporters.JunitReportConfig{
		// Remove details for specs where we don't care.
		OmitTimelinesForSpecState: types.SpecStatePassed | types.SpecStateSkipped,

		// Don't write <failure message="summary">. The same text is
		// also in the full text for the failure. If we were to write
		// both, then tools like kettle and spyglass would concatenate
		// the two strings and thus show duplicated information.
		OmitFailureMessageAttr: true,
	}

	return reporters.GenerateJUnitReportWithConfig(report, filename, config)
}
