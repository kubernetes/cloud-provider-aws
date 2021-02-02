module k8s.io/cloud-provider-aws

go 1.15

require (
	github.com/aws/aws-sdk-go v1.35.24
	github.com/golang/mock v1.4.1
	github.com/google/go-cmp v0.5.2
	github.com/spf13/cobra v1.1.1
	github.com/stretchr/testify v1.6.1
	gopkg.in/gcfg.v1 v1.2.0
	k8s.io/api v0.20.0
	k8s.io/apimachinery v0.20.0
	k8s.io/apiserver v0.20.0
	k8s.io/client-go v0.20.0
	k8s.io/cloud-provider v0.20.0
	k8s.io/code-generator v0.20.0
	k8s.io/component-base v0.20.0
	k8s.io/csi-translation-lib v0.20.0
	k8s.io/klog/v2 v2.5.0
	k8s.io/kubelet v0.20.0
	k8s.io/legacy-cloud-providers v0.20.0
	k8s.io/utils v0.0.0-20201110183641-67b214c5f920
	sigs.k8s.io/yaml v1.2.0
)
