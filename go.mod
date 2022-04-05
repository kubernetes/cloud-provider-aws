module k8s.io/cloud-provider-aws

go 1.15

require (
	github.com/aws/aws-sdk-go v1.43.32
	github.com/golang/mock v1.4.4
	github.com/google/go-cmp v0.5.5
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.6.1
	gopkg.in/gcfg.v1 v1.2.0
	gopkg.in/warnings.v0 v0.1.1 // indirect
	k8s.io/api v0.20.15
	k8s.io/apimachinery v0.20.15
	k8s.io/client-go v0.20.15
	k8s.io/cloud-provider v0.20.15
	k8s.io/code-generator v0.20.15
	k8s.io/component-base v0.20.15
	k8s.io/controller-manager v0.20.15
	k8s.io/csi-translation-lib v0.20.15
	k8s.io/klog/v2 v2.5.0
	k8s.io/kubelet v0.20.15
	sigs.k8s.io/yaml v1.2.0
)
