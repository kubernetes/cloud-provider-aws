module k8s.io/cloud-provider-aws

go 1.15

replace (
	k8s.io/api => k8s.io/kubernetes/staging/src/k8s.io/api v0.0.0-20201023141757-9e8ad8ce9d8a
	k8s.io/apiextensions-apiserver => k8s.io/kubernetes/staging/src/k8s.io/apiextensions-apiserver v0.0.0-20201023141757-9e8ad8ce9d8a
	k8s.io/apimachinery => k8s.io/kubernetes/staging/src/k8s.io/apimachinery v0.0.0-20201023141757-9e8ad8ce9d8a
	k8s.io/apiserver => k8s.io/kubernetes/staging/src/k8s.io/apiserver v0.0.0-20201023141757-9e8ad8ce9d8a
	k8s.io/cli-runtime => k8s.io/kubernetes/staging/src/k8s.io/cli-runtime v0.0.0-20201023141757-9e8ad8ce9d8a
	k8s.io/client-go => k8s.io/kubernetes/staging/src/k8s.io/client-go v0.0.0-20201023141757-9e8ad8ce9d8a
	k8s.io/cloud-provider => k8s.io/kubernetes/staging/src/k8s.io/cloud-provider v0.0.0-20201023141757-9e8ad8ce9d8a
	k8s.io/cluster-bootstrap => k8s.io/kubernetes/staging/src/k8s.io/cluster-bootstrap v0.0.0-20201023141757-9e8ad8ce9d8a
	k8s.io/code-generator => k8s.io/kubernetes/staging/src/k8s.io/code-generator v0.0.0-20201023141757-9e8ad8ce9d8a
	k8s.io/component-base => k8s.io/kubernetes/staging/src/k8s.io/component-base v0.0.0-20201023141757-9e8ad8ce9d8a
	k8s.io/cri-api => k8s.io/kubernetes/staging/src/k8s.io/cri-api v0.0.0-20201023141757-9e8ad8ce9d8a
	k8s.io/csi-translation-lib => k8s.io/kubernetes/staging/src/k8s.io/csi-translation-lib v0.0.0-20201023141757-9e8ad8ce9d8a
	k8s.io/kube-aggregator => k8s.io/kubernetes/staging/src/k8s.io/kube-aggregator v0.0.0-20201023141757-9e8ad8ce9d8a
	k8s.io/kube-controller-manager => k8s.io/kubernetes/staging/src/k8s.io/kube-controller-manager v0.0.0-20201023141757-9e8ad8ce9d8a
	k8s.io/kube-proxy => k8s.io/kubernetes/staging/src/k8s.io/kube-proxy v0.0.0-20201023141757-9e8ad8ce9d8a
	k8s.io/kube-scheduler => k8s.io/kubernetes/staging/src/k8s.io/kube-scheduler v0.0.0-20201023141757-9e8ad8ce9d8a
	k8s.io/kubectl => k8s.io/kubernetes/staging/src/k8s.io/kubectl v0.0.0-20201023141757-9e8ad8ce9d8a
	k8s.io/kubelet => k8s.io/kubernetes/staging/src/k8s.io/kubelet v0.0.0-20201023141757-9e8ad8ce9d8a
	k8s.io/legacy-cloud-providers => k8s.io/kubernetes/staging/src/k8s.io/legacy-cloud-providers v0.0.0-20201023141757-9e8ad8ce9d8a
	k8s.io/metrics => k8s.io/kubernetes/staging/src/k8s.io/metrics v0.0.0-20201023141757-9e8ad8ce9d8a
	k8s.io/sample-apiserver => k8s.io/kubernetes/staging/src/k8s.io/sample-apiserver v0.0.0-20201023141757-9e8ad8ce9d8a
)

require (
	github.com/aws/aws-sdk-go v1.28.2
	github.com/golang/mock v1.3.1
	github.com/google/go-cmp v0.4.0
	github.com/google/uuid v1.1.1
	github.com/spf13/cobra v1.0.0
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.4.0
	gopkg.in/gcfg.v1 v1.2.0
	k8s.io/api v0.0.0
	k8s.io/apimachinery v0.0.0
	k8s.io/apiserver v0.0.0
	k8s.io/client-go v0.0.0
	k8s.io/cloud-provider v0.0.0
	k8s.io/component-base v0.0.0
	k8s.io/klog v1.0.0
	k8s.io/klog/v2 v2.2.0
	k8s.io/kubernetes v0.0.0-20201023141757-9e8ad8ce9d8a
	k8s.io/legacy-cloud-providers v0.0.0
	k8s.io/utils v0.0.0-20201015054608-420da100c033
)
