module k8s.io/cloud-provider-aws

go 1.12

replace (
	// these replacements are pinned to 70132b0f130a which is the sha associated with the 1.17.0 tag on k/k
	// as you cannot pin them to v1.17.0 directly
	k8s.io/api => k8s.io/kubernetes/staging/src/k8s.io/api v0.0.0-20191206012503-70132b0f130a
	k8s.io/apiextensions-apiserver => k8s.io/kubernetes/staging/src/k8s.io/apiextensions-apiserver v0.0.0-20191206012503-70132b0f130a
	k8s.io/apimachinery => k8s.io/kubernetes/staging/src/k8s.io/apimachinery v0.0.0-20191206012503-70132b0f130a
	k8s.io/apiserver => k8s.io/kubernetes/staging/src/k8s.io/apiserver v0.0.0-20191206012503-70132b0f130a
	k8s.io/cli-runtime => k8s.io/kubernetes/staging/src/k8s.io/cli-runtime v0.0.0-20191206012503-70132b0f130a
	k8s.io/client-go => k8s.io/kubernetes/staging/src/k8s.io/client-go v0.0.0-20191206012503-70132b0f130a
	k8s.io/cloud-provider => k8s.io/kubernetes/staging/src/k8s.io/cloud-provider v0.0.0-20191206012503-70132b0f130a
	k8s.io/cluster-bootstrap => k8s.io/kubernetes/staging/src/k8s.io/cluster-bootstrap v0.0.0-20191206012503-70132b0f130a
	k8s.io/code-generator => k8s.io/kubernetes/staging/src/k8s.io/code-generator v0.0.0-20191206012503-70132b0f130a
	k8s.io/component-base => k8s.io/kubernetes/staging/src/k8s.io/component-base v0.0.0-20191206012503-70132b0f130a
	k8s.io/cri-api => k8s.io/kubernetes/staging/src/k8s.io/cri-api v0.0.0-20191206012503-70132b0f130a
	k8s.io/csi-translation-lib => k8s.io/kubernetes/staging/src/k8s.io/csi-translation-lib v0.0.0-20191206012503-70132b0f130a
	k8s.io/kube-aggregator => k8s.io/kubernetes/staging/src/k8s.io/kube-aggregator v0.0.0-20191206012503-70132b0f130a
	k8s.io/kube-controller-manager => k8s.io/kubernetes/staging/src/k8s.io/kube-controller-manager v0.0.0-20191206012503-70132b0f130a
	k8s.io/kube-proxy => k8s.io/kubernetes/staging/src/k8s.io/kube-proxy v0.0.0-20191206012503-70132b0f130a
	k8s.io/kube-scheduler => k8s.io/kubernetes/staging/src/k8s.io/kube-scheduler v0.0.0-20191206012503-70132b0f130a
	k8s.io/kubectl => k8s.io/kubernetes/staging/src/k8s.io/kubectl v0.0.0-20191206012503-70132b0f130a
	k8s.io/kubelet => k8s.io/kubernetes/staging/src/k8s.io/kubelet v0.0.0-20191206012503-70132b0f130a
	k8s.io/legacy-cloud-providers => k8s.io/kubernetes/staging/src/k8s.io/legacy-cloud-providers v0.0.0-20191206012503-70132b0f130a
	k8s.io/metrics => k8s.io/kubernetes/staging/src/k8s.io/metrics v0.0.0-20191206012503-70132b0f130a
	k8s.io/node-api => k8s.io/kubernetes/staging/src/k8s.io/node-api v0.0.0-20191206012503-70132b0f130a
	k8s.io/sample-apiserver => k8s.io/kubernetes/staging/src/k8s.io/sample-apiserver v0.0.0-20191206012503-70132b0f130a
)

require (
	github.com/spf13/cobra v0.0.5
	k8s.io/apimachinery v0.0.0
	k8s.io/apiserver v0.0.0
	k8s.io/cloud-provider v0.0.0
	k8s.io/component-base v0.17.0
	k8s.io/klog v1.0.0
	k8s.io/kubernetes v1.17.0
	k8s.io/legacy-cloud-providers v0.0.0
	k8s.io/utils v0.0.0-20191114184206-e782cd3c129f
)
