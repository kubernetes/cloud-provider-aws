<p align="center">
    <img src="assets/images/kubernetes_icon.svg" alt="Kubernetes logo" width="200" />
    <img src="assets/images/aws_logo.svg" alt="AWS Load Balancer logo" width="200" />
</p>
<p align="center">
    <strong>
        The
        <a href="https://aws.amazon.com/"> AWS </a>
        Cloud Provider for
        <a href="https://kubernetes.io/"> Kubernetes </a>
    </strong>
</p>
<p align="center">
    <a href="https://github.com/kubernetes/cloud-provider-aws/issues">
        <img alt="GitHub issues" src="https://img.shields.io/github/issues/kubernetes/cloud-provider-aws">
    </a>
    <a href="https://github.com/kubernetes/cloud-provider-aws/network">
        <img alt="GitHub forks" src="https://img.shields.io/github/forks/kubernetes/cloud-provider-aws">
    </a>
    <a href="https://github.com/kubernetes/cloud-provider-aws/stargazers">
        <img alt="GitHub stars" src="https://img.shields.io/github/stars/kubernetes/cloud-provider-aws">
    </a>
    <img alt="GitHub release (latest SemVer including pre-releases)" src="https://img.shields.io/github/v/release/kubernetes/cloud-provider-aws?include_prereleases">
</p>
<p align="center">
    <a href="https://github.com/kubernetes/cloud-provider-aws/blob/master/LICENSE">
        <img alt="GitHub license" src="https://img.shields.io/github/license/kubernetes/cloud-provider-aws">
    </a>
    <a href="https://goreportcard.com/report/github.com/kubernetes/cloud-provider-aws">
        <img src="https://goreportcard.com/badge/github.com/kubernetes/cloud-provider-aws" alt="go report card"/>
    </a>
    <a href="https://github.com/kubernetes/cloud-provider-aws/actions/workflows/deps.yml">
        <img src="https://github.com/kubernetes/cloud-provider-aws/actions/workflows/deps.yml/badge.svg" alt="Dependency Review"/>
    </a>
</p>

# cloud-provider-aws
The AWS cloud provider provides the interface between a Kubernetes cluster and AWS service APIs. This project allows a Kubernetes cluster to provision, monitor and remove AWS resources necessary for operation of the cluster.

<p align="center">
    <strong><a href="https://cloud-provider-aws.sigs.k8s.io/">See the online documentation here</a></strong>
</p>

## Compatibility with Kubernetes

The AWS cloud provider is released with a specific semantic version that correlates with the Kubernetes upstream version. The major and minor versions are equivalent to the compatible upstream release, and the patch version is reserved to denote subsequent releases of the cloud provider code for that Kubernetes release.  Currently, for a given cloud provider release version, compatibility is ONLY guaranteed between that release and the corresponding Kubernetes version, meaning you need to upgrade the cloud provider components every time you upgrade Kubernetes, just like you would do for the kube controller manager.  See the [external cloud provider versioning KEP](https://github.com/kubernetes/enhancements/tree/master/keps/sig-cloud-provider/1771-versioning-policy-for-external-cloud-providers) for more details.

## Migration from In-Tree
The in-tree cloud provider code has mostly stopped accepting new features, so future development for the AWS cloud provider should continue here.  The in-tree plugins will be removed in a future release of Kubernetes.

## Components

### AWS Cloud Controller Manager
The AWS Cloud Controller Manager is the controller that is primarily responsible for creating and updating AWS loadbalancers (classic and NLB) and node lifecycle management.  The controller loops that are migrating out of the kube controller manager include the route controller, the service controller, the node controller, and the node lifecycle controller.  See the [cloud controller manager KEP](https://github.com/kubernetes/enhancements/tree/master/keps/sig-cloud-provider/2392-cloud-controller-manager) for more details.

##### Container Images
AWS Cloud Controller Managed container images are available in `registry.k8s.io/provider-aws/cloud-controller-manager`.

### AWS Credential Provider
The AWS credential provider is a binary that is executed by kubelet to provide credentials for images in ECR.  Refer to the [credential provider extraction KEP](https://github.com/kubernetes/enhancements/tree/master/keps/sig-cloud-provider/2133-out-of-tree-credential-provider) for more details.

### Volume Plugins
All the EBS volume plugin related logic will be in maintenance mode. For new feature request or bug fixes, please create issue or pull request in [EBS CSI Driver](https://github.com/kubernetes-sigs/aws-ebs-csi-driver)
