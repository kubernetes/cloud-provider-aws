<p align="center">
    <img src="docs/assets/images/kubernetes_icon.svg" alt="Kubernetes logo" width="200" />
    <img src="docs/assets/images/aws_logo.svg" alt="AWS Load Balancer logo" width="200" />
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
    <a href="https://github.com/kubernetes/cloud-provider-aws/issues">
        <img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat" alt="contributions welcome"/>
    </a>
    <a href="https://github.com/kubernetes/cloud-provider-aws/blob/master/LICENSE">
        <img alt="GitHub license" src="https://img.shields.io/github/license/kubernetes/cloud-provider-aws">
    </a>
    <a href="https://goreportcard.com/badge/github.com/kubernetes/cloud-provider-aws">
        <img src="https://goreportcard.com/badge/github.com/kubernetes/cloud-provider-aws" alt="go report card"/>
    </a>
</p>

# cloud-provider-aws
The AWS cloud provider provides the interface between a Kubernetes cluster and AWS service APIs. This project allows a Kubernetes cluster to provision, monitor and remove AWS resources necessary for operation of the cluster.

<p align="center">
    <strong><a href="https://kubernetes.github.io/cloud-provider-aws/">See the online documentation here</a></strong>
</p>

## Note
* All the EBS volume plugin related logic will be in maintenance mode. For new feature request or bug fixes, please create issue or pull request in [EBS CSI Driver](https://github.com/kubernetes-sigs/aws-ebs-csi-driver)
