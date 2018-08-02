# cloud-provider-aws
The AWS cloud provider provides the interface between a Kubernetes cluster and AWS service APIs. This project allows a Kubernetes cluster to provision, monitor and remove resources necessary for operation of the cluster.

## Flags
The flag `--cloud-provider=external` needs to be passed to kubelet, kube-apiserver, and kube-controller-manager. You should not pass the --cloud-provider flag to `aws-cloud-controller-manager`.

## IAM Policy
For the aws-cloud-controller-manager to be able to communicate to AWS APIs, you will need to create a few IAM policies for your EC2 instances. The master policy is a bit open and can be scaled back depending on the use case. Adjust these based on your needs.

1. Master Policy

```
  {  
      "Version": "2012-10-17",
      "Statement": [
          {
              "Effect": "Allow",
              "Action": [
                  "ec2:*",
                  "elasticloadbalancing:*",
                  "ecr:GetAuthorizationToken",
                  "ecr:BatchCheckLayerAvailability",
                  "ecr:GetDownloadUrlForLayer",
                  "ecr:GetRepositoryPolicy",
                  "ecr:DescribeRepositories",
                  "ecr:ListImages",
                  "ecr:BatchGetImage"    
              ],
              "Resource": "*"      
          }  
      ] 
  }
  ```
2. Node Policy

```
  {
      "Version": "2012-10-17",
      "Statement": [
          {
              "Effect": "Allow",
              "Action": [
                  "ec2:Describe*",
                  "ecr:GetAuthorizationToken",
                  "ecr:BatchCheckLayerAvailability",
                  "ecr:GetDownloadUrlForLayer",
                  "ecr:GetRepositoryPolicy",
                  "ecr:DescribeRepositories",
                  "ecr:ListImages",
                  "ecr:BatchGetImage"
              ],
              "Resource": "*"
          } 
      ]
  }
  ```
  
## Proper Node Names
The cloud provider currently uses the instance private DNS name as the node name, but this is subject to change in the future.

### NOTE
Currently the implementation of the cloud provider is found in https://github.com/kubernetes/kubernetes/tree/master/pkg/cloudprovider/providers/aws, and vendored into this repository. In the future, the implementation will be migrated here and out of Kubernetes core.
