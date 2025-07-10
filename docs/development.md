# Development

This guide is for contributors and developers working on the AWS cloud controller manager (`cloud-provider-aws`).
It provides step-by-step instructions for setting up a development environment, building and testing the controller, and running end-to-end (e2e) tests on AWS.

You will learn how to:
- Set up a Kubernetes cluster for development (either locally or using an existing AWS cluster)
- Build and test the controller binary
- Run the controller locally or in your cluster
- Prepare and execute e2e tests

Whether you are adding new features, fixing bugs, or validating changes, this guide will help you get started and follow best practices for development in the Kubernetes ecosystem.

## Setting up environment

To develop and test the AWS cloud controller manager, you need access to a Kubernetes cluster running on AWS. You can either create a new cluster for development or use an existing one.

The following sections describe both approaches.

### Option 1: Create a local development cluster

You can bring up a single-node Kubernetes cluster on AWS by running the provided local-up script **on an AWS EC2 instance**.
**Note:** The EC2 instance must have the `KubernetesCluster` tag (the value can be any string).

```sh
./hack/local-up-cluster.sh
```

By default, this script uses the cloud provider binary from this repository.
**Prerequisite:** You must have the Kubernetes main repository cloned before running this script.

### Option 2: Use an existing cluster

If you already have a Kubernetes cluster running on AWS, you can test the controller binary directly from your local machine or another environment.
Follow these steps:

1. **Export AWS credentials** for the AWS account and region where your cluster is running.
2. **Scale down the in-cluster cloud controller manager deployment** to avoid conflicts.
3. **Create a cloud-config file** tailored to your environment:
```sh
cat << EOF >> $CLOUD_CONFIG
[Global]
Region                                          = us-east-1
VPC                                             = <VPC ID where the cluster is installed>
SubnetID                                        = <Single subnet ID used by load balancer controller>
KubernetesClusterTag                            = <kubernetes cluster ID>
DisableSecurityGroupIngress                     = false
ClusterServiceLoadBalancerHealthProbeMode       = Shared
ClusterServiceSharedLoadBalancerHealthProbePort = 0
EOF
```
    - Replace the placeholders with values from your AWS environment.
    - The `KubernetesClusterTag` should match the tag used on your cluster resources (e.g., `my-cluster-id` for `kubernetes.io/cluster/my-cluster-id`).

4. **Run the controller:**
```sh
$ ./aws-cloud-controller-manager -v=2 \
    --cloud-config="${CLOUD_CONFIG}" \
    --kubeconfig="${KUBECONFIG}" \
    --cloud-provider=aws \
    --use-service-account-credentials=true \
    --configure-cloud-routes=false \
    --leader-elect=true \
    --leader-elect-lease-duration=137s \
    --leader-elect-renew-deadline=107s \
    --leader-elect-retry-period=26s \
    --leader-elect-resource-namespace=openshift-cloud-controller-manager
```

> **Tip:** When running the controller outside of AWS (e.g., on your laptop), ensure your cloud config includes `Region`, `VPC`, `SubnetID`, and `KubernetesClusterTag` to avoid errors related to EC2 metadata service access.

## Basic Development Flow

When developing changes for the cloud provider, you'll be running the following commands:

```
# Build the package
make

# Running the unit tests
make test

# Updating formatting
make update-fmt

# Verifying formatting and lint and vet code
make check
```

## Running e2e Tests

To run the e2e tests, you'll need a few AWS resources set up:
1. An ECR repo to upload container images
2. An S3 bucket to store kops state
3. ssh access to an EC2 instance to run the tests on

You can override the region for the tests, but for the purpose of this guide, we'll stick to `us-west-2`.

### [Prereq] Create ECR repository

The e2e tests expect your AWS account to have the `provider-aws/cloud-controller-manager` ECR repository to upload container images. You can create it with the following command:

```
aws ecr create-repository --repository-name provider-aws/cloud-controller-manager --region us-west-2
```

### [Prereq] Create S3 kops state bucket

You can re-use any existing S3 bucket that you have access to or use the following command to create one:

```
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
# Use the account ID to avoid S3 bucket naming conflict
aws s3api create-bucket --bucket e2e-kops-state-$AWS_ACCOUNT_ID --region us-west-2 \
    --create-bucket-configuration LocationConstraint=us-west-2
```

### [Prereq] Set up EC2 instance

Use the AWS console to launch an EC2 instance with the latest Ubuntu AMI. When creating the instance, it should have the following set up:
1. ssh access so you can run the tests - requires an ssh key associated with the instance and port 22 access
2. An instance profile with admin access to the account. This can be paired down to more limited permissions.

The instance will need a number of packages installed to work. Below is example of commands that may get the instance sufficiently bootstrapped.

```
# Install dependencies
sudo apt-get update
sudo apt install zip
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
sudo snap install go --classic
sudo apt install gcc
sudo apt install make
sudo snap install docker
sudo chmod 666 /var/run/docker.sock

# Set up repo locally
export GITHUB_USER=[REPLACE WITH USERNAME]
git clone https://github.com/$GITHUB_USER/cloud-provider-aws.git
cd cloud-provider-aws
make && make test
```

### Run the tests!

You can run the tests with the following:

```
# Prepare to run e2e tests
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
# Replace if you're using a different bucket
export KOPS_STATE_STORE=s3://e2e-kops-state-$AWS_ACCOUNT_ID
# Set the version that will be used
export GIT_VERSION=v1.32.1
make test-e2e
```

> [!NOTE]
> If tests fail and the cluster isn't deleted, you can manually delete with `kops delete cluster --name ENTER_NAME`. The S3 kops state bucket will include all clusters not cleaned up.
