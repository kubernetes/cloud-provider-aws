# Development

A local single node cluster can be brought up on AWS by running the local up script while on an AWS EC2 instance.
Before running this, ensure that the instance you are running on has the `KubernetesCluster` tag. The tag can be any value.

```
./hack/local-up-cluster.sh
```

By default this script will use the cloud provider binary from this repository. You will need to have the k8s main repo cloned before running this script.

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
make test-e2
```

**NOTE: If tests fail and the cluster isn't deleted, you can manually delete with `kops delete cluster --name ENTER_NAME`. The S3 kops state bucket will include all clusters not cleaned up.**
