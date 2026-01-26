# Service type-LoadBalancer Network Load Balancer with Security Group

## Overview

The controller can be configured to enable managed Security Group (SG) for Services using AWS Network Load Balancer (NLB) by setting an opt-in configuration in your cloud config. When enabled, each NLB created for a Kubernetes Service of type `LoadBalancer` with annotation `service.beta.kubernetes.io/aws-load-balancer-type=nlb` will have a dedicated Security Group, managed by the cloud provider controller. We are calling this as opt-in Managed NLB Security Group ("Managed SG" mode).

> Note: The BYO SG (user-provided security groups) annotations (`service.beta.kubernetes.io/aws-load-balancer-security-groups` and `service.beta.kubernetes.io/aws-load-balancer-extra-security-groups`) are valid only for Classic Load Balancers. To learn more about supported annotations by load balancer type, see the [service_controller documentation][doc-ctrl-service].

[doc-ctrl-service]: https://github.com/kubernetes/cloud-provider-aws/blob/master/docs/service_controller.md

## Configuration

### Opt-in Managed Security Group mode

To enable this feature, add the following to your cloud config (usually `/etc/kubernetes/cloud-config` or as configured in your deployment):

```ini
[Global]
NLBSecurityGroupMode = Managed
```

- **Default behavior:** If `NLBSecurityGroupMode` is not set or set to any value other than `Managed`, NLBs are provisioned without a dedicated, controller-managed Security Group (legacy behavior).
- **Opt-in behavior:** When set to `Managed`, the controller will create, attach, update, and delete a dedicated SG for each NLB Service.
- **Bypass Opt-in behavior:** When the annotation is set, the controller will use the annotated security group.

## Feature Details and Use Cases

- **Why use this feature?**
  - Improved security: fine-grained, automated control over NLB ingress.
  - Automated lifecycle management of SGs, reducing manual intervention and risk of resource leaks.
- **When to use:**
  - When you want the controller to manage NLB security groups automatically for NLB.
  - When your security/compliance policies require explicit SGs for each NLB.

## Upgrade and Migration Notes

- **Enabling the feature:**
  - Existing Service type-loadBalancer NLB will not be retroactively assigned a managed SG. Only new Services (created after enabling the feature) will have managed SGs.
  - To migrate existing NLBs, you must recreate the Service or manually update the SGs.
- **Disabling the feature:**
  - If you disable the feature after using it, previously managed SGs will not be deleted automatically unless the Service and associated NLB is deleted.
- **Controller restart:**
  - Changing the config requires a controller restart for the new setting to take effect.

## Security Group Lifecycle

### Managed Security Group

- **Creation:**
  - SGs are created with owned cluster tag indicating they are managed by the controller.
- **Tagging:**
  - Managed SGs are tagged for identification and safe cleanup. Example cluster tag:
    - `kubernetes.io/cluster/<cluster-name>: owned`
- **Deletion:**
  - Managed SGs are deleted when the corresponding Service is deleted. The controller uses exponential backoff to handle AWS dependency violations.

## Testing and Validation

### Test 1 - **How to test the Managed Security Group:**

  1. Ensure your cloud-config has the configuration `NLBSecurityGroupMode = Managed`
  2. Create a Service of type `LoadBalancer` after enabling the feature.
```sh
APP_NAME=app
APP_NAMESPACE=$APP_NAME
SVC_NAME="${APP_NAME}-nlb-sg"
cat << EOF | kubectl create -f -
apiVersion: v1
kind: Service
metadata:
  name: "${SVC_NAME}"
  namespace: "${APP_NAMESPACE}"
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-type: nlb
spec:
  selector:
    app: "${APP_NAME}"
  ports:
    - port: 80
      targetPort: 8080
      protocol: TCP
  type: LoadBalancer
EOF
```
  3. Verify that a managed SG is created and attached to the NLB in the AWS console.
  4. Check that the SG is tagged appropriately and that ingress rules match your Service spec.
  5. Ensure you can reach the Service NLB endpoint:
```sh
LB_DNS=$(kubectl get svc $SVC_NAME -n ${APP_NAMESPACE} -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')

aws elbv2 describe-tags --resource-arns $(aws elbv2 describe-load-balancers | jq -r ".LoadBalancers[] | select(.DNSName==\"$LB_DNS\").LoadBalancerArn") | jq .TagDescriptions[].Tags

[
  {
    "Key": "kubernetes.io/service-name",
    "Value": "app/app-svc-ccm"
  },
  {
    "Key": "kubernetes.io/cluster/mrb-sg-zvcgr",
    "Value": "owned"
  }
]

# reach the LB endpoint
curl -v $LB_DNS
```
  4. Delete the Service and verify that the SG is deleted.


### Test 2 - **How to test the BYO Security Group:**

  1. Create a Security Group
```sh
APP_NAME_BASE=app
CLUSTER_ID=my-cluster # CHANGE_ME
SVC_NAME="${APP_NAME_BASE}-nlb-byosg"
SG_NAME="${CLUSTER_ID}-sg-${SVC_NAME}"

# Lookup VPC by cluster tag. Assuming the VPC is properly tagged with kubernetes cluster tag.
VPC_ID=$(aws ec2 describe-vpcs --filters "Name=tag-key,Values=kubernetes.io/cluster/${CLUSTER_ID}" --query Vpcs[].VpcId --output text)

# create a security group with AWS CLI, with kubernetes cluster tag with 'shared' value
SG_ID=$(aws ec2 create-security-group \
--vpc-id="${VPC_ID}" \
--group-name="${SG_NAME}" \
--description="BYO SG sample for service ${SVC_NAME}" \
--tag-specifications "ResourceType=security-group,Tags=[{Key=Name,Value=${SG_NAME}},{Key=kubernetes.io/cluster/${CLUSTER_ID},Value=shared}]" \
| tee -a | jq -r .GroupId)
```
  2. Create a service with the desired Security Group:
```sh
cat << EOF | kubectl create -f -
apiVersion: v1
kind: Service
metadata:
  name: "${SVC_NAME}"
  namespace: "${APP_NAMESPACE}"
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-type: nlb
    service.beta.kubernetes.io/aws-load-balancer-security-groups: "${SG_ID}"
spec:
  selector:
    app: "${APP_NAME_BASE}"
  ports:
    - name: http80
      port: 80
      targetPort: 8080
      protocol: TCP
  type: LoadBalancer
EOF
```
  3. Ensure you can reach the Service NLB endpoint (step 5 in the last section)
  4. Delete the Service.
  5. Check if the BYO Security Group was not deleted
  6. Delete the BYO Security Group manually

### Test 3 - **How to migrate a NLB from Managed Security Group to BYO SG:**

1. Create a Service with managed security group support (Test 1). Controller logs:
```
I0723 23:14:21.154007 2321315 aws.go:2295] Creating NLB security group "k8s-elb-aa4927fe5b89b468383dc27544066840" for service "app/app-nlb-sg"
I0723 23:14:21.855064 2321315 aws.go:2304] Created NLB security group "sg-0f15d6a526fd46e8f" for service "app/app-nlb-sg"
```
2. Create the BYO SG (Test 2, step 1).
```sh
$ echo $SG_ID
sg-011077cb034c10ee4
```
2. Patch the service with Security Group ID
```sh
kubectl patch service ${SVC_NAME} -n ${APP_NAMESPACE} --type=merge \
  --patch '{"metadata":{"annotations":{"service.beta.kubernetes.io/aws-load-balancer-security-groups":"'$SG_ID'"}}}'
```
Check the logs
```
I0723 23:16:17.272741 2321315 aws_loadbalancer.go:398] Detected security group changes, updating load balancer
I0723 23:16:18.160131 2321315 aws_loadbalancer.go:1882] deleting loadbalancer owned security group "sg-0f15d6a526fd46e8f"
I0723 23:16:18.556996 2321315 aws.go:3090] Managed Security Group "sg-0f15d6a526fd46e8f" deleted for service load balancer "aa4927fe5b89b468383dc27544066840"
I0723 23:16:18.557073 2321315 aws.go:3108] Deleted all security groups for load balancer: aa4927fe5b89b468383dc27544066840
I0723 23:16:18.557108 2321315 aws_loadbalancer.go:1891] loadbalancer owned security group "sg-0f15d6a526fd46e8f" deleted
I0723 23:16:18.988050 2321315 aws.go:1315] Existing security group ingress: sg-011077cb034c10ee4 []
```
3. Check if the NLB are using the custom security group
```sh
$ aws elbv2 describe-load-balancers | jq -r ".LoadBalancers[] | select(.DNSName==\"$LB_DNS\").SecurityGroups"
[
  "sg-011077cb034c10ee4"
]
```
4. Check if the managed security group was deleted (controller logs)
```sh
$ aws ec2 describe-security-groups --group-ids sg-0f15d6a526fd46e8f

An error occurred (InvalidGroup.NotFound) when calling the DescribeSecurityGroups operation: The security group 'sg-0f15d6a526fd46e8f' does not exist
```
5. Update the service ports to validate if the controller updates the ingress rule of BYO SG
```sh
kubectl patch service ${SVC_NAME} -n ${APP_NAMESPACE} --type=json \
  --patch '[{"op": "add", "path": "/spec/ports/-",
    "value": {"name":"http81","port":8888,"protocol":"TCP","targetPort":8080}}]'

kubectl patch service ${SVC_NAME} -n ${APP_NAMESPACE} --type=json \
  --patch '[{"op": "add", "path": "/spec/ports/-", "value": {"name":"http8888","port":8888,"protocol":"TCP","targetPort":8080}}]'
```
6. Check if security group ingress rules has been updated
```sh
$ aws ec2 describe-security-group-rules --filters Name=group-id,Values=$SG_ID | jq .SecurityGroupRules[].ToPort
80
8888
..
```
7. Delete the service
```sh
kubectl delete service ${SVC_NAME}
```
8. Ensure the BYO SG is not deleted
```sh
$ aws ec2 describe-security-groups --group-ids $SG_ID | jq .SecurityGroups[].GroupName
"clusterid-sg-app-nlb-sg"
```

## Troubleshooting

- **SG not deleted:**
  - Check for AWS dependency violations (e.g., NLB still deleting). The controller will retry deletion with backoff.
- **NLB not created:**
  - Ensure the controller has IAM permissions to manage Security Groups.
- **SG rules not as expected:**
  - Check your Service annotations and cloud config.
- **Config changes not taking effect:**
  - Ensure you have restarted the controller after changing the config.
