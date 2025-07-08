
# Service type-LoadBalancer Network Load Balancer with Security Group

## Overview

Starting with this release, you can enable controller-managed Security Groups (SGs) for AWS Network Load Balancers (NLBs) by setting an opt-in configuration in your cloud config. When enabled, each NLB created for a Kubernetes Service of type `LoadBalancer` will have a dedicated Security Group, managed by the cloud provider controller. We are calling this as opt-in Managed NLB Security Group ("Managed SG" mode).

Alternatively, you can also bring your own seucirty group ("BYO SG" mode) using existing annotations, overriding the opt-in managed NLB Security Group configuration.

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

### BYO Security Group mode

To enable this feature, create a service with annotation `service.beta.kubernetes.io/aws-load-balancer-security-groups` with the security group ID, ignoring the configuration `NLBSecurityGroupMode`.

This annotation is equivalent to ALBC [`alb.ingress.kubernetes.io/security-groups`](https://kubernetes-sigs.github.io/aws-load-balancer-controller/latest/guide/ingress/annotations/#frontend-nlb-security-groups).

Attention: to keep compatibility with ALBC, the annotation is not supported supported on NLB.

## Feature Details and Use Cases

- **Why use this feature?**
  - Improved security: fine-grained, automated control over NLB ingress.
  - Automated lifecycle management of SGs, reducing manual intervention and risk of resource leaks.
- **When to use:**
  - When you want the controller to manage NLB security groups automatically for NLB.
  - When your security/compliance policies require explicit SGs for each NLB.

## Upgrade and Migration Notes

- **Enabling the feature:**
  - Existing NLBs will not be retroactively assigned a managed SG. Only new NLBs (created after enabling the feature) will have managed SGs.
  - To migrate existing NLBs, you must recreate the Service or manually update the SGs.
- **Disabling the feature:**
  - If you disable the feature after using it, previously managed SGs will not be deleted automatically unless the Service and associated NLB is deleted.
- **Controller restart:**
  - Changing the config requires a controller restart for the new setting to take effect.

## Security Group Lifecycle

### Managed Security Group

- **Creation:**
  - SGs are created with tags indicating they are managed by the controller, including a tag like `kubernetes.io/cloud-provider-aws/NLBSecurityGroupMode=Managed`.
- **Tagging:**
  - Managed SGs are tagged for identification and safe cleanup. Example tags:
    - `kubernetes.io/cluster/<cluster-name>`
    - `kubernetes.io/cloud-provider-aws/NLBSecurityGroupMode=Managed`
- **Deletion:**
  - SGs are deleted when the corresponding NLB is deleted. The controller uses exponential backoff to handle AWS dependency violations.

### BYO Security Group

- **Creation:**
  - SGs are created and managed by the user, only required security group rules for the service is added to the user-provided security group.
- **Tagging:**
  - Users must tag the security group on creation.
- **Update:**
  - Service type-LoadBalancer NLB created without Security Group does not support updates in the annotation `service.beta.kubernetes.io/aws-load-balancer-security-groups`.
- **Deletion:**
  - SGs are not deleted when the corresponding Service NLB is deleted, the security group rules will be removed on service delete workflow.


## Testing and Validation

### **How to test the Managed Security Group:**

  1. Ensure your cloud-config has the configuration `NLBSecurityGroupMode = Managed`
  2. Create a Service of type `LoadBalancer` after enabling the feature.
```sh
APP_NAME=app
APP_NAMESPACE=$APP_NAME
SVC_NAME=$APP_NAME-svc-ccm
cat << EOF | kubectl create -f -
apiVersion: v1
kind: Service
metadata:
  name: $SVC_NAME
  namespace: ${APP_NAMESPACE}
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-type: nlb
spec:
  selector:
    app: $APP_NAME
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

### **How to test the BYO Security Group:**

  1. Create a Security Group
```sh
CLUSTER_ID=my-cluster # CHANGE_ME
SVC_NAME="$APP_NAME_BASE-svc-ccm-byosg"
SG_NAME="${CLUSTER_ID}-sg-${SVC_NAME}"

# Assuming your VPC is tagged properly, otherwise CHANGE_ME
VPC_ID=$(aws ec2 describe-vpcs --filters "Name=tag-key,Values=kubernetes.io/cluster/${CLUSTER_ID}" --query Vpcs[].VpcId --output text)

# create a security group with AWS CLI filtering the cluster ID from VPC tags
SG_ID=$(aws ec2 create-security-group \
--vpc-id="${VPC_ID}" \
--group-name="${SG_NAME}" \
--description="BYO SG sample for service ${SVC_NAME}" \
--tag-specifications "ResourceType=security-group,Tags=[{Key=Name,Value=${SG_NAME}},{Key=kubernetes.io/cluster/${CLUSTER_ID},Value=shared}]" \
| tee -a | jq -r .GroupId)
```
  2. Create a service with the desired Security Group:
```sh
cat << EOF | oc create -f -
apiVersion: v1
kind: Service
metadata:
  name: $SVC_NAME
  namespace: ${APP_NAMESPACE}
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-type: nlb
    service.beta.kubernetes.io/aws-load-balancer-security-groups: $SG_ID
spec:
  selector:
    app: $APP_NAME_BASE
  ports:
    - port: 80
      targetPort: 8080
      protocol: TCP
  type: LoadBalancer
EOF
```
  3. Ensure you can reach the Service NLB endpoint (step 5 in the last section)
  4. Delete the Service.
  5. Check if the BYO Security Group was not deleted
  6. Delete the BYO Security Group manually

## Troubleshooting

- **SG not deleted:**
  - Check for AWS dependency violations (e.g., NLB still deleting). The controller will retry deletion with backoff.
- **NLB not created:**
  - Ensure the controller has IAM permissions to manage Security Groups.
- **SG rules not as expected:**
  - Check your Service annotations and cloud config.
- **Config changes not taking effect:**
  - Ensure you have restarted the controller after changing the config.

## Scenarios for NLB

On Service Create:

| Config `NLBSecurityGroupMode` | Case | Result |
| -- | -- | -- |
| empty or !=`Managed` | Default Behavior | NLB created without SG |
| empty or !=`Managed` | annotation `service.beta.kubernetes.io/aws-load-balancer-security-groups=sg-id1` | BYO SG attached to NLB, ingress rules added to `sg-id1` |
| `Managed` | Managed SG | NLB created with SG managed by CCM |
| `Managed` | annotation `service.beta.kubernetes.io/aws-load-balancer-security-groups=sg-id1` | BYO SG attached to NLB, ingress rules added to `sg-id1` |
| `Managed` | annotation `service.beta.kubernetes.io/aws-load-balancer-security-groups=sg-id1,sg-id2` | BYO SGs attached to NLB, ingress rules added to `sg-id1` |

On Service Update:

| Create State | Case | Result |
| -- | -- | -- |
| NLB without SG | annotation added `service.beta.kubernetes.io/aws-load-balancer-security-groups=sg-id1` | Do nothing. NLB does not support attach SG to existing NLB created without SG support. |
| NLB with managed SG | annotation added `service.beta.kubernetes.io/aws-load-balancer-security-groups=sg-id1` | Do nothing. Replace managed SG on NLB with new SGs is not currently supported. |
| NLB with BYO SG | annotation updated `service.beta.kubernetes.io/aws-load-balancer-security-groups=sg-id2` | Controller must update the SG to sg-id2. |
| NLB with managed SG | port added | SG rules are updated matching the frontend/listeners. |
| NLB with managed SG | port removed | SG rules are updated matching the frontend/listeners. |

On Delete:

TBD