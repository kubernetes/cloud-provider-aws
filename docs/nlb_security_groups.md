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

## Troubleshooting

- **SG not deleted:**
  - Check for AWS dependency violations (e.g., NLB still deleting). The controller will retry deletion with backoff.
- **NLB not created:**
  - Ensure the controller has IAM permissions to manage Security Groups.
- **SG rules not as expected:**
  - Check your Service annotations and cloud config.
- **Config changes not taking effect:**
  - Ensure you have restarted the controller after changing the config.