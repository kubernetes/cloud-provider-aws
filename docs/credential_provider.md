# Credential Provider

This feature was alpha from Kubernetes 1.20 through 1.23, beta in Kubernetes
1.24 and 1.25, and is stable starting in Kubernetes 1.26.

As part of the cloud provider extraction, [KEP-2133](https://github.com/kubernetes/enhancements/pull/2151) proposed an extensible way to fetch credentials for pulling images. When kubelet needs credentials to fetch an image, it will now invoke a plugin based on the configuration provided by the cluster operator. Please see the original KEP for details.

We currently have the implementation for fetching ECR credentials. In order to use this new plugin, you'll have to:

- Pass the folder where the binary is located as `--image-credential-provider-bin-dir` to the kubelet.
- Create a new `CredentialProviderConfig` and pass its location to the kubelet via `--image-credential-provider-config`.

Example config:

```json
{
    "providers": [
        {
            "name": "ecr-credential-provider",
            "matchImages" : [
                "*.dkr.ecr.*.amazonaws.com",
                "*.dkr.ecr.*.amazonaws.com.cn"
            ],
            "apiVersion": "credentialprovider.kubelet.k8s.io/v1",
            "defaultCacheDuration": "0"
        }
    ]
}
```

Once you pass this config to the kubelet, every time it needs to fetch an image that matches one of the "matchImages" patterns, it will invoke the "ecr-credential-provider" binary in the `--image-credential-provider-bin-dir` folder. In turn, the plugin will fetch the credentials for kubelet and send it back via stdio. Note that the name of the "provider" in your config has to match the name of the binary.

**Note:** The credential provider will only be used if the image matches a path
in the list.
Globbing may be used, but each glob can only match a single subdomain segment.
So `*.io` does not match `*.k8s.io`.

## Authentication

The [AWS SDK credential chain](https://docs.aws.amazon.com/sdkref/latest/guide/standardized-credentials.html) is used to locate credentials for authenticating with AWS. For example, when you run the ECR credential provider on an EC2 instance, credentials are usually fetched from IMDS and no other configuration is necessary. If you do not run the ECR credential provider on EC2, you can specify credentials using environment variables, the `~/.aws/config` file, or any other standard method in the credential chain.

## Global ECR tokens

Existing configurations are unchanged: without `--ecr-private-token-type`, the
provider uses regional tokens.

Add `--ecr-private-token-type=global-token` to the provider `args` explicitly
to use a global token for private ECR registries. It does not apply to ECR
Public.

```json
{
    "providers": [
        {
            "name": "ecr-credential-provider",
            "matchImages": [
                "*.dkr.ecr.*.amazonaws.com"
            ],
            "apiVersion": "credentialprovider.kubelet.k8s.io/v1",
            "defaultCacheDuration": "0",
            "args": [
                "--ecr-private-token-type=global-token"
            ]
        }
    ]
}
```

For details, see [Private registry authentication in Amazon ECR](https://docs.aws.amazon.com/AmazonECR/latest/userguide/registry_auth.html).
