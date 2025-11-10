package aws

import (
	"context"
	"fmt"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	elb "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	smithyendpoints "github.com/aws/smithy-go/endpoints"
	smithymiddleware "github.com/aws/smithy-go/middleware"

	"k8s.io/client-go/pkg/version"
)

// Adds middleware to AWS SDK Go V2 clients.
func (p *awsSDKProvider) AddMiddleware(ctx context.Context, regionName string, cfg *aws.Config) {
	cfg.APIOptions = append(cfg.APIOptions,
		middleware.AddUserAgentKeyValue("kubernetes", version.Get().String()),
		func(stack *smithymiddleware.Stack) error {
			return stack.Finalize.Add(awsHandlerLoggerMiddleware(), smithymiddleware.Before)
		},
	)

	delayer := p.getCrossRequestRetryDelay(regionName)
	if delayer != nil {
		cfg.APIOptions = append(cfg.APIOptions,
			func(stack *smithymiddleware.Stack) error {
				stack.Finalize.Add(delayPreSign(delayer), smithymiddleware.Before)
				stack.Finalize.Insert(delayAfterRetry(delayer), "Retry", smithymiddleware.Before)
				return nil
			},
		)
	}

	p.addAPILoggingMiddleware(cfg)
}

// Adds logging middleware for AWS SDK Go V2 clients
func (p *awsSDKProvider) addAPILoggingMiddleware(cfg *aws.Config) {
	cfg.APIOptions = append(cfg.APIOptions,
		func(stack *smithymiddleware.Stack) error {
			stack.Serialize.Add(awsSendHandlerLoggerMiddleware(), smithymiddleware.After)
			stack.Deserialize.Add(awsValidateResponseHandlerLoggerMiddleware(), smithymiddleware.Before)
			return nil
		},
	)
}

// GetEC2EndpointOpts returns client configuration options that override
// the signing name and region, if appropriate.
func (cfg *CloudConfig) GetEC2EndpointOpts(region string) []func(*ec2.Options) {
	opts := []func(*ec2.Options){}
	for _, override := range cfg.ServiceOverride {
		if override.Service == ec2.ServiceID && override.Region == region {
			opts = append(opts,
				ec2.WithSigV4SigningName(override.SigningName),
				ec2.WithSigV4SigningRegion(override.SigningRegion),
			)
		}
	}
	return opts
}

// GetCustomEC2Resolver returns an endpoint resolver for EC2 Clients
func (cfg *CloudConfig) GetCustomEC2Resolver() ec2.EndpointResolverV2 {
	return &EC2Resolver{
		Resolver: ec2.NewDefaultEndpointResolverV2(),
		Cfg:      cfg,
	}
}

// EC2Resolver overrides the endpoint for an AWS SDK Go V2 EC2 Client,
// using the provided CloudConfig to determine if an override
// is appropriate.
type EC2Resolver struct {
	Resolver ec2.EndpointResolverV2
	Cfg      *CloudConfig
}

// ResolveEndpoint resolves the endpoint, overriding when custom configurations are set.
func (r *EC2Resolver) ResolveEndpoint(
	ctx context.Context, params ec2.EndpointParameters,
) (
	endpoint smithyendpoints.Endpoint, err error,
) {
	for _, override := range r.Cfg.ServiceOverride {
		if override.Service == ec2.ServiceID && override.Region == aws.ToString(params.Region) {
			customURL, err := url.Parse(override.URL)
			if err != nil {
				return smithyendpoints.Endpoint{}, fmt.Errorf("could not parse override URL, %w", err)
			}
			return smithyendpoints.Endpoint{
				URI: *customURL,
			}, nil
		}
	}
	return r.Resolver.ResolveEndpoint(ctx, params)
}

// GetELBEndpointOpts returns client configuration options that override
// the signing name and region, if appropriate.
func (cfg *CloudConfig) GetELBEndpointOpts(region string) []func(*elb.Options) {
	opts := []func(*elb.Options){}
	for _, override := range cfg.ServiceOverride {
		if override.Service == elb.ServiceID && override.Region == region {
			opts = append(opts,
				elb.WithSigV4SigningName(override.SigningName),
				elb.WithSigV4SigningRegion(override.SigningRegion),
			)
		}
	}
	return opts
}

// GetCustomELBResolver returns an endpoint resolver for ELB Clients
func (cfg *CloudConfig) GetCustomELBResolver() elb.EndpointResolverV2 {
	return &ELBResolver{
		Resolver: elb.NewDefaultEndpointResolverV2(),
		Cfg:      cfg,
	}
}

// ELBResolver overrides the endpoint for an AWS SDK Go V2 ELB Client,
// using the provided CloudConfig to determine if an override
// is appropriate.
type ELBResolver struct {
	Resolver elb.EndpointResolverV2
	Cfg      *CloudConfig
}

// ResolveEndpoint resolves the endpoint, overriding when custom configurations are set.
func (r *ELBResolver) ResolveEndpoint(
	ctx context.Context, params elb.EndpointParameters,
) (
	endpoint smithyendpoints.Endpoint, err error,
) {
	for _, override := range r.Cfg.ServiceOverride {
		if override.Service == elb.ServiceID && override.Region == aws.ToString(params.Region) {
			customURL, err := url.Parse(override.URL)
			if err != nil {
				return smithyendpoints.Endpoint{}, fmt.Errorf("could not parse override URL, %w", err)
			}
			return smithyendpoints.Endpoint{
				URI: *customURL,
			}, nil
		}
	}
	return r.Resolver.ResolveEndpoint(ctx, params)
}

// GetELBV2EndpointOpts returns client configuration options that override
// the signing name and region, if appropriate.
func (cfg *CloudConfig) GetELBV2EndpointOpts(region string) []func(*elbv2.Options) {
	opts := []func(*elbv2.Options){}
	for _, override := range cfg.ServiceOverride {
		if override.Service == elbv2.ServiceID && override.Region == region {
			opts = append(opts,
				elbv2.WithSigV4SigningName(override.SigningName),
				elbv2.WithSigV4SigningRegion(override.SigningRegion),
			)
		}
	}
	return opts
}

// GetCustomELBV2Resolver returns an endpoint resolver for ELB Clients
func (cfg *CloudConfig) GetCustomELBV2Resolver() elbv2.EndpointResolverV2 {
	return &ELBV2Resolver{
		Resolver: elbv2.NewDefaultEndpointResolverV2(),
		Cfg:      cfg,
	}
}

// ELBV2Resolver overrides the endpoint for an AWS SDK Go V2 ELB Client,
// using the provided CloudConfig to determine if an override
// is appropriate.
type ELBV2Resolver struct {
	Resolver elbv2.EndpointResolverV2
	Cfg      *CloudConfig
}

// ResolveEndpoint resolves the endpoint, overriding when custom configurations are set.
func (r *ELBV2Resolver) ResolveEndpoint(
	ctx context.Context, params elbv2.EndpointParameters,
) (
	endpoint smithyendpoints.Endpoint, err error,
) {
	for _, override := range r.Cfg.ServiceOverride {
		if override.Service == elbv2.ServiceID && override.Region == aws.ToString(params.Region) {
			customURL, err := url.Parse(override.URL)
			if err != nil {
				return smithyendpoints.Endpoint{}, fmt.Errorf("could not parse override URL, %w", err)
			}
			return smithyendpoints.Endpoint{
				URI: *customURL,
			}, nil
		}
	}
	return r.Resolver.ResolveEndpoint(ctx, params)
}

// GetKMSEndpointOpts returns client configuration options that override
// the signing name and region, if appropriate.
func (cfg *CloudConfig) GetKMSEndpointOpts(region string) []func(*kms.Options) {
	opts := []func(*kms.Options){}
	for _, override := range cfg.ServiceOverride {
		if override.Service == kms.ServiceID && override.Region == region {
			opts = append(opts,
				kms.WithSigV4SigningName(override.SigningName),
				kms.WithSigV4SigningRegion(override.SigningRegion),
			)
		}
	}
	return opts
}

// GetCustomKMSResolver returns an endpoint resolver for KMS Clients
func (cfg *CloudConfig) GetCustomKMSResolver() kms.EndpointResolverV2 {
	return &KMSResolver{
		Resolver: kms.NewDefaultEndpointResolverV2(),
		Cfg:      cfg,
	}
}

// KMSResolver overrides the endpoint for an AWS SDK Go V2 KMS Client,
// using the provided CloudConfig to determine if an override
// is appropriate.
type KMSResolver struct {
	Resolver kms.EndpointResolverV2
	Cfg      *CloudConfig
}

// ResolveEndpoint resolves the endpoint, overriding when custom configurations are set.
func (r *KMSResolver) ResolveEndpoint(
	ctx context.Context, params kms.EndpointParameters,
) (
	endpoint smithyendpoints.Endpoint, err error,
) {
	for _, override := range r.Cfg.ServiceOverride {
		if override.Service == kms.ServiceID && override.Region == aws.ToString(params.Region) {
			customURL, err := url.Parse(override.URL)
			if err != nil {
				return smithyendpoints.Endpoint{}, fmt.Errorf("could not parse override URL, %w", err)
			}
			return smithyendpoints.Endpoint{
				URI: *customURL,
			}, nil
		}
	}
	return r.Resolver.ResolveEndpoint(ctx, params)
}

// GetIMDSEndpointOpts overrides the endpoint URL for IMDS clients
func (cfg *CloudConfig) GetIMDSEndpointOpts() []func(*imds.Options) {
	opts := []func(*imds.Options){}
	for _, override := range cfg.ServiceOverride {
		if override.Service == imds.ServiceID {
			opts = append(opts, func(o *imds.Options) {
				o.Endpoint = override.URL
			})
		}
	}
	return opts
}

// GetAutoscalingEndpointOpts returns client configuration options that override
// the signing name and region, if appropriate.
func (cfg *CloudConfig) GetAutoscalingEndpointOpts(region string) []func(*autoscaling.Options) {
	opts := []func(*autoscaling.Options){}
	for _, override := range cfg.ServiceOverride {
		if override.Service == autoscaling.ServiceID && override.Region == region {
			opts = append(opts,
				autoscaling.WithSigV4SigningName(override.SigningName),
				autoscaling.WithSigV4SigningRegion(override.SigningRegion),
			)
		}
	}
	return opts
}

// GetCustomAutoscalingResolver returns an endpoint resolver for Autoscaling Clients
func (cfg *CloudConfig) GetCustomAutoscalingResolver() autoscaling.EndpointResolverV2 {
	return &AutoscalingResolver{
		Resolver: autoscaling.NewDefaultEndpointResolverV2(),
		Cfg:      cfg,
	}
}

// AutoscalingResolver overrides the endpoint for an AWS SDK Go V2 Autoscaling Client,
// using the provided CloudConfig to determine if an override
// is appropriate.
type AutoscalingResolver struct {
	Resolver autoscaling.EndpointResolverV2
	Cfg      *CloudConfig
}

// ResolveEndpoint resolves the endpoint, overriding when custom configurations are set.
func (r *AutoscalingResolver) ResolveEndpoint(
	ctx context.Context, params autoscaling.EndpointParameters,
) (
	endpoint smithyendpoints.Endpoint, err error,
) {
	for _, override := range r.Cfg.ServiceOverride {
		if override.Service == autoscaling.ServiceID && override.Region == aws.ToString(params.Region) {
			customURL, err := url.Parse(override.URL)
			if err != nil {
				return smithyendpoints.Endpoint{}, fmt.Errorf("could not parse override URL, %w", err)
			}
			return smithyendpoints.Endpoint{
				URI: *customURL,
			}, nil
		}
	}
	return r.Resolver.ResolveEndpoint(ctx, params)
}
