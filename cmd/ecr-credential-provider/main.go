/*
Copyright 2020 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
	"k8s.io/kubelet/pkg/apis/credentialprovider/v1alpha1"
)

var ecrPattern = regexp.MustCompile(`^(\d{12})\.dkr\.ecr(\-fips)?\.([a-zA-Z0-9][a-zA-Z0-9-_]*)\.(amazonaws\.com(\.cn)?|sc2s\.sgov\.gov|c2s\.ic\.gov)$`)

// ECR abstracts the calls we make to aws-sdk for testing purposes
type ECR interface {
	GetAuthorizationToken(input *ecr.GetAuthorizationTokenInput) (*ecr.GetAuthorizationTokenOutput, error)
}

type ecrPlugin struct {
	ecr ECR
}

func defaultECRProvider(region string, registryID string) (*ecr.ECR, error) {
	sess, err := session.NewSessionWithOptions(session.Options{
		Config:            aws.Config{Region: aws.String(region)},
		SharedConfigState: session.SharedConfigEnable,
	})
	if err != nil {
		return nil, err
	}

	return ecr.New(sess), nil
}

func (e *ecrPlugin) GetCredentials(ctx context.Context, image string, args []string) (*v1alpha1.CredentialProviderResponse, error) {
	registryID, region, registry, err := parseRepoURL(image)
	if err != nil {
		return nil, err
	}

	if e.ecr == nil {
		e.ecr, err = defaultECRProvider(region, registryID)
		if err != nil {
			return nil, err
		}
	}

	output, err := e.ecr.GetAuthorizationToken(&ecr.GetAuthorizationTokenInput{
		RegistryIds: []*string{aws.String(registryID)},
	})
	if err != nil {
		return nil, err
	}

	if output == nil {
		return nil, errors.New("response output from ECR was nil")
	}

	if len(output.AuthorizationData) == 0 {
		return nil, errors.New("authorization data was empty")
	}

	data := output.AuthorizationData[0]
	if data.AuthorizationToken == nil {
		return nil, errors.New("authorization token in response was nil")
	}

	decodedToken, err := base64.StdEncoding.DecodeString(aws.StringValue(data.AuthorizationToken))
	if err != nil {
		return nil, err
	}

	parts := strings.SplitN(string(decodedToken), ":", 2)
	if len(parts) != 2 {
		return nil, errors.New("error parsing username and password from authorization token")
	}

	cacheDuration := getCacheDuration(data.ExpiresAt)

	return &v1alpha1.CredentialProviderResponse{
		CacheKeyType:  v1alpha1.RegistryPluginCacheKeyType,
		CacheDuration: cacheDuration,
		Auth: map[string]v1alpha1.AuthConfig{
			registry: {
				Username: parts[0],
				Password: parts[1],
			},
		},
	}, nil

}

// getCacheDuration calculates the credentials cache duration based on the ExpiresAt time from the authorization data
func getCacheDuration(expiresAt *time.Time) *metav1.Duration {
	var cacheDuration *metav1.Duration
	if expiresAt == nil {
		// explicitly set cache duration to 0 if expiresAt was nil so that
		// kubelet does not cache it in-memory
		cacheDuration = &metav1.Duration{Duration: 0}
	} else {
		// halving duration in order to compensate for the time loss between
		// the token creation and passing it all the way to kubelet.
		duration := time.Second * time.Duration((expiresAt.Unix()-time.Now().Unix())/2)
		if duration > 0 {
			cacheDuration = &metav1.Duration{Duration: duration}
		}
	}
	return cacheDuration
}

// parseRepoURL parses and splits the registry URL
// returns (registryID, region, registry).
// <registryID>.dkr.ecr(-fips).<region>.amazonaws.com(.cn)
func parseRepoURL(image string) (string, string, string, error) {
	if !strings.Contains(image, "https://") {
		image = "https://" + image
	}
	parsed, err := url.Parse(image)
	if err != nil {
		return "", "", "", fmt.Errorf("error parsing image %s: %v", image, err)
	}

	splitURL := ecrPattern.FindStringSubmatch(parsed.Hostname())
	if len(splitURL) < 4 {
		return "", "", "", fmt.Errorf("%s is not a valid ECR repository URL", parsed.Hostname())
	}

	return splitURL[1], splitURL[3], parsed.Hostname(), nil
}

func main() {
	p := NewCredentialProvider(&ecrPlugin{})
	if err := p.Run(context.TODO()); err != nil {
		klog.Errorf("Error running credential provider plugin: %v", err)
		os.Exit(1)
	}
}
