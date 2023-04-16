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
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/kubelet/pkg/apis/credentialprovider/install"
	"k8s.io/kubelet/pkg/apis/credentialprovider/v1"
)

var (
	scheme = runtime.NewScheme()
	codecs = serializer.NewCodecFactory(scheme)
)

func init() {
	install.Install(scheme)
}

// CredentialProvider is an interface implemented by the kubelet credential provider plugin to fetch
// the username/password based on the provided image name.
type CredentialProvider interface {
	GetCredentials(ctx context.Context, image string, args []string) (response *v1.CredentialProviderResponse, err error)
}

// ExecPlugin implements the exec-based plugin for fetching credentials that is invoked by the kubelet.
type ExecPlugin struct {
	plugin CredentialProvider
}

// NewCredentialProvider returns an instance of execPlugin that fetches
// credentials based on the provided plugin implementing the CredentialProvider interface.
func NewCredentialProvider(plugin CredentialProvider) *ExecPlugin {
	return &ExecPlugin{plugin}
}

// Run executes the credential provider plugin. Required information for the plugin request (in
// the form of v1.CredentialProviderRequest) is provided via stdin from the kubelet.
// The CredentialProviderResponse, containing the username/password required for pulling
// the provided image, will be sent back to the kubelet via stdout.
func (e *ExecPlugin) Run(ctx context.Context) error {
	return e.runPlugin(ctx, os.Stdin, os.Stdout, os.Args[1:])
}

func (e *ExecPlugin) runPlugin(ctx context.Context, r io.Reader, w io.Writer, args []string) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}

	gvk, err := json.DefaultMetaFactory.Interpret(data)
	if err != nil {
		return err
	}

	if gvk.GroupVersion() != v1.SchemeGroupVersion {
		return fmt.Errorf("group version %s is not supported", gvk.GroupVersion())
	}

	request, err := decodeRequest(data)
	if err != nil {
		return err
	}

	if request.Image == "" {
		return errors.New("image in plugin request was empty")
	}

	response, err := e.plugin.GetCredentials(ctx, request.Image, args)
	if err != nil {
		return err
	}

	if response == nil {
		return errors.New("CredentialProviderResponse from plugin was nil")
	}

	encodedResponse, err := encodeResponse(response)
	if err != nil {
		return err
	}

	writer := bufio.NewWriter(w)
	defer writer.Flush()
	if _, err := writer.Write(encodedResponse); err != nil {
		return err
	}

	return nil
}

func decodeRequest(data []byte) (*v1.CredentialProviderRequest, error) {
	obj, gvk, err := codecs.UniversalDecoder(v1.SchemeGroupVersion).Decode(data, nil, nil)
	if err != nil {
		return nil, err
	}

	if gvk.Kind != "CredentialProviderRequest" {
		return nil, fmt.Errorf("kind was %q, expected CredentialProviderRequest", gvk.Kind)
	}

	if gvk.Group != v1.GroupName {
		return nil, fmt.Errorf("group was %q, expected %s", gvk.Group, v1.GroupName)
	}

	request, ok := obj.(*v1.CredentialProviderRequest)
	if !ok {
		return nil, fmt.Errorf("unable to convert %T to *CredentialProviderRequest", obj)
	}

	return request, nil
}

func encodeResponse(response *v1.CredentialProviderResponse) ([]byte, error) {
	mediaType := "application/json"
	info, ok := runtime.SerializerInfoForMediaType(codecs.SupportedMediaTypes(), mediaType)
	if !ok {
		return nil, fmt.Errorf("unsupported media type %q", mediaType)
	}

	encoder := codecs.EncoderForVersion(info.Serializer, v1.SchemeGroupVersion)
	data, err := runtime.Encode(encoder, response)
	if err != nil {
		return nil, fmt.Errorf("failed to encode response: %v", err)
	}

	return data, nil
}
