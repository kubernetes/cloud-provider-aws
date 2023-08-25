/*
Copyright 2014 The Kubernetes Authors.

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

package aws

import "testing"

func TestGetSourceAcctAndArn(t *testing.T) {
	type args struct {
		roleARN     string
		region      string
		clusterName string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		want1   string
		wantErr bool
	}{
		{
			name: "corect role arn",
			args: args{
				roleARN:     "arn:aws:iam::123456789876:role/test-cluster",
				region:      "us-west-2",
				clusterName: "test-cluster",
			},
			want:    "123456789876",
			want1:   "arn:aws:eks:us-west-2:123456789876:cluster/test-cluster",
			wantErr: false,
		},
		{
			name: "incorect role arn",
			args: args{
				roleARN:     "arn:aws:iam::123456789876",
				region:      "us-west-2",
				clusterName: "test-cluster",
			},
			want:    "",
			want1:   "",
			wantErr: true,
		},
		{
			name: "empty region",
			args: args{
				roleARN:     "arn:aws:iam::123456789876:role/test-cluster",
				region:      "",
				clusterName: "test-cluster",
			},
			want:    "",
			want1:   "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := GetSourceAcctAndArn(tt.args.roleARN, tt.args.region, tt.args.clusterName)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetSourceAcctAndArn() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetSourceAcctAndArn() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("GetSourceAcctAndArn() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
