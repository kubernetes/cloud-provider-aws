package awsnode

import "github.com/aws/aws-sdk-go/aws"

// NodeID is the ID used to uniquely identify a node within an AWS service
type NodeID string

// AwsString returns a pointer to the string value of the NodeID. Useful for AWS APIs
func (i NodeID) AwsString() *string {
	return aws.String(string(i))
}
