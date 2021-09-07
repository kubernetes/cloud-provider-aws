package aws

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
)

func TestUngroup(t *testing.T) {
	tests := []struct {
		name string

		inputSet          IPPermissionSet
		expectedOutputSet IPPermissionSet
	}{
		{
			"Single IP range in input set",
			NewIPPermissionSet(
				&ec2.IpPermission{
					FromPort:   aws.Int64(1),
					IpProtocol: aws.String("tcp"),
					IpRanges:   []*ec2.IpRange{{CidrIp: aws.String("10.0.0.0/16")}},
					ToPort:     aws.Int64(2),
				},
			),
			NewIPPermissionSet(
				&ec2.IpPermission{
					FromPort:   aws.Int64(1),
					IpProtocol: aws.String("tcp"),
					IpRanges:   []*ec2.IpRange{{CidrIp: aws.String("10.0.0.0/16")}},
					ToPort:     aws.Int64(2),
				},
			),
		},
		{
			"Three ip ranges in input set",
			NewIPPermissionSet(
				&ec2.IpPermission{
					FromPort:   aws.Int64(1),
					IpProtocol: aws.String("tcp"),
					IpRanges: []*ec2.IpRange{
						{CidrIp: aws.String("10.0.0.0/16")},
						{CidrIp: aws.String("10.1.0.0/16")},
						{CidrIp: aws.String("10.2.0.0/16")},
					},
					ToPort: aws.Int64(2),
				},
			),
			NewIPPermissionSet(
				&ec2.IpPermission{
					FromPort:   aws.Int64(1),
					IpProtocol: aws.String("tcp"),
					IpRanges:   []*ec2.IpRange{{CidrIp: aws.String("10.0.0.0/16")}},
					ToPort:     aws.Int64(2),
				},
				&ec2.IpPermission{
					FromPort:   aws.Int64(1),
					IpProtocol: aws.String("tcp"),
					IpRanges:   []*ec2.IpRange{{CidrIp: aws.String("10.1.0.0/16")}},
					ToPort:     aws.Int64(2),
				},
				&ec2.IpPermission{
					FromPort:   aws.Int64(1),
					IpProtocol: aws.String("tcp"),
					IpRanges:   []*ec2.IpRange{{CidrIp: aws.String("10.2.0.0/16")}},
					ToPort:     aws.Int64(2),
				},
			),
		},
		{
			"Three UserIdGroupPairs in input set",
			NewIPPermissionSet(
				&ec2.IpPermission{
					FromPort:   aws.Int64(1),
					IpProtocol: aws.String("tcp"),
					IpRanges: []*ec2.IpRange{
						{CidrIp: aws.String("10.0.0.0/16")},
					},
					UserIdGroupPairs: []*ec2.UserIdGroupPair{
						{
							GroupId:   aws.String("1"),
							GroupName: aws.String("group-1"),
							UserId:    aws.String("123"),
							VpcId:     aws.String("123"),
						},
						{
							GroupId:   aws.String("2"),
							GroupName: aws.String("group-2"),
							UserId:    aws.String("123"),
							VpcId:     aws.String("123"),
						},
						{
							GroupId:   aws.String("3"),
							GroupName: aws.String("group-3"),
							UserId:    aws.String("123"),
							VpcId:     aws.String("123"),
						},
					},
					ToPort: aws.Int64(2),
				},
			),
			NewIPPermissionSet(
				&ec2.IpPermission{
					FromPort:   aws.Int64(1),
					IpProtocol: aws.String("tcp"),
					IpRanges:   []*ec2.IpRange{{CidrIp: aws.String("10.0.0.0/16")}},
					UserIdGroupPairs: []*ec2.UserIdGroupPair{
						{
							GroupId:   aws.String("1"),
							GroupName: aws.String("group-1"),
							UserId:    aws.String("123"),
							VpcId:     aws.String("123"),
						},
					},
					ToPort: aws.Int64(2),
				},
				&ec2.IpPermission{
					FromPort:   aws.Int64(1),
					IpProtocol: aws.String("tcp"),
					IpRanges:   []*ec2.IpRange{{CidrIp: aws.String("10.0.0.0/16")}},
					UserIdGroupPairs: []*ec2.UserIdGroupPair{
						{
							GroupId:   aws.String("2"),
							GroupName: aws.String("group-2"),
							UserId:    aws.String("123"),
							VpcId:     aws.String("123"),
						},
					},
					ToPort: aws.Int64(2),
				},
				&ec2.IpPermission{
					FromPort:   aws.Int64(1),
					IpProtocol: aws.String("tcp"),
					IpRanges:   []*ec2.IpRange{{CidrIp: aws.String("10.0.0.0/16")}},
					UserIdGroupPairs: []*ec2.UserIdGroupPair{
						{
							GroupId:   aws.String("3"),
							GroupName: aws.String("group-3"),
							UserId:    aws.String("123"),
							VpcId:     aws.String("123"),
						},
					},
					ToPort: aws.Int64(2),
				},
			),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			outputSet := test.inputSet.Ungroup()
			if !outputSet.Equal(test.expectedOutputSet) {
				t.Errorf("[%s] Unexpected IP Permission Set after Ungroup().\n\nInput:\n%#v\n\nResult:\n%#v\n\nExpected:\n%#v\n\n", test.name, test.inputSet, outputSet, test.expectedOutputSet)
			}
		})
	}
}
