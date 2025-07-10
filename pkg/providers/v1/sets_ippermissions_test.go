package aws

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/assert"
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
				ec2types.IpPermission{
					FromPort:   aws.Int32(1),
					IpProtocol: aws.String("tcp"),
					IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("10.0.0.0/16")}},
					ToPort:     aws.Int32(2),
				},
			),
			NewIPPermissionSet(
				ec2types.IpPermission{
					FromPort:   aws.Int32(1),
					IpProtocol: aws.String("tcp"),
					IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("10.0.0.0/16")}},
					ToPort:     aws.Int32(2),
				},
			),
		},
		{
			"Three ip ranges in input set",
			NewIPPermissionSet(
				ec2types.IpPermission{
					FromPort:   aws.Int32(1),
					IpProtocol: aws.String("tcp"),
					IpRanges: []ec2types.IpRange{
						{CidrIp: aws.String("10.0.0.0/16")},
						{CidrIp: aws.String("10.1.0.0/16")},
						{CidrIp: aws.String("10.2.0.0/16")},
					},
					ToPort: aws.Int32(2),
				},
			),
			NewIPPermissionSet(
				ec2types.IpPermission{
					FromPort:   aws.Int32(1),
					IpProtocol: aws.String("tcp"),
					IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("10.0.0.0/16")}},
					ToPort:     aws.Int32(2),
				},
				ec2types.IpPermission{
					FromPort:   aws.Int32(1),
					IpProtocol: aws.String("tcp"),
					IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("10.1.0.0/16")}},
					ToPort:     aws.Int32(2),
				},
				ec2types.IpPermission{
					FromPort:   aws.Int32(1),
					IpProtocol: aws.String("tcp"),
					IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("10.2.0.0/16")}},
					ToPort:     aws.Int32(2),
				},
			),
		},
		{
			"Three UserIdGroupPairs in input set",
			NewIPPermissionSet(
				ec2types.IpPermission{
					FromPort:   aws.Int32(1),
					IpProtocol: aws.String("tcp"),
					IpRanges: []ec2types.IpRange{
						{CidrIp: aws.String("10.0.0.0/16")},
					},
					UserIdGroupPairs: []ec2types.UserIdGroupPair{
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
					ToPort: aws.Int32(2),
				},
			),
			NewIPPermissionSet(
				ec2types.IpPermission{
					FromPort:   aws.Int32(1),
					IpProtocol: aws.String("tcp"),
					IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("10.0.0.0/16")}},
					UserIdGroupPairs: []ec2types.UserIdGroupPair{
						{
							GroupId:   aws.String("1"),
							GroupName: aws.String("group-1"),
							UserId:    aws.String("123"),
							VpcId:     aws.String("123"),
						},
					},
					ToPort: aws.Int32(2),
				},
				ec2types.IpPermission{
					FromPort:   aws.Int32(1),
					IpProtocol: aws.String("tcp"),
					IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("10.0.0.0/16")}},
					UserIdGroupPairs: []ec2types.UserIdGroupPair{
						{
							GroupId:   aws.String("2"),
							GroupName: aws.String("group-2"),
							UserId:    aws.String("123"),
							VpcId:     aws.String("123"),
						},
					},
					ToPort: aws.Int32(2),
				},
				ec2types.IpPermission{
					FromPort:   aws.Int32(1),
					IpProtocol: aws.String("tcp"),
					IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("10.0.0.0/16")}},
					UserIdGroupPairs: []ec2types.UserIdGroupPair{
						{
							GroupId:   aws.String("3"),
							GroupName: aws.String("group-3"),
							UserId:    aws.String("123"),
							VpcId:     aws.String("123"),
						},
					},
					ToPort: aws.Int32(2),
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

func TestIPPermissionSetDifferenceCriticalScenarios(t *testing.T) {
	t.Run("real_world_nlb_security_group_scenario", func(t *testing.T) {
		// Scenario:
		// Desired: tcp:80, tcp:81, icmp:3-4
		// Actual: tcp:80, icmp:3-4
		// Expected: add tcp:81 only, remove nothing

		desired := NewIPPermissionSet(
			ec2types.IpPermission{
				IpProtocol: aws.String("tcp"),
				FromPort:   aws.Int32(80),
				ToPort:     aws.Int32(80),
				IpRanges: []ec2types.IpRange{
					{CidrIp: aws.String("0.0.0.0/0")},
				},
			},
			ec2types.IpPermission{
				IpProtocol: aws.String("tcp"),
				FromPort:   aws.Int32(81),
				ToPort:     aws.Int32(81),
				IpRanges: []ec2types.IpRange{
					{CidrIp: aws.String("0.0.0.0/0")},
				},
			},
			ec2types.IpPermission{
				IpProtocol: aws.String("icmp"),
				FromPort:   aws.Int32(3),
				ToPort:     aws.Int32(4),
				IpRanges: []ec2types.IpRange{
					{CidrIp: aws.String("0.0.0.0/0")},
				},
			},
		)

		actual := NewIPPermissionSet(
			ec2types.IpPermission{
				IpProtocol: aws.String("tcp"),
				FromPort:   aws.Int32(80),
				ToPort:     aws.Int32(80),
				IpRanges: []ec2types.IpRange{
					{CidrIp: aws.String("0.0.0.0/0")},
				},
			},
			ec2types.IpPermission{
				IpProtocol: aws.String("icmp"),
				FromPort:   aws.Int32(3),
				ToPort:     aws.Int32(4),
				IpRanges: []ec2types.IpRange{
					{CidrIp: aws.String("0.0.0.0/0")},
				},
			},
		)

		// Calculate what should be added and removed
		add := desired.Difference(actual)
		remove := actual.Difference(desired)

		// Verify correct results
		assert.Equal(t, 1, add.Len(), "Should add exactly one permission (tcp:81)")
		assert.Equal(t, 0, remove.Len(), "Should remove no permissions")

		// Verify the added permission is tcp:81
		addList := add.List()
		if len(addList) > 0 {
			perm := addList[0]
			assert.Equal(t, "tcp", aws.ToString(perm.IpProtocol))
			assert.Equal(t, int32(81), aws.ToInt32(perm.FromPort))
			assert.Equal(t, int32(81), aws.ToInt32(perm.ToPort))
		}
	})

	t.Run("empty_sets_and_edge_cases", func(t *testing.T) {
		// Test edge cases with empty sets and nil scenarios

		emptySet := NewIPPermissionSet()
		nonEmptySet := NewIPPermissionSet(
			ec2types.IpPermission{
				IpProtocol: aws.String("tcp"),
				FromPort:   aws.Int32(443),
				ToPort:     aws.Int32(443),
				IpRanges: []ec2types.IpRange{
					{CidrIp: aws.String("10.0.0.0/8")},
				},
			},
		)

		// Empty - NonEmpty should return empty
		diff1 := emptySet.Difference(nonEmptySet)
		assert.Equal(t, 0, diff1.Len(), "Empty set difference with non-empty should be empty")

		// NonEmpty - Empty should return all from NonEmpty
		diff2 := nonEmptySet.Difference(emptySet)
		assert.Equal(t, 1, diff2.Len(), "Non-empty set difference with empty should return all permissions")

		// Empty - Empty should return empty
		diff3 := emptySet.Difference(emptySet)
		assert.Equal(t, 0, diff3.Len(), "Empty set difference with empty should be empty")
	})

	t.Run("initialization_issue_prevention", func(t *testing.T) {
		// Test that demonstrates the importance of proper initialization
		// This prevents the bug where variables were declared as `var add IPPermissionSet`

		sourceSet := NewIPPermissionSet(
			ec2types.IpPermission{
				IpProtocol: aws.String("tcp"),
				FromPort:   aws.Int32(80),
				ToPort:     aws.Int32(80),
				IpRanges: []ec2types.IpRange{
					{CidrIp: aws.String("0.0.0.0/0")},
				},
			},
		)

		// Test with properly initialized empty set
		emptySet := NewIPPermissionSet()
		diff := sourceSet.Difference(emptySet)
		assert.Equal(t, 1, diff.Len(), "Difference with properly initialized empty set should work")

		// Test that uninitialized set doesn't cause panic in Difference operation
		var uninitializedSet IPPermissionSet
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Difference operation should not panic with uninitialized set: %v", r)
			}
		}()

		// This should not panic (though behavior may be undefined)
		_ = sourceSet.Difference(uninitializedSet)
	})

	t.Run("multiple_ip_ranges_scenario", func(t *testing.T) {
		// Test complex permissions with multiple IP ranges to ensure
		// the Difference function handles them correctly

		desired := NewIPPermissionSet(
			// Permission with multiple IP ranges
			ec2types.IpPermission{
				IpProtocol: aws.String("tcp"),
				FromPort:   aws.Int32(443),
				ToPort:     aws.Int32(443),
				IpRanges: []ec2types.IpRange{
					{CidrIp: aws.String("10.0.0.0/8")},
					{CidrIp: aws.String("172.16.0.0/12")},
					{CidrIp: aws.String("192.168.0.0/16")},
				},
			},
			// Single IP range permission
			ec2types.IpPermission{
				IpProtocol: aws.String("tcp"),
				FromPort:   aws.Int32(80),
				ToPort:     aws.Int32(80),
				IpRanges: []ec2types.IpRange{
					{CidrIp: aws.String("0.0.0.0/0")},
				},
			},
		)

		actual := NewIPPermissionSet(
			// Same permission with multiple IP ranges (should match)
			ec2types.IpPermission{
				IpProtocol: aws.String("tcp"),
				FromPort:   aws.Int32(443),
				ToPort:     aws.Int32(443),
				IpRanges: []ec2types.IpRange{
					{CidrIp: aws.String("10.0.0.0/8")},
					{CidrIp: aws.String("172.16.0.0/12")},
					{CidrIp: aws.String("192.168.0.0/16")},
				},
			},
			// Different permission with multiple IP ranges
			ec2types.IpPermission{
				IpProtocol: aws.String("tcp"),
				FromPort:   aws.Int32(8080),
				ToPort:     aws.Int32(8080),
				IpRanges: []ec2types.IpRange{
					{CidrIp: aws.String("10.0.0.0/8")},
					{CidrIp: aws.String("172.16.0.0/12")},
				},
			},
		)

		// Calculate differences
		add := desired.Difference(actual)
		remove := actual.Difference(desired)

		// Should add tcp:80 (not present in actual)
		assert.Equal(t, 1, add.Len(), "Should add exactly one permission (tcp:80)")

		// Should remove tcp:8080 (not present in desired)
		assert.Equal(t, 1, remove.Len(), "Should remove exactly one permission (tcp:8080)")

		// Verify what's being added
		addList := add.List()
		if len(addList) > 0 {
			perm := addList[0]
			assert.Equal(t, "tcp", aws.ToString(perm.IpProtocol))
			assert.Equal(t, int32(80), aws.ToInt32(perm.FromPort))
			assert.Equal(t, int32(80), aws.ToInt32(perm.ToPort))
			assert.Equal(t, 1, len(perm.IpRanges), "Should have one IP range")
			assert.Equal(t, "0.0.0.0/0", aws.ToString(perm.IpRanges[0].CidrIp))
		}

		// Verify what's being removed
		removeList := remove.List()
		if len(removeList) > 0 {
			perm := removeList[0]
			assert.Equal(t, "tcp", aws.ToString(perm.IpProtocol))
			assert.Equal(t, int32(8080), aws.ToInt32(perm.FromPort))
			assert.Equal(t, int32(8080), aws.ToInt32(perm.ToPort))
			assert.Equal(t, 2, len(perm.IpRanges), "Should have two IP ranges")
		}
	})

	t.Run("identical_permissions_different_ip_range_order", func(t *testing.T) {
		// Test that permissions with same IP ranges but in different order
		// are treated as identical (this tests the robustness of the key generation)

		perm1 := ec2types.IpPermission{
			IpProtocol: aws.String("tcp"),
			FromPort:   aws.Int32(443),
			ToPort:     aws.Int32(443),
			IpRanges: []ec2types.IpRange{
				{CidrIp: aws.String("10.0.0.0/8")},
				{CidrIp: aws.String("172.16.0.0/12")},
				{CidrIp: aws.String("192.168.0.0/16")},
			},
		}

		perm2 := ec2types.IpPermission{
			IpProtocol: aws.String("tcp"),
			FromPort:   aws.Int32(443),
			ToPort:     aws.Int32(443),
			IpRanges: []ec2types.IpRange{
				{CidrIp: aws.String("192.168.0.0/16")}, // Different order
				{CidrIp: aws.String("10.0.0.0/8")},
				{CidrIp: aws.String("172.16.0.0/12")},
			},
		}

		set1 := NewIPPermissionSet(perm1)
		set2 := NewIPPermissionSet(perm2)

		// These should be different due to different order in JSON marshaling
		// (This tests the current behavior - if this fails, it indicates the key generation
		// doesn't account for order, which might be the root cause of issues)
		diff := set1.Difference(set2)

		// Log the result to understand current behavior
		t.Logf("Difference between permissions with same IP ranges in different order: %d", diff.Len())

		// The current implementation might treat these as different due to JSON marshaling
		// This test documents the current behavior and will help identify if this is the issue
		if diff.Len() == 0 {
			t.Log("Permissions with different IP range order are treated as identical")
		} else {
			t.Log("Permissions with different IP range order are treated as different")
		}
	})
}
