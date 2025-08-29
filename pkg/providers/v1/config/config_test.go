package config

import (
	"fmt"
	"testing"
)

func TestCloudConfig_IsNLBSecurityGroupModeManaged(t *testing.T) {
	tests := []struct {
		name          string
		modeValue     string
		expected      bool
		testFunc      func(t *testing.T)
		expectedError error
	}{
		// Basic functionality tests
		{
			name:      "managed mode returns true",
			modeValue: NLBSecurityGroupModeManaged,
			expected:  true,
		},
		{
			name:      "empty string returns false",
			modeValue: "",
			expected:  false,
		},
		{
			name:          "lowercase managed returns false",
			modeValue:     "managed",
			expected:      false,
			expectedError: fmt.Errorf("invalid NLB security group mode: %q. Expected: %q", "managed", NLBSecurityGroupModeManaged),
		},
		{
			name:          "uppercase managed returns false",
			modeValue:     "MANAGED",
			expected:      false,
			expectedError: fmt.Errorf("invalid NLB security group mode: %q. Expected: %q", "MANAGED", NLBSecurityGroupModeManaged),
		},
		{
			name:          "mixed case managed returns false",
			modeValue:     "MaNaGeD",
			expected:      false,
			expectedError: fmt.Errorf("invalid NLB security group mode: %q. Expected: %q", "MaNaGeD", NLBSecurityGroupModeManaged),
		},
		{
			name:          "disabled mode returns false",
			modeValue:     "Disabled",
			expected:      false,
			expectedError: fmt.Errorf("invalid NLB security group mode: %q. Expected: %q", "Disabled", NLBSecurityGroupModeManaged),
		},
		{
			name:          "byo mode returns false",
			modeValue:     "BYO",
			expected:      false,
			expectedError: fmt.Errorf("invalid NLB security group mode: %q. Expected: %q", "BYO", NLBSecurityGroupModeManaged),
		},
		{
			name:          "random string returns false",
			modeValue:     "random-value",
			expected:      false,
			expectedError: fmt.Errorf("invalid NLB security group mode: %q. Expected: %q", "random-value", NLBSecurityGroupModeManaged),
		},
		{
			name:          "whitespace only returns false",
			modeValue:     "  ",
			expected:      false,
			expectedError: fmt.Errorf("invalid NLB security group mode: %q. Expected: %q", "  ", NLBSecurityGroupModeManaged),
		},
		{
			name:          "managed with whitespace returns false",
			modeValue:     " Managed ",
			expected:      false,
			expectedError: fmt.Errorf("invalid NLB security group mode: %q. Expected: %q", " Managed ", NLBSecurityGroupModeManaged),
		},
		{
			name:          "managed with prefix returns false",
			modeValue:     "prefix-Managed",
			expected:      false,
			expectedError: fmt.Errorf("invalid NLB security group mode: %q. Expected: %q", "prefix-Managed", NLBSecurityGroupModeManaged),
		},
		{
			name:          "managed with suffix returns false",
			modeValue:     "Managed-suffix",
			expected:      false,
			expectedError: fmt.Errorf("invalid NLB security group mode: %q. Expected: %q", "Managed-suffix", NLBSecurityGroupModeManaged),
		},
		// Zero value test
		{
			name: "no value config returns false",
			testFunc: func(t *testing.T) {
				// Test with no managed config (uninitialized)
				cfg := &CloudConfig{}

				result, err := cfg.IsNLBSecurityGroupModeManaged()

				if result != false {
					t.Errorf("IsNLBSecurityGroupModeManaged() with no managed config = %v, expected false", result)
				}
				if err != nil {
					t.Errorf("IsNLBSecurityGroupModeManaged() with no managed config = %v, expected nil", err)
				}
			},
		},
		// Nil config edge case test
		{
			name: "nil config should panic",
			testFunc: func(t *testing.T) {
				// Test edge case with nil config (should panic as expected)
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("Expected panic when calling IsNLBSecurityGroupModeManaged on nil config")
					}
				}()

				var cfg *CloudConfig
				cfg.IsNLBSecurityGroupModeManaged()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.testFunc != nil {
				// Execute custom test function for special test types
				tt.testFunc(t)
				return
			}

			// Standard test execution for basic functionality tests
			cfg := &CloudConfig{}
			cfg.Global.NLBSecurityGroupMode = tt.modeValue

			result, err := cfg.IsNLBSecurityGroupModeManaged()

			// Validate expected error
			if tt.expectedError != nil {
				if err == nil {
					t.Errorf("IsNLBSecurityGroupModeManaged() = %v, expected error %v for mode value %q",
						result, tt.expectedError, tt.modeValue)
				}
				if err != nil && err.Error() != tt.expectedError.Error() {
					t.Errorf("IsNLBSecurityGroupModeManaged() = %v, expected error %v for mode value %q",
						result, tt.expectedError, tt.modeValue)
				}
			}

			// Validate expected result
			if result != tt.expected {
				t.Errorf("IsNLBSecurityGroupModeManaged() = %v, expected %v for mode value %q",
					result, tt.expected, tt.modeValue)
			}
		})
	}
}
