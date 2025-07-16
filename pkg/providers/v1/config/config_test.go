package config

import (
	"testing"
)

func TestCloudConfig_IsNLBSecurityGroupModeManaged(t *testing.T) {
	tests := []struct {
		name      string
		modeValue string
		expected  bool
	}{
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
			name:      "lowercase managed returns false",
			modeValue: "managed",
			expected:  false,
		},
		{
			name:      "uppercase managed returns false",
			modeValue: "MANAGED",
			expected:  false,
		},
		{
			name:      "mixed case managed returns false",
			modeValue: "MaNaGeD",
			expected:  false,
		},
		{
			name:      "disabled mode returns false",
			modeValue: "Disabled",
			expected:  false,
		},
		{
			name:      "byo mode returns false",
			modeValue: "BYO",
			expected:  false,
		},
		{
			name:      "random string returns false",
			modeValue: "random-value",
			expected:  false,
		},
		{
			name:      "whitespace only returns false",
			modeValue: "  ",
			expected:  false,
		},
		{
			name:      "managed with whitespace returns false",
			modeValue: " Managed ",
			expected:  false,
		},
		{
			name:      "managed with prefix returns false",
			modeValue: "prefix-Managed",
			expected:  false,
		},
		{
			name:      "managed with suffix returns false",
			modeValue: "Managed-suffix",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &CloudConfig{}
			cfg.Global.NLBSecurityGroupMode = tt.modeValue

			result := cfg.IsNLBSecurityGroupModeManaged()

			if result != tt.expected {
				t.Errorf("IsNLBSecurityGroupModeManaged() = %v, expected %v for mode value %q",
					result, tt.expected, tt.modeValue)
			}
		})
	}
}

func TestCloudConfig_IsNLBSecurityGroupModeManaged_ZeroValue(t *testing.T) {
	// Test with zero-value config (uninitialized)
	cfg := &CloudConfig{}

	result := cfg.IsNLBSecurityGroupModeManaged()

	if result != false {
		t.Errorf("IsNLBSecurityGroupModeManaged() with zero-value config = %v, expected false", result)
	}
}

func TestCloudConfig_IsNLBSecurityGroupModeManaged_NilConfig(t *testing.T) {
	// Test edge case with nil config (should panic as expected)
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected panic when calling IsNLBSecurityGroupModeManaged on nil config")
		}
	}()

	var cfg *CloudConfig
	cfg.IsNLBSecurityGroupModeManaged()
}
