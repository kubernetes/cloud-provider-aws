// +build !providerless

/*
Copyright 2019 The Kubernetes Authors.

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

package azure

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/Azure/azure-sdk-for-go/services/compute/mgmt/2019-07-01/compute"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/pointer"
)

func TestCommonAttachDisk(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	testCases := []struct {
		desc            string
		vmList          map[string]string
		nodeName        types.NodeName
		isDataDisksFull bool
		expectedLun     int32
		expectedErr     bool
	}{
		{
			desc:        "LUN -1 and error shall be returned if there's no such instance corresponding to given nodeName",
			nodeName:    "vm1",
			expectedLun: -1,
			expectedErr: true,
		},
		{
			desc:            "LUN -1 and error shall be returned if there's no available LUN for instance",
			vmList:          map[string]string{"vm1": "PowerState/Running"},
			nodeName:        "vm1",
			isDataDisksFull: true,
			expectedLun:     -1,
			expectedErr:     true,
		},
		{
			desc:        "correct LUN and no error shall be returned if everything is good",
			vmList:      map[string]string{"vm1": "PowerState/Running"},
			nodeName:    "vm1",
			expectedLun: -1,
			expectedErr: true,
		},
	}

	for i, test := range testCases {
		testCloud := GetTestCloud(ctrl)
		common := &controllerCommon{
			location:              testCloud.Location,
			storageEndpointSuffix: testCloud.Environment.StorageEndpointSuffix,
			resourceGroup:         testCloud.ResourceGroup,
			subscriptionID:        testCloud.SubscriptionID,
			cloud:                 testCloud,
			vmLockMap:             newLockMap(),
		}
		diskURI := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/disks/disk-name",
			testCloud.SubscriptionID, testCloud.ResourceGroup)
		setTestVirtualMachines(testCloud, test.vmList, test.isDataDisksFull)

		lun, err := common.AttachDisk(true, "", diskURI, test.nodeName, compute.CachingTypesReadOnly)
		assert.Equal(t, test.expectedLun, lun, "TestCase[%d]: %s", i, test.desc)
		assert.Equal(t, test.expectedErr, err != nil, "TestCase[%d]: %s, return error: %v", i, test.desc, err)
	}
}

func TestCommonDetachDisk(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	testCases := []struct {
		desc        string
		vmList      map[string]string
		nodeName    types.NodeName
		diskName    string
		expectedErr bool
	}{
		{
			desc:        "error should not be returned if there's no such instance corresponding to given nodeName",
			nodeName:    "vm1",
			expectedErr: false,
		},
		{
			desc:        "no error shall be returned if there's no matching disk according to given diskName",
			vmList:      map[string]string{"vm1": "PowerState/Running"},
			nodeName:    "vm1",
			diskName:    "disk2",
			expectedErr: false,
		},
		{
			desc:        "no error shall be returned if the disk exsists",
			vmList:      map[string]string{"vm1": "PowerState/Running"},
			nodeName:    "vm1",
			diskName:    "disk1",
			expectedErr: false,
		},
	}

	for i, test := range testCases {
		testCloud := GetTestCloud(ctrl)
		common := &controllerCommon{
			location:              testCloud.Location,
			storageEndpointSuffix: testCloud.Environment.StorageEndpointSuffix,
			resourceGroup:         testCloud.ResourceGroup,
			subscriptionID:        testCloud.SubscriptionID,
			cloud:                 testCloud,
			vmLockMap:             newLockMap(),
		}
		diskURI := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/disks/disk-name",
			testCloud.SubscriptionID, testCloud.ResourceGroup)
		setTestVirtualMachines(testCloud, test.vmList, false)

		err := common.DetachDisk(test.diskName, diskURI, test.nodeName)
		assert.Equal(t, test.expectedErr, err != nil, "TestCase[%d]: %s, err: %v", i, test.desc, err)
	}
}

func TestGetDiskLun(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	testCases := []struct {
		desc        string
		diskName    string
		diskURI     string
		expectedLun int32
		expectedErr bool
	}{
		{
			desc:        "LUN -1 and error shall be returned if diskName != disk.Name or diskURI != disk.Vhd.URI",
			diskName:    "disk2",
			expectedLun: -1,
			expectedErr: true,
		},
		{
			desc:        "correct LUN and no error shall be returned if diskName = disk.Name",
			diskName:    "disk1",
			expectedLun: 0,
			expectedErr: false,
		},
	}

	for i, test := range testCases {
		testCloud := GetTestCloud(ctrl)
		common := &controllerCommon{
			location:              testCloud.Location,
			storageEndpointSuffix: testCloud.Environment.StorageEndpointSuffix,
			resourceGroup:         testCloud.ResourceGroup,
			subscriptionID:        testCloud.SubscriptionID,
			cloud:                 testCloud,
			vmLockMap:             newLockMap(),
		}
		setTestVirtualMachines(testCloud, map[string]string{"vm1": "PowerState/Running"}, false)

		lun, err := common.GetDiskLun(test.diskName, test.diskURI, "vm1")
		assert.Equal(t, test.expectedLun, lun, "TestCase[%d]: %s", i, test.desc)
		assert.Equal(t, test.expectedErr, err != nil, "TestCase[%d]: %s", i, test.desc)
	}
}

func TestGetNextDiskLun(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	testCases := []struct {
		desc            string
		isDataDisksFull bool
		expectedLun     int32
		expectedErr     bool
	}{
		{
			desc:            "the minimal LUN shall be returned if there's enough room for extra disks",
			isDataDisksFull: false,
			expectedLun:     1,
			expectedErr:     false,
		},
		{
			desc:            "LUN -1 and  error shall be returned if there's no available LUN",
			isDataDisksFull: true,
			expectedLun:     -1,
			expectedErr:     true,
		},
	}

	for i, test := range testCases {
		testCloud := GetTestCloud(ctrl)
		common := &controllerCommon{
			location:              testCloud.Location,
			storageEndpointSuffix: testCloud.Environment.StorageEndpointSuffix,
			resourceGroup:         testCloud.ResourceGroup,
			subscriptionID:        testCloud.SubscriptionID,
			cloud:                 testCloud,
			vmLockMap:             newLockMap(),
		}
		setTestVirtualMachines(testCloud, map[string]string{"vm1": "PowerState/Running"}, test.isDataDisksFull)

		lun, err := common.GetNextDiskLun("vm1")
		assert.Equal(t, test.expectedLun, lun, "TestCase[%d]: %s", i, test.desc)
		assert.Equal(t, test.expectedErr, err != nil, "TestCase[%d]: %s", i, test.desc)
	}
}

func TestDisksAreAttached(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	testCases := []struct {
		desc             string
		diskNames        []string
		nodeName         types.NodeName
		expectedAttached map[string]bool
		expectedErr      bool
	}{
		{
			desc:             "an error shall be returned if there's no such instance corresponding to given nodeName",
			diskNames:        []string{"disk1"},
			nodeName:         "vm2",
			expectedAttached: map[string]bool{"disk1": false},
			expectedErr:      false,
		},
		{
			desc:             "proper attach map shall be returned if everything is good",
			diskNames:        []string{"disk1", "disk2"},
			nodeName:         "vm1",
			expectedAttached: map[string]bool{"disk1": true, "disk2": false},
			expectedErr:      false,
		},
	}

	for i, test := range testCases {
		testCloud := GetTestCloud(ctrl)
		common := &controllerCommon{
			location:              testCloud.Location,
			storageEndpointSuffix: testCloud.Environment.StorageEndpointSuffix,
			resourceGroup:         testCloud.ResourceGroup,
			subscriptionID:        testCloud.SubscriptionID,
			cloud:                 testCloud,
			vmLockMap:             newLockMap(),
		}
		setTestVirtualMachines(testCloud, map[string]string{"vm1": "PowerState/Running"}, false)

		attached, err := common.DisksAreAttached(test.diskNames, test.nodeName)
		assert.Equal(t, test.expectedAttached, attached, "TestCase[%d]: %s", i, test.desc)
		assert.Equal(t, test.expectedErr, err != nil, "TestCase[%d]: %s", i, test.desc)
	}
}

func TestFilteredDetatchingDisks(t *testing.T) {

	disks := []compute.DataDisk{
		{
			Name:         pointer.StringPtr("DiskName1"),
			ToBeDetached: pointer.BoolPtr(false),
			ManagedDisk: &compute.ManagedDiskParameters{
				ID: pointer.StringPtr("ManagedID"),
			},
		},
		{
			Name:         pointer.StringPtr("DiskName2"),
			ToBeDetached: pointer.BoolPtr(true),
		},
		{
			Name:         pointer.StringPtr("DiskName3"),
			ToBeDetached: nil,
		},
		{
			Name:         pointer.StringPtr("DiskName4"),
			ToBeDetached: nil,
		},
	}

	filteredDisks := filterDetachingDisks(disks)
	assert.Equal(t, 3, len(filteredDisks))
	assert.Equal(t, "DiskName1", *filteredDisks[0].Name)
	assert.Equal(t, "ManagedID", *filteredDisks[0].ManagedDisk.ID)
	assert.Equal(t, "DiskName3", *filteredDisks[1].Name)

	disks = []compute.DataDisk{}
	filteredDisks = filterDetachingDisks(disks)
	assert.Equal(t, 0, len(filteredDisks))
}

func TestGetValidCreationData(t *testing.T) {
	sourceResourceSnapshotID := "/subscriptions/xxx/resourceGroups/xxx/providers/Microsoft.Compute/snapshots/xxx"
	sourceResourceVolumeID := "/subscriptions/xxx/resourceGroups/xxx/providers/Microsoft.Compute/disks/xxx"

	tests := []struct {
		subscriptionID   string
		resourceGroup    string
		sourceResourceID string
		sourceType       string
		expected1        compute.CreationData
		expected2        error
	}{
		{
			subscriptionID:   "",
			resourceGroup:    "",
			sourceResourceID: "",
			sourceType:       "",
			expected1: compute.CreationData{
				CreateOption: compute.Empty,
			},
			expected2: nil,
		},
		{
			subscriptionID:   "",
			resourceGroup:    "",
			sourceResourceID: "/subscriptions/xxx/resourceGroups/xxx/providers/Microsoft.Compute/snapshots/xxx",
			sourceType:       sourceSnapshot,
			expected1: compute.CreationData{
				CreateOption:     compute.Copy,
				SourceResourceID: &sourceResourceSnapshotID,
			},
			expected2: nil,
		},
		{
			subscriptionID:   "xxx",
			resourceGroup:    "xxx",
			sourceResourceID: "xxx",
			sourceType:       sourceSnapshot,
			expected1: compute.CreationData{
				CreateOption:     compute.Copy,
				SourceResourceID: &sourceResourceSnapshotID,
			},
			expected2: nil,
		},
		{
			subscriptionID:   "",
			resourceGroup:    "",
			sourceResourceID: "/subscriptions/23/providers/Microsoft.Compute/disks/name",
			sourceType:       sourceSnapshot,
			expected1:        compute.CreationData{},
			expected2:        fmt.Errorf("sourceResourceID(%s) is invalid, correct format: %s", "/subscriptions//resourceGroups//providers/Microsoft.Compute/snapshots//subscriptions/23/providers/Microsoft.Compute/disks/name", diskSnapshotPathRE),
		},
		{
			subscriptionID:   "",
			resourceGroup:    "",
			sourceResourceID: "http://test.com/vhds/name",
			sourceType:       sourceSnapshot,
			expected1:        compute.CreationData{},
			expected2:        fmt.Errorf("sourceResourceID(%s) is invalid, correct format: %s", "/subscriptions//resourceGroups//providers/Microsoft.Compute/snapshots/http://test.com/vhds/name", diskSnapshotPathRE),
		},
		{
			subscriptionID:   "",
			resourceGroup:    "",
			sourceResourceID: "/subscriptions/xxx/snapshots/xxx",
			sourceType:       sourceSnapshot,
			expected1:        compute.CreationData{},
			expected2:        fmt.Errorf("sourceResourceID(%s) is invalid, correct format: %s", "/subscriptions//resourceGroups//providers/Microsoft.Compute/snapshots//subscriptions/xxx/snapshots/xxx", diskSnapshotPathRE),
		},
		{
			subscriptionID:   "",
			resourceGroup:    "",
			sourceResourceID: "/subscriptions/xxx/resourceGroups/xxx/providers/Microsoft.Compute/snapshots/xxx/snapshots/xxx/snapshots/xxx",
			sourceType:       sourceSnapshot,
			expected1:        compute.CreationData{},
			expected2:        fmt.Errorf("sourceResourceID(%s) is invalid, correct format: %s", "/subscriptions/xxx/resourceGroups/xxx/providers/Microsoft.Compute/snapshots/xxx/snapshots/xxx/snapshots/xxx", diskSnapshotPathRE),
		},
		{
			subscriptionID:   "",
			resourceGroup:    "",
			sourceResourceID: "xxx",
			sourceType:       "",
			expected1: compute.CreationData{
				CreateOption: compute.Empty,
			},
			expected2: nil,
		},
		{
			subscriptionID:   "",
			resourceGroup:    "",
			sourceResourceID: "/subscriptions/xxx/resourceGroups/xxx/providers/Microsoft.Compute/disks/xxx",
			sourceType:       sourceVolume,
			expected1: compute.CreationData{
				CreateOption:     compute.Copy,
				SourceResourceID: &sourceResourceVolumeID,
			},
			expected2: nil,
		},
		{
			subscriptionID:   "xxx",
			resourceGroup:    "xxx",
			sourceResourceID: "xxx",
			sourceType:       sourceVolume,
			expected1: compute.CreationData{
				CreateOption:     compute.Copy,
				SourceResourceID: &sourceResourceVolumeID,
			},
			expected2: nil,
		},
		{
			subscriptionID:   "",
			resourceGroup:    "",
			sourceResourceID: "/subscriptions/xxx/resourceGroups/xxx/providers/Microsoft.Compute/snapshots/xxx",
			sourceType:       sourceVolume,
			expected1:        compute.CreationData{},
			expected2:        fmt.Errorf("sourceResourceID(%s) is invalid, correct format: %s", "/subscriptions//resourceGroups//providers/Microsoft.Compute/disks//subscriptions/xxx/resourceGroups/xxx/providers/Microsoft.Compute/snapshots/xxx", managedDiskPathRE),
		},
	}

	for _, test := range tests {
		result, err := getValidCreationData(test.subscriptionID, test.resourceGroup, test.sourceResourceID, test.sourceType)
		if !reflect.DeepEqual(result, test.expected1) || !reflect.DeepEqual(err, test.expected2) {
			t.Errorf("input sourceResourceID: %v, sourceType: %v, getValidCreationData result: %v, expected1 : %v, err: %v, expected2: %v", test.sourceResourceID, test.sourceType, result, test.expected1, err, test.expected2)
		}
	}
}

func TestCheckDiskExists(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx, cancel := getContextWithCancel()
	defer cancel()

	testCloud := GetTestCloud(ctrl)
	common := &controllerCommon{
		location:              testCloud.Location,
		storageEndpointSuffix: testCloud.Environment.StorageEndpointSuffix,
		resourceGroup:         testCloud.ResourceGroup,
		subscriptionID:        testCloud.SubscriptionID,
		cloud:                 testCloud,
		vmLockMap:             newLockMap(),
	}
	// create a new disk before running test
	newDiskName := "newdisk"
	newDiskURI := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/disks/%s",
		testCloud.SubscriptionID, testCloud.ResourceGroup, newDiskName)
	fDC := newFakeDisksClient()
	rerr := fDC.CreateOrUpdate(ctx, testCloud.ResourceGroup, newDiskName, compute.Disk{})
	assert.Equal(t, rerr == nil, true, "return error: %v", rerr)
	testCloud.DisksClient = fDC

	testCases := []struct {
		diskURI        string
		expectedResult bool
		expectedErr    bool
	}{
		{
			diskURI:        "incorrect disk URI format",
			expectedResult: false,
			expectedErr:    true,
		},
		{
			diskURI:        "/subscriptions/xxx/resourceGroups/xxx/providers/Microsoft.Compute/disks/non-existing-disk",
			expectedResult: false,
			expectedErr:    false,
		},
		{
			diskURI:        newDiskURI,
			expectedResult: true,
			expectedErr:    false,
		},
	}

	for i, test := range testCases {
		exist, err := common.checkDiskExists(ctx, test.diskURI)
		assert.Equal(t, test.expectedResult, exist, "TestCase[%d]", i, exist)
		assert.Equal(t, test.expectedErr, err != nil, "TestCase[%d], return error: %v", i, err)
	}
}

func TestFilterNonExistingDisks(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx, cancel := getContextWithCancel()
	defer cancel()

	testCloud := GetTestCloud(ctrl)
	common := &controllerCommon{
		location:              testCloud.Location,
		storageEndpointSuffix: testCloud.Environment.StorageEndpointSuffix,
		resourceGroup:         testCloud.ResourceGroup,
		subscriptionID:        testCloud.SubscriptionID,
		cloud:                 testCloud,
		vmLockMap:             newLockMap(),
	}
	// create a new disk before running test
	diskURIPrefix := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/disks/",
		testCloud.SubscriptionID, testCloud.ResourceGroup)
	newDiskName := "newdisk"
	newDiskURI := diskURIPrefix + newDiskName
	fDC := newFakeDisksClient()
	rerr := fDC.CreateOrUpdate(ctx, testCloud.ResourceGroup, newDiskName, compute.Disk{})
	assert.Equal(t, rerr == nil, true, "return error: %v", rerr)
	testCloud.DisksClient = fDC

	disks := []compute.DataDisk{
		{
			Name: &newDiskName,
			ManagedDisk: &compute.ManagedDiskParameters{
				ID: &newDiskURI,
			},
		},
		{
			Name: pointer.StringPtr("DiskName2"),
			ManagedDisk: &compute.ManagedDiskParameters{
				ID: pointer.StringPtr(diskURIPrefix + "DiskName2"),
			},
		},
		{
			Name: pointer.StringPtr("DiskName3"),
			ManagedDisk: &compute.ManagedDiskParameters{
				ID: pointer.StringPtr(diskURIPrefix + "DiskName3"),
			},
		},
		{
			Name: pointer.StringPtr("DiskName4"),
			ManagedDisk: &compute.ManagedDiskParameters{
				ID: pointer.StringPtr(diskURIPrefix + "DiskName4"),
			},
		},
	}

	filteredDisks := common.filterNonExistingDisks(ctx, disks)
	assert.Equal(t, 1, len(filteredDisks))
	assert.Equal(t, newDiskName, *filteredDisks[0].Name)

	disks = []compute.DataDisk{}
	filteredDisks = filterDetachingDisks(disks)
	assert.Equal(t, 0, len(filteredDisks))
}
