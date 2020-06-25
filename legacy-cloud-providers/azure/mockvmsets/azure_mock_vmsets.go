// +build !providerless

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

package mockvmsets

import (
	reflect "reflect"

	compute "github.com/Azure/azure-sdk-for-go/services/compute/mgmt/2019-07-01/compute"
	network "github.com/Azure/azure-sdk-for-go/services/network/mgmt/2019-06-01/network"
	gomock "github.com/golang/mock/gomock"
	v1 "k8s.io/api/core/v1"
	types "k8s.io/apimachinery/pkg/types"
	cloudprovider "k8s.io/cloud-provider"
	cache "k8s.io/legacy-cloud-providers/azure/cache"
)

// MockVMSet is a mock of VMSet interface
type MockVMSet struct {
	ctrl     *gomock.Controller
	recorder *MockVMSetMockRecorder
}

// MockVMSetMockRecorder is the mock recorder for MockVMSet
type MockVMSetMockRecorder struct {
	mock *MockVMSet
}

// NewMockVMSet creates a new mock instance
func NewMockVMSet(ctrl *gomock.Controller) *MockVMSet {
	mock := &MockVMSet{ctrl: ctrl}
	mock.recorder = &MockVMSetMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockVMSet) EXPECT() *MockVMSetMockRecorder {
	return m.recorder
}

// GetInstanceIDByNodeName mocks base method
func (m *MockVMSet) GetInstanceIDByNodeName(name string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetInstanceIDByNodeName", name)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetInstanceIDByNodeName indicates an expected call of GetInstanceIDByNodeName
func (mr *MockVMSetMockRecorder) GetInstanceIDByNodeName(name interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetInstanceIDByNodeName", reflect.TypeOf((*MockVMSet)(nil).GetInstanceIDByNodeName), name)
}

// GetInstanceTypeByNodeName mocks base method
func (m *MockVMSet) GetInstanceTypeByNodeName(name string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetInstanceTypeByNodeName", name)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetInstanceTypeByNodeName indicates an expected call of GetInstanceTypeByNodeName
func (mr *MockVMSetMockRecorder) GetInstanceTypeByNodeName(name interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetInstanceTypeByNodeName", reflect.TypeOf((*MockVMSet)(nil).GetInstanceTypeByNodeName), name)
}

// GetIPByNodeName mocks base method
func (m *MockVMSet) GetIPByNodeName(name string) (string, string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetIPByNodeName", name)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(string)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// GetIPByNodeName indicates an expected call of GetIPByNodeName
func (mr *MockVMSetMockRecorder) GetIPByNodeName(name interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetIPByNodeName", reflect.TypeOf((*MockVMSet)(nil).GetIPByNodeName), name)
}

// GetPrimaryInterface mocks base method
func (m *MockVMSet) GetPrimaryInterface(nodeName string) (network.Interface, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPrimaryInterface", nodeName)
	ret0, _ := ret[0].(network.Interface)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetPrimaryInterface indicates an expected call of GetPrimaryInterface
func (mr *MockVMSetMockRecorder) GetPrimaryInterface(nodeName interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPrimaryInterface", reflect.TypeOf((*MockVMSet)(nil).GetPrimaryInterface), nodeName)
}

// GetNodeNameByProviderID mocks base method
func (m *MockVMSet) GetNodeNameByProviderID(providerID string) (types.NodeName, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetNodeNameByProviderID", providerID)
	ret0, _ := ret[0].(types.NodeName)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetNodeNameByProviderID indicates an expected call of GetNodeNameByProviderID
func (mr *MockVMSetMockRecorder) GetNodeNameByProviderID(providerID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetNodeNameByProviderID", reflect.TypeOf((*MockVMSet)(nil).GetNodeNameByProviderID), providerID)
}

// GetZoneByNodeName mocks base method
func (m *MockVMSet) GetZoneByNodeName(name string) (cloudprovider.Zone, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetZoneByNodeName", name)
	ret0, _ := ret[0].(cloudprovider.Zone)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetZoneByNodeName indicates an expected call of GetZoneByNodeName
func (mr *MockVMSetMockRecorder) GetZoneByNodeName(name interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetZoneByNodeName", reflect.TypeOf((*MockVMSet)(nil).GetZoneByNodeName), name)
}

// GetPrimaryVMSetName mocks base method
func (m *MockVMSet) GetPrimaryVMSetName() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPrimaryVMSetName")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetPrimaryVMSetName indicates an expected call of GetPrimaryVMSetName
func (mr *MockVMSetMockRecorder) GetPrimaryVMSetName() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPrimaryVMSetName", reflect.TypeOf((*MockVMSet)(nil).GetPrimaryVMSetName))
}

// GetVMSetNames mocks base method
func (m *MockVMSet) GetVMSetNames(service *v1.Service, nodes []*v1.Node) (*[]string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetVMSetNames", service, nodes)
	ret0, _ := ret[0].(*[]string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetVMSetNames indicates an expected call of GetVMSetNames
func (mr *MockVMSetMockRecorder) GetVMSetNames(service, nodes interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetVMSetNames", reflect.TypeOf((*MockVMSet)(nil).GetVMSetNames), service, nodes)
}

// EnsureHostsInPool mocks base method
func (m *MockVMSet) EnsureHostsInPool(service *v1.Service, nodes []*v1.Node, backendPoolID, vmSetName string, isInternal bool) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "EnsureHostsInPool", service, nodes, backendPoolID, vmSetName, isInternal)
	ret0, _ := ret[0].(error)
	return ret0
}

// EnsureHostsInPool indicates an expected call of EnsureHostsInPool
func (mr *MockVMSetMockRecorder) EnsureHostsInPool(service, nodes, backendPoolID, vmSetName, isInternal interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "EnsureHostsInPool", reflect.TypeOf((*MockVMSet)(nil).EnsureHostsInPool), service, nodes, backendPoolID, vmSetName, isInternal)
}

// EnsureHostInPool mocks base method
func (m *MockVMSet) EnsureHostInPool(service *v1.Service, nodeName types.NodeName, backendPoolID, vmSetName string, isInternal bool) (string, string, string, *compute.VirtualMachineScaleSetVM, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "EnsureHostInPool", service, nodeName, backendPoolID, vmSetName, isInternal)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(string)
	ret2, _ := ret[2].(string)
	ret3, _ := ret[3].(*compute.VirtualMachineScaleSetVM)
	ret4, _ := ret[4].(error)
	return ret0, ret1, ret2, ret3, ret4
}

// EnsureHostInPool indicates an expected call of EnsureHostInPool
func (mr *MockVMSetMockRecorder) EnsureHostInPool(service, nodeName, backendPoolID, vmSetName, isInternal interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "EnsureHostInPool", reflect.TypeOf((*MockVMSet)(nil).EnsureHostInPool), service, nodeName, backendPoolID, vmSetName, isInternal)
}

// EnsureBackendPoolDeleted mocks base method
func (m *MockVMSet) EnsureBackendPoolDeleted(service *v1.Service, backendPoolID, vmSetName string, backendAddressPools *[]network.BackendAddressPool) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "EnsureBackendPoolDeleted", service, backendPoolID, vmSetName, backendAddressPools)
	ret0, _ := ret[0].(error)
	return ret0
}

// EnsureBackendPoolDeleted indicates an expected call of EnsureBackendPoolDeleted
func (mr *MockVMSetMockRecorder) EnsureBackendPoolDeleted(service, backendPoolID, vmSetName, backendAddressPools interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "EnsureBackendPoolDeleted", reflect.TypeOf((*MockVMSet)(nil).EnsureBackendPoolDeleted), service, backendPoolID, vmSetName, backendAddressPools)
}

// AttachDisk mocks base method
func (m *MockVMSet) AttachDisk(isManagedDisk bool, diskName, diskURI string, nodeName types.NodeName, lun int32, cachingMode compute.CachingTypes, diskEncryptionSetID string, writeAcceleratorEnabled bool) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AttachDisk", isManagedDisk, diskName, diskURI, nodeName, lun, cachingMode, diskEncryptionSetID, writeAcceleratorEnabled)
	ret0, _ := ret[0].(error)
	return ret0
}

// AttachDisk indicates an expected call of AttachDisk
func (mr *MockVMSetMockRecorder) AttachDisk(isManagedDisk, diskName, diskURI, nodeName, lun, cachingMode, diskEncryptionSetID, writeAcceleratorEnabled interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AttachDisk", reflect.TypeOf((*MockVMSet)(nil).AttachDisk), isManagedDisk, diskName, diskURI, nodeName, lun, cachingMode, diskEncryptionSetID, writeAcceleratorEnabled)
}

// DetachDisk mocks base method
func (m *MockVMSet) DetachDisk(diskName, diskURI string, nodeName types.NodeName) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DetachDisk", diskName, diskURI, nodeName)
	ret0, _ := ret[0].(error)
	return ret0
}

// DetachDisk indicates an expected call of DetachDisk
func (mr *MockVMSetMockRecorder) DetachDisk(diskName, diskURI, nodeName interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DetachDisk", reflect.TypeOf((*MockVMSet)(nil).DetachDisk), diskName, diskURI, nodeName)
}

// GetDataDisks mocks base method
func (m *MockVMSet) GetDataDisks(nodeName types.NodeName, string cache.AzureCacheReadType) ([]compute.DataDisk, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetDataDisks", nodeName, string)
	ret0, _ := ret[0].([]compute.DataDisk)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetDataDisks indicates an expected call of GetDataDisks
func (mr *MockVMSetMockRecorder) GetDataDisks(nodeName, string interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetDataDisks", reflect.TypeOf((*MockVMSet)(nil).GetDataDisks), nodeName, string)
}

// GetPowerStatusByNodeName mocks base method
func (m *MockVMSet) GetPowerStatusByNodeName(name string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPowerStatusByNodeName", name)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetPowerStatusByNodeName indicates an expected call of GetPowerStatusByNodeName
func (mr *MockVMSetMockRecorder) GetPowerStatusByNodeName(name interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPowerStatusByNodeName", reflect.TypeOf((*MockVMSet)(nil).GetPowerStatusByNodeName), name)
}

// GetPrivateIPsByNodeName mocks base method
func (m *MockVMSet) GetPrivateIPsByNodeName(name string) ([]string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPrivateIPsByNodeName", name)
	ret0, _ := ret[0].([]string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetPrivateIPsByNodeName indicates an expected call of GetPrivateIPsByNodeName
func (mr *MockVMSetMockRecorder) GetPrivateIPsByNodeName(name interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPrivateIPsByNodeName", reflect.TypeOf((*MockVMSet)(nil).GetPrivateIPsByNodeName), name)
}
