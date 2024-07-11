// Code generated by MockGen. DO NOT EDIT.
// Source: ocm.go

// Package ocmmock is a generated GoMock package.
package ocmmock

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	sdk "github.com/openshift-online/ocm-sdk-go"
	v1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	v10 "github.com/openshift-online/ocm-sdk-go/servicelogs/v1"
	ocm "github.com/openshift/configuration-anomaly-detection/pkg/ocm"
)

// MockClient is a mock of Client interface.
type MockClient struct {
	ctrl     *gomock.Controller
	recorder *MockClientMockRecorder
}

// MockClientMockRecorder is the mock recorder for MockClient.
type MockClientMockRecorder struct {
	mock *MockClient
}

// NewMockClient creates a new mock instance.
func NewMockClient(ctrl *gomock.Controller) *MockClient {
	mock := &MockClient{ctrl: ctrl}
	mock.recorder = &MockClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockClient) EXPECT() *MockClientMockRecorder {
	return m.recorder
}

// AwsClassicJumpRoleCompatible mocks base method.
func (m *MockClient) AwsClassicJumpRoleCompatible(cluster *v1.Cluster) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AwsClassicJumpRoleCompatible", cluster)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AwsClassicJumpRoleCompatible indicates an expected call of AwsClassicJumpRoleCompatible.
func (mr *MockClientMockRecorder) AwsClassicJumpRoleCompatible(cluster interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AwsClassicJumpRoleCompatible", reflect.TypeOf((*MockClient)(nil).AwsClassicJumpRoleCompatible), cluster)
}

// GetClusterMachinePools mocks base method.
func (m *MockClient) GetClusterMachinePools(internalClusterID string) ([]*v1.MachinePool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetClusterMachinePools", internalClusterID)
	ret0, _ := ret[0].([]*v1.MachinePool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetClusterMachinePools indicates an expected call of GetClusterMachinePools.
func (mr *MockClientMockRecorder) GetClusterMachinePools(internalClusterID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetClusterMachinePools", reflect.TypeOf((*MockClient)(nil).GetClusterMachinePools), internalClusterID)
}

// GetConnection mocks base method.
func (m *MockClient) GetConnection() *sdk.Connection {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetConnection")
	ret0, _ := ret[0].(*sdk.Connection)
	return ret0
}

// GetConnection indicates an expected call of GetConnection.
func (mr *MockClientMockRecorder) GetConnection() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetConnection", reflect.TypeOf((*MockClient)(nil).GetConnection))
}

// GetServiceLog mocks base method.
func (m *MockClient) GetServiceLog(cluster *v1.Cluster, filter string) (*v10.ClusterLogsUUIDListResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetServiceLog", cluster, filter)
	ret0, _ := ret[0].(*v10.ClusterLogsUUIDListResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetServiceLog indicates an expected call of GetServiceLog.
func (mr *MockClientMockRecorder) GetServiceLog(cluster, filter interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetServiceLog", reflect.TypeOf((*MockClient)(nil).GetServiceLog), cluster, filter)
}

// GetSupportRoleARN mocks base method.
func (m *MockClient) GetSupportRoleARN(internalClusterID string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetSupportRoleARN", internalClusterID)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetSupportRoleARN indicates an expected call of GetSupportRoleARN.
func (mr *MockClientMockRecorder) GetSupportRoleARN(internalClusterID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSupportRoleARN", reflect.TypeOf((*MockClient)(nil).GetSupportRoleARN), internalClusterID)
}

// IsAccessProtected mocks base method.
func (m *MockClient) IsAccessProtected(cluster *v1.Cluster) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsAccessProtected", cluster)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// IsAccessProtected indicates an expected call of IsAccessProtected.
func (mr *MockClientMockRecorder) IsAccessProtected(cluster interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsAccessProtected", reflect.TypeOf((*MockClient)(nil).IsAccessProtected), cluster)
}

// PostLimitedSupportReason mocks base method.
func (m *MockClient) PostLimitedSupportReason(limitedSupportReason *ocm.LimitedSupportReason, cluster *v1.Cluster) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PostLimitedSupportReason", limitedSupportReason, cluster)
	ret0, _ := ret[0].(error)
	return ret0
}

// PostLimitedSupportReason indicates an expected call of PostLimitedSupportReason.
func (mr *MockClientMockRecorder) PostLimitedSupportReason(limitedSupportReason, cluster interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PostLimitedSupportReason", reflect.TypeOf((*MockClient)(nil).PostLimitedSupportReason), limitedSupportReason, cluster)
}

// PostServiceLog mocks base method.
func (m *MockClient) PostServiceLog(clusterID string, sl *ocm.ServiceLog) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PostServiceLog", clusterID, sl)
	ret0, _ := ret[0].(error)
	return ret0
}

// PostServiceLog indicates an expected call of PostServiceLog.
func (mr *MockClientMockRecorder) PostServiceLog(clusterID, sl interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PostServiceLog", reflect.TypeOf((*MockClient)(nil).PostServiceLog), clusterID, sl)
}
