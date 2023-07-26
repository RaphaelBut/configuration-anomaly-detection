// Code generated by MockGen. DO NOT EDIT.
// Source: pagerduty.go

// Package pdmock is a generated GoMock package.
package pdmock

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	pagerduty "github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
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

// AddNote mocks base method.
func (m *MockClient) AddNote(notes string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddNote", notes)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddNote indicates an expected call of AddNote.
func (mr *MockClientMockRecorder) AddNote(notes interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddNote", reflect.TypeOf((*MockClient)(nil).AddNote), notes)
}

// CreateNewAlert mocks base method.
func (m *MockClient) CreateNewAlert(newAlert pagerduty.NewAlert, serviceID string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateNewAlert", newAlert, serviceID)
	ret0, _ := ret[0].(error)
	return ret0
}

// CreateNewAlert indicates an expected call of CreateNewAlert.
func (mr *MockClientMockRecorder) CreateNewAlert(newAlert, serviceID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateNewAlert", reflect.TypeOf((*MockClient)(nil).CreateNewAlert), newAlert, serviceID)
}

// EscalateAlert mocks base method.
func (m *MockClient) EscalateAlert() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "EscalateAlert")
	ret0, _ := ret[0].(error)
	return ret0
}

// EscalateAlert indicates an expected call of EscalateAlert.
func (mr *MockClientMockRecorder) EscalateAlert() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "EscalateAlert", reflect.TypeOf((*MockClient)(nil).EscalateAlert))
}

// EscalateAlertWithNote mocks base method.
func (m *MockClient) EscalateAlertWithNote(notes string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "EscalateAlertWithNote", notes)
	ret0, _ := ret[0].(error)
	return ret0
}

// EscalateAlertWithNote indicates an expected call of EscalateAlertWithNote.
func (mr *MockClientMockRecorder) EscalateAlertWithNote(notes interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "EscalateAlertWithNote", reflect.TypeOf((*MockClient)(nil).EscalateAlertWithNote), notes)
}

// GetEventType mocks base method.
func (m *MockClient) GetEventType() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetEventType")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetEventType indicates an expected call of GetEventType.
func (mr *MockClientMockRecorder) GetEventType() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetEventType", reflect.TypeOf((*MockClient)(nil).GetEventType))
}

// GetServiceID mocks base method.
func (m *MockClient) GetServiceID() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetServiceID")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetServiceID indicates an expected call of GetServiceID.
func (mr *MockClientMockRecorder) GetServiceID() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetServiceID", reflect.TypeOf((*MockClient)(nil).GetServiceID))
}

// ResolveAlertsForCluster mocks base method.
func (m *MockClient) ResolveAlertsForCluster(clusterID string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ResolveAlertsForCluster", clusterID)
	ret0, _ := ret[0].(error)
	return ret0
}

// ResolveAlertsForCluster indicates an expected call of ResolveAlertsForCluster.
func (mr *MockClientMockRecorder) ResolveAlertsForCluster(clusterID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResolveAlertsForCluster", reflect.TypeOf((*MockClient)(nil).ResolveAlertsForCluster), clusterID)
}

// SilenceAlertWithNote mocks base method.
func (m *MockClient) SilenceAlertWithNote(notes string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SilenceAlertWithNote", notes)
	ret0, _ := ret[0].(error)
	return ret0
}

// SilenceAlertWithNote indicates an expected call of SilenceAlertWithNote.
func (mr *MockClientMockRecorder) SilenceAlertWithNote(notes interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SilenceAlertWithNote", reflect.TypeOf((*MockClient)(nil).SilenceAlertWithNote), notes)
}
