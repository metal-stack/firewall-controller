// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/metal-stack/firewall-controller/pkg/nftables (interfaces: FQDNCache)

// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	v1 "github.com/metal-stack/firewall-controller/api/v1"
	dns "github.com/metal-stack/firewall-controller/pkg/dns"
)

// MockFQDNCache is a mock of FQDNCache interface.
type MockFQDNCache struct {
	ctrl     *gomock.Controller
	recorder *MockFQDNCacheMockRecorder
}

// MockFQDNCacheMockRecorder is the mock recorder for MockFQDNCache.
type MockFQDNCacheMockRecorder struct {
	mock *MockFQDNCache
}

// NewMockFQDNCache creates a new mock instance.
func NewMockFQDNCache(ctrl *gomock.Controller) *MockFQDNCache {
	mock := &MockFQDNCache{ctrl: ctrl}
	mock.recorder = &MockFQDNCacheMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockFQDNCache) EXPECT() *MockFQDNCacheMockRecorder {
	return m.recorder
}

// GetSetsForFQDN mocks base method.
func (m *MockFQDNCache) GetSetsForFQDN(arg0 v1.FQDNSelector, arg1 []v1.IPSet) []v1.IPSet {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetSetsForFQDN", arg0, arg1)
	ret0, _ := ret[0].([]v1.IPSet)
	return ret0
}

// GetSetsForFQDN indicates an expected call of GetSetsForFQDN.
func (mr *MockFQDNCacheMockRecorder) GetSetsForFQDN(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSetsForFQDN", reflect.TypeOf((*MockFQDNCache)(nil).GetSetsForFQDN), arg0, arg1)
}

// GetSetsForRendering mocks base method.
func (m *MockFQDNCache) GetSetsForRendering(arg0 []v1.FQDNSelector) []dns.RenderIPSet {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetSetsForRendering", arg0)
	ret0, _ := ret[0].([]dns.RenderIPSet)
	return ret0
}

// GetSetsForRendering indicates an expected call of GetSetsForRendering.
func (mr *MockFQDNCacheMockRecorder) GetSetsForRendering(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSetsForRendering", reflect.TypeOf((*MockFQDNCache)(nil).GetSetsForRendering), arg0)
}

// IsInitialized mocks base method.
func (m *MockFQDNCache) IsInitialized() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsInitialized")
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsInitialized indicates an expected call of IsInitialized.
func (mr *MockFQDNCacheMockRecorder) IsInitialized() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsInitialized", reflect.TypeOf((*MockFQDNCache)(nil).IsInitialized))
}
