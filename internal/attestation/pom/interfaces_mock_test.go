// Code generated by MockGen. DO NOT EDIT.
// Source: interfaces.go
//
// Generated by this command:
//
//	mockgen -source=interfaces.go -destination=interfaces_mock_test.go -package=pom_test
//

// Package pom_test is a generated GoMock package.
package pom_test

import (
	context "context"
	json "encoding/json"
	reflect "reflect"
	time "time"

	models "github.com/DIMO-Network/attestation-api/internal/models"
	verifiable "github.com/DIMO-Network/attestation-api/pkg/verifiable"
	cloudevent "github.com/DIMO-Network/model-garage/pkg/cloudevent"
	gomock "go.uber.org/mock/gomock"
)

// MockVCRepo is a mock of VCRepo interface.
type MockVCRepo struct {
	ctrl     *gomock.Controller
	recorder *MockVCRepoMockRecorder
	isgomock struct{}
}

// MockVCRepoMockRecorder is the mock recorder for MockVCRepo.
type MockVCRepoMockRecorder struct {
	mock *MockVCRepo
}

// NewMockVCRepo creates a new mock instance.
func NewMockVCRepo(ctrl *gomock.Controller) *MockVCRepo {
	mock := &MockVCRepo{ctrl: ctrl}
	mock.recorder = &MockVCRepoMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockVCRepo) EXPECT() *MockVCRepoMockRecorder {
	return m.recorder
}

// StorePOMVC mocks base method.
func (m *MockVCRepo) StorePOMVC(ctx context.Context, vehicleDID, producerDID string, vinvc json.RawMessage) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StorePOMVC", ctx, vehicleDID, producerDID, vinvc)
	ret0, _ := ret[0].(error)
	return ret0
}

// StorePOMVC indicates an expected call of StorePOMVC.
func (mr *MockVCRepoMockRecorder) StorePOMVC(ctx, vehicleDID, producerDID, vinvc any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StorePOMVC", reflect.TypeOf((*MockVCRepo)(nil).StorePOMVC), ctx, vehicleDID, producerDID, vinvc)
}

// MockIdentityAPI is a mock of IdentityAPI interface.
type MockIdentityAPI struct {
	ctrl     *gomock.Controller
	recorder *MockIdentityAPIMockRecorder
	isgomock struct{}
}

// MockIdentityAPIMockRecorder is the mock recorder for MockIdentityAPI.
type MockIdentityAPIMockRecorder struct {
	mock *MockIdentityAPI
}

// NewMockIdentityAPI creates a new mock instance.
func NewMockIdentityAPI(ctrl *gomock.Controller) *MockIdentityAPI {
	mock := &MockIdentityAPI{ctrl: ctrl}
	mock.recorder = &MockIdentityAPIMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockIdentityAPI) EXPECT() *MockIdentityAPIMockRecorder {
	return m.recorder
}

// GetVehicleInfo mocks base method.
func (m *MockIdentityAPI) GetVehicleInfo(ctx context.Context, vehicleDID cloudevent.NFTDID) (*models.VehicleInfo, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetVehicleInfo", ctx, vehicleDID)
	ret0, _ := ret[0].(*models.VehicleInfo)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetVehicleInfo indicates an expected call of GetVehicleInfo.
func (mr *MockIdentityAPIMockRecorder) GetVehicleInfo(ctx, vehicleDID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetVehicleInfo", reflect.TypeOf((*MockIdentityAPI)(nil).GetVehicleInfo), ctx, vehicleDID)
}

// MockConnectivityRepo is a mock of ConnectivityRepo interface.
type MockConnectivityRepo struct {
	ctrl     *gomock.Controller
	recorder *MockConnectivityRepoMockRecorder
	isgomock struct{}
}

// MockConnectivityRepoMockRecorder is the mock recorder for MockConnectivityRepo.
type MockConnectivityRepoMockRecorder struct {
	mock *MockConnectivityRepo
}

// NewMockConnectivityRepo creates a new mock instance.
func NewMockConnectivityRepo(ctrl *gomock.Controller) *MockConnectivityRepo {
	mock := &MockConnectivityRepo{ctrl: ctrl}
	mock.recorder = &MockConnectivityRepoMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockConnectivityRepo) EXPECT() *MockConnectivityRepoMockRecorder {
	return m.recorder
}

// GetAutoPiEvents mocks base method.
func (m *MockConnectivityRepo) GetAutoPiEvents(ctx context.Context, pairedDevice *models.PairedDevice, after, before time.Time, limit int) ([]cloudevent.CloudEvent[json.RawMessage], error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAutoPiEvents", ctx, pairedDevice, after, before, limit)
	ret0, _ := ret[0].([]cloudevent.CloudEvent[json.RawMessage])
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAutoPiEvents indicates an expected call of GetAutoPiEvents.
func (mr *MockConnectivityRepoMockRecorder) GetAutoPiEvents(ctx, pairedDevice, after, before, limit any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAutoPiEvents", reflect.TypeOf((*MockConnectivityRepo)(nil).GetAutoPiEvents), ctx, pairedDevice, after, before, limit)
}

// GetCompassStatusEvents mocks base method.
func (m *MockConnectivityRepo) GetCompassStatusEvents(ctx context.Context, vehicleDID cloudevent.NFTDID, after, before time.Time, limit int) ([]cloudevent.CloudEvent[json.RawMessage], error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetCompassStatusEvents", ctx, vehicleDID, after, before, limit)
	ret0, _ := ret[0].([]cloudevent.CloudEvent[json.RawMessage])
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetCompassStatusEvents indicates an expected call of GetCompassStatusEvents.
func (mr *MockConnectivityRepoMockRecorder) GetCompassStatusEvents(ctx, vehicleDID, after, before, limit any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetCompassStatusEvents", reflect.TypeOf((*MockConnectivityRepo)(nil).GetCompassStatusEvents), ctx, vehicleDID, after, before, limit)
}

// GetHashDogEvents mocks base method.
func (m *MockConnectivityRepo) GetHashDogEvents(ctx context.Context, pairedDevice *models.PairedDevice, after, before time.Time, limit int) ([]cloudevent.CloudEvent[json.RawMessage], error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetHashDogEvents", ctx, pairedDevice, after, before, limit)
	ret0, _ := ret[0].([]cloudevent.CloudEvent[json.RawMessage])
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetHashDogEvents indicates an expected call of GetHashDogEvents.
func (mr *MockConnectivityRepoMockRecorder) GetHashDogEvents(ctx, pairedDevice, after, before, limit any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetHashDogEvents", reflect.TypeOf((*MockConnectivityRepo)(nil).GetHashDogEvents), ctx, pairedDevice, after, before, limit)
}

// GetRuptelaStatusEvents mocks base method.
func (m *MockConnectivityRepo) GetRuptelaStatusEvents(ctx context.Context, vehicleDID cloudevent.NFTDID, after, before time.Time, limit int) ([]cloudevent.CloudEvent[json.RawMessage], error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRuptelaStatusEvents", ctx, vehicleDID, after, before, limit)
	ret0, _ := ret[0].([]cloudevent.CloudEvent[json.RawMessage])
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRuptelaStatusEvents indicates an expected call of GetRuptelaStatusEvents.
func (mr *MockConnectivityRepoMockRecorder) GetRuptelaStatusEvents(ctx, vehicleDID, after, before, limit any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRuptelaStatusEvents", reflect.TypeOf((*MockConnectivityRepo)(nil).GetRuptelaStatusEvents), ctx, vehicleDID, after, before, limit)
}

// GetSyntheticstatusEvents mocks base method.
func (m *MockConnectivityRepo) GetSyntheticstatusEvents(ctx context.Context, vehicleDID cloudevent.NFTDID, after, before time.Time, limit int) ([]cloudevent.CloudEvent[json.RawMessage], error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetSyntheticstatusEvents", ctx, vehicleDID, after, before, limit)
	ret0, _ := ret[0].([]cloudevent.CloudEvent[json.RawMessage])
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetSyntheticstatusEvents indicates an expected call of GetSyntheticstatusEvents.
func (mr *MockConnectivityRepoMockRecorder) GetSyntheticstatusEvents(ctx, vehicleDID, after, before, limit any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSyntheticstatusEvents", reflect.TypeOf((*MockConnectivityRepo)(nil).GetSyntheticstatusEvents), ctx, vehicleDID, after, before, limit)
}

// MockIssuer is a mock of Issuer interface.
type MockIssuer struct {
	ctrl     *gomock.Controller
	recorder *MockIssuerMockRecorder
	isgomock struct{}
}

// MockIssuerMockRecorder is the mock recorder for MockIssuer.
type MockIssuerMockRecorder struct {
	mock *MockIssuer
}

// NewMockIssuer creates a new mock instance.
func NewMockIssuer(ctrl *gomock.Controller) *MockIssuer {
	mock := &MockIssuer{ctrl: ctrl}
	mock.recorder = &MockIssuerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockIssuer) EXPECT() *MockIssuerMockRecorder {
	return m.recorder
}

// CreatePOMVC mocks base method.
func (m *MockIssuer) CreatePOMVC(vinSubject verifiable.POMSubject) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreatePOMVC", vinSubject)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreatePOMVC indicates an expected call of CreatePOMVC.
func (mr *MockIssuerMockRecorder) CreatePOMVC(vinSubject any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreatePOMVC", reflect.TypeOf((*MockIssuer)(nil).CreatePOMVC), vinSubject)
}
