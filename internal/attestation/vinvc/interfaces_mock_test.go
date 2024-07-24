// Code generated by MockGen. DO NOT EDIT.
// Source: interfaces.go
//
// Generated by this command:
//
//	mockgen -source=interfaces.go -destination=interfaces_mock_test.go -package=vinvc_test
//

// Package vinvc_test is a generated GoMock package.
package vinvc_test

import (
	context "context"
	json "encoding/json"
	reflect "reflect"
	time "time"

	models "github.com/DIMO-Network/attestation-api/internal/models"
	verifiable "github.com/DIMO-Network/attestation-api/pkg/verifiable"
	common "github.com/ethereum/go-ethereum/common"
	gomock "go.uber.org/mock/gomock"
)

// MockVCRepo is a mock of VCRepo interface.
type MockVCRepo struct {
	ctrl     *gomock.Controller
	recorder *MockVCRepoMockRecorder
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

// GetLatestVINVC mocks base method.
func (m *MockVCRepo) GetLatestVINVC(ctx context.Context, tokenID uint32) (*verifiable.Credential, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetLatestVINVC", ctx, tokenID)
	ret0, _ := ret[0].(*verifiable.Credential)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetLatestVINVC indicates an expected call of GetLatestVINVC.
func (mr *MockVCRepoMockRecorder) GetLatestVINVC(ctx, tokenID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetLatestVINVC", reflect.TypeOf((*MockVCRepo)(nil).GetLatestVINVC), ctx, tokenID)
}

// StoreVINVC mocks base method.
func (m *MockVCRepo) StoreVINVC(ctx context.Context, tokenID uint32, vinvc json.RawMessage) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StoreVINVC", ctx, tokenID, vinvc)
	ret0, _ := ret[0].(error)
	return ret0
}

// StoreVINVC indicates an expected call of StoreVINVC.
func (mr *MockVCRepoMockRecorder) StoreVINVC(ctx, tokenID, vinvc any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StoreVINVC", reflect.TypeOf((*MockVCRepo)(nil).StoreVINVC), ctx, tokenID, vinvc)
}

// MockIdentityAPI is a mock of IdentityAPI interface.
type MockIdentityAPI struct {
	ctrl     *gomock.Controller
	recorder *MockIdentityAPIMockRecorder
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
func (m *MockIdentityAPI) GetVehicleInfo(ctx context.Context, tokenID uint32) (*models.VehicleInfo, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetVehicleInfo", ctx, tokenID)
	ret0, _ := ret[0].(*models.VehicleInfo)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetVehicleInfo indicates an expected call of GetVehicleInfo.
func (mr *MockIdentityAPIMockRecorder) GetVehicleInfo(ctx, tokenID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetVehicleInfo", reflect.TypeOf((*MockIdentityAPI)(nil).GetVehicleInfo), ctx, tokenID)
}

// MockFingerprintRepo is a mock of FingerprintRepo interface.
type MockFingerprintRepo struct {
	ctrl     *gomock.Controller
	recorder *MockFingerprintRepoMockRecorder
}

// MockFingerprintRepoMockRecorder is the mock recorder for MockFingerprintRepo.
type MockFingerprintRepoMockRecorder struct {
	mock *MockFingerprintRepo
}

// NewMockFingerprintRepo creates a new mock instance.
func NewMockFingerprintRepo(ctrl *gomock.Controller) *MockFingerprintRepo {
	mock := &MockFingerprintRepo{ctrl: ctrl}
	mock.recorder = &MockFingerprintRepoMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockFingerprintRepo) EXPECT() *MockFingerprintRepoMockRecorder {
	return m.recorder
}

// GetLatestFingerprintMessages mocks base method.
func (m *MockFingerprintRepo) GetLatestFingerprintMessages(ctx context.Context, pairedDeviceAddr common.Address) (*models.DecodedFingerprintData, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetLatestFingerprintMessages", ctx, pairedDeviceAddr)
	ret0, _ := ret[0].(*models.DecodedFingerprintData)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetLatestFingerprintMessages indicates an expected call of GetLatestFingerprintMessages.
func (mr *MockFingerprintRepoMockRecorder) GetLatestFingerprintMessages(ctx, pairedDeviceAddr any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetLatestFingerprintMessages", reflect.TypeOf((*MockFingerprintRepo)(nil).GetLatestFingerprintMessages), ctx, pairedDeviceAddr)
}

// MockVINAPI is a mock of VINAPI interface.
type MockVINAPI struct {
	ctrl     *gomock.Controller
	recorder *MockVINAPIMockRecorder
}

// MockVINAPIMockRecorder is the mock recorder for MockVINAPI.
type MockVINAPIMockRecorder struct {
	mock *MockVINAPI
}

// NewMockVINAPI creates a new mock instance.
func NewMockVINAPI(ctrl *gomock.Controller) *MockVINAPI {
	mock := &MockVINAPI{ctrl: ctrl}
	mock.recorder = &MockVINAPIMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockVINAPI) EXPECT() *MockVINAPIMockRecorder {
	return m.recorder
}

// DecodeVIN mocks base method.
func (m *MockVINAPI) DecodeVIN(ctx context.Context, vin, countryCode string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DecodeVIN", ctx, vin, countryCode)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DecodeVIN indicates an expected call of DecodeVIN.
func (mr *MockVINAPIMockRecorder) DecodeVIN(ctx, vin, countryCode any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DecodeVIN", reflect.TypeOf((*MockVINAPI)(nil).DecodeVIN), ctx, vin, countryCode)
}

// MockIssuer is a mock of Issuer interface.
type MockIssuer struct {
	ctrl     *gomock.Controller
	recorder *MockIssuerMockRecorder
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

// CreateBitstringStatusListVC mocks base method.
func (m *MockIssuer) CreateBitstringStatusListVC(tokenID uint32, revoked bool) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateBitstringStatusListVC", tokenID, revoked)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateBitstringStatusListVC indicates an expected call of CreateBitstringStatusListVC.
func (mr *MockIssuerMockRecorder) CreateBitstringStatusListVC(tokenID, revoked any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateBitstringStatusListVC", reflect.TypeOf((*MockIssuer)(nil).CreateBitstringStatusListVC), tokenID, revoked)
}

// CreateKeyControlDoc mocks base method.
func (m *MockIssuer) CreateKeyControlDoc() ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateKeyControlDoc")
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateKeyControlDoc indicates an expected call of CreateKeyControlDoc.
func (mr *MockIssuerMockRecorder) CreateKeyControlDoc() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateKeyControlDoc", reflect.TypeOf((*MockIssuer)(nil).CreateKeyControlDoc))
}

// CreateVINVC mocks base method.
func (m *MockIssuer) CreateVINVC(vinSubject verifiable.VINSubject, expTime time.Time) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateVINVC", vinSubject, expTime)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateVINVC indicates an expected call of CreateVINVC.
func (mr *MockIssuerMockRecorder) CreateVINVC(vinSubject, expTime any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateVINVC", reflect.TypeOf((*MockIssuer)(nil).CreateVINVC), vinSubject, expTime)
}
