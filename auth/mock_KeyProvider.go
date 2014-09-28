package auth

import "github.com/stretchr/testify/mock"

import "crypto/ecdsa"

type MockKeyProvider struct {
	mock.Mock
}

func (m *MockKeyProvider) GetKey(id string) (*ecdsa.PublicKey, error) {
	ret := m.Called(id)

	r0 := ret.Get(0).(*ecdsa.PublicKey)
	r1 := ret.Error(1)

	return r0, r1
}
