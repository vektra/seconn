package auth

import "github.com/stretchr/testify/mock"

type MockMessageConnection struct {
	mock.Mock
}

func (m *MockMessageConnection) GetMessage() ([]byte, error) {
	ret := m.Called()

	r0 := ret.Get(0).([]byte)
	r1 := ret.Error(1)

	return r0, r1
}
func (m *MockMessageConnection) SendMessage(msg []byte) error {
	ret := m.Called(msg)

	r0 := ret.Error(0)

	return r0
}
func (m *MockMessageConnection) AuthToken() []byte {
	ret := m.Called()

	r0 := ret.Get(0).([]byte)

	return r0
}
func (m *MockMessageConnection) PeerAuthToken() []byte {
	ret := m.Called()

	r0 := ret.Get(0).([]byte)

	return r0
}
