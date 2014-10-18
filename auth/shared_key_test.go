package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/gob"
	"testing"

	"github.com/stretchr/testify/require"

	"code.google.com/p/go.crypto/pbkdf2"
)

func TestSharedKeyAuth(t *testing.T) {
	var client MockMessageConnection

	token := []byte("aabbcc")

	password := []byte("a1b2c3")

	dk := pbkdf2.Key(password, password, 4096, 32, sha256.New)

	hm := hmac.New(sha256.New, dk)

	hm.Write(token)

	val1 := signedShared{
		Token:     token,
		Signature: hm.Sum(nil),
	}

	var msg1 bytes.Buffer

	err := gob.NewEncoder(&msg1).Encode(&val1)
	require.NoError(t, err)

	client.On("GetMessage").Return(msg1.Bytes(), nil)
	client.On("PeerAuthToken").Return(token)

	err = VerifySharedKey(&client, dk)
	require.NoError(t, err)

	client.AssertExpectations(t)
}

func TestSharedKeyAuthErrorsWithBadKey(t *testing.T) {
	var client MockMessageConnection

	token := []byte("aabbcc")

	password := []byte("a1b2c3")

	dk := pbkdf2.Key(password, password, 4096, 32, sha256.New)

	hm := hmac.New(sha256.New, dk)

	hm.Write(token)

	val1 := signedShared{
		Token:     token,
		Signature: hm.Sum(nil),
	}

	var msg1 bytes.Buffer

	err := gob.NewEncoder(&msg1).Encode(&val1)
	require.NoError(t, err)

	client.On("GetMessage").Return(msg1.Bytes(), nil)
	client.On("PeerAuthToken").Return(token)

	err = VerifySharedKey(&client, dk[1:])
	require.Equal(t, err, ErrInvalidSignature)

	client.AssertExpectations(t)
}

func TestSharedKeyAuthErrorsWithDifferentToken(t *testing.T) {
	var client MockMessageConnection

	token := []byte("aabbcc")
	token2 := []byte("aabbdd")

	password := []byte("a1b2c3")

	dk := pbkdf2.Key(password, password, 4096, 32, sha256.New)

	hm := hmac.New(sha256.New, dk)

	hm.Write(token)

	val1 := signedShared{
		Token:     token,
		Signature: hm.Sum(nil),
	}

	var msg1 bytes.Buffer

	err := gob.NewEncoder(&msg1).Encode(&val1)
	require.NoError(t, err)

	client.On("GetMessage").Return(msg1.Bytes(), nil)
	client.On("PeerAuthToken").Return(token2)

	err = VerifySharedKey(&client, dk)
	require.Equal(t, err, ErrWrongToken)

	client.AssertExpectations(t)
}

func TestSharedKeyServer(t *testing.T) {
	var server MockMessageConnection

	token1 := []byte("aabbcc")

	password := []byte("a1b2c3")

	dk := pbkdf2.Key(password, password, 4096, 32, sha256.New)

	hm := hmac.New(sha256.New, dk)

	hm.Write(token1)

	val1 := signedShared{
		Token:     token1,
		Signature: hm.Sum(nil),
	}

	var msg1 bytes.Buffer

	err := gob.NewEncoder(&msg1).Encode(&val1)
	require.NoError(t, err)

	server.On("SendMessage", msg1.Bytes()).Return(nil)
	server.On("AuthToken").Return(token1)

	err = SendSharedKey(&server, dk)
	require.NoError(t, err)

	server.AssertExpectations(t)
}
