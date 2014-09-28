package auth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/gob"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSignedTokenClient(t *testing.T) {
	var client MockMessageConnection
	var key MockKeyProvider

	var msg1 bytes.Buffer

	k1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	token := []byte("aabbcc")

	r, s, err := ecdsa.Sign(rand.Reader, k1, token)
	require.NoError(t, err)

	val1 := signedToken{
		Token:      token,
		KeyID:      "k1",
		SignatureR: r,
		SignatureS: s,
	}

	err = gob.NewEncoder(&msg1).Encode(&val1)
	require.NoError(t, err)

	client.On("GetMessage").Return(msg1.Bytes(), nil)
	client.On("PeerAuthToken").Return(token)

	key.On("GetKey", "k1").Return(&k1.PublicKey, nil)

	err = VerifySignedToken(&client, &key)
	require.NoError(t, err)

	client.AssertExpectations(t)
	key.AssertExpectations(t)
}

func TestSignedTokenClientDifferentKeyUsed(t *testing.T) {
	var client MockMessageConnection
	var key MockKeyProvider

	var msg1 bytes.Buffer

	k1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	k2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	token := []byte("aabbcc")

	r, s, err := ecdsa.Sign(rand.Reader, k2, token)
	require.NoError(t, err)

	val1 := signedToken{
		Token:      token,
		KeyID:      "k1",
		SignatureR: r,
		SignatureS: s,
	}

	err = gob.NewEncoder(&msg1).Encode(&val1)
	require.NoError(t, err)

	client.On("GetMessage").Return(msg1.Bytes(), nil)
	client.On("PeerAuthToken").Return(token)

	key.On("GetKey", "k1").Return(&k1.PublicKey, nil)

	err = VerifySignedToken(&client, &key)
	require.Equal(t, err, ErrInvalidSignature)

	client.AssertExpectations(t)
	key.AssertExpectations(t)
}

func TestSignedTokenClientDifferentTokenPassed(t *testing.T) {
	var client MockMessageConnection
	var key MockKeyProvider

	var msg1 bytes.Buffer

	k2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	token1 := []byte("aabbcc")
	token2 := []byte("ddeeff")

	r, s, err := ecdsa.Sign(rand.Reader, k2, token2)
	require.NoError(t, err)

	val1 := signedToken{
		Token:      token2,
		KeyID:      "k1",
		SignatureR: r,
		SignatureS: s,
	}

	err = gob.NewEncoder(&msg1).Encode(&val1)
	require.NoError(t, err)

	client.On("GetMessage").Return(msg1.Bytes(), nil)
	client.On("PeerAuthToken").Return(token1)

	err = VerifySignedToken(&client, &key)
	require.Equal(t, err, ErrWrongToken)

	client.AssertExpectations(t)
	key.AssertExpectations(t)
}

func TestSignedTokenServer(t *testing.T) {
	var server MockMessageConnection

	var old io.Reader

	zero, err := os.Open("/dev/zero")
	require.NoError(t, err)

	defer zero.Close()

	old, randReader = randReader, zero

	defer func() {
		randReader = old
	}()

	token1 := []byte("aabbcc")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	r, s, err := ecdsa.Sign(randReader, key, token1)
	require.NoError(t, err)

	val1 := signedToken{
		Token:      token1,
		KeyID:      "k1",
		SignatureR: r,
		SignatureS: s,
	}

	var msg1 bytes.Buffer

	err = gob.NewEncoder(&msg1).Encode(&val1)
	require.NoError(t, err)

	server.On("SendMessage", msg1.Bytes()).Return(nil)
	server.On("AuthToken").Return(token1)

	err = SendSignedToken(&server, "k1", key)
	require.NoError(t, err)

	server.AssertExpectations(t)
}
