package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyFile(t *testing.T) {
	file, err := ioutil.TempFile("", "key")
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	data := elliptic.Marshal(elliptic.P256(), key.X, key.Y)

	_, err = file.Write(data)
	require.NoError(t, err)

	path := file.Name()

	file.Close()

	kf := KeyFromFile(path)

	fkey, err := kf.GetKey("x")
	require.NoError(t, err)

	assert.Equal(t, &key.PublicKey, fkey)
}
