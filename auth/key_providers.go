package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"io/ioutil"
)

type KeyFile struct {
	Path string
}

func (k *KeyFile) GetKey(id string) (*ecdsa.PublicKey, error) {
	data, err := ioutil.ReadFile(k.Path)
	if err != nil {
		return nil, err
	}

	x, y := elliptic.Unmarshal(elliptic.P256(), data)

	pkey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	return pkey, nil
}

func KeyFromFile(path string) *KeyFile {
	return &KeyFile{Path: path}
}
