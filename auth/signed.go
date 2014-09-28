package auth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"io"

	"encoding/gob"
	"errors"
	"math/big"
)

var randReader io.Reader = rand.Reader

type MessageConnection interface {
	GetMessage() ([]byte, error)
	SendMessage(msg []byte) error
	AuthToken() []byte
	PeerAuthToken() []byte
}

type KeyProvider interface {
	GetKey(id string) (*ecdsa.PublicKey, error)
}

var (
	ErrInvalidSignature = errors.New("invalid signature")
	ErrWrongToken       = errors.New("wrong token")
)

type signedToken struct {
	Token      []byte
	KeyID      string
	SignatureR *big.Int
	SignatureS *big.Int
}

func VerifySignedToken(conn MessageConnection, keys KeyProvider) error {
	msg, err := conn.GetMessage()
	if err != nil {
		return err
	}

	var signed signedToken

	err = gob.NewDecoder(bytes.NewReader(msg)).Decode(&signed)
	if err != nil {
		return err
	}

	if !bytes.Equal(conn.PeerAuthToken(), signed.Token) {
		return ErrWrongToken
	}

	key, err := keys.GetKey(signed.KeyID)
	if err != nil {
		return err
	}

	if !ecdsa.Verify(key, signed.Token, signed.SignatureR, signed.SignatureS) {
		return ErrInvalidSignature
	}

	return nil
}

func SendSignedToken(conn MessageConnection, id string, key *ecdsa.PrivateKey) error {
	token := conn.AuthToken()

	r, s, err := ecdsa.Sign(randReader, key, token)

	signed := signedToken{
		Token:      token,
		KeyID:      id,
		SignatureR: r,
		SignatureS: s,
	}

	var msg1 bytes.Buffer

	err = gob.NewEncoder(&msg1).Encode(&signed)
	if err != nil {
		return err
	}

	return conn.SendMessage(msg1.Bytes())
}
