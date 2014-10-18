package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/gob"
)

type signedShared struct {
	Token     []byte
	Signature []byte
}

func VerifySharedKey(conn MessageConnection, key []byte) error {
	msg, err := conn.GetMessage()
	if err != nil {
		return err
	}

	var signed signedShared

	err = gob.NewDecoder(bytes.NewReader(msg)).Decode(&signed)
	if err != nil {
		return err
	}

	if !bytes.Equal(conn.PeerAuthToken(), signed.Token) {
		return ErrWrongToken
	}

	hm := hmac.New(sha256.New, key)
	hm.Write(signed.Token)

	computed := hm.Sum(nil)

	if !hmac.Equal(computed, signed.Signature) {
		return ErrInvalidSignature
	}

	return nil
}

func SendSharedKey(conn MessageConnection, key []byte) error {
	token := conn.AuthToken()

	hm := hmac.New(sha256.New, key)
	hm.Write(token)

	computed := hm.Sum(nil)

	signed := signedShared{
		Token:     token,
		Signature: computed,
	}

	var msg1 bytes.Buffer

	err := gob.NewEncoder(&msg1).Encode(&signed)
	if err != nil {
		return err
	}

	return conn.SendMessage(msg1.Bytes())
}
