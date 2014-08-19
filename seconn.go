package seconn

import (
	"encoding/binary"
	"errors"
	"io"
	"net"

	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"

	"code.google.com/p/go.crypto/curve25519"
)

var WriteBufferSize = 128

type Conn struct {
	net.Conn
	privKey *[32]byte
	pubKey  *[32]byte
	peerKey *[32]byte
	shared  *[32]byte
	stream  cipher.Stream

	writeBuf []byte
}

func GenerateKey(rand io.Reader) (publicKey, privateKey *[32]byte, err error) {
	publicKey = new([32]byte)
	privateKey = new([32]byte)
	_, err = io.ReadFull(rand, privateKey[:])
	if err != nil {
		publicKey = nil
		privateKey = nil
		return
	}

	curve25519.ScalarBaseMult(publicKey, privateKey)
	return
}

func NewConn(c net.Conn) (*Conn, error) {
	pub, priv, err := GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	conn := &Conn{
		Conn:     c,
		privKey:  priv,
		pubKey:   pub,
		writeBuf: make([]byte, 128),
	}

	return conn, nil
}

func NewClient(u net.Conn) (*Conn, error) {
	c, err := NewConn(u)
	if err != nil {
		return nil, err
	}

	c.Negotiate(false)

	return c, nil
}

func NewServer(u net.Conn) (*Conn, error) {
	c, err := NewConn(u)
	if err != nil {
		return nil, err
	}

	c.Negotiate(true)

	return c, nil
}

func (c *Conn) Negotiate(server bool) error {
	err := binary.Write(c.Conn, binary.BigEndian, uint32(len(c.pubKey)))
	if err != nil {
		return err
	}

	n, err := c.Conn.Write((*c.pubKey)[:])
	if err != nil {
		return err
	}

	if n != len(c.pubKey) {
		return io.ErrShortWrite
	}

	other := uint32(0)

	err = binary.Read(c.Conn, binary.BigEndian, &other)
	if err != nil {
		return err
	}

	c.peerKey = new([32]byte)

	n, err = c.Conn.Read((*c.peerKey)[:])
	if err != nil {
		return err
	}

	if n != len(c.peerKey) {
		return io.ErrShortBuffer
	}

	c.shared = new([32]byte)

	curve25519.ScalarMult(c.shared, c.privKey, c.peerKey)

	block, err := aes.NewCipher((*c.shared)[:])
	if err != nil {
		return err
	}

	var iv []byte

	if server {
		err = binary.Read(c.Conn, binary.BigEndian, &other)
		if err != nil {
			return err
		}

		iv = make([]byte, other)

		n, err := io.ReadFull(c.Conn, iv)
		if err != nil {
			return err
		}

		if n != int(other) {
			return io.ErrShortBuffer
		}
	} else {
		iv = make([]byte, aes.BlockSize)
		n, err := io.ReadFull(rand.Reader, iv)
		if err != nil {
			return err
		}

		if n != aes.BlockSize {
			return io.ErrShortBuffer
		}

		err = binary.Write(c.Conn, binary.BigEndian, uint32(len(iv)))
		if err != nil {
			return err
		}

		n, err = c.Conn.Write(iv)
		if err != nil {
			return err
		}

		if n != len(iv) {
			return io.ErrShortWrite
		}
	}

	stream := cipher.NewOFB(block, iv)
	if stream == nil {
		return errors.New("unable to create stream cipher")
	}

	c.stream = stream

	return nil
}

func (c *Conn) Read(buf []byte) (int, error) {
	n, err := c.Conn.Read(buf)
	if err != nil {
		return 0, err
	}

	c.stream.XORKeyStream(buf[:n], buf[:n])
	return n, err
}

func (c *Conn) Write(buf []byte) (int, error) {
	left := len(buf)
	cur := 0

	for {
		if left <= len(c.writeBuf) {
			c.stream.XORKeyStream(c.writeBuf, buf[cur:])

			n, err := c.Conn.Write(c.writeBuf[:left])
			if err != nil {
				return 0, err
			}

			if n != left {
				return 0, io.ErrShortWrite
			}

			break
		} else {
			c.stream.XORKeyStream(c.writeBuf, buf[cur:cur+len(c.writeBuf)])

			n, err := c.Conn.Write(c.writeBuf)
			if err != nil {
				return 0, err
			}

			if n != len(c.writeBuf) {
				return 0, io.ErrShortWrite
			}

			cur += n
			left -= n
		}
	}

	return len(buf), nil
}

func (c *Conn) GetMessage() ([]byte, error) {
	l := uint32(0)

	err := binary.Read(c, binary.BigEndian, &l)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, l)

	n, err := io.ReadFull(c, buf)
	if err != nil {
		return nil, err
	}

	if n != len(buf) {
		return nil, io.ErrShortBuffer
	}

	return buf, nil
}

func (c *Conn) SendMessage(msg []byte) error {
	err := binary.Write(c, binary.BigEndian, uint32(len(msg)))
	if err != nil {
		return err
	}

	n, err := c.Write(msg)
	if err != nil {
		return err
	}

	if n != len(msg) {
		return io.ErrShortWrite
	}

	return nil
}
