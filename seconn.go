package seconn

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"net"

	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"

	"code.google.com/p/go.crypto/curve25519"
)

// The size of the internal encrypted write buffer
var WriteBufferSize = 128

// How many bytes to write over the connection before we rekey
// This is bidirectional, so it will trip whenever either side
// has sent this ammount.
var RekeyAfterBytes = 1024 * 1024

var ErrBadMac = errors.New("bad mac detected")

type Conn struct {
	net.Conn
	privKey *[32]byte
	pubKey  *[32]byte
	peerKey *[32]byte
	shared  *[32]byte

	server    bool
	writeBuf  []byte
	readBuf   bytes.Buffer
	rekeyLeft int

	read  *half
	write *half
}

type half struct {
	stream cipher.Stream
	seq    []byte
	dbuf   []byte
	digest []byte
	hash   hash.Hash
}

func (h *half) setup(key, iv []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	stream := cipher.NewOFB(block, iv)
	if stream == nil {
		return errors.New("unable to create stream cipher")
	}

	h.stream = stream
	h.seq = make([]byte, 8)
	h.hash = hmac.New(sha256.New, key)
	h.digest = make([]byte, h.hash.Size())
	h.dbuf = make([]byte, h.hash.Size())

	return nil
}

func (h *half) incSeq() {
	for i := 0; i < len(h.seq); i++ {
		c := h.seq[i]
		h.seq[i] = c + 1

		if c < 255 {
			return
		}
	}
}

func (h *half) macStart(header []byte) {
	h.hash.Reset()
	h.hash.Write(h.seq)
	h.hash.Write(header)
}

func (h *half) macPayload(payload []byte) {
	h.hash.Write(payload)
}

func (h *half) macFinish() []byte {
	return h.hash.Sum(h.digest[:0])
}

func (h *half) mac(header, payload []byte) []byte {
	h.hash.Reset()
	h.hash.Write(h.seq)
	h.hash.Write(header)
	h.hash.Write(payload)
	return h.hash.Sum(h.digest[:0])
}

// Generate new public and private keys. Automatically called by Negotiate
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

// Create a new connection. Negotiate must be called before the
// connection can be used.
func NewConn(c net.Conn) (*Conn, error) {
	conn := &Conn{
		Conn:     c,
		writeBuf: make([]byte, 128),
	}

	return conn, nil
}

// Create a new connection and negotiate as the client
func NewClient(u net.Conn) (*Conn, error) {
	c, err := NewConn(u)
	if err != nil {
		return nil, err
	}

	c.Negotiate(false)

	return c, nil
}

// Create a new connection and negotiate as the server
func NewServer(u net.Conn) (*Conn, error) {
	c, err := NewConn(u)
	if err != nil {
		return nil, err
	}

	c.Negotiate(true)

	return c, nil
}

// On the next Write(), rekey the stream
func (c *Conn) RekeyNext() {
	c.rekeyLeft = 0
}

// Exchange keys and setup the encryption
func (c *Conn) Negotiate(server bool) error {
	pub, priv, err := GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	c.pubKey = pub
	c.privKey = priv

	c.server = server

	err = binary.Write(c.Conn, binary.BigEndian, uint32(len(c.pubKey)))
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

	c.rekeyLeft = RekeyAfterBytes

	c.read = &half{}
	c.write = &half{}

	sharedKey := (*c.shared)[:]

	c.read.setup(sharedKey, iv)
	c.write.setup(sharedKey, iv)

	return nil
}

// Read data into buf, automatically decrypting it
func (c *Conn) Read(buf []byte) (int, error) {
	n, err := c.readBuf.Read(buf)
	if n > 0 {
		return n, err
	}

	var headerData [4]byte

	header := headerData[:]

retry:

	n, err = io.ReadFull(c.Conn, header)
	if err != nil {
		return 0, err
	}

	if n != 4 {
		return 0, io.ErrShortBuffer
	}

	c.read.macStart(header)

	c.read.stream.XORKeyStream(header, header)

	cnt := binary.BigEndian.Uint32(header)

	if cnt == 0 {
		c.Negotiate(c.server)
		goto retry
	}

	if len(buf) < int(cnt) {
		io.CopyN(&c.readBuf, c.Conn, int64(cnt))
		c.read.macPayload(c.readBuf.Bytes())
	} else {
		n, err = io.ReadFull(c.Conn, buf[:cnt])
		if err != nil {
			return 0, err
		}

		if n != int(cnt) {
			return 0, io.ErrShortBuffer
		}

		c.read.macPayload(buf[:cnt])
	}

	n, err = io.ReadFull(c.Conn, c.read.dbuf)
	if err != nil {
		return 0, err
	}

	if n != len(c.read.dbuf) {
		return 0, io.ErrShortBuffer
	}

	// fmt.Printf("header: %#v\nbody: %#v", header, buf[:cnt])
	localMac := c.read.macFinish()

	// fmt.Printf("local: %#v\nremote: %#v\n", localMac, c.read.dbuf)

	// fmt.Printf("macs: %d <=> %d\n", len(localMac), len(c.read.dbuf))

	if subtle.ConstantTimeCompare(localMac, c.read.dbuf) != 1 {
		c.readBuf.Reset()
		return 0, ErrBadMac
	}

	var read int

	if len(buf) < int(cnt) {
		c.read.stream.XORKeyStream(c.readBuf.Bytes(), c.readBuf.Bytes())
		read, err = c.readBuf.Read(buf)
		if err != nil {
			return 0, err
		}
	} else {
		read = int(cnt)
		c.read.stream.XORKeyStream(buf[:cnt], buf[:cnt])
	}

	c.read.incSeq()

	return read, nil
}

// Write data, automatically encrypting it
func (c *Conn) Write(buf []byte) (int, error) {
	var headerData [4]byte

	header := headerData[:]

	if c.rekeyLeft <= 0 {
		binary.BigEndian.PutUint32(header, uint32(0))
		c.write.stream.XORKeyStream(header, header)

		n, err := c.Conn.Write(header)
		if err != nil {
			return 0, err
		}

		if n != len(header) {
			return 0, io.ErrShortWrite
		}

		c.Negotiate(c.server)
	}

	binary.BigEndian.PutUint32(header, uint32(len(buf)))

	c.write.stream.XORKeyStream(header, header)

	c.write.macStart(header)

	n, err := c.Conn.Write(header)
	if err != nil {
		return 0, err
	}

	if n != len(header) {
		return 0, io.ErrShortWrite
	}

	total := len(buf)

	for {
		if len(c.writeBuf) >= len(buf) {
			wb := c.writeBuf[:len(buf)]

			c.write.stream.XORKeyStream(wb, buf)

			n, err = c.Conn.Write(wb)
			if err != nil {
				return 0, err
			}

			if n != len(wb) {
				return 0, io.ErrShortWrite
			}

			c.write.macPayload(wb)
			break

		} else {
			wb := c.writeBuf

			c.write.stream.XORKeyStream(wb, buf[:len(c.writeBuf)])

			n, err = c.Conn.Write(wb)
			if err != nil {
				return 0, err
			}

			if n != len(wb) {
				return 0, io.ErrShortWrite
			}

			c.write.macPayload(wb)

			buf = buf[len(c.writeBuf):]
		}
	}

	cmac := c.write.macFinish()

	// fmt.Printf("header: %#v\nbody: %#v", header, wb)
	// fmt.Printf("cmac: %#v\n", cmac)

	n, err = c.Conn.Write(cmac)
	if err != nil {
		return 0, err
	}

	if n != len(cmac) {
		return 0, io.ErrShortWrite
	}

	c.write.incSeq()

	return total, nil
}

// Read a message as a []byte
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

// Write msg to the other side
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
