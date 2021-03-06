package seconn

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/vektra/errors"

	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"

	"code.google.com/p/go.crypto/curve25519"
	"code.google.com/p/go.crypto/hkdf"
)

// The size of the internal encrypted write buffer
var WriteBufferSize = 128

// How many bytes to write over the connection before we rekey
// This is bidirectional, so it will trip whenever either side
// has sent this ammount.
var RekeyAfterBytes = 100 * 1024 * 1024

var KeyValidityPeriod = 1 * time.Hour

var ErrBadRekey = errors.New("error in rekey processing")

var ErrProtocolError = errors.New("protocol error")

const cKeySize = 32

const (
	pData            uint32 = 0
	pStartRekey      uint32 = 1
	pClientKeyUpdate uint32 = 2
	pFinalizeRekey   uint32 = 3
)

type Conn struct {
	net.Conn
	privKey *[32]byte
	pubKey  *[32]byte
	peerKey *[32]byte
	shared  *[32]byte

	server   bool
	writeBuf []byte
	readBuf  bytes.Buffer

	rekeyAfter time.Time
	rekeyLeft  int

	writeLock sync.Mutex

	read  *half
	write *half

	nextPubKey  *[32]byte
	nextPrivKey *[32]byte
	nextPeerKey *[32]byte
	nextShared  *[32]byte
	nextKeys    [][]byte
	nextIv      []byte

	headerBuf []byte
}

type half struct {
	aead cipher.AEAD
	seq  []byte
}

func (h *half) setup(key, iv []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	h.aead = aead
	h.seq = make([]byte, aead.NonceSize())

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

func makeKeys(shared, salt, info []byte) [][]byte {
	hkdf := hkdf.New(sha512.New, shared, salt, info)

	k1 := make([]byte, aes.BlockSize)
	k2 := make([]byte, aes.BlockSize)

	if n, err := io.ReadFull(hkdf, k1); n != aes.BlockSize || err != nil {
		panic("unable to derive key")
	}

	if n, err := io.ReadFull(hkdf, k2); n != aes.BlockSize || err != nil {
		panic("unable to derive key")
	}

	return [][]byte{k1, k2}
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

	newKeys := makeKeys(sharedKey, iv, nil)

	if c.server {
		c.read.setup(newKeys[1], iv)
		c.write.setup(newKeys[0], iv)
	} else {
		c.read.setup(newKeys[0], iv)
		c.write.setup(newKeys[1], iv)
	}

	c.headerBuf = make([]byte, 4+c.write.aead.Overhead())

	c.rekeyAfter = time.Now().Add(KeyValidityPeriod)

	return nil
}

// A token that can be compared with the other sides PeerAuthToken
// to validate that both sides are talking to who they think they're talking
// too.
//
// The token needs to be authenticated across the connection because
// seconn doesn't detect a rogue man-in-the-middle. This token is in fact
// used to detect a man-in-the-middle.

func (c *Conn) AuthToken() []byte {
	mac := hmac.New(sha256.New, (*c.shared)[:])
	mac.Write((*c.pubKey)[:])
	return mac.Sum(nil)
}

// See AuthToken(). This is the AuthToken for the other side of the connection.

func (c *Conn) PeerAuthToken() []byte {
	mac := hmac.New(sha256.New, (*c.shared)[:])
	mac.Write((*c.peerKey)[:])
	return mac.Sum(nil)
}

func (c *Conn) readAndCheck(cnt uint32) ([]byte, error) {
	wireCnt := int(cnt) + c.read.aead.Overhead()

	buf := make([]byte, wireCnt)

	n, err := io.ReadFull(c.Conn, buf)
	if err != nil {
		return nil, err
	}

	if n != int(wireCnt) {
		return nil, io.ErrShortBuffer
	}

	pt, err := c.read.aead.Open(buf[:0], c.read.seq, buf, nil)
	c.read.incSeq()

	return pt, err
}

func (c *Conn) readRekey(cnt uint32) error {
	buf, err := c.readAndCheck(cnt)
	if err != nil {
		return err
	}

	if len(buf) != cKeySize+aes.BlockSize {
		return ErrBadRekey
	}

	c.nextPeerKey = new([32]byte)
	copy((*c.nextPeerKey)[:], buf[:cKeySize])

	c.nextIv = buf[cKeySize:]

	return c.sendClientRekey()
}

func (c *Conn) readServerRekeyed(cnt uint32) error {
	buf, err := c.readAndCheck(cnt)
	if err != nil {
		return err
	}

	if len(buf) != cKeySize {
		return ErrBadRekey
	}

	c.nextPeerKey = new([32]byte)
	copy((*c.nextPeerKey)[:], buf[:cKeySize])

	c.nextShared = new([32]byte)

	curve25519.ScalarMult(c.nextShared, c.nextPrivKey, c.nextPeerKey)

	sharedKey := (*c.nextShared)[:]

	c.nextKeys = makeKeys(sharedKey, c.nextIv, nil)

	c.read.setup(c.nextKeys[1], c.nextIv)

	return c.sendServerRekeyed()
}

func (c *Conn) readClientRekeyFinal(size uint32) error {
	buf, err := c.readAndCheck(size)
	if err != nil {
		return err
	}

	if len(buf) != 0 {
		return ErrBadRekey
	}

	c.read.setup(c.nextKeys[0], c.nextIv)

	c.shared = c.nextShared
	c.privKey = c.nextPrivKey
	c.peerKey = c.nextPeerKey
	c.pubKey = c.nextPubKey

	c.nextShared = nil
	c.nextPrivKey = nil
	c.nextPeerKey = nil
	c.nextPeerKey = nil
	c.nextIv = nil
	c.nextKeys = nil

	return nil
}

var ErrBadHeader = errors.New("bad header")

// Read data into buf, automatically decrypting it
func (c *Conn) Read(buf []byte) (int, error) {
	n, err := c.readBuf.Read(buf)
	if n > 0 {
		return n, err
	}

retry:
	n, err = io.ReadFull(c.Conn, c.headerBuf)
	if err != nil {
		return 0, err
	}

	if n != len(c.headerBuf) {
		return 0, io.ErrShortBuffer
	}

	header, err := c.read.aead.Open(c.headerBuf[:0], c.read.seq, c.headerBuf, nil)
	if err != nil {
		return 0, errors.Cause(ErrBadHeader, err)
	}

	c.read.incSeq()

	cnt := binary.BigEndian.Uint32(header)

	cmd := cnt & 0xff

	cnt = cnt >> 8

	switch cmd {
	case pData:
		// it's normal data, handled below
	case pStartRekey:
		err = c.readRekey(cnt)
		if err != nil {
			return 0, err
		}
		goto retry
	case pClientKeyUpdate:
		err = c.readServerRekeyed(cnt)
		if err != nil {
			return 0, err
		}
		goto retry
	case pFinalizeRekey:
		err = c.readClientRekeyFinal(cnt)
		if err != nil {
			return 0, err
		}
		goto retry
	default:
		return 0, ErrProtocolError
	}

	wireCnt := cnt + uint32(c.write.aead.Overhead())

	io.CopyN(&c.readBuf, c.Conn, int64(wireCnt))

	pt, err := c.read.aead.Open(
		c.readBuf.Bytes()[:0],
		c.read.seq,
		c.readBuf.Bytes(),
		nil,
	)

	if err != nil {
		return 0, err
	}

	c.read.incSeq()

	// Because we rewrite the buffer to contain the plaintext, we need to truncate
	// it to that size since otherwise it will still contain some of the ciphertext
	c.readBuf.Truncate(len(pt))

	var toExtract int

	if len(buf) < int(cnt) {
		toExtract = len(buf)
	} else {
		toExtract = int(cnt)
	}

	read, err := c.readBuf.Read(buf[:toExtract])

	if err != nil {
		return 0, err
	}

	return read, nil
}

func (c *Conn) sendBuffer(cmd uint32, buf *bytes.Buffer) error {
	var headerData [4]byte

	header := headerData[:]

	headerInt := cmd | uint32(buf.Len()<<8)

	binary.BigEndian.PutUint32(header, headerInt)

	c.writeLock.Lock()
	defer c.writeLock.Unlock()

	ct := c.write.aead.Seal(c.writeBuf[:0], c.write.seq, header, nil)
	c.write.incSeq()

	n, err := c.Conn.Write(ct)
	if err != nil {
		return err
	}

	if n != len(ct) {
		return io.ErrShortWrite
	}

	buf.Grow(c.write.aead.Overhead())

	ct = c.write.aead.Seal(buf.Bytes()[:0], c.write.seq, buf.Bytes(), nil)
	c.write.incSeq()

	n, err = c.Conn.Write(ct)
	if err != nil {
		return err
	}

	if n != len(ct) {
		return io.ErrShortWrite
	}

	return nil
}

func (c *Conn) startRekey() error {
	c.rekeyLeft = RekeyAfterBytes
	c.rekeyAfter = time.Now().Add(KeyValidityPeriod)

	pub, priv, err := GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	c.nextPubKey = pub
	c.nextPrivKey = priv

	iv := make([]byte, aes.BlockSize)
	n, err := io.ReadFull(rand.Reader, iv)
	if err != nil {
		return err
	}

	if n != aes.BlockSize {
		return io.ErrShortBuffer
	}

	c.nextIv = iv

	var buf bytes.Buffer
	buf.Write((*pub)[:])
	buf.Write(iv)

	err = c.sendBuffer(pStartRekey, &buf)
	if err != nil {
		return err
	}

	return nil
}

func (c *Conn) sendClientRekey() error {
	pub, priv, err := GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	c.nextPubKey = pub
	c.nextPrivKey = priv

	var buf bytes.Buffer
	buf.Write((*pub)[:])

	err = c.sendBuffer(pClientKeyUpdate, &buf)
	if err != nil {
		return err
	}

	c.nextShared = new([32]byte)

	curve25519.ScalarMult(c.nextShared, c.nextPrivKey, c.nextPeerKey)

	sharedKey := (*c.nextShared)[:]

	c.nextKeys = makeKeys(sharedKey, c.nextIv, nil)

	c.write.setup(c.nextKeys[1], c.nextIv)

	return nil
}

func (c *Conn) sendServerRekeyed() error {
	var buf bytes.Buffer

	err := c.sendBuffer(pFinalizeRekey, &buf)
	if err != nil {
		return err
	}

	c.write.setup(c.nextKeys[0], c.nextIv)

	c.shared = c.nextShared
	c.privKey = c.nextPrivKey
	c.peerKey = c.nextPeerKey
	c.pubKey = c.nextPubKey

	c.nextShared = nil
	c.nextPrivKey = nil
	c.nextPeerKey = nil
	c.nextPeerKey = nil
	c.nextIv = nil
	c.nextKeys = nil

	return nil
}

// Write data, automatically encrypting it
func (c *Conn) Write(buf []byte) (int, error) {
	var headerData [4]byte

	header := headerData[:]

	var err error

	if c.server && c.nextPeerKey == nil {
		if c.rekeyLeft <= 0 || time.Now().After(c.rekeyAfter) {
			err = c.startRekey()
		} else {
			c.rekeyLeft -= len(buf)
		}
	}

	if err != nil {
		return 0, err
	}

	total := len(buf)

	c.writeLock.Lock()
	defer c.writeLock.Unlock()

	for len(buf) > 0 {
		var chunk []byte

		if len(c.writeBuf) >= len(buf) {
			chunk = buf
			buf = nil
		} else {
			chunk = buf[:len(c.writeBuf)]
			buf = buf[len(c.writeBuf):]
		}

		headerInt := uint32(len(chunk)) << 8

		binary.BigEndian.PutUint32(header, headerInt)

		ct := c.write.aead.Seal(c.writeBuf[:0], c.write.seq, header, nil)

		c.write.incSeq()

		n, err := c.Conn.Write(ct)
		if err != nil {
			return 0, err
		}

		if n != len(ct) {
			return 0, io.ErrShortWrite
		}

		ct = c.write.aead.Seal(c.writeBuf[:0], c.write.seq, chunk, nil)

		c.write.incSeq()

		n, err = c.Conn.Write(ct)
		if err != nil {
			return 0, err
		}

		if n != len(ct) {
			return 0, io.ErrShortWrite
		}
	}

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
