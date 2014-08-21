package seconn

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"net"
	"sync"
	"time"

	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"

	"code.google.com/p/go.crypto/curve25519"
	"code.google.com/p/go.crypto/pbkdf2"
)

// The size of the internal encrypted write buffer
var WriteBufferSize = 128

// How many bytes to write over the connection before we rekey
// This is bidirectional, so it will trip whenever either side
// has sent this ammount.
var RekeyAfterBytes = 100 * 1024 * 1024

var KeyValidityPeriod = 1 * time.Hour

var ErrBadMac = errors.New("bad mac detected")

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
	nextKeys    []byte
	nextIv      []byte
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

	newKeys := pbkdf2.Key(sharedKey, iv, 4096, aes.BlockSize*2, sha512.New)

	if c.server {
		c.read.setup(newKeys[:aes.BlockSize], iv)
		c.write.setup(newKeys[aes.BlockSize:], iv)
	} else {
		c.read.setup(newKeys[aes.BlockSize:], iv)
		c.write.setup(newKeys[:aes.BlockSize], iv)
	}

	c.rekeyAfter = time.Now().Add(KeyValidityPeriod)

	return nil
}

func (c *Conn) readAndCheck(cnt uint32) ([]byte, error) {
	buf := make([]byte, cnt)

	n, err := io.ReadFull(c.Conn, buf)
	if err != nil {
		return nil, err
	}

	if n != int(cnt) {
		return nil, io.ErrShortBuffer
	}

	c.read.macPayload(buf)

	n, err = io.ReadFull(c.Conn, c.read.dbuf)
	if err != nil {
		return nil, err
	}

	if n != len(c.read.dbuf) {
		return nil, io.ErrShortBuffer
	}

	localMac := c.read.macFinish()

	if subtle.ConstantTimeCompare(localMac, c.read.dbuf) != 1 {
		return nil, ErrBadMac
	}

	c.read.stream.XORKeyStream(buf, buf)

	c.read.incSeq()

	return buf, nil
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

	c.nextKeys = pbkdf2.Key(sharedKey, c.nextIv, 4096, aes.BlockSize*2, sha512.New)

	c.read.setup(c.nextKeys[:aes.BlockSize], c.nextIv)

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

	c.read.setup(c.nextKeys[aes.BlockSize:], c.nextIv)

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

	localMac := c.read.macFinish()

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

	var headerData [4]byte

	header := headerData[:]

	headerInt := pStartRekey | uint32(buf.Len()<<8)

	binary.BigEndian.PutUint32(header, headerInt)

	c.writeLock.Lock()
	defer c.writeLock.Unlock()

	c.write.stream.XORKeyStream(header, header)

	c.write.macStart(header)

	n, err = c.Conn.Write(header)
	if err != nil {
		return err
	}

	if n != len(header) {
		return io.ErrShortWrite
	}

	c.write.stream.XORKeyStream(buf.Bytes(), buf.Bytes())

	c.write.macPayload(buf.Bytes())

	n, err = c.Conn.Write(buf.Bytes())
	if err != nil {
		return err
	}

	if n != buf.Len() {
		return io.ErrShortWrite
	}

	cmac := c.write.macFinish()

	n, err = c.Conn.Write(cmac)
	if err != nil {
		return err
	}

	if n != len(cmac) {
		return io.ErrShortWrite
	}

	c.write.incSeq()

	c.rekeyLeft = RekeyAfterBytes

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

	var headerData [4]byte

	header := headerData[:]

	headerInt := pClientKeyUpdate | uint32(buf.Len()<<8)

	binary.BigEndian.PutUint32(header, headerInt)

	c.writeLock.Lock()
	defer c.writeLock.Unlock()

	c.write.stream.XORKeyStream(header, header)

	n, err := c.Conn.Write(header)
	if err != nil {
		return err
	}

	if n != len(header) {
		return io.ErrShortWrite
	}

	c.write.macStart(header)

	c.write.stream.XORKeyStream(buf.Bytes(), buf.Bytes())

	c.write.macPayload(buf.Bytes())

	n, err = c.Conn.Write(buf.Bytes())
	if err != nil {
		return err
	}

	if n != buf.Len() {
		return io.ErrShortWrite
	}

	cmac := c.write.macFinish()

	n, err = c.Conn.Write(cmac)
	if err != nil {
		return err
	}

	if n != len(cmac) {
		return io.ErrShortWrite
	}

	c.write.incSeq()

	c.nextShared = new([32]byte)

	curve25519.ScalarMult(c.nextShared, c.nextPrivKey, c.nextPeerKey)

	sharedKey := (*c.nextShared)[:]

	c.nextKeys = pbkdf2.Key(sharedKey, c.nextIv, 4096, aes.BlockSize*2, sha512.New)
	c.write.setup(c.nextKeys[:aes.BlockSize], c.nextIv)

	return nil
}

func (c *Conn) sendServerRekeyed() error {
	var headerData [4]byte

	header := headerData[:]

	headerInt := pFinalizeRekey

	binary.BigEndian.PutUint32(header, headerInt)

	c.writeLock.Lock()
	defer c.writeLock.Unlock()

	c.write.stream.XORKeyStream(header, header)

	c.write.macStart(header)

	n, err := c.Conn.Write(header)
	if err != nil {
		return err
	}

	if n != len(header) {
		return io.ErrShortWrite
	}

	cmac := c.write.macFinish()

	n, err = c.Conn.Write(cmac)
	if err != nil {
		return err
	}

	if n != len(cmac) {
		return io.ErrShortWrite
	}

	c.write.incSeq()

	c.write.setup(c.nextKeys[aes.BlockSize:], c.nextIv)

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

	headerInt := uint32(len(buf)) << 8

	binary.BigEndian.PutUint32(header, headerInt)

	c.writeLock.Lock()
	defer c.writeLock.Unlock()

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
