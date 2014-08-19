package seconn

import (
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/hashicorp/yamux"
	"github.com/stretchr/testify/assert"
)

func TestSeconnBasic(t *testing.T) {
	l, err := net.Listen("tcp", ":0")
	defer l.Close()

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()

		o, err := l.Accept()
		defer o.Close()

		wo, err := NewServer(o)
		assert.NoError(t, err)

		n, err := wo.Write([]byte("hello"))
		assert.NoError(t, err)
		assert.Equal(t, 5, n)
	}()

	c, err := net.Dial("tcp", l.Addr().String())
	defer c.Close()

	wc, err := NewClient(c)
	assert.NoError(t, err)

	buf := make([]byte, 10)

	n, err := wc.Read(buf)
	assert.Equal(t, 5, n)
	assert.NoError(t, err)
	assert.Equal(t, []byte("hello"), buf[:n])

	wg.Wait()
}

func TestSeconnEncrypts(t *testing.T) {
	l, err := net.Listen("tcp", ":0")
	defer l.Close()

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()

		o, err := l.Accept()
		defer o.Close()

		wo, err := NewConn(o)
		assert.NoError(t, err)

		err = wo.Negotiate(true)
		assert.NoError(t, err)

		n, err := wo.Write([]byte("hello"))
		assert.NoError(t, err)
		assert.Equal(t, 5, n)
	}()

	c, err := net.Dial("tcp", l.Addr().String())
	defer c.Close()

	wc, err := NewConn(c)
	assert.NoError(t, err)

	err = wc.Negotiate(false)
	assert.NoError(t, err)

	buf := make([]byte, 10)

	n, err := wc.Conn.Read(buf)
	assert.NoError(t, err)
	assert.NotEqual(t, []byte("hello"), buf[:n])

	wg.Wait()
}

func TestSeconnWriteBuffersProperly(t *testing.T) {
	l, err := net.Listen("tcp", ":0")
	defer l.Close()

	data := make([]byte, WriteBufferSize+(WriteBufferSize/2))

	n, err := io.ReadFull(rand.Reader, data)
	assert.NoError(t, err)

	if n != len(data) {
		panic("couldn't get enough data")
	}

	var wg sync.WaitGroup

	wg.Add(1)

	go func() {
		defer wg.Done()

		o, err := l.Accept()
		defer o.Close()

		wo, err := NewConn(o)
		assert.NoError(t, err)

		err = wo.Negotiate(true)
		assert.NoError(t, err)

		n, err := wo.Write(data)
		assert.NoError(t, err)
		assert.Equal(t, len(data), n)
	}()

	c, err := net.Dial("tcp", l.Addr().String())
	defer c.Close()

	wc, err := NewConn(c)
	assert.NoError(t, err)

	err = wc.Negotiate(false)
	assert.NoError(t, err)

	buf := make([]byte, len(data))

	n, err = wc.Conn.Read(buf)
	assert.NoError(t, err)
	assert.NotEqual(t, data, buf[:n])

	wg.Wait()
}

func TestSeconnCanSendMessage(t *testing.T) {
	l, err := net.Listen("tcp", ":0")
	defer l.Close()

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()

		o, err := l.Accept()
		defer o.Close()

		wo, err := NewServer(o)
		assert.NoError(t, err)

		auth, err := wo.GetMessage()
		assert.NoError(t, err)
		assert.Equal(t, []byte("vektra:rocks"), auth)

		n, err := wo.Write([]byte("hello"))
		assert.NoError(t, err)
		assert.Equal(t, 5, n)
	}()

	c, err := net.Dial("tcp", l.Addr().String())
	defer c.Close()

	wc, err := NewClient(c)
	assert.NoError(t, err)

	err = wc.SendMessage([]byte("vektra:rocks"))
	assert.NoError(t, err)

	buf := make([]byte, 10)

	n, err := wc.Read(buf)
	assert.Equal(t, 5, n)
	assert.NoError(t, err)
	assert.Equal(t, []byte("hello"), buf[:n])

	wg.Wait()
}

func TestSeconnReKey(t *testing.T) {
	l, err := net.Listen("tcp", ":0")
	defer l.Close()

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()

		o, err := l.Accept()
		defer o.Close()

		wo, err := NewServer(o)
		assert.NoError(t, err)

		n, err := wo.Write([]byte("hello"))
		assert.NoError(t, err)
		assert.Equal(t, 5, n)

		wo.RekeyNext()

		n, err = wo.Write([]byte("hello"))
		assert.NoError(t, err)
		assert.Equal(t, 5, n)
	}()

	c, err := net.Dial("tcp", l.Addr().String())
	defer c.Close()

	wc, err := NewClient(c)
	assert.NoError(t, err)

	buf := make([]byte, 5)

	firstKey := make([]byte, 32)

	copy(firstKey, (*wc.shared)[:])

	n, err := wc.Read(buf)
	assert.Equal(t, 5, n)
	assert.NoError(t, err)
	assert.Equal(t, []byte("hello"), buf[:n])

	n, err = wc.Read(buf)
	assert.Equal(t, 5, n)
	assert.NoError(t, err)
	assert.Equal(t, []byte("hello"), buf[:n])

	secondKey := (*wc.shared)[:]

	assert.NotEqual(t, firstKey, secondKey)

	wg.Wait()
}

func TestSeconnReadBuffersProperly(t *testing.T) {
	l, err := net.Listen("tcp", ":0")
	defer l.Close()

	data := make([]byte, WriteBufferSize+(WriteBufferSize/2))

	n, err := io.ReadFull(rand.Reader, data)
	assert.NoError(t, err)

	if n != len(data) {
		panic("couldn't get enough data")
	}

	var wg sync.WaitGroup

	wg.Add(1)

	go func() {
		defer wg.Done()

		o, err := l.Accept()
		defer o.Close()

		wo, err := NewConn(o)
		assert.NoError(t, err)

		err = wo.Negotiate(true)
		assert.NoError(t, err)

		n, err := wo.Write(data)
		assert.NoError(t, err)
		assert.Equal(t, len(data), n)
	}()

	c, err := net.Dial("tcp", l.Addr().String())
	defer c.Close()

	wc, err := NewConn(c)
	assert.NoError(t, err)

	err = wc.Negotiate(false)
	assert.NoError(t, err)

	buf := make([]byte, 16)

	n, err = wc.Read(buf)
	assert.NoError(t, err)
	assert.Equal(t, data[:n], buf[:n])

	assert.Equal(t, len(data)-16, len(wc.readBuf.Bytes()))

	buf = make([]byte, len(data))

	n, err = wc.Read(buf)
	assert.NoError(t, err)
	assert.Equal(t, data[16:], buf[:n])
	assert.Equal(t, 0, wc.readBuf.Len())

	wg.Wait()
}

func TestSeconnYamux(t *testing.T) {
	l, err := net.Listen("tcp", ":0")
	defer l.Close()

	cfg := yamux.DefaultConfig()

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()

		o, err := l.Accept()

		wo, err := NewServer(o)
		assert.NoError(t, err)

		sess, err := yamux.Server(wo, cfg)
		assert.NoError(t, err)

		defer sess.Close()

		str, err := sess.Accept()
		assert.NoError(t, err)

		defer str.Close()

		n, err := str.Write([]byte("hello"))
		assert.NoError(t, err)
		assert.Equal(t, 5, n)
	}()

	c, err := net.Dial("tcp", l.Addr().String())
	defer c.Close()

	wc, err := NewClient(c)
	assert.NoError(t, err)

	sess, err := yamux.Client(wc, cfg)
	assert.NoError(t, err)

	str, err := sess.OpenStream()
	assert.NoError(t, err)

	buf := make([]byte, 10)

	n, err := str.Read(buf)
	assert.Equal(t, 5, n)
	assert.NoError(t, err)
	assert.Equal(t, []byte("hello"), buf[:n])

	wg.Wait()
}

func TestSeconnYamuxSimilar(t *testing.T) {
	l, err := net.Listen("tcp", ":0")
	defer l.Close()

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()

		o, err := l.Accept()

		wo, err := NewServer(o)
		assert.NoError(t, err)

		defer wo.Close()

		buf := make([]byte, 12)

		n, err := wo.Read(buf)

		assert.NoError(t, err)
		assert.Equal(t, 12, n)

		msg2 := []byte{0x0, 0x1, 0x0, 0x2, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0}

		n, err = wo.Write(msg2)
		assert.Equal(t, 12, n)
		assert.NoError(t, err)
	}()

	c, err := net.Dial("tcp", l.Addr().String())
	defer c.Close()

	wc, err := NewClient(c)
	assert.NoError(t, err)

	msg1 := []byte{0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0}

	n, err := wc.Write(msg1)
	assert.Equal(t, 12, n)
	assert.NoError(t, err)

	buf := make([]byte, 12)

	n, err = wc.Read(buf)

	assert.NoError(t, err)
	assert.Equal(t, 12, n)

	wg.Wait()
}
