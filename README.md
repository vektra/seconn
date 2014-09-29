Se(cure) Conn(ection)
=====================

seconn is a simple golang library that provides an encrypted connection over
a net.Conn.

It uses curve25519 to establish a shared key between the 2 parties and then
uses AES encryption to pass the data back and forth.

How do a do any kind of authentication to prevent a MITM attack?
================================================================

Check out the `auth` package. It uses the GetMessage/SendMessage API
to perform a signed token exchange and verifies that the server side
is using the agreed upon key.
