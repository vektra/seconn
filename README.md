Se(cure) Conn(ection)
=====================

seconn is a simple golang library that provides an encrypted connection over
a net.Conn.

It uses curve25519 to establish a shared key between the 2 parties and then
uses AES encryption to pass the data back and forth.

Why doesn't it do auth?
=======================

I believe that authentication is a layer that should happen on top of encryption,
not intertwinned with it. Thusly seconn provides a simple GetMessage/SendMessage
api to easily implement any authentication scheme desired.
