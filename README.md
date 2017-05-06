# eessh

A toy SSH client written in C.

All the code is written from scratch, except the crypto algorithms (DH, RSA, AES, SHA1 and SHA2), which we take from OpenSSL's libcrypto.

I'm writing this project mostly to learn about cryptography and the SSH protocol, but the goal is to build a functional SSH client capable of running a remote login session.


### Current Status

Done:

- Transport (sending and receiving packets)
- Key exchange (but not key re-exchange, although that shouldn't be hard)
- Algorithms supported:
  - Key exchange: `diffie-hellman-group1-sha1`, `diffie-hellman-group14-sha1`
  - Server host key: `ssh-rsa`, `rsa-sha2-256`, `rsa-sha2-512`
  - Ciphers: `aes128-cbc`, `aes128-ctr`
  - MAC: `hmac-sha2-256`, `hmac-sha2-512`

  These algorithms seem to be enough to connect to most OpenSSH servers
  in the wild. Note that some algorithms listed as REQUIRED by the RFC
  are not supported (namely, `ssh-dss`, `3des-cbc` and `hmac-sha1`). A
  lot of servers I've seen don't support some of those either (and no one
  seems to support `3des-cbc` anymore).


Planned:

- User authentication: at least `password` since it's so easy, but `publickey`
  would be nice (and the RFC requires it).

- Channels:
  - basic framework for channels: multiple channels, handle window sizes, etc.
  - "`session`" channel for interactive ssh
