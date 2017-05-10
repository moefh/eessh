# eessh

A toy SSH client written in C.

All code is written from scratch, except the crypto algorithms
(Diffie-Hellman, RSA, AES, SHA-1 and SHA-2), which we take from
OpenSSL's libcrypto (not included, we just link to it).

I'm writing this project mostly to learn about cryptography and the
SSH protocol, but the goal is to build a functional SSH client capable
of running a remote login session.


### Current Status

Opening a remote shell works, but with password authentication only.
Terminal size is fixed at 80x25, and terminal support is minimal (we
don't send any "encoded terminal modes" in the `pty-req` request), but
it *seems* to work fine -- it seems good enough to run emacs remotely.

Details of what works, listed in order of completion:

- Transport (sending and receiving packets)

- Key exchange (but not key re-exchange, although that shouldn't be hard)

- Algorithms:

  - Key exchange: `diffie-hellman-group1-sha1`, `diffie-hellman-group14-sha1`
  - Server host key: `ssh-rsa`, `rsa-sha2-256`, `rsa-sha2-512`
  - Ciphers: `aes128-cbc`, `aes128-ctr`
  - MAC: `hmac-sha2-256`, `hmac-sha2-512`

  These algorithms seem to be enough to connect to most OpenSSH servers
  in the wild. Note the absence of some algorithms listed as REQUIRED
  by the RFC (namely, `ssh-dss`, `3des-cbc` and `hmac-sha1`). A lot of
  servers I've seen don't support some of those either (in particular, no
  one seems to care about `3des-cbc` anymore).

- Pluggable server identity verification (including a "demo" that works
  like OpenSSH's `known_hosts`).

- Password user authentication

- Multiple channel support

- Interactive session channel with terminal

What's missing:

- Key re-exchange

- Public key user authentication

- Better terminal support
