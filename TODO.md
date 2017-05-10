
### Shell

- support terminal window size change (SIGWINCH)

- transmit local signals

- inform the client of remote program/shell exit code


### Crypto

- Support key re-exchange.

- Fix comparisons with `memcmp` to prevent timing attacks.


### RFC compliance

- (maybe) support old algorithms still marked as REQUIRED by RFC 4253:
  - MAC:  `hmac-sha1` 
  - cipher: `3des-cbc`
  - public key verification: `ssh-dss`
