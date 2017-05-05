## Key Exchange
As defined in [RFC 4253](https://tools.ietf.org/html/rfc4253#section-7),
from the perspective of the client.

### Preparation

#### [implemented in `ssh/kex.c`]

Client and server exchange packets of type `SSH_MSG_KEXINIT` to
negotiate the algorithms that will be used for key exchange and
future data transmission:

| Algorithm                    | Usage                                        | Implemented here                 |
|------------------------------|----------------------------------------------|----------------------------------|
| `kex_algorithm`              | used in the key exchange itself              | `diffie-hellman-group1-sha1`, `diffie-hellman-group14-sha1` |
| `server_host_key_algorithm`  | used to verify the server key                | `ssh-rsa`                        |
| `encryption_algorithm`       | cipher used to encrypt transmitted data      | `aes128-cbc`, `aes128-ctr`       |
| `mac_algorithm`              | MAC used to check the integrity of the data  | `hmac-sha2-256`, `hmac-sha2-512` |
| `compression_algorithm`      | used to compress data (before encryption)    | `none`                           |

Encryption, MAC and compression can be different for each direction (i.e.,
client->server can use a different algorithm than server->client).

The algorithm selected for `kex_algorithm` is then executed as follows.

### Running the key exchange

#### [implemented in `ssh/kex_dh.c`]

1. The client sends `e` (its public key)

2. The server sends `K_S` (its identification), `f` (its public key) and the
signature of `H`, a hash computed using the hash algorithm specified by
`kex_algorithm` (`sha1` in the case of `diffie-hellman-group1-sha1` and
`diffie-hellman-group14-sha1`) over:

        values previously transmitted between the client and server
        "K_S"
        "e"
        "f"
        "shared_key", derived from "e" and "f"

   The signature of `H` is computed using `server_host_key_algorithm`.

3. The client derives "`shared_key`" from "`e`" and "`f`", computes `H`
and checks it's is a valid signature for `K_S`, and also if `K_S` matches
the identity of the server it meant to connect (if it has the server
identity stored).

Both parties now have `H` and `shared_secret`. This concludes the
`kex_algorithm`-specific part of the key exchange.

### Finalizing the key exchange

#### [implemented in `ssh/kex.c`]

Back in the generic key exchange, the client uses `H` and `shared_secret`
to generate the cipher `IV` and `key` for `encryption_algorithm` and `key`
for `mac_algorithm`.

It then sends `SSH_MSG_NEWKEYS` and receives `SSH_MSG_NEWKEYS` messages,
indicating that the computed keys are to be be put to use.
(NOTE: exchanging `SSH_MSG_NEWKEYS` is currently done, for no good reason,
in `ssh/kex_dh.c`; this should be moved to `ssh/kex.c`).
