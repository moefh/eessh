/* algorithms.h */

#ifndef CRYPTO_ALGORITHMS_H_FILE
#define CRYPTO_ALGORITHMS_H_FILE

enum SSH_PUBKEY_TYPE {
  SSH_PUBKEY_RSA,

  SSH_PUBKEY_INVALID
};

enum SSH_HASH_TYPE {
  SSH_HASH_SHA1,
  SSH_HASH_SHA2_256,
  SSH_HASH_SHA2_512,

  SSH_HASH_INVALID
};

enum SSH_CIPHER_TYPE {
  SSH_CIPHER_NONE,
  SSH_CIPHER_AES128_CTR,
  SSH_CIPHER_AES128_CBC,

  SSH_CIPHER_INVALID
};

enum SSH_CIPHER_DIRECTION {
  SSH_CIPHER_ENCRYPT,
  SSH_CIPHER_DECRYPT
};

struct CRYPTO_CIPHER_CTX;
struct CRYPTO_HASH_CTX;

#endif /* CRYPTO_ALGORITHMS_H_FILE */
