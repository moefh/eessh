/* aes.h */

#ifndef CRYPTO_AES_H_FILE
#define CRYPTO_AES_H_FILE

#include <stdint.h>
#include <stddef.h>

#include "common/buffer.h"
#include "crypto/algorithms.h"

struct CRYPTO_CIPHER_CTX *crypto_aes_new(enum SSH_CIPHER_TYPE type, enum SSH_CIPHER_DIRECTION dir, const struct SSH_STRING *iv, const struct SSH_STRING *key);
void crypto_aes_free(struct CRYPTO_CIPHER_CTX *ctx);
int crypto_aes_crypt(struct CRYPTO_CIPHER_CTX *ctx, uint8_t *out, uint8_t *data, uint32_t len);

#endif /* CRYPTO_AES_H_FILE */
