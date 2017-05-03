/* shas.h */

#ifndef CRYPTO_SHA2_H_FILE
#define CRYPTO_SHA2_H_FILE

#include <stdint.h>

#include "common/buffer.h"
#include "crypto/algorithms.h"

int crypto_sha2_single(enum SSH_HASH_TYPE type, void *out, uint32_t *out_len, const void *data, uint32_t data_len);
int crypto_sha2_get_block_size(enum SSH_HASH_TYPE type);

struct CRYPTO_HASH_CTX *crypto_sha2_new(enum SSH_HASH_TYPE type);
void crypto_sha2_free(struct CRYPTO_HASH_CTX *crypto_ctx);
int crypto_sha2_copy_ctx(struct CRYPTO_HASH_CTX *crypto_to_ctx, const struct CRYPTO_HASH_CTX *crypto_from_ctx);
int crypto_sha2_update(struct CRYPTO_HASH_CTX *crypto_ctx, const void *data, uint32_t len);
int crypto_sha2_final(struct CRYPTO_HASH_CTX *crypto_ctx, void *out, uint32_t *out_len);

#endif /* CRYPTO_SHA2_H_FILE */
