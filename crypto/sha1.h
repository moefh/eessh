/* sha1.h */

#ifndef CRYPTO_SHA1_H_FILE
#define CRYPTO_SHA1_H_FILE

#include <stdint.h>

#include "common/buffer.h"
#include "crypto/algorithms.h"

int crypto_sha1_single(enum SSH_HASH_TYPE type, void *out, uint32_t *out_len, const void *data, uint32_t data_len);
int crypto_sha1_get_block_size(enum SSH_HASH_TYPE type);

#endif /* CRYPTO_SHA1_H_FILE */
