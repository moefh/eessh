/* hash.h */

#ifndef HASH_H_FILE
#define HASH_H_FILE

#include <stdint.h>

#include "common/buffer.h"
#include "crypto/algorithms.h"

#define SSH_HASH_MAX_LEN 64

enum SSH_HASH_TYPE ssh_hash_get_by_name(const char *name);
int ssh_hash_get_len(enum SSH_HASH_TYPE type);
int ssh_hash_get_block_size(enum SSH_HASH_TYPE type);
int ssh_hash_compute(enum SSH_HASH_TYPE type, struct SSH_STRING *digest, const struct SSH_STRING *data);

#endif /* HASH_H_FILE */
