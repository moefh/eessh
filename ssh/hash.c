/* hash.c */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "ssh/hash.h"

#include "common/error.h"

#include "crypto/sha1.h"
#include "crypto/sha2.h"

static const struct SSH_HASH_ALGO {
  const char *name;
  enum SSH_HASH_TYPE type;
  int len;
} hash_algos[] = {
  { "sha1",     SSH_HASH_SHA1,     20 },
  { "sha2-256", SSH_HASH_SHA2_256, 32 },
  { "sha2-512", SSH_HASH_SHA2_512, 64 },
};
  
enum SSH_HASH_TYPE ssh_hash_get_by_name(const char *name)
{
  int i;

  for (i = 0; i < sizeof(hash_algos)/sizeof(hash_algos[0]); i++) {
    if (strcmp(hash_algos[i].name, name) == 0)
      return hash_algos[i].type;
  }
  return SSH_HASH_INVALID;
}

static const struct SSH_HASH_ALGO *get_algo(enum SSH_HASH_TYPE type)
{
  int i;
  
  for (i = 0; i < sizeof(hash_algos)/sizeof(hash_algos[0]); i++) {
    if (hash_algos[i].type == type)
      return &hash_algos[i];
  }
  return NULL;
}

int ssh_hash_get_len(enum SSH_HASH_TYPE type)
{
  const struct SSH_HASH_ALGO *algo = get_algo(type);
  if (algo == NULL)
    return -1;
  return algo->len;
}

int ssh_hash_get_block_size(enum SSH_HASH_TYPE type)
{
  switch (type) {
  case SSH_HASH_SHA1:
    return crypto_sha1_get_block_size(type);

  case SSH_HASH_SHA2_256:
  case SSH_HASH_SHA2_512:
    return crypto_sha2_get_block_size(type);

  default:
    ssh_set_error("invalid hash type: %d", type);
    return -1;
  }
}

int ssh_hash_compute(enum SSH_HASH_TYPE type, struct SSH_STRING *out, const struct SSH_STRING *data)
{
  uint32_t out_len;
  
  switch (type) {
  case SSH_HASH_SHA1:
    if (crypto_sha1_single(type, out->str, &out_len, data->str, data->len) < 0)
      return -1;
    out->len = out_len;
    return 0;

  case SSH_HASH_SHA2_256:
  case SSH_HASH_SHA2_512:
    if (crypto_sha2_single(type, out->str, &out_len, data->str, data->len) < 0)
      return -1;
    out->len = out_len;
    return 0;
    
  default:
    ssh_set_error("invalid hash type: %d", type);
    return -1;
  }
}
