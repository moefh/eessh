/* cipher.c */

#include <stdlib.h>
#include <string.h>

#include "ssh/cipher.h"

#include "common/error.h"
#include "common/alloc.h"
#include "crypto/algorithms.h"
#include "crypto/aes.h"

struct SSH_CIPHER_CTX {
  const struct CIPHER_ALGO *algo;
  struct CRYPTO_CIPHER_CTX *ctx;
};

typedef struct CRYPTO_CIPHER_CTX *(*func_new)(enum SSH_CIPHER_TYPE type, enum SSH_CIPHER_DIRECTION dir, const struct SSH_STRING *iv, const struct SSH_STRING *key);
typedef void (*func_free)(struct CRYPTO_CIPHER_CTX *ctx);
typedef int (*func_crypt)(struct CRYPTO_CIPHER_CTX *ctx, uint8_t *out, uint8_t *data, uint32_t len);

static const struct CIPHER_ALGO {
  const char *name;
  enum SSH_CIPHER_TYPE type;
  uint32_t block_len;
  uint32_t key_len;
  uint32_t iv_len;
  func_new new;
  func_free free;
  func_crypt crypt;
} cipher_algos[] = {
  { "aes128-cbc", SSH_CIPHER_AES128_CBC, 16, 16, 16, crypto_aes_new, crypto_aes_free, crypto_aes_crypt },
  { "aes128-ctr", SSH_CIPHER_AES128_CTR, 16, 16, 16, crypto_aes_new, crypto_aes_free, crypto_aes_crypt },
};

enum SSH_CIPHER_TYPE ssh_cipher_get_by_name(const char *name)
{
  return ssh_cipher_get_by_name_n((uint8_t *) name, strlen(name));
}

enum SSH_CIPHER_TYPE ssh_cipher_get_by_name_n(const uint8_t *name, size_t name_len)
{
  int i;

  for (i = 0; i < sizeof(cipher_algos)/sizeof(cipher_algos[0]); i++) {
    if (strncmp((char *) name, cipher_algos[i].name, name_len) == 0 && cipher_algos[i].name[name_len] == '\0')
      return cipher_algos[i].type;
  }

  ssh_set_error("invalid cipher name: '%.*s'", (int) name_len, name);
  return SSH_CIPHER_INVALID;
}

static const struct CIPHER_ALGO *cipher_get_algo(enum SSH_CIPHER_TYPE type)
{
  int i;
  
  for (i = 0; i < sizeof(cipher_algos)/sizeof(cipher_algos[0]); i++)
    if (cipher_algos[i].type == type)
      return &cipher_algos[i];
  ssh_set_error("invalid cipher type: %d", type);
  return NULL;
}

int ssh_cipher_get_block_len(enum SSH_CIPHER_TYPE type)
{
  const struct CIPHER_ALGO *algo = cipher_get_algo(type);
  if (algo == NULL)
    return -1;
  return algo->block_len;
}

int ssh_cipher_get_key_len(enum SSH_CIPHER_TYPE type)
{
  const struct CIPHER_ALGO *algo = cipher_get_algo(type);
  if (algo == NULL)
    return -1;
  return algo->iv_len;
}

int ssh_cipher_get_iv_len(enum SSH_CIPHER_TYPE type)
{
  const struct CIPHER_ALGO *algo = cipher_get_algo(type);
  if (algo == NULL)
    return -1;
  return algo->iv_len;
}

struct SSH_CIPHER_CTX *ssh_cipher_new(enum SSH_CIPHER_TYPE type, enum SSH_CIPHER_DIRECTION dir, const struct SSH_STRING *iv, const struct SSH_STRING *key)
{
  struct SSH_CIPHER_CTX *ret;
  void *crypto_ctx;
  
  const struct CIPHER_ALGO *algo = cipher_get_algo(type);
  if (algo == NULL)
    return NULL;

  crypto_ctx = algo->new(type, dir, iv, key);
  if (crypto_ctx == NULL) {
    ssh_free(crypto_ctx);
    return NULL;
  }

  ret = ssh_alloc(sizeof(*ret));
  if (ret == NULL) {
    ssh_set_error("out of memory");
    return NULL;
  }
  ret->algo = algo;
  ret->ctx = crypto_ctx;
  return ret;
}

void ssh_cipher_free(struct SSH_CIPHER_CTX *ctx)
{
  ctx->algo->free(ctx->ctx);
  ssh_free(ctx);
}

int ssh_cipher_crypt(struct SSH_CIPHER_CTX *ctx, uint8_t *out, uint8_t *data, uint32_t len)
{
#if 0
  uint32_t cur;

  for (cur = 0; cur < len; cur += 16) {
    if (ctx->algo->crypt(ctx->ctx, out + cur, data + cur, 16) < 0)
      return -1;
  }
  return 0;
#else
  return ctx->algo->crypt(ctx->ctx, out, data, len);
#endif
}
