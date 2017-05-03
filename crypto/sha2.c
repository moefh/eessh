/* sha2.c */

#include <stdlib.h>
#include <stdint.h>

#include <openssl/evp.h>

#include "crypto/sha2.h"

#include "common/error.h"
#include "common/alloc.h"

#define TO_MD_CTX(ctx) ((EVP_MD_CTX *) (ctx))

static const EVP_MD *get_hash_evp(enum SSH_HASH_TYPE type)
{
  switch (type) {
  case SSH_HASH_SHA2_256: return EVP_sha256();
  case SSH_HASH_SHA2_512: return EVP_sha512();
  default:
    ssh_set_error("invalid sha2 algorithm: %d", type);
    return NULL;
  }
}

int crypto_sha2_single(enum SSH_HASH_TYPE type, void *out, uint32_t *out_len, const void *data, uint32_t data_len)
{
  unsigned int digest_len;
  const EVP_MD *evp;

  if ((evp = get_hash_evp(type)) == NULL)
    return -1;

  if (! EVP_Digest(data, data_len, out, &digest_len, evp, NULL)) {
    ssh_set_error("error generating sha2 hash");
    return -1;
  }
  if (out_len != NULL)
    *out_len = digest_len;
  return 0;
}

int crypto_sha2_get_block_size(enum SSH_HASH_TYPE type)
{
  const EVP_MD *evp;

  if ((evp = get_hash_evp(type)) == NULL)
    return -1;

  int ret = EVP_MD_block_size(evp);
  if (ret < 0)
    ssh_set_error("invalid sha2 hash block size");
  return ret;
}

struct CRYPTO_HASH_CTX *crypto_sha2_new(enum SSH_HASH_TYPE type)
{
  const EVP_MD *evp;
  EVP_MD_CTX *ctx;

  if ((evp = get_hash_evp(type)) == NULL)
    return NULL;

  if ((ctx = ssh_alloc(sizeof(EVP_MD_CTX))) == NULL) {
    ssh_set_error("out of memory");
    return NULL;
  }
  EVP_MD_CTX_init(ctx);
  if (EVP_DigestInit_ex(ctx, evp, NULL) == 0) {
    ssh_free(ctx);
    ssh_set_error("error initializing sha2 hash");
    return NULL;
  }

  return (struct CRYPTO_HASH_CTX *) ctx;
}

int crypto_sha2_copy_ctx(struct CRYPTO_HASH_CTX *crypto_to_ctx, const struct CRYPTO_HASH_CTX *crypto_from_ctx)
{
  EVP_MD_CTX *to_ctx = TO_MD_CTX(crypto_to_ctx);
  const EVP_MD_CTX *from_ctx = TO_MD_CTX(crypto_from_ctx);

  if (EVP_MD_CTX_copy_ex(to_ctx, from_ctx) == 0) {
    ssh_set_error("error copying sha2 hash");
    return -1;
  }
  return 0;
}

int crypto_sha2_update(struct CRYPTO_HASH_CTX *crypto_ctx, const void *data, uint32_t len)
{
  EVP_MD_CTX *ctx = TO_MD_CTX(crypto_ctx);

  if (EVP_DigestUpdate(ctx, data, len) == 0) {
    ssh_set_error("error updating sha2 hash");
    return -1;
  }
  return 0;
}

int crypto_sha2_final(struct CRYPTO_HASH_CTX *crypto_ctx, void *out, uint32_t *out_len)
{
  EVP_MD_CTX *ctx = TO_MD_CTX(crypto_ctx);
  unsigned int digest_len;

  if (EVP_DigestFinal_ex(ctx, out, &digest_len) == 0) {
    ssh_set_error("error finalizing sha2 hash");
    return -1;
  }
  if (out_len != NULL)
    *out_len = digest_len;
  return 0;
}

void crypto_sha2_free(struct CRYPTO_HASH_CTX *crypto_ctx)
{
  EVP_MD_CTX *ctx = TO_MD_CTX(crypto_ctx);

  EVP_MD_CTX_cleanup(ctx);
  ssh_free(ctx);
}
