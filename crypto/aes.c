/* aes.c */

#include <stdlib.h>
#include <stdint.h>

#include <openssl/evp.h>

#include "crypto/aes.h"

#include "common/error.h"
#include "common/debug.h"
#include "crypto/algorithms.h"

#define TO_EVP_CTX(ctx) ((EVP_CIPHER_CTX *) (ctx))

static const EVP_CIPHER *get_evp_cipher(enum SSH_CIPHER_TYPE type)
{
  switch (type) {
  case SSH_CIPHER_AES128_CTR: return EVP_aes_128_ctr();
  case SSH_CIPHER_AES128_CBC: return EVP_aes_128_cbc();

  default:
    ssh_set_error("invalid AES cipher: %d", type);
    return NULL;
  }
}

struct CRYPTO_CIPHER_CTX *crypto_aes_new(enum SSH_CIPHER_TYPE type, enum SSH_CIPHER_DIRECTION dir, const struct SSH_STRING *iv, const struct SSH_STRING *key)
{
  const EVP_CIPHER *cipher;
  EVP_CIPHER_CTX *ctx;
  
  cipher = get_evp_cipher(type);
  if (cipher == NULL)
    return NULL;
    
  ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL) {
    ssh_set_error("out of memory");
    return NULL;
  }

  EVP_CIPHER_CTX_init(ctx);
  if (EVP_CipherInit(ctx, cipher, NULL, NULL, dir == SSH_CIPHER_ENCRYPT) == 0) {
    EVP_CIPHER_CTX_free(ctx);
    ssh_set_error("error initializing AES cipher");
    return NULL;
  }
  if (key->len < EVP_CIPHER_CTX_key_length(ctx)
      || iv->len < EVP_CIPHER_CTX_iv_length(ctx)) {
    ssh_set_error("invalid key or IV size (%d,%d) vs (%d,%d)", (int) key->len, (int) iv->len, (int)EVP_CIPHER_CTX_key_length(ctx), (int)EVP_CIPHER_CTX_iv_length(ctx));
    EVP_CIPHER_CTX_free(ctx);
    return NULL;
  }
  if (EVP_CipherInit(ctx, NULL, key->str, iv->str, -1) == 0) {
    EVP_CIPHER_CTX_free(ctx);
    ssh_set_error("error initializing AES cipher");
    return NULL;
  }
  
  return (struct CRYPTO_CIPHER_CTX *) ctx;
}

void crypto_aes_free(struct CRYPTO_CIPHER_CTX *cipher_ctx)
{
  EVP_CIPHER_CTX *ctx = TO_EVP_CTX(cipher_ctx);
  
  EVP_CIPHER_CTX_free(ctx);
}

int crypto_aes_crypt(struct CRYPTO_CIPHER_CTX *cipher_ctx, uint8_t *out, uint8_t *data, uint32_t len)
{
  EVP_CIPHER_CTX *ctx = TO_EVP_CTX(cipher_ctx);

  //ssh_log("CIPHER: processing %u bytes\n", len);
  //dump_mem("CIPHER [BEFORE PROCESSING]", data, len);

  if (EVP_Cipher(ctx, out, data, len) == 0) {
    ssh_set_error("cipher error");
    return -1;
  }

  //dump_mem("CIPHER [AFTER PROCESSING]", out, len);
  
  return 0;
}
