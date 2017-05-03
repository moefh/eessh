/* sha1.c */

#include <stdlib.h>
#include <stdint.h>

#include <openssl/evp.h>

#include "crypto/sha1.h"

#include "common/error.h"

int crypto_sha1_single(enum SSH_HASH_TYPE type, void *out, uint32_t *out_len, const void *data, uint32_t data_len)
{
  unsigned int digest_len;

  if (! EVP_Digest(data, data_len, out, &digest_len, EVP_sha1(), NULL)) {
    ssh_set_error("error generating sha1 hash");
    return -1;
  }
  if (out_len != NULL)
    *out_len = digest_len;
  return 0;
}

int crypto_sha1_get_block_size(enum SSH_HASH_TYPE type)
{
  int ret = EVP_MD_block_size(EVP_sha1());
  if (ret < 0)
    ssh_set_error("invalid sha1 hash block size");
  return ret;
}
