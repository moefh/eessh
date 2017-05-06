/* rsa.c */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <openssl/rsa.h>

#include "crypto/rsa.h"

#include "common/error.h"
#include "common/debug.h"
#include "common/buffer.h"
#include "crypto/algorithms.h"
#include "crypto/oid.h"
#include "crypto/bignum.h"

int crypto_rsa_verify(enum SSH_HASH_TYPE hash_type, struct SSH_STRING *e, struct SSH_STRING *n, struct SSH_STRING *signature, struct SSH_STRING *hash)
{
  struct SSH_STRING oid;
  struct SSH_STRING use_sig;
  struct SSH_BUFFER sig_buf;
  struct SSH_BUFFER decrypted_buf;
  uint8_t *decrypted;
  RSA *rsa;
  size_t rsa_size;
  int decrypted_len;
  int oid_ok, hash_ok;
  int must_free_sig;
  
  if (crypto_oid_get_for_hash(hash_type, &oid) < 0)
    return -1;

  if ((rsa = RSA_new()) == NULL
      || (rsa->e = BN_new()) == NULL
      || (rsa->n = BN_new()) == NULL) {
    if (rsa != NULL)
      RSA_free(rsa);
    ssh_set_error("out of memory");
    return -1;
  }
  if (crypto_string_to_bignum(rsa->e, e) < 0)
    return -1;
  if (crypto_string_to_bignum(rsa->n, n) < 0)
    return -1;

  rsa_size = RSA_size(rsa);
  if (rsa_size < signature->len) {
    ssh_set_error("signature too large");
    return -1;
  } else if (rsa_size > signature->len) {
    uint8_t *p;

    // fill signature with 0s at the start
    sig_buf = ssh_buf_new();
    p = ssh_buf_get_write_pointer(&sig_buf, rsa_size - signature->len);
    memset(p, 0, rsa_size - signature->len);
    p = ssh_buf_get_write_pointer(&sig_buf, signature->len);
    memcpy(p, signature->str, signature->len);

    use_sig = ssh_str_new_from_buffer(&sig_buf);
    must_free_sig = 1;
  } else {
    use_sig = *signature;
    must_free_sig = 0;
  }

  // decrypt signature
  decrypted_buf = ssh_buf_new();
  decrypted = ssh_buf_get_write_pointer(&decrypted_buf, rsa_size);
  decrypted_len = RSA_public_decrypt(use_sig.len, use_sig.str, decrypted, rsa, RSA_PKCS1_PADDING);

  if (decrypted_len < 0 || hash->len + oid.len != (size_t) decrypted_len) {
    RSA_free(rsa);
    ssh_buf_free(&decrypted_buf);
    if (must_free_sig)
      ssh_buf_free(&sig_buf);
    ssh_set_error("RSA error decypting signature");
    return -1;
  }
  RSA_free(rsa);
  if (must_free_sig)
    ssh_buf_free(&sig_buf);

  // TODO: protect against timing attacks
  oid_ok = (memcmp(decrypted, oid.str, oid.len) == 0);
  hash_ok = (memcmp(decrypted + oid.len, hash->str, hash->len) == 0);
  ssh_buf_free(&decrypted_buf);
  if (! oid_ok || ! hash_ok) {
    ssh_set_error("invalid signature (%d, %d)", oid_ok, hash_ok);
    return -1;
  }

  return 0;
}
