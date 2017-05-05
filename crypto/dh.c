/* dh.c */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <openssl/dh.h>

#include "crypto/dh.h"

#include "common/error.h"
#include "common/alloc.h"
#include "crypto/bignum.h"

#define GET_DH(p) ((DH *) (p))

struct CRYPTO_DH *crypto_dh_new(const char *hex_gen, const char *hex_modulus)
{
  DH *dh = DH_new();

  if (BN_hex2bn(&dh->p, hex_modulus) == 0) {
    DH_free(dh);
    ssh_set_error("can't set DH modulus");
    return NULL;
  }

  if (BN_hex2bn(&dh->g, hex_gen) == 0) {
    DH_free(dh);
    ssh_set_error("can't set DH generator");
    return NULL;
  }

  if (DH_generate_key(dh) == 0) {
    DH_free(dh);
    ssh_set_error("can't generate DH key");
    return NULL;
  }
  
  return (struct CRYPTO_DH *) dh;
}

int crypto_dh_compute_key(struct CRYPTO_DH *crypto_dh, struct SSH_STRING *ret_key, const struct SSH_STRING *server_pubkey)
{
  DH *dh = GET_DH(crypto_dh);
  BIGNUM *bn_server_pubkey;
  uint32_t len;
  uint8_t *key;

  bn_server_pubkey = BN_new();
  if (crypto_string_to_bignum(bn_server_pubkey, server_pubkey) < 0)
    return -1;
    
  len = DH_size(dh);
  key = ssh_alloc(len+1);
  if (key == NULL) {
    BN_clear_free(bn_server_pubkey);
    return -1;
  }
  if (DH_compute_key(key+1, bn_server_pubkey, dh) != len) {
    ssh_free(key);
    BN_clear_free(bn_server_pubkey);
    ssh_set_error("error computing key");
    return -1;
  }
  
  // prefix key with a 0 if necessary
  if ((key[1] & 0x80) != 0) {
    key[0] = 0;
    len++;
  } else {
    memmove(key, key+1, len);
  }

  BN_clear_free(bn_server_pubkey);
  ret_key->str = key;
  ret_key->len = len;
  return 0;
}

int crypto_dh_get_pubkey(struct CRYPTO_DH *crypto_dh, struct SSH_STRING *out)
{
  DH *dh = GET_DH(crypto_dh);

  return crypto_bignum_to_string(dh->pub_key, out);
}

void crypto_dh_free(struct CRYPTO_DH *crypto_dh)
{
  DH *dh = GET_DH(crypto_dh);
  if (dh != NULL)
    DH_free(dh);
}

