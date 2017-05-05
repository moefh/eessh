/* pubkey.c */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "ssh/pubkey.h"

#include "ssh/hash.h"
#include "common/error.h"
#include "crypto/rsa.h"

#define DECLARE_VERIFY_FUNC(name) static int name(struct SSH_BUF_READER *key_buf, struct SSH_STRING *signature, struct SSH_STRING *data)
typedef int (*verify_func)(struct SSH_BUF_READER *key_buf, struct SSH_STRING *signature, struct SSH_STRING *data);

DECLARE_VERIFY_FUNC(rsa_verify);

static const struct SSH_PUBKEY_ALGO {
  enum SSH_PUBKEY_TYPE type;
  const char *name;
  enum SSH_HASH_TYPE hash_type;
  verify_func verify;
} pubkey_algos[] = {
  { SSH_PUBKEY_RSA, "ssh-rsa", SSH_HASH_SHA1, rsa_verify },
};

static const struct SSH_PUBKEY_ALGO *get_pubkey_algo(const struct SSH_STRING *name)
{
  int i;

  for (i = 0; i < sizeof(pubkey_algos)/sizeof(pubkey_algos[0]); i++) {
    size_t algo_name_len = strlen(pubkey_algos[i].name);
    if (algo_name_len == name->len && memcmp(pubkey_algos[i].name, name->str, name->len) == 0)
      return &pubkey_algos[i];
  }
  return NULL;
}

int ssh_pubkey_verify_signature(struct SSH_STRING *key_data, struct SSH_STRING *signature, struct SSH_STRING *data)
{
  struct SSH_BUF_READER key_buf;
  struct SSH_STRING key_type;
  const struct SSH_PUBKEY_ALGO *key_algo;
  
  key_buf = ssh_buf_reader_new_from_string(key_data);
  if (ssh_buf_read_string(&key_buf, &key_type) < 0)
    return -1;
  
  key_algo = get_pubkey_algo(&key_type);
  if (key_algo == NULL) {
    ssh_set_error("invalid public key algorithm: '%.*s'", (int) key_type.len, key_type.str);
    return -1;
  }

  return key_algo->verify(&key_buf, signature, data);
}

static int rsa_verify(struct SSH_BUF_READER *key_data, struct SSH_STRING *signature, struct SSH_STRING *data)
{
  struct SSH_BUF_READER sig_buf;
  struct SSH_STRING sig_type;
  struct SSH_STRING sig_data;
  struct SSH_STRING e, n;
  const struct SSH_PUBKEY_ALGO *pubkey_algo;
  struct SSH_STRING hash;
  uint8_t hash_data[SSH_HASH_MAX_LEN];
  
  // read (e, n) from key
  if (ssh_buf_read_string(key_data, &e) < 0
      || ssh_buf_read_string(key_data, &n) < 0)
    return -1;
  //dump_string(&e, "e");
  //dump_string(&n, "n");

  // read hash type from signature
  sig_buf = ssh_buf_reader_new_from_string(signature);
  if (ssh_buf_read_string(&sig_buf, &sig_type) < 0)
    return -1;
  pubkey_algo = get_pubkey_algo(&sig_type);
  if (pubkey_algo == NULL) {
    ssh_set_error("invalid signature algorithm: '%.*s'", (int) sig_type.len, sig_type.str);
    return -1;
  }

  // hash data
  hash = ssh_str_new(hash_data, 0);
  if (ssh_hash_compute(pubkey_algo->hash_type, &hash, data) < 0)
    return -1;

  //dump_string(data, "RSA VERIFY DATA");
  //dump_string(&hash, "RSA VERIFY DATA HASH");
  
  // read data from signature
  if (ssh_buf_read_string(&sig_buf, &sig_data) < 0)
    return -1;

  // verify
  if (crypto_rsa_verify(pubkey_algo->hash_type, &e, &n, &sig_data, &hash) < 0)
    return -1;

  return 0;
}
