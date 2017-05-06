/* pubkey.c */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "ssh/pubkey.h"

#include "ssh/hash.h"
#include "common/error.h"
#include "common/debug.h"
#include "crypto/rsa.h"

#define DECLARE_VERIFY_FUNC(name) static int name(struct SSH_BUF_READER *key_buf, struct SSH_STRING *signature, struct SSH_STRING *data)
typedef int (*verify_func)(struct SSH_BUF_READER *key_buf, struct SSH_STRING *signature, struct SSH_STRING *data);

DECLARE_VERIFY_FUNC(rsa_verify);

static const struct SSH_PUBKEY_ALGO {
  const char *name;
  enum SSH_PUBKEY_TYPE type;
  enum SSH_HASH_TYPE hash_type;
  verify_func verify;
} pubkey_algos[] = {
  { "ssh-rsa",      SSH_PUBKEY_RSA, SSH_HASH_SHA1,     rsa_verify },
  { "rsa-sha2-512", SSH_PUBKEY_RSA, SSH_HASH_SHA2_512, rsa_verify },
  { "rsa-sha2-256", SSH_PUBKEY_RSA, SSH_HASH_SHA2_256, rsa_verify },
};

static const struct SSH_PUBKEY_ALGO *get_pubkey_algo(const uint8_t *name, size_t name_len)
{
  int i;

  for (i = 0; i < sizeof(pubkey_algos)/sizeof(pubkey_algos[0]); i++) {
    if (memcmp(pubkey_algos[i].name, name, name_len) == 0 && pubkey_algos[i].name[name_len] == '\0')
      return &pubkey_algos[i];
  }
  return NULL;
}

enum SSH_PUBKEY_TYPE ssh_pubkey_get_by_name_n(const uint8_t *name, size_t name_len)
{
  const struct SSH_PUBKEY_ALGO *key_algo = get_pubkey_algo(name, name_len);

  if (key_algo == NULL)
    return SSH_PUBKEY_INVALID;
  return key_algo->type;
}

enum SSH_PUBKEY_TYPE ssh_pubkey_get_by_name_str(const struct SSH_STRING *name)
{
  return ssh_pubkey_get_by_name_n(name->str, name->len);
}

enum SSH_PUBKEY_TYPE ssh_pubkey_get_by_name(const char *name)
{
  return ssh_pubkey_get_by_name_n((uint8_t *)name, strlen(name));
}

int ssh_pubkey_get_supported_algos(struct SSH_BUFFER *ret)
{
  int i;

  ssh_buf_clear(ret);
  for (i = 0; i < sizeof(pubkey_algos)/sizeof(pubkey_algos[0]); i++) {
    if ((i > 0 && ssh_buf_append_u8(ret, ',') < 0)
        || ssh_buf_append_data(ret, (uint8_t *) pubkey_algos[i].name, strlen(pubkey_algos[i].name)) < 0)
      return -1;
  }
  return 0;
}

int ssh_pubkey_verify_signature(enum SSH_PUBKEY_TYPE key_type, struct SSH_STRING *key_data, struct SSH_STRING *signature, struct SSH_STRING *data)
{
  struct SSH_BUF_READER key_buf;
  struct SSH_STRING key_type_str;
  const struct SSH_PUBKEY_ALGO *key_algo;
  
  key_buf = ssh_buf_reader_new_from_string(key_data);
  if (ssh_buf_read_string(&key_buf, &key_type_str) < 0)
    return -1;
  
  key_algo = get_pubkey_algo(key_type_str.str, key_type_str.len);
  if (key_algo == NULL) {
    ssh_set_error("invalid public key algorithm: '%.*s'", (int) key_type_str.len, key_type_str.str);
    return -1;
  }

  if (key_algo->type != key_type) {
    ssh_set_error("key type '%.*s' doesn't match expected type (%d != %d)", (int) key_type_str.len, key_type_str.str, key_algo->type, key_type);
    return -1;
  }
  
  return key_algo->verify(&key_buf, signature, data);
}

static int rsa_verify(struct SSH_BUF_READER *key, struct SSH_STRING *signature, struct SSH_STRING *data)
{
  struct SSH_BUF_READER sig_buf;
  struct SSH_STRING sig_type;
  struct SSH_STRING sig_data;
  struct SSH_STRING e, n;
  const struct SSH_PUBKEY_ALGO *pubkey_algo;
  struct SSH_STRING hash;
  uint8_t hash_data[SSH_HASH_MAX_LEN];
  
  // read (e, n) from key
  if (ssh_buf_read_string(key, &e) < 0
      || ssh_buf_read_string(key, &n) < 0)
    return -1;

  // read hash type from signature
  sig_buf = ssh_buf_reader_new_from_string(signature);
  if (ssh_buf_read_string(&sig_buf, &sig_type) < 0)
    return -1;
  pubkey_algo = get_pubkey_algo(sig_type.str, sig_type.len);
  if (pubkey_algo == NULL) {
    ssh_set_error("invalid signature algorithm: '%.*s'", (int) sig_type.len, sig_type.str);
    return -1;
  }

  // hash data
  hash = ssh_str_new(hash_data, 0);
  if (ssh_hash_compute(pubkey_algo->hash_type, &hash, data) < 0)
    return -1;

  // read data from signature
  if (ssh_buf_read_string(&sig_buf, &sig_data) < 0)
    return -1;

  // verify
  if (crypto_rsa_verify(pubkey_algo->hash_type, &e, &n, &sig_data, &hash) < 0)
    return -1;

  return 0;
}
