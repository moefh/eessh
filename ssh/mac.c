/* mac.c */

#include <stdlib.h>
#include <string.h>

#include "ssh/mac.h"

#include "common/error.h"
#include "common/alloc.h"
#include "crypto/algorithms.h"
#include "crypto/sha2.h"
#include "ssh/hash.h"

typedef struct CRYPTO_HASH_CTX *(*func_hash_new)(uint32_t bits);
typedef int (*func_hash_single)(enum SSH_HASH_TYPE type, void *out, uint32_t *out_len, const void *data, uint32_t len);
typedef void (*func_hash_free)(struct CRYPTO_HASH_CTX *crypto_ctx);
typedef int (*func_hash_copy_ctx)(struct CRYPTO_HASH_CTX *crypto_to_ctx, const struct CRYPTO_HASH_CTX *crypto_from_ctx);
typedef int (*func_hash_update)(struct CRYPTO_HASH_CTX *crypto_ctx, const void *data, uint32_t len);
typedef int (*func_hash_final)(struct CRYPTO_HASH_CTX *crypto_ctx, void *out, uint32_t *out_len);

#define LIST_HASH_FUNCS(algo) crypto_##algo##_single, crypto_##algo##_new, crypto_##algo##_free, crypto_##algo##_copy_ctx, crypto_##algo##_update, crypto_##algo##_final

static const struct MAC_ALGO {
  const char *name;
  enum SSH_MAC_TYPE type;
  enum SSH_HASH_TYPE hash_type;

  uint32_t len;

  func_hash_single hash_single;
  func_hash_new hash_new;
  func_hash_free hash_free;
  func_hash_copy_ctx hash_copy_ctx;
  func_hash_update hash_update;
  func_hash_final hash_final;
} mac_algos[] = {
  { "hmac-sha2-256", SSH_MAC_HMAC_SHA2_256, SSH_HASH_SHA2_256, 32, LIST_HASH_FUNCS(sha2) },
  { "hmac-sha2-512", SSH_MAC_HMAC_SHA2_512, SSH_HASH_SHA2_512, 64, LIST_HASH_FUNCS(sha2) },
};

struct SSH_MAC_CTX {
  const struct MAC_ALGO *algo;
  struct CRYPTO_HASH_CTX *ctx;
  struct CRYPTO_HASH_CTX *ictx;
  struct CRYPTO_HASH_CTX *octx;
  uint32_t block_size;
};

enum SSH_MAC_TYPE ssh_mac_get_by_name(const char *name)
{
  return ssh_mac_get_by_name_n((uint8_t *) name, strlen(name));
}

enum SSH_MAC_TYPE ssh_mac_get_by_name_n(const uint8_t *name, size_t name_len)
{
  int i;

  for (i = 0; i < sizeof(mac_algos)/sizeof(mac_algos[0]); i++) {
    if (strncmp((char *) name, mac_algos[i].name, name_len) == 0 && mac_algos[i].name[name_len] == '\0')
      return mac_algos[i].type;
  }

  ssh_set_error("invalid mac name: '%.*s'", (int) name_len, name);
  return SSH_MAC_INVALID;
}

static const struct MAC_ALGO *mac_get_algo(enum SSH_MAC_TYPE type)
{
  int i;
  
  for (i = 0; i < sizeof(mac_algos)/sizeof(mac_algos[0]); i++)
    if (mac_algos[i].type == type)
      return &mac_algos[i];
  ssh_set_error("invalid mac type: %d", type);
  return NULL;
}

int ssh_mac_get_len(enum SSH_MAC_TYPE type)
{
  const struct MAC_ALGO *algo = mac_get_algo(type);
  if (algo == NULL)
    return -1;
  return algo->len;
}

static int mac_set_key(struct SSH_MAC_CTX *mac, const struct SSH_STRING *key)
{
  const struct MAC_ALGO *algo = mac->algo;
  uint8_t key_data[SSH_HASH_MAX_LEN];
  int i;

  //ssh_log("setting mac key: block size is %d\n", mac->block_size);
  
  // fit key in digest, hashing or filling 0s as necessary
  if (key->len > mac->block_size) {
    //ssh_log("- hash key to fit\n");
    if (algo->hash_single(algo->hash_type, key_data, NULL, key->str, key->len) < 0)
      return -1;
  } else {
    //ssh_log("- copying key\n");
    memcpy(key_data, key->str, key->len);
    if (key->len < mac->block_size)
      memset(key_data + key->len, 0, mac->block_size - key->len);
  }

  //dump_mem(key_data, mac->block_size, ">>>>> SET MAC KEY");
  
  // init ictx
  for (i = 0; i < mac->block_size; i++)
    key_data[i] ^= 0x36;
  //dump_mem(key_data, mac->block_size, ">>>>> UPDATE ICTX");
  if (algo->hash_update(mac->ictx, key_data, mac->block_size) < 0) {
    memset(key_data, 0, mac->block_size);
    return -1;
  }

  // init octx
  for (i = 0; i < mac->block_size; i++)
    key_data[i] ^= 0x36 ^ 0x5c; // 0x36 to undo ictx preparation
  //dump_mem(key_data, mac->block_size, ">>>>> UPDATE OCTX");
  if (algo->hash_update(mac->octx, key_data, mac->block_size) < 0) {
    memset(key_data, 0, mac->block_size);
    return -1;
  }
  
  memset(key_data, 0, mac->block_size);
  return 0;
}

struct SSH_MAC_CTX *ssh_mac_new(enum SSH_MAC_TYPE type, const struct SSH_STRING *key)
{
  struct SSH_MAC_CTX *mac;
  int block_size;
  const struct MAC_ALGO *algo = mac_get_algo(type);
  if (algo == NULL)
    return NULL;

  block_size = ssh_hash_get_block_size(algo->hash_type);
  if (block_size < 0)
    return NULL;
  
  mac = ssh_alloc(sizeof(struct SSH_MAC_CTX));
  if (mac == NULL)
    return NULL;

  mac->algo = algo;
  mac->ctx = NULL;
  mac->ictx = NULL;
  mac->octx = NULL;
  mac->block_size = block_size;

  if ((mac->ctx = algo->hash_new(algo->hash_type)) == NULL
      || (mac->ictx = algo->hash_new(algo->hash_type)) == NULL
      || (mac->octx = algo->hash_new(algo->hash_type)) == NULL
      || mac_set_key(mac, key) < 0) {
    ssh_mac_free(mac);
    return NULL;
  }

  return mac;
}

void ssh_mac_free(struct SSH_MAC_CTX *mac)
{
  if (mac->ctx != NULL)
    mac->algo->hash_free(mac->ctx);
  if (mac->ictx != NULL)
    mac->algo->hash_free(mac->ictx);
  if (mac->octx != NULL)
    mac->algo->hash_free(mac->octx);
  ssh_free(mac);
}

int ssh_mac_compute(struct SSH_MAC_CTX *mac, uint8_t *out, uint32_t seq_num, const uint8_t *data, uint32_t len)
{
  const struct MAC_ALGO *algo = mac->algo;
  uint8_t buf[SSH_HASH_MAX_LEN];
  uint8_t seq_num_buf[4];
  uint32_t buf_len;

  //ssh_log("SEQNO FOR HASH: %u\n", seq_num);
  //dump_mem(data, len, "PACKDATA FOR HASH");

  ssh_buf_set_u32(seq_num_buf, seq_num);

  // inner hash
  if (algo->hash_copy_ctx(mac->ctx, mac->ictx) < 0)
    return -1;
  if (algo->hash_update(mac->ctx, seq_num_buf, 4) < 0)
    return -1;
  if (algo->hash_update(mac->ctx, data, len) < 0)
    return -1;
  if (algo->hash_final(mac->ctx, buf, &buf_len) < 0)
    return -1;
  //dump_mem(buf, buf_len, ">>>>> INNER HASH");

  // outer hash
  if (algo->hash_copy_ctx(mac->ctx, mac->octx) < 0)
    return -1;
  if (algo->hash_update(mac->ctx, buf, algo->len) < 0)
    return -1;
  if (algo->hash_final(mac->ctx, out, &buf_len) < 0)
    return -1;
  //dump_mem(out, buf_len, ">>>>> OUTER HASH");

  //dump_mem(out, algo->len, ">>>>>>>>>>>>>>>>> COMPUTED HASH");
  //memset(out, 0, algo->len);
  
  memset(buf, 0, algo->len);
  return 0;
}
