/* kex.c
 *
 * SSH key exchange conforming to RFC 4253 section 7
 */

#include <stdlib.h>
#include <string.h>

#include "ssh/kex.h"
#include "ssh/kex_internal.h"

#include "ssh/kex_dh.h"

#include "common/error.h"
#include "common/alloc.h"
#include "common/debug.h"
#include "ssh/ssh_constants.h"
#include "ssh/debug.h"
#include "ssh/hash.h"
#include "crypto/algorithms.h"
#include "crypto/random.h"

typedef int (*func_kex_run)(struct SSH_CONN *conn, struct SSH_KEX *kex);

static const struct KEX_ALGO {
  const char *name;
  enum SSH_KEX_TYPE kex_type;
  enum SSH_HASH_TYPE hash_type;
  func_kex_run run;
} kex_algos[] = {
  { "diffie-hellman-group1-sha1",  SSH_KEX_DH_GROUP_1,  SSH_HASH_SHA1, ssh_kex_dh_run },
  { "diffie-hellman-group14-sha1", SSH_KEX_DH_GROUP_14, SSH_HASH_SHA1, ssh_kex_dh_run },
};

static const char kex_algo[] = "diffie-hellman-group14-sha1";
static const char server_host_key_algo[] = "ssh-rsa";
static const char encryption_algo_cts[] = "aes128-ctr";
static const char encryption_algo_stc[] = "aes128-ctr";
static const char mac_algo_cts[] = "hmac-sha2-256";
static const char mac_algo_stc[] = "hmac-sha2-256";
static const char compression_algo_cts[] = "none";
static const char compression_algo_stc[] = "none";
static const char language_cts[] = "";
static const char language_stc[] = "";

enum SSH_KEX_TYPE ssh_kex_get_by_name_n(const uint8_t *name, size_t name_len)
{
  int i;

  for (i = 0; i < sizeof(kex_algos)/sizeof(kex_algos[0]); i++) {
    if (strncmp((const char *) name, kex_algos[i].name, name_len) == 0 && kex_algos[i].name[name_len] == '\0')
      return kex_algos[i].kex_type;
  }

  ssh_set_error("invalid key exchange algorithm '%.*s'", (int) name_len, name);
  return SSH_KEX_INVALID;
}

enum SSH_KEX_TYPE ssh_kex_get_by_name(const char *name)
{
  return ssh_kex_get_by_name_n((const uint8_t *) name, strlen(name));
}

static int kex_save_kexinit_data(struct SSH_BUFFER *dest, uint8_t *data, size_t len)
{
  if (len <= data[4] + 1) {
    ssh_set_error("bad packet length to save");
    return -1;
  }
  ssh_buf_clear(dest);
  return ssh_buf_append_data(dest, data + 5, len - data[4] - 5);
}

static int kex_send_init_msg(struct SSH_CONN *conn, struct SSH_KEX *kex)
{
  uint8_t *p;
  struct SSH_BUFFER *pack;

  pack = ssh_conn_new_packet(conn);
  if (pack == NULL)
    return -1;
    
  if (ssh_buf_write_u8(pack, SSH_MSG_KEXINIT))
    return -1;

  // cookie
  p = ssh_buf_get_write_pointer(pack, 16);
  if (p == NULL)
    return -1;
  if (crypto_random_gen(p, 16) < 0)
    return -1;

  if (ssh_buf_write_cstring(pack, kex_algo)
      || ssh_buf_write_cstring(pack, server_host_key_algo)
      || ssh_buf_write_cstring(pack, encryption_algo_cts)
      || ssh_buf_write_cstring(pack, encryption_algo_stc)
      || ssh_buf_write_cstring(pack, mac_algo_cts)
      || ssh_buf_write_cstring(pack, mac_algo_stc)
      || ssh_buf_write_cstring(pack, compression_algo_cts)
      || ssh_buf_write_cstring(pack, compression_algo_stc)
      || ssh_buf_write_cstring(pack, language_cts)
      || ssh_buf_write_cstring(pack, language_stc))
    return -1;

  if (ssh_buf_write_u8(pack, 0)        // first_kex_packet_follows
      || ssh_buf_write_u32(pack, 0))   // reserved
    return -1;

  ssh_log("* sending SSH_MSG_KEXINIT...\n");
  
  if (ssh_conn_send_packet(conn) < 0)
    return -1;
  if (kex_save_kexinit_data(&kex->client_kexinit, pack->data, pack->len) < 0)
    return -1;
  dump_kexinit_packet("sent packet", pack, 0);
  return 0;
}

static int kex_recv_init_msg(struct SSH_CONN *conn, struct SSH_KEX *kex)
{
  struct SSH_BUF_READER *pack;

  pack = ssh_conn_recv_packet_skip_ignore(conn);
  if (pack == NULL)
    return -1;
  if (ssh_packet_get_type(pack) != SSH_MSG_KEXINIT) {
    ssh_set_error("unexpected packet of type %d (expected SSH_MSG_KEXINIT=%d)", ssh_packet_get_type(pack), SSH_MSG_KEXINIT);
    return -1;
  }
  if (kex_save_kexinit_data(&kex->server_kexinit, pack->data, pack->len) < 0)
    return -1;
  
  ssh_log("* got SSH_MSG_KEXINIT:\n");
  dump_kexinit_packet_reader("received packet", pack, 0);

  return 0;
}

static const struct KEX_ALGO *kex_get_algo(enum SSH_KEX_TYPE type)
{
  int i;

  for (i = 0; i < sizeof(kex_algos)/sizeof(kex_algos[0]); i++) {
    if (kex_algos[i].kex_type == type)
      return &kex_algos[i];
  }

  ssh_set_error("invalid key exchange type: %d", type);
  return NULL;
}

/*
 * Generate 'gen_key_len' bytes of data in 'ret_key' according to
 * RFC 4253 section 7.2 (https://tools.ietf.org/html/rfc4253#section-7.2)
 */
static int gen_key(struct SSH_STRING *ret_key, uint32_t gen_key_len, uint8_t key_id, struct SSH_CONN *conn, struct SSH_KEX *kex)
{
  struct SSH_BUFFER data;
  struct SSH_STRING data_str;
  struct SSH_BUFFER hash;
  struct SSH_STRING hash_str;
  struct SSH_STRING *session_id = ssh_conn_get_session_id(conn);
  
  //ssh_log("---------------------------\n");
  //dump_mem(conn->shared_secret.str, conn->shared_secret.len, "shared secret");
  //dump_mem(conn->exchange_hash.str, conn->exchange_hash.len, "hash");
  //dump_mem(&key_id, 1, "id");
  //dump_mem(conn->session_id.str, conn->session_id.len, "session_id");

  // K[1] = HASH(K || H || X || session_id)    (X is e.g., "A")
  data = ssh_buf_new();
  if (ssh_buf_write_string(&data, &kex->shared_secret) < 0
      || ssh_buf_append_string(&data, &kex->exchange_hash) < 0
      || ssh_buf_append_u8(&data, key_id) < 0
      || ssh_buf_append_string(&data, session_id) < 0) {
    ssh_buf_free(&data);
    return -1;
  }

  hash = ssh_buf_new();
  if (ssh_buf_grow(&hash, SSH_HASH_MAX_LEN)) {
    ssh_buf_free(&data);
    ssh_buf_free(&hash);
    return -1;
  }
  hash_str = ssh_str_new_from_buffer(&hash);
  data_str = ssh_str_new_from_buffer(&data);
  if (ssh_hash_compute(kex->hash_type, &hash_str, &data_str) < 0) {
    ssh_buf_free(&hash);
    ssh_buf_free(&data);
    return -1;
  }
  hash.len = hash_str.len;

  // K[n] = HASH(K || H || K[1] || ... || K[n-1])
  while (hash.len < gen_key_len) {
    //ssh_log("digesting %d/%d\n", (int) hash.len, (int) gen_key_len);
    ssh_buf_clear(&data);
    if (ssh_buf_write_string(&data, &kex->shared_secret) < 0
	|| ssh_buf_append_string(&data, &kex->exchange_hash) < 0
	|| ssh_buf_append_buffer(&data, &hash) < 0) {
      ssh_buf_free(&data);
      ssh_buf_free(&hash);
      return -1;
    }
    
    if (ssh_buf_grow(&hash, SSH_HASH_MAX_LEN)) {
      ssh_buf_free(&data);
      ssh_buf_free(&hash);
      return -1;
    }
    hash_str = ssh_str_new(hash.data + hash.len, 0);
    data_str = ssh_str_new_from_buffer(&data);
    if (ssh_hash_compute(kex->hash_type, &hash_str, &data_str) < 0) {
      ssh_buf_free(&data);
      ssh_buf_free(&hash);
      return -1;
    }
    hash.len += hash_str.len;
  }
  ssh_buf_free(&data);

  //ssh_log("key for '%c' ", key_id);
  //dump_mem(hash.data, gen_key_len, "");
  
  // key = K[1] || .. || K[n]
  hash_str = ssh_str_new(hash.data, gen_key_len);
  if (ssh_str_dup_string(ret_key, &hash_str)) {
    ssh_buf_free(&hash);
    return -1;
  }
  ssh_buf_free(&hash);
  return 0;
}

static int kex_generate_keys(struct SSH_CONN *conn, struct SSH_KEX *kex)
{
  struct SSH_STRING cipher_iv_cts = ssh_str_new_empty();
  struct SSH_STRING cipher_iv_stc = ssh_str_new_empty();
  struct SSH_STRING cipher_key_cts = ssh_str_new_empty();
  struct SSH_STRING cipher_key_stc = ssh_str_new_empty();
  struct SSH_STRING mac_key_cts = ssh_str_new_empty();
  struct SSH_STRING mac_key_stc = ssh_str_new_empty();
  int cipher_iv_cts_len, cipher_iv_stc_len;
  int cipher_key_cts_len, cipher_key_stc_len;
  int mac_key_cts_len, mac_key_stc_len;
  int ret;
  
  ssh_log("* computing encryption and integrity keys\n");

  if ((cipher_iv_cts_len = ssh_cipher_get_iv_len(kex->cipher_type_cts)) < 0
      || (cipher_iv_stc_len = ssh_cipher_get_iv_len(kex->cipher_type_stc)) < 0
      || (cipher_key_cts_len = ssh_cipher_get_key_len(kex->cipher_type_cts)) < 0
      || (cipher_key_stc_len = ssh_cipher_get_key_len(kex->cipher_type_stc)) < 0
      || (mac_key_cts_len = ssh_mac_get_len(kex->mac_type_cts)) < 0
      || (mac_key_stc_len = ssh_mac_get_len(kex->mac_type_stc)) < 0)
    return -1;

  if (gen_key(&cipher_iv_cts, cipher_iv_cts_len, 'A', conn, kex) < 0
      || gen_key(&cipher_iv_stc, cipher_iv_stc_len, 'B', conn, kex) < 0
      || gen_key(&cipher_key_cts, cipher_key_cts_len, 'C', conn, kex) < 0
      || gen_key(&cipher_key_stc, cipher_key_stc_len, 'D', conn, kex) < 0
      || gen_key(&mac_key_cts, mac_key_cts_len, 'E', conn, kex) < 0
      || gen_key(&mac_key_stc, mac_key_stc_len, 'F', conn, kex) < 0
      || ssh_conn_set_cipher(conn, SSH_CONN_CTS, kex->cipher_type_cts, &cipher_iv_cts, &cipher_key_cts) < 0
      || ssh_conn_set_cipher(conn, SSH_CONN_STC, kex->cipher_type_stc, &cipher_iv_stc, &cipher_key_stc) < 0
      || ssh_conn_set_mac(conn, SSH_CONN_CTS, kex->mac_type_cts, &mac_key_cts) < 0
      || ssh_conn_set_mac(conn, SSH_CONN_STC, kex->mac_type_stc, &mac_key_stc) < 0)
    ret = -1;
  else {
    ret = 0;
    ssh_log("* keys set\n");
  }

  ssh_str_free(&cipher_iv_cts);
  ssh_str_free(&cipher_iv_stc);
  ssh_str_free(&cipher_key_cts);
  ssh_str_free(&cipher_key_stc);
  ssh_str_free(&mac_key_cts);
  ssh_str_free(&mac_key_stc);
  return ret;
}

static int ssh_kex_start(struct SSH_CONN *conn, struct SSH_KEX *kex)
{
  const struct KEX_ALGO *algo;

  if (kex_send_init_msg(conn, kex) < 0
      || kex_recv_init_msg(conn, kex) < 0)
    return -1;

  // TODO: choose algorithm based on client and server lists in KEX_INIT packets
  if ((kex->type = ssh_kex_get_by_name(kex_algo)) == SSH_KEX_INVALID
      || (kex->cipher_type_cts = ssh_cipher_get_by_name(encryption_algo_cts)) == SSH_CIPHER_INVALID
      || (kex->cipher_type_stc = ssh_cipher_get_by_name(encryption_algo_stc)) == SSH_CIPHER_INVALID
      || (kex->mac_type_cts = ssh_mac_get_by_name(mac_algo_cts)) == SSH_MAC_INVALID
      || (kex->mac_type_stc = ssh_mac_get_by_name(mac_algo_stc)) == SSH_MAC_INVALID) {
    ssh_set_error("no algorithms shared with server");
    return -1;
  }

  if ((algo = kex_get_algo(kex->type)) == NULL)
    return -1;
  kex->hash_type = algo->hash_type;
  
  return algo->run(conn, kex);
}

int ssh_kex_finish(struct SSH_CONN *conn, struct SSH_KEX *kex, struct SSH_STRING *shared_secret, struct SSH_STRING *exchange_hash)
{
  struct SSH_STRING *session_id = ssh_conn_get_session_id(conn);
  
  // set the session_id if this is the first key exchange
  if (session_id->len == 0) {
    if (ssh_str_dup_string(session_id, exchange_hash) < 0) {
      ssh_str_free(shared_secret);
      ssh_str_free(exchange_hash);
      return -1;
    }
  }

  ssh_str_free(&kex->shared_secret);
  kex->shared_secret = *shared_secret;
  *shared_secret = ssh_str_new_empty();

  ssh_str_free(&kex->exchange_hash);
  kex->exchange_hash = *exchange_hash;
  *exchange_hash = ssh_str_new_empty();

  return kex_generate_keys(conn, kex);
}

/* ================================================================================================== */
/* === RUN ========================================================================================== */
/* ================================================================================================== */

static struct SSH_KEX *kex_new(struct SSH_CONN *conn)
{
  struct SSH_KEX *kex;

  if ((kex = ssh_alloc(sizeof(struct SSH_KEX))) == NULL)
    return NULL;
  kex->exchange_hash = ssh_str_new_empty();
  kex->shared_secret = ssh_str_new_empty();
  kex->client_kexinit = ssh_buf_new();
  kex->server_kexinit = ssh_buf_new();
  return kex;
}

static void kex_free(struct SSH_KEX *kex)
{
  ssh_str_free(&kex->exchange_hash);
  ssh_str_free(&kex->shared_secret);
  ssh_buf_free(&kex->client_kexinit);
  ssh_buf_free(&kex->server_kexinit);
  ssh_free(kex);
}

int ssh_kex_run(struct SSH_CONN *conn)
{
  struct SSH_KEX *kex;
  int ret;

  if ((kex = kex_new(conn)) == NULL)
    return -1;
  //ssh_conn_set_kex(conn, kex);

  ret = ssh_kex_start(conn, kex);

  //ssh_conn_set_kex(conn, NULL);
  kex_free(kex);
  return ret;
}

