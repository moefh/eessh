/* kex_dh.c
 *
 * Diffie-Hellman key exchange for SSH conforming to RFC 4253 section 8
 */

#include <stdlib.h>
#include <string.h>

#include "ssh/kex_dh.h"
#include "ssh/kex_internal.h"

#include "common/error.h"
#include "common/debug.h"
#include "ssh/debug.h"
#include "ssh/hash.h"
#include "ssh/verify.h"
#include "ssh/kex.h"
#include "ssh/connection.h"
#include "ssh/ssh_constants.h"
#include "crypto/dh.h"

const static struct DH_ALGO {
  const char *name;
  enum SSH_KEX_TYPE type;
  enum SSH_HASH_TYPE hash_type;
  const char *gen;
  const char *modulus;
} dh_algos[] = {
  {
    "diffie-hellman-group1-sha1",
    SSH_KEX_DH_GROUP_1,
    SSH_HASH_SHA1,
    "2",
    "FFFFFFFF" "FFFFFFFF" "C90FDAA2" "2168C234" "C4C6628B" "80DC1CD1"
    "29024E08" "8A67CC74" "020BBEA6" "3B139B22" "514A0879" "8E3404DD"
    "EF9519B3" "CD3A431B" "302B0A6D" "F25F1437" "4FE1356D" "6D51C245"
    "E485B576" "625E7EC6" "F44C42E9" "A637ED6B" "0BFF5CB6" "F406B7ED"
    "EE386BFB" "5A899FA5" "AE9F2411" "7C4B1FE6" "49286651" "ECE65381"
    "FFFFFFFF" "FFFFFFFF"
  },
  {
    "diffie-hellman-group14-sha1",
    SSH_KEX_DH_GROUP_14,
    SSH_HASH_SHA1,
    "2",
    "FFFFFFFF" "FFFFFFFF" "C90FDAA2" "2168C234" "C4C6628B" "80DC1CD1"
    "29024E08" "8A67CC74" "020BBEA6" "3B139B22" "514A0879" "8E3404DD"
    "EF9519B3" "CD3A431B" "302B0A6D" "F25F1437" "4FE1356D" "6D51C245"
    "E485B576" "625E7EC6" "F44C42E9" "A637ED6B" "0BFF5CB6" "F406B7ED"
    "EE386BFB" "5A899FA5" "AE9F2411" "7C4B1FE6" "49286651" "ECE45B3D"
    "C2007CB8" "A163BF05" "98DA4836" "1C55D39A" "69163FA8" "FD24CF5F"
    "83655D23" "DCA3AD96" "1C62F356" "208552BB" "9ED52907" "7096966D"
    "670C354E" "4ABC9804" "F1746C08" "CA18217C" "32905E46" "2E36CE3B"
    "E39E772C" "180E8603" "9B2783A2" "EC07A28F" "B5C55DF0" "6F4C52C9"
    "DE2BCBF6" "95581718" "3995497C" "EA956AE5" "15D22618" "98FA0510"
    "15728E5A" "8AACAA68" "FFFFFFFF" "FFFFFFFF"
  },
};

/* send SSH_MSG_NEWKEYS packet */
static int dh_kex_send_init_msg(struct CRYPTO_DH *dh, struct SSH_CONN *conn)
{
  struct SSH_STRING e;
  struct SSH_BUFFER *pack;
 
  if (crypto_dh_get_pubkey(dh, &e) < 0)
    return -1;

  ssh_log("* sending SSH_MSG_KEXDH_INIT...\n");

  pack = ssh_conn_new_packet(conn);
  if (pack == NULL)
    return -1;

  if (ssh_buf_write_u8(pack, SSH_MSG_KEXDH_INIT) < 0
      || ssh_buf_write_string(pack, &e) < 0)
    return -1;
  
  if (ssh_conn_send_packet(conn) < 0)
    return -1;
  //ssh_packet_dump(pack, 0);
  return 0;
}

/* send SSH_MSG_NEWKEYS packet */
static int dh_kex_send_newkeys_msg(struct SSH_CONN *conn)
{
  struct SSH_BUFFER *pack;

  pack = ssh_conn_new_packet(conn);
  if (pack == NULL)
    return -1;
    
  if (ssh_buf_write_u8(pack, SSH_MSG_NEWKEYS))
    return -1;
  if (ssh_conn_send_packet(conn) < 0)
    return -1;
  return 0;
}

/* receive SSH_MSG_NEWKEYS packet */
static int dh_kex_recv_newkeys_msg(struct SSH_CONN *conn)
{
  struct SSH_BUF_READER *pack;
  
  pack = ssh_conn_recv_packet_skip_ignore(conn);
  if (pack == NULL)
    return -1;

  if (ssh_packet_get_type(pack) != SSH_MSG_NEWKEYS) {
    ssh_set_error("unexpected packet type: %d (expected SSH_MSG_NEWKEYS=%d)", ssh_packet_get_type(pack), SSH_MSG_NEWKEYS);
    return -1;
  }
  dump_packet_reader("received SSH_MSG_NEWKEYS", pack, 0);

  return 0;
}

/*
 * Compute exchange hash according to RFC 4253 section 8
 * (see https://tools.ietf.org/html/rfc4253#section-8)
 */
static int dh_kex_hash(struct SSH_STRING *ret_hash, enum SSH_HASH_TYPE hash_type, const struct SSH_STRING *server_host_key,
		       const struct SSH_STRING *client_pubkey, const struct SSH_STRING *server_pubkey,
		       const struct SSH_STRING *shared_secret, struct SSH_CONN *conn, struct SSH_KEX *kex)
{
  struct SSH_BUFFER data;
  struct SSH_STRING data_str;
  struct SSH_STRING hash;
  struct SSH_VERSION_STRING *server_version;
  uint8_t hash_data[SSH_HASH_MAX_LEN];

  server_version = ssh_conn_get_server_version_string(conn);
  
  data = ssh_buf_new();
  if (ssh_buf_write_cstring_n(&data, ssh_client_version_string, strlen(ssh_client_version_string)-2) < 0
      || ssh_buf_write_cstring_n(&data, (char *) server_version->buf, server_version->len) < 0
      || ssh_buf_write_buffer(&data, &kex->client_kexinit) < 0
      || ssh_buf_write_buffer(&data, &kex->server_kexinit) < 0
      || ssh_buf_write_string(&data, server_host_key) < 0
      || ssh_buf_write_string(&data, client_pubkey) < 0
      || ssh_buf_write_string(&data, server_pubkey) < 0
      || ssh_buf_write_string(&data, shared_secret) < 0)
    return -1;
  //dump_mem(data.data, data.len, "DATA BEING HASHED");

  // hash data
  data_str = ssh_str_new_from_buffer(&data);
  hash = ssh_str_new(hash_data, 0);
  if (ssh_hash_compute(hash_type, &hash, &data_str) < 0) {
    ssh_buf_free(&data);
    return -1;
  }
  ssh_buf_free(&data);

  if (ssh_str_dup_string(ret_hash, &hash) < 0)
    return -1;
  
  return 0;
}

/* read server key exchange reply */
static int dh_kex_read_reply(struct CRYPTO_DH *dh, struct SSH_CONN *conn, struct SSH_KEX *kex, enum SSH_HASH_TYPE sig_hash_type)
{
  struct SSH_BUF_READER *pack;
  struct SSH_STRING server_host_key;
  struct SSH_STRING client_pubkey;
  struct SSH_STRING server_pubkey;
  struct SSH_STRING shared_secret;
  struct SSH_STRING server_hash_sig;
  struct SSH_STRING exchange_hash;
  
  // SSH_MSG_KEXDH_REPLY
  pack = ssh_conn_recv_packet_skip_ignore(conn);
  if (pack == NULL)
    return -1;
  //ssh_packet_dump(pack, 0);
  if (ssh_packet_get_type(pack) != SSH_MSG_KEXDH_REPLY) {
    ssh_set_error("unexpected packet type: %d (expected SSH_MSG_KEXDH_REPLY=%d)", ssh_packet_get_type(pack), SSH_MSG_KEXDH_REPLY);
    return -1;
  }
  ssh_log("* got SSH_MSG_KEXDH_REPLY\n");
  if (ssh_buf_read_u8(pack, NULL) < 0
      || ssh_buf_read_string(pack, &server_host_key) < 0
      || ssh_buf_read_string(pack, &server_pubkey) < 0
      || ssh_buf_read_string(pack, &server_hash_sig) < 0)
    return -1;
  //dump_string(&server_host_key, "* server_host_key");
  //dump_string(&server_pubkey, "* server_pubkey");
  //dump_string(&server_hash_sig, "* hash_sig");

  if (crypto_dh_compute_key(dh, &shared_secret, &server_pubkey) < 0)
    return -1;

  if (crypto_dh_get_pubkey(dh, &client_pubkey) < 0) {
    ssh_str_free(&shared_secret);
    return -1;
  }

  if (dh_kex_hash(&exchange_hash, sig_hash_type, &server_host_key, &client_pubkey, &server_pubkey, &shared_secret, conn, kex) < 0) {
    ssh_str_free(&shared_secret);
    return -1;
  }

  //dump_string(&client_pubkey, "client pubkey");
  //dump_string(&server_pubkey, "server pubkey");
  //dump_string(&shared_secret, "shared secret");
  
  if (ssh_verify_check_signature(&server_host_key, &server_hash_sig, &exchange_hash) < 0) {
    ssh_str_free(&shared_secret);
    return -1;
  }
  ssh_log("* server signature verified\n");
  
  if (dh_kex_recv_newkeys_msg(conn) < 0
      || dh_kex_send_newkeys_msg(conn) < 0) {
    ssh_str_free(&shared_secret);
    ssh_str_free(&exchange_hash);
    return -1;
  }

  return ssh_kex_finish(conn, kex, &shared_secret, &exchange_hash);
}

const struct DH_ALGO *kex_dh_get_algo(enum SSH_KEX_TYPE type)
{
  int i;
  
  for (i = 0; i < sizeof(dh_algos)/sizeof(dh_algos[0]); i++) {
    if (dh_algos[i].type == type)
      return &dh_algos[i];
  }
  ssh_set_error("unknown kex DH type %d", type);
  return NULL;
}

int ssh_kex_dh_run(struct SSH_CONN *conn, struct SSH_KEX *kex)
{
  struct CRYPTO_DH *dh;
  const struct DH_ALGO *dh_algo;

  if ((dh_algo = kex_dh_get_algo(kex->type)) == NULL
      || (dh = crypto_dh_new(dh_algo->gen, dh_algo->modulus)) == NULL)
    return -1;

  if (dh_kex_send_init_msg(dh, conn) < 0
      || dh_kex_read_reply(dh, conn, kex, dh_algo->hash_type) < 0) {
    crypto_dh_free(dh);
    return -1;
  }

  crypto_dh_free(dh);
  return 0;
}
