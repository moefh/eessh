/* kex_i.h */

#ifndef KEX_I_H_FILE
#define KEX_I_H_FILE

#include <stdint.h>

#include "common/buffer.h"
#include "crypto/algorithms.h"
#include "ssh/mac_i.h"

enum SSH_KEX_TYPE {
  SSH_KEX_DH_GROUP_1,
  SSH_KEX_DH_GROUP_14,

  SSH_KEX_INVALID
};
struct SSH_KEX {
  uint8_t first_kex_packet_follows;
  enum SSH_KEX_TYPE type;
  enum SSH_HASH_TYPE hash_type;
  enum SSH_PUBKEY_TYPE pubkey_type;  
  enum SSH_CIPHER_TYPE cipher_type_cts;
  enum SSH_CIPHER_TYPE cipher_type_stc;
  enum SSH_MAC_TYPE mac_type_cts;
  enum SSH_MAC_TYPE mac_type_stc;
  struct SSH_STRING shared_secret;
  struct SSH_STRING exchange_hash;
  struct SSH_BUFFER server_kexinit;
  struct SSH_BUFFER client_kexinit;
};

enum SSH_KEX_TYPE ssh_kex_get_by_name_n(const uint8_t *name, size_t len);
enum SSH_KEX_TYPE ssh_kex_get_by_name(const char *name);

struct SSH_CONN;

int ssh_kex_run(struct SSH_CONN *conn);
int ssh_kex_finish(struct SSH_CONN *conn, struct SSH_KEX *kex, struct SSH_STRING *shared_secret, struct SSH_STRING *exchange_hash);

#endif /* KEX_I_H_FILE */
