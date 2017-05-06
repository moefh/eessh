/* kex_internal.h */

#ifndef KEX_INTERNAL_H_FILE
#define KEX_INTERNAL_H_FILE

#include <stdint.h>

#include "common/buffer.h"

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

int ssh_kex_finish(struct SSH_CONN *conn, struct SSH_KEX *kex, struct SSH_STRING *shared_secret, struct SSH_STRING *exchange_hash);

#endif /* KEX_INTERNAL_H_FILE */
