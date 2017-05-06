/* mac.h */

#ifndef MAC_H_FILE
#define MAC_H_FILE

#include <stdint.h>

#include "common/buffer.h"
#include "crypto/algorithms.h"

enum SSH_MAC_TYPE {
  SSH_MAC_NONE,
  SSH_MAC_HMAC_SHA2_256,
  SSH_MAC_HMAC_SHA2_512,

  SSH_MAC_INVALID
};

struct SSH_MAC_CTX;

enum SSH_MAC_TYPE ssh_mac_get_by_name(const char *name);
enum SSH_MAC_TYPE ssh_mac_get_by_name_n(const uint8_t *name, size_t name_len);
enum SSH_MAC_TYPE ssh_mac_get_by_name_str(const struct SSH_STRING *name);
int ssh_mac_get_supported_algos(struct SSH_BUFFER *ret);

int ssh_mac_get_len(enum SSH_MAC_TYPE type);

struct SSH_MAC_CTX *ssh_mac_new(enum SSH_MAC_TYPE type, const struct SSH_STRING *key);
void ssh_mac_free(struct SSH_MAC_CTX *mac);
int ssh_mac_compute(struct SSH_MAC_CTX *mac, uint8_t *out, uint32_t seq_num, const uint8_t *data, uint32_t len);

#endif /* MAC_H_FILE */
