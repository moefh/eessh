/* pubkey_i.h */

#ifndef PUBKEY_I_H_FILE
#define PUBKEY_I_H_FILE

#include <stdint.h>

#include "crypto/algorithms.h"
#include "common/buffer.h"

enum SSH_PUBKEY_TYPE ssh_pubkey_get_by_name(const char *name);
enum SSH_PUBKEY_TYPE ssh_pubkey_get_by_name_n(const uint8_t *name, size_t name_len);
enum SSH_PUBKEY_TYPE ssh_pubkey_get_by_name_str(const struct SSH_STRING *name);
int ssh_pubkey_get_supported_algos(struct SSH_BUFFER *ret);

int ssh_pubkey_verify_signature(enum SSH_PUBKEY_TYPE key_type, struct SSH_STRING *key, struct SSH_STRING *signature, struct SSH_STRING *data);

#endif /* PUBKEY_I_H_FILE */
