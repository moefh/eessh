/* pubkey.h */

#ifndef PUBKEY_H_FILE
#define PUBKEY_H_FILE

#include <stdint.h>

#include "crypto/algorithms.h"
#include "common/buffer.h"

enum SSH_PUBKEY_TYPE ssh_pubkey_get_by_name(const char *name);
int ssh_pubkey_verify_signature(enum SSH_PUBKEY_TYPE key_type, struct SSH_STRING *key, struct SSH_STRING *signature, struct SSH_STRING *data);

#endif /* PUBKEY_H_FILE */
