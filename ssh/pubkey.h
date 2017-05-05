/* pubkey.h */

#ifndef PUBKEY_H_FILE
#define PUBKEY_H_FILE

#include <stdint.h>

#include "crypto/algorithms.h"
#include "common/buffer.h"

int ssh_pubkey_verify_signature(struct SSH_STRING *key, struct SSH_STRING *signature, struct SSH_STRING *data);

#endif /* PUBKEY_H_FILE */
