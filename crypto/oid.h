/* oid.h */

#ifndef CRYPTO_OID_H_FILE
#define CRYPTO_OID_H_FILE

#include "crypto/algorithms.h"
#include "common/buffer.h"

int crypto_oid_get_for_hash(enum SSH_HASH_TYPE hash_type, struct SSH_STRING *out);

#endif /* CRYPTO_OID_H_FILE */
