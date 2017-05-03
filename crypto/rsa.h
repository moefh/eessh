/* rsa.h */

#ifndef CRYPTO_RSA_H_FILE
#define CRYPTO_RSA_H_FILE

#include "common/buffer.h"
#include "crypto/algorithms.h"

int crypto_rsa_verify(enum SSH_HASH_TYPE hash_type, struct SSH_STRING *e, struct SSH_STRING *n, struct SSH_STRING *signature, struct SSH_STRING *data_hash);

#endif /* CRYPTO_RSA_H_FILE */
